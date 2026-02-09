#pragma once
#ifndef FLOW_TRACKER_H
#define FLOW_TRACKER_H

#include "FlowTable.h"
#include "PacketParser.h"
#include "ProtocolDetector.h"
#include <memory>
#include <iostream>
#include <chrono>
#include <pcap.h>

namespace WareHound {

// FLOW TRACKER  
// Coordinates:
// - PacketParser (packet parsing)
// - FlowTable (flow storage)
// - TCP State Machine (connection tracking)
// - ProtocolDetector (application protocol detection)

class FlowTracker {
public:

    struct Config {
        size_t table_size = FlowTable::DEFAULT_TABLE_SIZE;
        size_t max_flows = FlowTable::DEFAULT_MAX_FLOWS;
        uint64_t flow_timeout_us = 300 * 1000000ULL;  // 5 minutes
        uint64_t cleanup_interval_us = 60 * 1000000ULL;  // 1 minute
        bool collect_payload = false;
        size_t max_payload_size = 65536;
    };
    
    // Pre-computed aggregate statistics (updated atomically during packet processing)
    struct AggregateStats {
        std::atomic<uint64_t> total_tcp_packets{0};
        std::atomic<uint64_t> total_udp_packets{0};
        std::atomic<uint64_t> total_tcp_bytes{0};
        std::atomic<uint64_t> total_udp_bytes{0};
        std::atomic<uint32_t> unique_protocols{0};
        std::atomic<uint64_t> established_flows{0};
        std::atomic<uint64_t> closed_flows{0};
    };
    
    explicit FlowTracker(const Config& config = Config())
        : config_(config)
        , flow_table_(config.table_size, config.max_flows)
        , last_cleanup_us_(0)
        , packets_processed_(0)
        , bytes_processed_(0)
        , start_time_us_(0)
        , aggregate_stats_()
    {
    }
    
    // PROCESS PACKET 
    FlowEntry* ProcessPacket(const uint8_t* raw_data, uint32_t len,
                              uint64_t timestamp_us) 
    {
        if (start_time_us_ == 0) {
            start_time_us_ = timestamp_us;
        }
        
        packets_processed_++;
        bytes_processed_ += len;
        
        // 1. Parse packet
        ParsedPacket parsed;
        if (!PacketParser::Parse(raw_data, len, timestamp_us, parsed)) {
            return nullptr;
        }
        
        // 2. Check for valid IP and transport layer
        if (!parsed.valid_ip || !parsed.valid_transport) {
            return nullptr;
        }
        
        // 3. Only TCP and UDP support flows
        if (parsed.ip_protocol != IPPROTO_TCP && parsed.ip_protocol != IPPROTO_UDP) {
            return nullptr;
        }
        
        // 4. Create flow key
        FlowKey key = parsed.ToFlowKey();
        
        // 5. Lookup or create flow
        bool created = false;
        FlowEntry* flow = flow_table_.LookupOrCreate(key, timestamp_us, &created);
        
        if (flow == nullptr) {
            return nullptr;
        }
        
        // 6. Determine packet direction
        bool to_server = flow->IsToServer(key);
        
        // 7. Update statistics
        UpdateFlowStats(flow, parsed, to_server);
        
        // 7a. Update aggregate stats atomically (no lock needed)
        if (parsed.ip_protocol == IPPROTO_TCP) {
            aggregate_stats_.total_tcp_packets.fetch_add(1, std::memory_order_relaxed);
            aggregate_stats_.total_tcp_bytes.fetch_add(len, std::memory_order_relaxed);
        } else if (parsed.ip_protocol == IPPROTO_UDP) {
            aggregate_stats_.total_udp_packets.fetch_add(1, std::memory_order_relaxed);
            aggregate_stats_.total_udp_bytes.fetch_add(len, std::memory_order_relaxed);
        }
        
        // 8. Update TCP state machine (if TCP)
        if (parsed.ip_protocol == IPPROTO_TCP) {
            TcpState prev_state = flow->stats.tcp_state;
            UpdateTcpState(flow, parsed, to_server);
            TcpState new_state = flow->stats.tcp_state;
            
            // Track state transitions for aggregate stats
            if (prev_state != TcpState::ESTABLISHED && new_state == TcpState::ESTABLISHED) {
                aggregate_stats_.established_flows.fetch_add(1, std::memory_order_relaxed);
            } else if (prev_state != TcpState::CLOSED && new_state == TcpState::CLOSED) {
                aggregate_stats_.closed_flows.fetch_add(1, std::memory_order_relaxed);
            }
        }
        
        // 9. Detect application protocol (if not yet detected)
        if (flow->stats.app_protocol == AppProtocol::UNKNOWN) {
            uint8_t confidence = 0;
            AppProtocol proto = ProtocolDetector::Detect(parsed, &confidence);
            if (proto != AppProtocol::UNKNOWN) {
                flow->stats.app_protocol = proto;
                flow->stats.app_confidence = confidence;
                
                // Update protocol statistics atomically
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    if (protocol_counts_.find(static_cast<int>(proto)) == protocol_counts_.end()) {
                        aggregate_stats_.unique_protocols.fetch_add(1, std::memory_order_relaxed);
                    }
                    protocol_counts_[static_cast<int>(proto)]++;
                }
            }
        }
        
        // 10. Collect payload (if enabled)
        if (config_.collect_payload && parsed.payload && parsed.payload_len > 0) {
            flow->payload_collection_enabled = true;
            flow->payload_max_size = config_.max_payload_size;
            flow->AppendPayload(parsed.payload, parsed.payload_len, to_server);
        }
        
        // 11. Periodic cleanup of expired flows
        MaybeCleanup(timestamp_us);
        
        return flow;
    }
    

    // PROCESS PACKET (with pcap header) - Convenience wrapper
    FlowEntry* ProcessPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
        if (pkthdr == nullptr || packet == nullptr) {
            return nullptr;
        }
        
        uint64_t timestamp_us = static_cast<uint64_t>(pkthdr->ts.tv_sec) * 1000000 + 
                                pkthdr->ts.tv_usec;
        
        return ProcessPacket(packet, pkthdr->caplen, timestamp_us);
    }
    

    FlowTable& GetFlowTable() { return flow_table_; }
    const FlowTable& GetFlowTable() const { return flow_table_; }
    
    size_t GetFlowCount() const { return flow_table_.GetFlowCount(); }
    uint64_t GetPacketsProcessed() const { return packets_processed_; }
    uint64_t GetBytesProcessed() const { return bytes_processed_; }
    
    // Get pre-computed aggregate stats (lock-free, atomic reads)
    const AggregateStats& GetAggregateStats() const { return aggregate_stats_; }
    
    uint64_t GetTcpPackets() const { return aggregate_stats_.total_tcp_packets.load(std::memory_order_relaxed); }
    uint64_t GetUdpPackets() const { return aggregate_stats_.total_udp_packets.load(std::memory_order_relaxed); }
    uint64_t GetTcpBytes() const { return aggregate_stats_.total_tcp_bytes.load(std::memory_order_relaxed); }
    uint64_t GetUdpBytes() const { return aggregate_stats_.total_udp_bytes.load(std::memory_order_relaxed); }
    uint32_t GetUniqueProtocolCount() const { return aggregate_stats_.unique_protocols.load(std::memory_order_relaxed); }
    uint64_t GetEstablishedFlows() const { return aggregate_stats_.established_flows.load(std::memory_order_relaxed); }
    uint64_t GetClosedFlows() const { return aggregate_stats_.closed_flows.load(std::memory_order_relaxed); }
    
    // GET PROTOCOL COUNTS - For statistics
    void GetProtocolCounts(int* counts, int max_count) const {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        int copy_count = (std::min)(max_count, static_cast<int>(protocol_counts_.size()));
        for (int i = 0; i < copy_count; i++) {
            auto it = protocol_counts_.find(i);
            counts[i] = (it != protocol_counts_.end()) ? static_cast<int>(it->second) : 0;
        }
    }
    
    // GET CAPTURE DURATION - In seconds
    double GetCaptureDurationSeconds() const {
        if (start_time_us_ == 0) return 0.0;
        auto now = std::chrono::steady_clock::now();
        auto start = std::chrono::steady_clock::time_point(
            std::chrono::microseconds(start_time_us_));
        return std::chrono::duration<double>(now - start).count();
    }
    

    // FORCE CLEANUP - Manual cleanup trigger
    size_t ForceCleanup(uint64_t current_time_us) {
        return flow_table_.CleanupExpired(current_time_us, config_.flow_timeout_us);
    }
    
    // CLEAR - Clear all flows and reset statistics
    void Clear() {
        flow_table_.Clear();
        packets_processed_ = 0;
        bytes_processed_ = 0;
        start_time_us_ = 0;
        
        // Reset aggregate stats
        aggregate_stats_.total_tcp_packets.store(0, std::memory_order_relaxed);
        aggregate_stats_.total_udp_packets.store(0, std::memory_order_relaxed);
        aggregate_stats_.total_tcp_bytes.store(0, std::memory_order_relaxed);
        aggregate_stats_.total_udp_bytes.store(0, std::memory_order_relaxed);
        aggregate_stats_.unique_protocols.store(0, std::memory_order_relaxed);
        aggregate_stats_.established_flows.store(0, std::memory_order_relaxed);
        aggregate_stats_.closed_flows.store(0, std::memory_order_relaxed);
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        protocol_counts_.clear();
    }
    
    // PRINT STATS - Debug output
    void PrintStats() const {
        std::cout << "[FlowTracker Stats]" << std::endl;
        std::cout << "  Packets processed: " << packets_processed_ << std::endl;
        std::cout << "  Bytes processed: " << bytes_processed_ << std::endl;
        flow_table_.PrintStats();
    }

private:
    Config config_;
    FlowTable flow_table_;
    uint64_t last_cleanup_us_;
    std::atomic<uint64_t> packets_processed_;
    std::atomic<uint64_t> bytes_processed_;
    uint64_t start_time_us_;
    
    mutable std::mutex stats_mutex_;
    std::unordered_map<int, uint64_t> protocol_counts_;
    
    // Pre-computed aggregate statistics (lock-free)
    AggregateStats aggregate_stats_;
    

    // UPDATE FLOW STATS - Update counters
    void UpdateFlowStats(FlowEntry* flow, const ParsedPacket& parsed, bool to_server) {
        FlowStats& stats = flow->stats;
        
        // Timestamps
        stats.last_seen_us = parsed.timestamp_us;
        
        // Directional counters
        if (to_server) {
            stats.packets_to_server++;
            stats.bytes_to_server += parsed.capture_len;
        } else {
            stats.packets_to_client++;
            stats.bytes_to_client += parsed.capture_len;
        }
        
        // TCP window size
        if (parsed.ip_protocol == IPPROTO_TCP) {
            if (to_server) {
                stats.tcp_window_client = parsed.tcp_window;
            } else {
                stats.tcp_window_server = parsed.tcp_window;
            }
        }
    }
    

    // UPDATE TCP STATE - TCP state machine
    void UpdateTcpState(FlowEntry* flow, const ParsedPacket& parsed, bool to_server) {
        FlowStats& stats = flow->stats;
        uint8_t flags = parsed.tcp_flags;
        
        bool syn = (flags & TcpFlags::SYN) != 0;
        bool ack = (flags & TcpFlags::ACK) != 0;
        bool fin = (flags & TcpFlags::FIN) != 0;
        bool rst = (flags & TcpFlags::RST) != 0;
        
        // Update flags
        if (syn) stats.has_syn = true;
        if (syn && ack) stats.has_syn_ack = true;
        if (fin) stats.has_fin = true;
        if (rst) stats.has_rst = true;
        
        // RST always closes connection
        if (rst) {
            stats.tcp_state = TcpState::CLOSED;
            return;
        }
        
        // Save seq/ack numbers
        if (to_server) {
            stats.tcp_ack_client = parsed.tcp_ack;
            if (syn && !ack) {
                stats.tcp_seq_client = parsed.tcp_seq;
            }
        } else {
            stats.tcp_ack_server = parsed.tcp_ack;
            if (syn && ack) {
                stats.tcp_seq_server = parsed.tcp_seq;
            }
        }
        
        // State machine transitions
        switch (stats.tcp_state) {
            case TcpState::CLOSED:
                if (syn && !ack) {
                    stats.tcp_state = TcpState::SYN_SENT;
                }
                break;
                
            case TcpState::SYN_SENT:
                if (syn && ack) {
                    stats.tcp_state = TcpState::SYN_RCVD;
                }
                break;
                
            case TcpState::SYN_RCVD:
                if (ack && !syn && !fin) {
                    stats.tcp_state = TcpState::ESTABLISHED;
                }
                break;
                
            case TcpState::ESTABLISHED:
                if (fin) {
                    if (to_server) {
                        stats.tcp_state = TcpState::FIN_WAIT_1;
                    } else {
                        stats.tcp_state = TcpState::CLOSE_WAIT;
                    }
                }
                break;
                
            case TcpState::FIN_WAIT_1:
                if (fin && ack) {
                    stats.tcp_state = TcpState::TIME_WAIT;
                } else if (ack && !fin) {
                    stats.tcp_state = TcpState::FIN_WAIT_2;
                } else if (fin && !ack) {
                    stats.tcp_state = TcpState::CLOSING;
                }
                break;
                
            case TcpState::FIN_WAIT_2:
                if (fin) {
                    stats.tcp_state = TcpState::TIME_WAIT;
                }
                break;
                
            case TcpState::CLOSE_WAIT:
                if (fin) {
                    stats.tcp_state = TcpState::LAST_ACK;
                }
                break;
                
            case TcpState::CLOSING:
                if (ack) {
                    stats.tcp_state = TcpState::TIME_WAIT;
                }
                break;
                
            case TcpState::LAST_ACK:
                if (ack) {
                    stats.tcp_state = TcpState::CLOSED;
                }
                break;
                
            case TcpState::TIME_WAIT:
                break;
                
            default:
                break;
        }
    }
    

    void MaybeCleanup(uint64_t current_time_us) {
        if (current_time_us - last_cleanup_us_ > config_.cleanup_interval_us) {
            flow_table_.CleanupExpired(current_time_us, config_.flow_timeout_us);
            last_cleanup_us_ = current_time_us;
        }
    }
};

} 

#endif 
