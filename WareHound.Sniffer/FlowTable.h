#pragma once
#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include "PacketParser.h"
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <atomic>
#include <iostream>
#include <algorithm>
#include <functional>

namespace WareHound {

struct FlowStats {
    uint64_t first_seen_us = 0;
    uint64_t last_seen_us = 0;
    
    // Packet counts
    uint64_t packets_to_server = 0;
    uint64_t packets_to_client = 0;
    
    // Byte counts
    uint64_t bytes_to_server = 0;
    uint64_t bytes_to_client = 0;
    
    // TCP state
    TcpState tcp_state = TcpState::CLOSED;
    uint32_t tcp_seq_client = 0;
    uint32_t tcp_seq_server = 0;
    uint32_t tcp_ack_client = 0;
    uint32_t tcp_ack_server = 0;
    uint16_t tcp_window_client = 0;
    uint16_t tcp_window_server = 0;
    
    // TCP flags seen
    bool has_syn = false;
    bool has_syn_ack = false;
    bool has_fin = false;
    bool has_rst = false;
    
    // Application protocol
    AppProtocol app_protocol = AppProtocol::UNKNOWN;
    uint8_t app_confidence = 0;
    
    // Total packets and bytes
    uint64_t TotalPackets() const { return packets_to_server + packets_to_client; }
    uint64_t TotalBytes() const { return bytes_to_server + bytes_to_client; }
};


// FLOW ENTRY - Single flow in the table
struct FlowEntry {
    FlowKey key;
    FlowStats stats;
    bool active = true;
    
    // Payload collection (optional)
    bool payload_collection_enabled = false;
    size_t payload_max_size = 65536;
    std::vector<uint8_t> payload_to_server;
    std::vector<uint8_t> payload_to_client;
    
    FlowEntry() = default;
    explicit FlowEntry(const FlowKey& k) : key(k) {}
    
    // Determine if packet is going to server (original direction)
    bool IsToServer(const FlowKey& pkt_key) const {
        return pkt_key.src_ip == key.src_ip && pkt_key.src_port == key.src_port;
    }
    
    // Append payload data
    void AppendPayload(const uint8_t* data, uint16_t len, bool to_server) {
        if (!payload_collection_enabled || data == nullptr || len == 0) return;
        
        auto& buffer = to_server ? payload_to_server : payload_to_client;
        size_t remaining = payload_max_size - buffer.size();
        size_t to_copy = (std::min)(static_cast<size_t>(len), remaining);
        
        if (to_copy > 0) {
            buffer.insert(buffer.end(), data, data + to_copy);
        }
    }
};

// FLOW TABLE - Hash table for storing flows
class FlowTable {
public:
    static constexpr size_t DEFAULT_TABLE_SIZE = 65536;
    static constexpr size_t DEFAULT_MAX_FLOWS = 100000;
    
    FlowTable(size_t table_size = DEFAULT_TABLE_SIZE, size_t max_flows = DEFAULT_MAX_FLOWS)
        : max_flows_(max_flows)
        , flow_count_(0)
        , total_lookups_(0)
        , total_insertions_(0)
    {
        flows_.reserve(table_size);
    }
    
    // LOOKUP OR CREATE - Find existing flow or create new one
    FlowEntry* LookupOrCreate(const FlowKey& key, uint64_t timestamp_us, bool* created = nullptr) {
        std::unique_lock<std::shared_mutex> lock(mutex_);  // Exclusive lock for write
        total_lookups_++;
        
        auto it = flows_.find(key);
        if (it != flows_.end()) {
            if (created) *created = false;
            return &it->second;
        }
        
        // Check capacity
        if (flows_.size() >= max_flows_) {
            if (created) *created = false;
            return nullptr;
        }
        
        // Create new flow
        FlowEntry entry(key);
        entry.stats.first_seen_us = timestamp_us;
        entry.stats.last_seen_us = timestamp_us;
        
        auto result = flows_.emplace(key, std::move(entry));
        total_insertions_++;
        flow_count_++;
        
        if (created) *created = true;
        return &result.first->second;
    }
    
    // LOOKUP - Find existing flow (no creation)
    FlowEntry* Lookup(const FlowKey& key) {
        std::shared_lock<std::shared_mutex> lock(mutex_);  // Shared lock for read
        total_lookups_++;
        
        auto it = flows_.find(key);
        return (it != flows_.end()) ? &it->second : nullptr;
    }
    
    // CLEANUP EXPIRED - Remove flows older than timeout
    size_t CleanupExpired(uint64_t current_time_us, uint64_t timeout_us) {
        std::unique_lock<std::shared_mutex> lock(mutex_);  // Exclusive lock for write
        size_t removed = 0;
        
        for (auto it = flows_.begin(); it != flows_.end(); ) {
            if (current_time_us - it->second.stats.last_seen_us > timeout_us) {
                it = flows_.erase(it);
                removed++;
                flow_count_--;
            } else {
                ++it;
            }
        }
        
        return removed;
    }
    
    // CLEAR - Remove all flows
    void Clear() {
        std::unique_lock<std::shared_mutex> lock(mutex_);  // Exclusive lock for write
        flows_.clear();
        flow_count_ = 0;
    }
    

    size_t GetFlowCount() const { return flow_count_; }
    size_t GetMaxFlows() const { return max_flows_; }
    uint64_t GetTotalLookups() const { return total_lookups_; }
    uint64_t GetTotalInsertions() const { return total_insertions_; }
    
    std::vector<FlowEntry> GetAllFlows() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);  // Shared lock for read
        std::vector<FlowEntry> result;
        result.reserve(flows_.size());
        
        for (const auto& pair : flows_) {
            result.push_back(pair.second);
        }
        
        return result;
    }
    
    template<typename Comparator>
    std::vector<FlowEntry> GetTopFlows(size_t topN, Comparator comp) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);  // Shared lock for read
        
        if (flows_.empty()) {
            return {};
        }
        
        // Collect pointers to avoid copying all flows
        std::vector<const FlowEntry*> flowPtrs;
        flowPtrs.reserve(flows_.size());
        for (const auto& pair : flows_) {
            flowPtrs.push_back(&pair.second);
        }
        
        // Partial sort to get top N
        size_t n = (std::min)(topN, flowPtrs.size());
        std::partial_sort(flowPtrs.begin(), flowPtrs.begin() + n, flowPtrs.end(),
            [&comp](const FlowEntry* a, const FlowEntry* b) {
                return comp(*a, *b);
            });
        
        // Copy only top N flows
        std::vector<FlowEntry> result;
        result.reserve(n);
        for (size_t i = 0; i < n; i++) {
            result.push_back(*flowPtrs[i]);
        }
        
        return result;
    }
    
    // Convenience method: Get top flows by total packets
    std::vector<FlowEntry> GetTopFlowsByPackets(size_t topN) const {
        return GetTopFlows(topN, [](const FlowEntry& a, const FlowEntry& b) {
            return a.stats.TotalPackets() > b.stats.TotalPackets();
        });
    }
    
    // Convenience method: Get top flows by total bytes
    std::vector<FlowEntry> GetTopFlowsByBytes(size_t topN) const {
        return GetTopFlows(topN, [](const FlowEntry& a, const FlowEntry& b) {
            return a.stats.TotalBytes() > b.stats.TotalBytes();
        });
    }
    
    // Convenience method: Get top flows by last activity
    std::vector<FlowEntry> GetTopFlowsByActivity(size_t topN) const {
        return GetTopFlows(topN, [](const FlowEntry& a, const FlowEntry& b) {
            return a.stats.last_seen_us > b.stats.last_seen_us;
        });
    }
    
    // AGGREGATE STATS - Compute aggregate stats without copying flows
    struct AggregatedFlowStats {
        uint64_t total_packets = 0;
        uint64_t total_bytes = 0;
        std::unordered_map<int, uint64_t> protocol_counts;  // AppProtocol -> packet count
        std::unordered_map<int, uint64_t> protocol_bytes;   // AppProtocol -> byte count
    };
    
    AggregatedFlowStats GetAggregatedStats() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);  // Shared lock for read
        
        AggregatedFlowStats stats;
        for (const auto& pair : flows_) {
            const FlowEntry& flow = pair.second;
            uint64_t packets = flow.stats.TotalPackets();
            uint64_t bytes = flow.stats.TotalBytes();
            
            stats.total_packets += packets;
            stats.total_bytes += bytes;
            
            int proto = static_cast<int>(flow.stats.app_protocol);
            stats.protocol_counts[proto] += packets;
            stats.protocol_bytes[proto] += bytes;
        }
        
        return stats;
    }
    
    // PRINT STATS - Debug output
    void PrintStats() const {
        std::cout << "  Active flows: " << flow_count_ << std::endl;
        std::cout << "  Max flows: " << max_flows_ << std::endl;
        std::cout << "  Total lookups: " << total_lookups_ << std::endl;
        std::cout << "  Total insertions: " << total_insertions_ << std::endl;
    }

private:
    std::unordered_map<FlowKey, FlowEntry, FlowKeyHash> flows_;
    mutable std::shared_mutex mutex_;  // Shared mutex for concurrent reads
    size_t max_flows_;
    std::atomic<size_t> flow_count_;
    std::atomic<uint64_t> total_lookups_;
    std::atomic<uint64_t> total_insertions_;
};

} // namespace WareHound

#endif // FLOW_TABLE_H
