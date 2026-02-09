#pragma once
#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <cstring>
#include <functional>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace WareHound {

// TCP FLAGS
namespace TcpFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
    constexpr uint8_t ECE = 0x40;
    constexpr uint8_t CWR = 0x80;
}

// TCP STATE - For connection tracking
enum class TcpState : uint8_t {
    CLOSED = 0,
    LISTEN,
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT
};

// APPLICATION PROTOCOL - Detected protocol
enum class AppProtocol : uint8_t {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    FTP,
    FTP_DATA,
    SSH,
    TELNET,
    SMTP,
    POP3,
    IMAP,
    DHCP,
    NTP,
    SNMP,
    LDAP,
    SMB,
    RDP,
    MYSQL,
    POSTGRESQL,
    REDIS,
    MONGODB,
    QUIC
};

// FLOW KEY - Unique identifier for a network flow
struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port &&
               protocol == other.protocol;
    }
    
    // Create normalized key (smaller IP first for bidirectional matching)
    FlowKey Normalize() const {
        if (src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port)) {
            return *this;
        }
        return FlowKey{dst_ip, src_ip, dst_port, src_port, protocol};
    }
};


// FLOW KEY HASH
struct FlowKeyHash {
    size_t operator()(const FlowKey& key) const {
        size_t h1 = std::hash<uint32_t>()(key.src_ip);
        size_t h2 = std::hash<uint32_t>()(key.dst_ip);
        size_t h3 = std::hash<uint16_t>()(key.src_port);
        size_t h4 = std::hash<uint16_t>()(key.dst_port);
        size_t h5 = std::hash<uint8_t>()(key.protocol);
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
    }
};

// PARSED PACKET - Result of packet parsing
struct ParsedPacket {
    // Timestamps
    uint64_t timestamp_us = 0;
    
    // Capture info
    uint32_t capture_len = 0;
    uint32_t original_len = 0;
    
    // Ethernet
    uint8_t eth_src[6] = {0};
    uint8_t eth_dst[6] = {0};
    uint16_t eth_type = 0;
    
    // IP
    bool valid_ip = false;
    uint8_t ip_version = 0;
    uint8_t ip_header_len = 0;
    uint8_t ip_tos = 0;
    uint16_t ip_total_len = 0;
    uint16_t ip_id = 0;
    uint8_t ip_ttl = 0;
    uint8_t ip_protocol = 0;
    uint32_t ip_src = 0;
    uint32_t ip_dst = 0;
    
    // Transport
    bool valid_transport = false;
    
    // TCP specific
    uint16_t tcp_src_port = 0;
    uint16_t tcp_dst_port = 0;
    uint32_t tcp_seq = 0;
    uint32_t tcp_ack = 0;
    uint8_t tcp_header_len = 0;
    uint8_t tcp_flags = 0;
    uint16_t tcp_window = 0;
    
    // UDP specific
    uint16_t udp_src_port = 0;
    uint16_t udp_dst_port = 0;
    uint16_t udp_len = 0;
    
    // Payload
    const uint8_t* payload = nullptr;
    uint16_t payload_len = 0;
    
    // Convert to flow key
    FlowKey ToFlowKey() const {
        FlowKey key;
        key.src_ip = ip_src;
        key.dst_ip = ip_dst;
        key.protocol = ip_protocol;
        
        if (ip_protocol == IPPROTO_TCP) {
            key.src_port = tcp_src_port;
            key.dst_port = tcp_dst_port;
        } else if (ip_protocol == IPPROTO_UDP) {
            key.src_port = udp_src_port;
            key.dst_port = udp_dst_port;
        } else {
            key.src_port = 0;
            key.dst_port = 0;
        }
        
        return key.Normalize();
    }
};


// PACKET PARSER - Parse raw packet data
class PacketParser {
public:
    static bool Parse(const uint8_t* data, uint32_t len, uint64_t timestamp_us, 
                      ParsedPacket& result) 
    {
        if (data == nullptr || len < 14) {
            return false;
        }
        
        result.timestamp_us = timestamp_us;
        result.capture_len = len;
        result.original_len = len;
        
        // Parse Ethernet header (14 bytes)
        memcpy(result.eth_dst, data, 6);
        memcpy(result.eth_src, data + 6, 6);
        result.eth_type = (data[12] << 8) | data[13];
        
        const uint8_t* ip_data = data + 14;
        uint32_t remaining = len - 14;
        
        // Handle VLAN tagging (802.1Q)
        if (result.eth_type == 0x8100 && remaining >= 4) {
            result.eth_type = (ip_data[2] << 8) | ip_data[3];
            ip_data += 4;
            remaining -= 4;
        }
        
        // Only handle IPv4 for now
        if (result.eth_type != 0x0800 || remaining < 20) {
            return true;  // Valid Ethernet but not IP
        }
        
        // Parse IP header
        result.ip_version = (ip_data[0] >> 4) & 0x0F;
        result.ip_header_len = (ip_data[0] & 0x0F) * 4;
        
        if (result.ip_version != 4 || result.ip_header_len < 20 || 
            remaining < result.ip_header_len) {
            return true;
        }
        
        result.valid_ip = true;
        result.ip_tos = ip_data[1];
        result.ip_total_len = (ip_data[2] << 8) | ip_data[3];
        result.ip_id = (ip_data[4] << 8) | ip_data[5];
        result.ip_ttl = ip_data[8];
        result.ip_protocol = ip_data[9];
        memcpy(&result.ip_src, ip_data + 12, 4);
        memcpy(&result.ip_dst, ip_data + 16, 4);
        
        const uint8_t* transport_data = ip_data + result.ip_header_len;
        remaining -= result.ip_header_len;
        
        // Parse TCP
        if (result.ip_protocol == IPPROTO_TCP && remaining >= 20) {
            result.valid_transport = true;
            result.tcp_src_port = (transport_data[0] << 8) | transport_data[1];
            result.tcp_dst_port = (transport_data[2] << 8) | transport_data[3];
            result.tcp_seq = (transport_data[4] << 24) | (transport_data[5] << 16) |
                            (transport_data[6] << 8) | transport_data[7];
            result.tcp_ack = (transport_data[8] << 24) | (transport_data[9] << 16) |
                            (transport_data[10] << 8) | transport_data[11];
            result.tcp_header_len = ((transport_data[12] >> 4) & 0x0F) * 4;
            result.tcp_flags = transport_data[13];
            result.tcp_window = (transport_data[14] << 8) | transport_data[15];
            
            if (remaining > result.tcp_header_len) {
                result.payload = transport_data + result.tcp_header_len;
                result.payload_len = static_cast<uint16_t>(remaining - result.tcp_header_len);
            }
        }
        // Parse UDP
        else if (result.ip_protocol == IPPROTO_UDP && remaining >= 8) {
            result.valid_transport = true;
            result.udp_src_port = (transport_data[0] << 8) | transport_data[1];
            result.udp_dst_port = (transport_data[2] << 8) | transport_data[3];
            result.udp_len = (transport_data[4] << 8) | transport_data[5];
            
            if (remaining > 8) {
                result.payload = transport_data + 8;
                result.payload_len = static_cast<uint16_t>(remaining - 8);
            }
        }
        
        return true;
    }
};

} 

#endif 
