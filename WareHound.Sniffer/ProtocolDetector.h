#pragma once
#ifndef PROTOCOL_DETECTOR_H
#define PROTOCOL_DETECTOR_H

#include "PacketParser.h"
#include <cstring>
#include <cstdint>

namespace WareHound {

class ProtocolDetector {
public:
    
    // DETECT - Main detection function
    static AppProtocol Detect(const ParsedPacket& packet, uint8_t* confidence = nullptr) {
        AppProtocol result = AppProtocol::UNKNOWN;
        uint8_t conf = 0;
        
        // Method 1: By port (fast)
        result = DetectByPort(packet, &conf);
        
        // Method 2: By signature (if payload exists and port detection uncertain)
        if (packet.payload != nullptr && packet.payload_len > 0) {
            uint8_t sig_conf = 0;
            AppProtocol sig_result = DetectBySignature(packet.payload, packet.payload_len, &sig_conf);
            
            // Signature has priority if found
            if (sig_result != AppProtocol::UNKNOWN && sig_conf >= conf) {
                result = sig_result;
                conf = sig_conf;
            }
        }
        
        if (confidence) *confidence = conf;
        return result;
    }
    
    //=========================================================================
    // DETECT BY PORT - Detection by port number
    //=========================================================================
    static AppProtocol DetectByPort(const ParsedPacket& packet, uint8_t* confidence = nullptr) {
        uint16_t port = 0;
        
        if (packet.ip_protocol == IPPROTO_TCP) {
            port = (std::min)(packet.tcp_src_port, packet.tcp_dst_port);
        } else if (packet.ip_protocol == IPPROTO_UDP) {
            port = (std::min)(packet.udp_src_port, packet.udp_dst_port);
        }
        
        if (confidence) *confidence = 70;  // Default 70% confidence for port
        
        // Well-known ports
        switch (port) {
            case 20:   if (confidence) *confidence = 80; return AppProtocol::FTP_DATA;
            case 21:   if (confidence) *confidence = 90; return AppProtocol::FTP;
            case 22:   if (confidence) *confidence = 90; return AppProtocol::SSH;
            case 23:   if (confidence) *confidence = 80; return AppProtocol::TELNET;
            case 25:   if (confidence) *confidence = 85; return AppProtocol::SMTP;
            case 53:   if (confidence) *confidence = 95; return AppProtocol::DNS;
            case 67:
            case 68:   if (confidence) *confidence = 95; return AppProtocol::DHCP;
            case 80:   if (confidence) *confidence = 85; return AppProtocol::HTTP;
            case 110:  if (confidence) *confidence = 85; return AppProtocol::POP3;
            case 123:  if (confidence) *confidence = 95; return AppProtocol::NTP;
            case 143:  if (confidence) *confidence = 85; return AppProtocol::IMAP;
            case 161:
            case 162:  if (confidence) *confidence = 90; return AppProtocol::SNMP;
            case 389:  if (confidence) *confidence = 85; return AppProtocol::LDAP;
            case 443:  if (confidence) *confidence = 90; return AppProtocol::HTTPS;
            case 445:  if (confidence) *confidence = 90; return AppProtocol::SMB;
            case 3306: if (confidence) *confidence = 85; return AppProtocol::MYSQL;
            case 3389: if (confidence) *confidence = 90; return AppProtocol::RDP;
            case 5432: if (confidence) *confidence = 85; return AppProtocol::POSTGRESQL;
            case 6379: if (confidence) *confidence = 85; return AppProtocol::REDIS;
            case 27017: if (confidence) *confidence = 85; return AppProtocol::MONGODB;
            
            // Alternative HTTP ports
            case 8080:
            case 8443:
            case 8000:
            case 3000: if (confidence) *confidence = 60; return AppProtocol::HTTP;
            
            default:
                if (confidence) *confidence = 0;
                return AppProtocol::UNKNOWN;
        }
    }
    
 
    // DETECT BY SIGNATURE - Detection by payload signature
    static AppProtocol DetectBySignature(const uint8_t* payload, uint16_t len, 
                                          uint8_t* confidence = nullptr) 
    {
        if (payload == nullptr || len < 2) {
            if (confidence) *confidence = 0;
            return AppProtocol::UNKNOWN;
        }
        
        if (confidence) *confidence = 95;  // Signatures are usually accurate
        
        //---------------------------------------------------------------------
        // HTTP Request
        //---------------------------------------------------------------------
        if (len >= 4) {
            if (memcmp(payload, "GET ", 4) == 0 ||
                memcmp(payload, "POST", 4) == 0 ||
                memcmp(payload, "HEAD", 4) == 0 ||
                memcmp(payload, "PUT ", 4) == 0 ||
                memcmp(payload, "DELE", 4) == 0 ||  // DELETE
                memcmp(payload, "OPTI", 4) == 0 ||  // OPTIONS
                memcmp(payload, "PATC", 4) == 0 ||  // PATCH
                memcmp(payload, "CONN", 4) == 0) {  // CONNECT
                return AppProtocol::HTTP;
            }
        }
        
        //---------------------------------------------------------------------
        // HTTP Response
        //---------------------------------------------------------------------
        if (len >= 8) {
            if (memcmp(payload, "HTTP/1.", 7) == 0 ||
                memcmp(payload, "HTTP/2", 6) == 0) {
                return AppProtocol::HTTP;
            }
        }
        
        //---------------------------------------------------------------------
        // TLS/SSL Handshake
        //---------------------------------------------------------------------
        if (len >= 3) {
            // ContentType: Handshake (0x16), Version: SSL 3.0+ (0x03 0x0x)
            if (payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x04) {
                return AppProtocol::HTTPS;
            }
            // TLS Application Data (0x17)
            if (payload[0] == 0x17 && payload[1] == 0x03 && payload[2] <= 0x04) {
                return AppProtocol::HTTPS;
            }
            // TLS Alert (0x15)
            if (payload[0] == 0x15 && payload[1] == 0x03 && payload[2] <= 0x04) {
                return AppProtocol::HTTPS;
            }
        }
        
        //---------------------------------------------------------------------
        // SSH
        //---------------------------------------------------------------------
        if (len >= 4) {
            if (memcmp(payload, "SSH-", 4) == 0) {
                return AppProtocol::SSH;
            }
        }
        
        //---------------------------------------------------------------------
        // DNS (UDP typically, but also TCP)
        //---------------------------------------------------------------------
        if (len >= 12) {
            // DNS header: Transaction ID (2), Flags (2), Questions (2), etc.
            uint16_t flags = (payload[2] << 8) | payload[3];
            uint8_t opcode = (flags >> 11) & 0x0F;
            uint16_t qdcount = (payload[4] << 8) | payload[5];
            
            // Standard query (0), inverse query (1), or status (2)
            if (opcode <= 2 && qdcount > 0 && qdcount < 100) {
                if (confidence) *confidence = 80;
                return AppProtocol::DNS;
            }
        }
        
        //---------------------------------------------------------------------
        // SMTP
        //---------------------------------------------------------------------
        if (len >= 4) {
            if (memcmp(payload, "EHLO", 4) == 0 ||
                memcmp(payload, "HELO", 4) == 0 ||
                memcmp(payload, "MAIL", 4) == 0 ||
                memcmp(payload, "RCPT", 4) == 0 ||
                memcmp(payload, "DATA", 4) == 0 ||
                memcmp(payload, "QUIT", 4) == 0 ||
                memcmp(payload, "220 ", 4) == 0 ||
                memcmp(payload, "250 ", 4) == 0) {
                return AppProtocol::SMTP;
            }
        }
        
        //---------------------------------------------------------------------
        // FTP
        //---------------------------------------------------------------------
        if (len >= 4) {
            if (memcmp(payload, "USER", 4) == 0 ||
                memcmp(payload, "PASS", 4) == 0 ||
                memcmp(payload, "LIST", 4) == 0 ||
                memcmp(payload, "RETR", 4) == 0 ||
                memcmp(payload, "STOR", 4) == 0 ||
                memcmp(payload, "220-", 4) == 0 ||
                memcmp(payload, "220 ", 4) == 0 ||
                memcmp(payload, "230 ", 4) == 0 ||
                memcmp(payload, "331 ", 4) == 0) {
                return AppProtocol::FTP;
            }
        }
        
        //---------------------------------------------------------------------
        // MySQL
        //---------------------------------------------------------------------
        if (len >= 5) {
            uint32_t pkt_len = payload[0] | (payload[1] << 8) | (payload[2] << 16);
            if (payload[3] == 0 && pkt_len < 0xFFFFFF && len >= pkt_len + 4) {
                if (memcmp(payload + 5, "5.", 2) == 0 ||
                    memcmp(payload + 5, "8.", 2) == 0 ||
                    memcmp(payload + 5, "10.", 3) == 0) {  // MariaDB
                    return AppProtocol::MYSQL;
                }
            }
        }
        
        //---------------------------------------------------------------------
        // Redis
        //---------------------------------------------------------------------
        if (len >= 1) {
            // Redis RESP protocol starts with +, -, :, $, *
            if (payload[0] == '+' || payload[0] == '-' || 
                payload[0] == ':' || payload[0] == '$' || payload[0] == '*') {
                for (uint16_t i = 1; i < len - 1; ++i) {
                    if (payload[i] == '\r' && payload[i+1] == '\n') {
                        if (confidence) *confidence = 70;
                        return AppProtocol::REDIS;
                    }
                }
            }
        }
        
        //---------------------------------------------------------------------
        // SMB
        //---------------------------------------------------------------------
        if (len >= 4) {
            // SMB header: 0xFF 'S' 'M' 'B' (SMB1) or 0xFE 'S' 'M' 'B' (SMB2)
            if ((payload[0] == 0xFF || payload[0] == 0xFE) &&
                payload[1] == 'S' && payload[2] == 'M' && payload[3] == 'B') {
                return AppProtocol::SMB;
            }
        }
        
        //---------------------------------------------------------------------
        // Not detected
        //---------------------------------------------------------------------
        if (confidence) *confidence = 0;
        return AppProtocol::UNKNOWN;
    }
    
    // GET PROTOCOL NAME - Convert enum to string
    static const char* GetProtocolName(AppProtocol protocol) {
        switch (protocol) {
            case AppProtocol::HTTP:       return "HTTP";
            case AppProtocol::HTTPS:      return "HTTPS";
            case AppProtocol::DNS:        return "DNS";
            case AppProtocol::FTP:        return "FTP";
            case AppProtocol::FTP_DATA:   return "FTP-DATA";
            case AppProtocol::SSH:        return "SSH";
            case AppProtocol::TELNET:     return "TELNET";
            case AppProtocol::SMTP:       return "SMTP";
            case AppProtocol::POP3:       return "POP3";
            case AppProtocol::IMAP:       return "IMAP";
            case AppProtocol::DHCP:       return "DHCP";
            case AppProtocol::NTP:        return "NTP";
            case AppProtocol::SNMP:       return "SNMP";
            case AppProtocol::LDAP:       return "LDAP";
            case AppProtocol::SMB:        return "SMB";
            case AppProtocol::RDP:        return "RDP";
            case AppProtocol::MYSQL:      return "MySQL";
            case AppProtocol::POSTGRESQL: return "PostgreSQL";
            case AppProtocol::REDIS:      return "Redis";
            case AppProtocol::MONGODB:    return "MongoDB";
            case AppProtocol::QUIC:       return "QUIC";
            default:                      return "UNKNOWN";
        }
    }
};

} 

#endif // PROTOCOL_DETECTOR_H
