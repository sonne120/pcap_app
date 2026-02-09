#include "SnifferExports.h"
#include "Sniffer.h"
#include "builderDevice.h"
#include <vector>
#include <string>
#include <pcap.h>
#include <cstring>

static std::vector<std::string> g_deviceNames;

extern "C" {

    SNIFFER_API int Sniffer_GetDeviceCount() {
        g_deviceNames = builderDevice::Builder(0).ListDevices().Build().getDevices();
        return static_cast<int>(g_deviceNames.size());
    }

    SNIFFER_API const char* Sniffer_GetDeviceName(int index) {
        if (index >= 0 && index < static_cast<int>(g_deviceNames.size())) {
            return g_deviceNames[index].c_str();
        }
        return nullptr;
    }

    // PCAP file save 
    SNIFFER_API bool Sniffer_SavePcap(const char* filePath, const Snapshot* packets, int packetCount) {
        if (!filePath || !packets || packetCount <= 0) {
            return false;
        }

        // Create a dead pcap handle for writing (Ethernet link type)
        pcap_t* dead_pcap = pcap_open_dead(DLT_EN10MB, 65536);
        if (!dead_pcap) {
            return false;
        }

        pcap_dumper_t* dumper = pcap_dump_open(dead_pcap, filePath);
        if (!dumper) {
            pcap_close(dead_pcap);
            return false;
        }

        for (int i = 0; i < packetCount; i++) {
            const Snapshot& pkt = packets[i];
            
            if (pkt.capture_len == 0 || pkt.capture_len > 65536) {
                continue; 
            }

            struct pcap_pkthdr hdr;
            hdr.ts.tv_sec = static_cast<long>(pkt.timestamp_sec);
            hdr.ts.tv_usec = static_cast<long>(pkt.timestamp_usec);
            hdr.caplen = pkt.capture_len;
            hdr.len = pkt.original_len;

            pcap_dump(reinterpret_cast<u_char*>(dumper), &hdr, pkt.raw_data);
        }

        pcap_dump_close(dumper);
        pcap_close(dead_pcap);
        return true;
    }

    // PCAP file load 
    SNIFFER_API Snapshot* Sniffer_LoadPcap(const char* filePath, int* packetCount) {
        if (!filePath || !packetCount) {
            return nullptr;
        }
        *packetCount = 0;

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_offline(filePath, errbuf);
        if (!handle) {
            return nullptr;
        }

        struct pcap_pkthdr* header;
        const u_char* data;
        std::vector<Snapshot> loadedPackets;

        int res;
        while ((res = pcap_next_ex(handle, &header, &data)) >= 0) {
            if (res == 0) continue; 

            Snapshot pkt;
            memset(&pkt, 0, sizeof(Snapshot));

            pkt.capture_len = header->caplen;
            pkt.original_len = header->len;
            pkt.timestamp_sec = static_cast<uint64_t>(header->ts.tv_sec);
            pkt.timestamp_usec = static_cast<uint32_t>(header->ts.tv_usec);

            uint32_t copy_len = (header->caplen > 65536) ? 65536 : header->caplen;
            memcpy(pkt.raw_data, data, copy_len);

            // Parse basic packet info (Ethernet + IP headers)
            if (header->caplen >= 34) { // Minimum for Ethernet + IP
                const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(data);
                
                // Format MAC addresses
                snprintf(pkt.source_mac, sizeof(pkt.source_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                    eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
                snprintf(pkt.dest_mac, sizeof(pkt.dest_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                    eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

                // Parse IP header
                const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(data + 14);
                inet_ntop(AF_INET, &ip_hdr->ip_src, pkt.source_ip, sizeof(pkt.source_ip));
                inet_ntop(AF_INET, &ip_hdr->ip_dst, pkt.dest_ip, sizeof(pkt.dest_ip));
                pkt.id = ntohs(ip_hdr->ip_id);

                // Determine protocol and ports
                int protocol = ip_hdr->ip_p;
                int ip_header_len = (ip_hdr->ip_vhl & 0x0f) * 4;
                
                if (protocol == IPPROTO_TCP && header->caplen >= 14 + ip_header_len + 4) {
                    const u_char* tcp_data = data + 14 + ip_header_len;
                    pkt.source_port = ntohs(*reinterpret_cast<const uint16_t*>(tcp_data));
                    pkt.dest_port = ntohs(*reinterpret_cast<const uint16_t*>(tcp_data + 2));
                    strncpy(pkt.proto, "TCP", sizeof(pkt.proto));
                } else if (protocol == IPPROTO_UDP && header->caplen >= 14 + ip_header_len + 4) {
                    const u_char* udp_data = data + 14 + ip_header_len;
                    pkt.source_port = ntohs(*reinterpret_cast<const uint16_t*>(udp_data));
                    pkt.dest_port = ntohs(*reinterpret_cast<const uint16_t*>(udp_data + 2));
                    strncpy(pkt.proto, "UDP", sizeof(pkt.proto));
                } else if (protocol == IPPROTO_ICMP) {
                    strncpy(pkt.proto, "ICMP", sizeof(pkt.proto));
                } else {
                    snprintf(pkt.proto, sizeof(pkt.proto), "PROTO-%d", protocol);
                }
            }

            loadedPackets.push_back(pkt);
        }

        pcap_close(handle);

        if (loadedPackets.empty()) {
            return nullptr;
        }

        *packetCount = static_cast<int>(loadedPackets.size());
        Snapshot* result = new Snapshot[*packetCount];
        memcpy(result, loadedPackets.data(), sizeof(Snapshot) * (*packetCount));

        return result;
    }

    // Free memory 
    SNIFFER_API void Sniffer_FreePcapData(Snapshot* data) {
        delete[] data;
    }
}
