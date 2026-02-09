#include "Sniffer.h"
#include "ipc.h" 
#include "builderDevice.h"
#include "handleProto.h"
#include "FlowTracker.h"
#include <shared_mutex>
#include <fstream>
#include <ws2tcpip.h>  // for inet_ntop

// Forward declaration for statistics integration
extern void ProcessPacketForStats(const uint8_t* data, uint32_t len, uint64_t timestamp_us);

// DNS Cache
static std::map<std::string, std::string> g_dnsCache;
static std::shared_mutex g_dnsCacheMutex;
static const size_t MAX_DNS_CACHE_SIZE = 10000;

static void addToDnsCache(const std::string& ip, const std::string& hostname) {
    std::unique_lock<std::shared_mutex> lock(g_dnsCacheMutex);
    if (g_dnsCache.size() >= MAX_DNS_CACHE_SIZE) {
        // Remove oldest entry (first in map)
        if (!g_dnsCache.empty()) {
            g_dnsCache.erase(g_dnsCache.begin());
        }
    }
    g_dnsCache[ip] = hostname;
}

static bool lookupDnsCache(const std::string& ip, char* output, int max_len) {
    std::shared_lock<std::shared_mutex> lock(g_dnsCacheMutex);
    auto it = g_dnsCache.find(ip);
    if (it != g_dnsCache.end() && !it->second.empty()) {
        strncpy(output, it->second.c_str(), max_len - 1);
        output[max_len - 1] = '\0';
        return true;
    }
    return false;
}

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// DNS label compression pointer mask
static const uint8_t DNS_COMPRESSION_MASK = 0xC0;
static const int MAX_DNS_NAME_LENGTH = 253;
static const int MAX_LABEL_LENGTH = 63;

static bool extract_dns_name(const u_char* data, size_t data_len, int& offset, char* output, int max_len) {
    if (!data || !output || max_len <= 0) {
        return false;
    }

    std::string hostname;
    hostname.reserve(MAX_DNS_NAME_LENGTH);

    int safety_counter = 0;
    const int MAX_ITERATIONS = 128;

    while (safety_counter++ < MAX_ITERATIONS) {

        if (offset < 0 || static_cast<size_t>(offset) >= data_len) {
            break;
        }

        uint8_t length = data[offset];

        if (length == 0) {
            offset++;
            break;
        }

        // Check for DNS compression pointer
        if ((length & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_MASK) {
            // Compression pointer - skip for now, just break
            offset += 2;
            break;
        }

        // Validate label length
        if (length > MAX_LABEL_LENGTH) {
            break;
        }

        offset++;

        // Bounds check for label data
        if (static_cast<size_t>(offset + length) > data_len) {
            break;
        }

        // Add separator if not first label
        if (!hostname.empty()) {
            hostname += ".";
        }

        // Copy label characters
        for (int i = 0; i < length; i++) {
            char c = static_cast<char>(data[offset + i]);
            if (c >= 32 && c <= 126) {
                hostname += c;
            }
        }

        offset += length;

        // Prevent hostname from getting too long
        if (hostname.length() >= MAX_DNS_NAME_LENGTH) {
            break;
        }
    }

    if (hostname.empty()) {
        return false;
    }

    strncpy(output, hostname.c_str(), max_len - 1);
    output[max_len - 1] = '\0';
    return true;
}

// Skip a DNS name in the packet (handles compression pointers)
static int skip_dns_name(const u_char* data, size_t data_len, int offset) {
    int safety_counter = 0;
    const int MAX_ITERATIONS = 128;
    
    while (safety_counter++ < MAX_ITERATIONS && offset < static_cast<int>(data_len)) {
        uint8_t length = data[offset];
        
        if (length == 0) {
            return offset + 1;
        }
        
        if ((length & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_MASK) {
            return offset + 2;
        }
        
        if (length > MAX_LABEL_LENGTH) {
            return -1;
        }
        
        offset += 1 + length;
    }
    return -1;
}

// Parse DNS response and cache IP→hostname mappings
static void parse_dns_response(const u_char* dns_data, size_t dns_data_len, const char* hostname) {
    if (!dns_data || dns_data_len < sizeof(struct dns_header) || !hostname || hostname[0] == '\0') {
        return;
    }
    
    const struct dns_header* dns = (const struct dns_header*)dns_data;
    uint16_t qdcount = ntohs(dns->qdcount);
    uint16_t ancount = ntohs(dns->ancount);
    
    // Skip if no answers
    if (ancount == 0 || ancount > 100) {
        return;
    }
    
    int offset = sizeof(struct dns_header);
    
    // Skip question section
    for (int i = 0; i < qdcount && offset > 0; i++) {
        offset = skip_dns_name(dns_data, dns_data_len, offset);
        if (offset < 0) return;
        offset += 4; // QTYPE (2) + QCLASS (2)
        if (offset > static_cast<int>(dns_data_len)) return;
    }
    
    // Parse answer section
    for (int i = 0; i < ancount && offset > 0; i++) {
        // Skip name
        offset = skip_dns_name(dns_data, dns_data_len, offset);
        if (offset < 0 || offset + 10 > static_cast<int>(dns_data_len)) return;
        
        uint16_t rtype = ntohs(*(uint16_t*)(dns_data + offset));
        offset += 2;
        uint16_t rclass = ntohs(*(uint16_t*)(dns_data + offset));
        offset += 2;
        offset += 4; // TTL
        uint16_t rdlength = ntohs(*(uint16_t*)(dns_data + offset));
        offset += 2;
        
        if (offset + rdlength > static_cast<int>(dns_data_len)) return;
        
        // A record (IPv4)
        if (rtype == 1 && rclass == 1 && rdlength == 4) {
            char ip_str[INET_ADDRSTRLEN];
            struct in_addr addr;
            memcpy(&addr, dns_data + offset, 4);
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
            addToDnsCache(ip_str, hostname);
        }
        // AAAA record (IPv6)
        else if (rtype == 28 && rclass == 1 && rdlength == 16) {
            char ip_str[INET6_ADDRSTRLEN];
            struct in6_addr addr;
            memcpy(&addr, dns_data + offset, 16);
            inet_ntop(AF_INET6, &addr, ip_str, INET6_ADDRSTRLEN);
            addToDnsCache(ip_str, hostname);
        }
        
        offset += rdlength;
    }
}


// PacketBuffer Implementation

PacketBuffer::PacketBuffer(size_t maxSize) : maxSize(maxSize) {}

void PacketBuffer::Push(const tagSnapshot& item) {
    std::unique_lock<std::mutex> lock(mutex);
    notFull.wait(lock, [this] { return queue.size() < maxSize; });
    queue.push(item);
    lock.unlock();
    notEmpty.notify_one();
}

bool PacketBuffer::Pop(tagSnapshot& item) {
    std::unique_lock<std::mutex> lock(mutex);
    notEmpty.wait(lock, [this] { return !queue.empty(); });
    item = queue.front();
    queue.pop();
    lock.unlock();
    notFull.notify_one();
    return true;
}

bool PacketBuffer::IsFull() const {
    std::lock_guard<std::mutex> lock(mutex);
    return queue.size() >= maxSize;
}

bool PacketBuffer::IsEmpty() const {
    std::lock_guard<std::mutex> lock(mutex);
    return queue.empty();
}

PacketCapturer::PacketCapturer(std::shared_ptr<PacketBuffer> buffer, HANDLE eventHandle) 
    : buffer(buffer), _eventHandles(eventHandle) {

}

PacketCapturer::~PacketCapturer() {
    Stop();
}

void PacketCapturer::Start(pcap_t* handle, std::atomic<bool>& running, HANDLE eventHandle) {
    captureThread = std::thread(&PacketCapturer::CaptureLoop, this, handle, std::ref(running), eventHandle);
}

void PacketCapturer::Stop() {
    if (captureThread.joinable()) {
        captureThread.join();
    }
}

void PacketCapturer::CaptureLoop(pcap_t* handle, std::atomic<bool>& running, HANDLE eventHandle) {
    int res;
    struct pcap_pkthdr* pkthdr;
    const u_char* packetd_ptr;
    int packet_count = 0;

    std::cout << "[CaptureLoop] Starting capture loop..." << std::endl;

    while (running) {
        if (!handle) {
             std::this_thread::sleep_for(std::chrono::milliseconds(100));
             continue;
        }

        res = pcap_next_ex(handle, &pkthdr, &packetd_ptr);
        
        if (res == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            tagSnapshot new_item; 
            parserHelper.defaultToStruct(new_item); 
            buffer->Push(new_item);
            continue;
        }

        if (res > 0) {
            packet_count++;
            if (packet_count == 1) {
                std::cout << "[CaptureLoop] First packet captured! caplen=" << pkthdr->caplen << ", len=" << pkthdr->len << std::endl;
            }
            ProcessPacket(pkthdr, packetd_ptr);
        }
        else if (res == 0) {
            // Timeout
            continue;
        }
        else {
            // Error or EOF
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    std::cout << "[CaptureLoop] Exiting capture loop." << std::endl;
}

void PacketCapturer::ProcessPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    // Process packet for native statistics (FlowTracker)
    uint64_t timestamp_us = static_cast<uint64_t>(pkthdr->ts.tv_sec) * 1000000 + pkthdr->ts.tv_usec;
    ProcessPacketForStats(packet, pkthdr->caplen, timestamp_us);

    int link_hdr_length = 0; 
    
    const u_char* packetd_ptr = packet;
    struct ether_header* eptr = (struct ether_header*)packetd_ptr;
    struct ip* ip_hdr = (struct ip*)(packetd_ptr + sizeof(struct ether_header));

    char packet_srcip[INET_ADDRSTRLEN];
    char packet_dstip[INET_ADDRSTRLEN];
    strcpy(packet_srcip, inet_ntoa(ip_hdr->ip_src));
    strcpy(packet_dstip, inet_ntoa(ip_hdr->ip_dst));

    char source_mac[32]; 
    char dest_mac[32];
    ether_ntoa(eptr->ether_shost, source_mac, sizeof(source_mac));
    ether_ntoa(eptr->ether_dhost, dest_mac, sizeof(dest_mac));

    char host_names[22];
    strcpy(host_names, ""); 

    int packet_id = ntohs(ip_hdr->ip_id);
    int protocol_type = ip_hdr->ip_p;
    
    int src_port = 0;
    int dst_port = 0;

    if (protocol_type == IPPROTO_TCP) {
        struct sniff_tcp* tcpip_header = (struct sniff_tcp*)(packetd_ptr + sizeof(struct ether_header) + sizeof(struct ip));
        dst_port = ntohs(tcpip_header->th_dport);
        src_port = ntohs(tcpip_header->th_sport);

        if (!lookupDnsCache(packet_dstip, host_names, sizeof(host_names))) {
            lookupDnsCache(packet_srcip, host_names, sizeof(host_names));
        }
    }
    else if (protocol_type == IPPROTO_UDP) {
        struct sniff_udp* udp_header = (struct sniff_udp*)(packetd_ptr + sizeof(struct ether_header) + sizeof(struct ip));
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);

        if (src_port == 53 || dst_port == 53) {
            // Calculate DNS payload location and size
            const u_char* dns_data = (u_char*)udp_header + sizeof(struct sniff_udp);
            size_t udp_len = ntohs(udp_header->uh_len);

            // Validate UDP length
            if (udp_len > sizeof(struct sniff_udp) + sizeof(struct dns_header)) {
                size_t dns_data_len = udp_len - sizeof(struct sniff_udp);
                struct dns_header* dns = (struct dns_header*)dns_data;

                // Check for valid DNS query/response
                uint16_t qdcount = ntohs(dns->qdcount);
                if (qdcount > 0 && qdcount < 100) {
                    int offset = sizeof(struct dns_header);
                    if (extract_dns_name(dns_data, dns_data_len, offset, host_names, sizeof(host_names))) {
                        // For DNS responses (from port 53), parse answer section to cache IP->hostname
                        if (src_port == 53) {
                            parse_dns_response(dns_data, dns_data_len, host_names);
                        }
                    }
                }
            }
        }
        else {
            // Non-DNS UDP - try cache lookup
            if (!lookupDnsCache(packet_dstip, host_names, sizeof(host_names))) {
                lookupDnsCache(packet_srcip, host_names, sizeof(host_names));
            }
        }
    }
    else {
        // ICMP or other protocols - try cache lookup
        if (!lookupDnsCache(packet_dstip, host_names, sizeof(host_names))) {
            lookupDnsCache(packet_srcip, host_names, sizeof(host_names));
        }
    }

    // Use handleProto class to resolve protocol name
    char protoStr[22] = "UNKNOWN";
    handleProto protoHandler;
    handleProto* pHandler = &protoHandler;
    protoHandler.protoStr = protoStr;
    protoHandler._src_port = &src_port;
    protoHandler._dst_port = &dst_port;
    
    // Initialize and call the handler
    handleProto hp(pHandler);
    
    auto it = hp.caseMap.find(protocol_type);
    if (it != hp.caseMap.end()) {
        it->second();
    } else {
        snprintf(protoStr, 22, "PROTO-%d", protocol_type);
    }

    tagSnapshot item;
    parserHelper.addToStruct(protoStr, packet_srcip, packet_dstip, source_mac, dest_mac, packet_id, dst_port, src_port, host_names, item);
    
    // Store raw packet data for PCAP save functionality
    item.capture_len = pkthdr->caplen;
    item.original_len = pkthdr->len;
    item.timestamp_sec = static_cast<uint64_t>(pkthdr->ts.tv_sec);
    item.timestamp_usec = static_cast<uint32_t>(pkthdr->ts.tv_usec);
    
    // Copy raw packet bytes (limited to 65536 max)
    uint32_t copy_len = (pkthdr->caplen > 65536) ? 65536 : pkthdr->caplen;
    memcpy(item.raw_data, packet, copy_len);
    
    buffer->Push(item);
}

// PacketDispatcher Implementation
PacketDispatcher::PacketDispatcher(std::shared_ptr<PacketBuffer> buffer) 
    : buffer(buffer) {}

PacketDispatcher::~PacketDispatcher() {
    Stop();
}

void PacketDispatcher::Subscribe(std::shared_ptr<IPacketSubscriber> subscriber) {
    subscribers.push_back(subscriber);
}

void PacketDispatcher::Start(std::atomic<bool>& running) {
    dispatchThread = std::thread(&PacketDispatcher::DispatchLoop, this, std::ref(running));
}

void PacketDispatcher::Stop() {
    if (dispatchThread.joinable()) {
        dispatchThread.join();
    }
}

void PacketDispatcher::DispatchLoop(std::atomic<bool>& running) {
    tagSnapshot item;
    while (running) {
        if (buffer->Pop(item)) {
            for (auto& sub : subscribers) {
                sub->OnPacketCaptured(item);
            }
        } else {
             std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

// PipeWriterSubscriber Implementation
PipeWriterSubscriber::PipeWriterSubscriber() {
#ifdef _WIN32
    hPipe = ::hPipe; 
#endif
}

PipeWriterSubscriber::~PipeWriterSubscriber() {
}

void PipeWriterSubscriber::OnPacketCaptured(const tagSnapshot& packet) {
#ifdef _WIN32
    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        
        BOOL success = WriteFile(hPipe, &packet, sizeof(tagSnapshot), &written, NULL);
        
        if (!success) {
            hPipe = INVALID_HANDLE_VALUE;
        } else if (written != sizeof(tagSnapshot)) {
            std::cerr << "PipeWriter  Incomplete write: " << written << "/" << sizeof(tagSnapshot) << " bytes" << std::endl;
        }
    }
#else
    // Linux/Mac implementation
    // std::cout << "Packet: " << packet.id << std::endl;
#endif
}


// SnifferBuilder Implementation
SnifferBuilder::SnifferBuilder() : deviceIndex(0), eventHandle(nullptr) {}

SnifferBuilder& SnifferBuilder::UseDevice(int deviceIndex) {
    this->deviceIndex = deviceIndex;
    return *this;
}

SnifferBuilder& SnifferBuilder::UseFile(const std::string& filename) {
    this->filename = filename;
    return *this;
}

SnifferBuilder& SnifferBuilder::AddSubscriber(std::shared_ptr<IPacketSubscriber> subscriber) {
    subscribers.push_back(subscriber);
    return *this;
}

SnifferBuilder& SnifferBuilder::SetEventHandle(HANDLE handle) {
    this->eventHandle = handle;
    return *this;
}

std::unique_ptr<Sniffer> SnifferBuilder::Build() {
    pcap_t* handle = nullptr;
    
    if (deviceIndex > 0) {
        try {
            handle = builderDevice::Builder(deviceIndex)
                .FindDevices()
                .SelectDevice()
                .OpenSelectedDevice()
                .Build()
                .getHandler();
        } catch (...) {
        }
    }
    
    return std::make_unique<Sniffer>(handle, subscribers, eventHandle);
}

// Sniffer Implementation (Facade)
Sniffer::Sniffer(pcap_t* handle, std::vector<std::shared_ptr<IPacketSubscriber>> subscribers, HANDLE eventHandle)
    : handle(handle), eventHandle(eventHandle), running(false) {
    buffer = std::make_shared<PacketBuffer>();
    capturer = std::make_unique<PacketCapturer>(buffer, eventHandle);
    dispatcher = std::make_unique<PacketDispatcher>(buffer);
    
    for (auto& sub : subscribers) {
        dispatcher->Subscribe(sub);
    }
}

Sniffer::~Sniffer() {
    Stop();
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
        std::cout << "Sniffer Handle closed." << std::endl;
    }
}

void Sniffer::Start() {
    running = true;
    
    if (handle == nullptr && _adhandle1 != nullptr) {
        handle = _adhandle1;
    }
    
    capturer->Start(handle, running, eventHandle);
    dispatcher->Start(running);
    
}

void Sniffer::Stop() {
    running = false;
    capturer->Stop();
    dispatcher->Stop();
}
