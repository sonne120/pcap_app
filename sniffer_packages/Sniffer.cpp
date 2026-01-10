#include "Sniffer.h"
#include "ipc.h" 
#include "builderDevice.h"


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

    // Hostname lookup (blocking!)
    // struct hostent* host = gethostbyaddr((const char*)&ip_hdr->ip_dst, sizeof(ip_hdr->ip_dst), AF_INET);
    // char host_names[22];
    // if (host != nullptr) {
    //     strncpy(host_names, host->h_name, 21);
    //     host_names[21] = '\0';
    // } else {
    //     strcpy(host_names, "Not found");
    // }

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
    } else if (protocol_type == IPPROTO_UDP) {
        struct sniff_udp* udp_header = (struct sniff_udp*)(packetd_ptr + sizeof(struct ether_header) + sizeof(struct ip));
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);
    }

 
    char protoStr[22] = "UNKNOWN";
    switch (protocol_type) {
        case IPPROTO_TCP: strcpy(protoStr, "TCP"); break;
        case IPPROTO_UDP: strcpy(protoStr, "UDP"); break;
        case IPPROTO_ICMP: strcpy(protoStr, "ICMP"); break;
        // ... add others as needed
        default: snprintf(protoStr, 22, "PROTO-%d", protocol_type); break;
    }

    tagSnapshot item;
    parserHelper.addToStruct(protoStr, packet_srcip, packet_dstip, source_mac, dest_mac, packet_id, dst_port, src_port, host_names, item);
    
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

// Sniffer Implementation
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
