#pragma once
#ifndef BUILDER_DEVICE_H
#define BUILDER_DEVICE_H

#ifndef SNIFFER_PCAP_DISABLED
  #include <pcap.h>
#else
  // ----- PCAP STUB DEFINITIONS (capture disabled) -----
  struct pcap_if_stub { char* name; char* description; pcap_if_stub* next; };
  typedef pcap_if_stub pcap_if_t;
  struct pcap_stub_handle; typedef pcap_stub_handle pcap_t;
  #ifndef PCAP_ERRBUF_SIZE
    #define PCAP_ERRBUF_SIZE 256
  #endif
  #ifndef PCAP_SRC_IF_STRING
    #define PCAP_SRC_IF_STRING "rpcap://"
  #endif
  #ifndef PCAP_OPENFLAG_PROMISCUOUS
    #define PCAP_OPENFLAG_PROMISCUOUS 1
  #endif
  extern char errbuf[PCAP_ERRBUF_SIZE];
  inline int pcap_findalldevs_ex(const char*, void*, pcap_if_t** list, char*) { *list = nullptr; return 0; }
  inline void pcap_freealldevs(pcap_if_t*) {}
  inline pcap_t* pcap_open(const char*, int, int, int, void*, char*) { return nullptr; }
  inline pcap_t* pcap_open_offline(const char*, char*) { return nullptr; }
#endif

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif
extern char errbuf[PCAP_ERRBUF_SIZE];

class builderDevice {
public:
    class Builder {
    public:
        explicit Builder(int devIndex);
        ~Builder();

        Builder& FindDevices();
        Builder& SelectDevice();
        Builder& OpenSelectedDevice();
        Builder& ListDevices();
        Builder& OpenFromFile(const std::string& filePath);

        builderDevice Build();

    private:
        int inum;
        int deviceCount;
        pcap_if_t* alldevs;
        pcap_if_t* selectedDev;
        pcap_t* handle;
        std::vector<std::string> deviceList;

        friend class builderDevice;
    };

    pcap_t* getHandler() const;
    const std::vector<std::string>& getDevices() const;

private:
    builderDevice(const Builder& builder);

    int inum;
    pcap_t* adhandle;
    std::vector<std::string> list;
};

#endif
