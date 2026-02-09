#pragma once

#ifdef WAREHOUND_SNIFFER_EXPORTS
#define SNIFFER_API __declspec(dllexport)
#else
#define SNIFFER_API __declspec(dllimport)
#endif

#include "struct.h"

extern "C" {
    typedef void(__cdecl* PacketCallback)(const char* packetData);

    SNIFFER_API int Sniffer_GetDeviceCount();
    SNIFFER_API const char* Sniffer_GetDeviceName(int index);
    
    // PCAP file operations
    SNIFFER_API bool Sniffer_SavePcap(const char* filePath, const Snapshot* packets, int packetCount);
    SNIFFER_API Snapshot* Sniffer_LoadPcap(const char* filePath, int* packetCount);
    SNIFFER_API void Sniffer_FreePcapData(Snapshot* data);
}
