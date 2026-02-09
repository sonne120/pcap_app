#pragma once
#ifndef STATISTICS_EXPORTS_H
#define STATISTICS_EXPORTS_H

#ifdef WAREHOUND_SNIFFER_EXPORTS
#    define SNIFFER_API __declspec(dllexport)
#else
#    define SNIFFER_API __declspec(dllimport)
#endif

#include <cstdint>

// NATIVE STATISTICS STRUCTURES 

#pragma pack(push, 1)

// Protocol statistics entry
struct NativeProtocolStats {
    char protocolName[32];
    uint64_t packetCount;
    uint64_t byteCount;
    double percentage;
};

// IP talker statistics entry
struct NativeTalkerStats {
    char ipAddress[64];
    uint64_t packetCount;
    uint64_t byteCount;
};

// Port statistics entry
struct NativePortStats {
    uint16_t port;
    char serviceName[32];
    uint64_t packetCount;
};

// Overall capture statistics
struct NativeCaptureStatistics {
    uint64_t totalPackets;
    uint64_t totalBytes;
    uint64_t activeFlows;
    double packetsPerSecond;
    double bytesPerSecond;
    double captureDurationSeconds;
    int uniqueProtocols;
    int uniqueSourceIPs;
    int uniqueDestIPs;
};

#pragma pack(pop)

//=============================================================================
// STATISTICS EXPORTS - C API for C# interop
//=============================================================================

extern "C" {
    // Enable/disable native statistics collection
    SNIFFER_API void Sniffer_EnableNativeStats(void* sniffer, bool enable);
    SNIFFER_API bool Sniffer_IsNativeStatsEnabled(void* sniffer);
    
    // Get overall capture statistics
    SNIFFER_API bool Sniffer_GetCaptureStatistics(void* sniffer, NativeCaptureStatistics* stats);
    
    // Get protocol breakdown (returns count of protocols)
    SNIFFER_API int Sniffer_GetProtocolStats(void* sniffer, NativeProtocolStats* stats, int maxCount);
    
    // Get top talkers (returns count of talkers)
    SNIFFER_API int Sniffer_GetTopSourceIPs(void* sniffer, NativeTalkerStats* stats, int maxCount);
    SNIFFER_API int Sniffer_GetTopDestIPs(void* sniffer, NativeTalkerStats* stats, int maxCount);
    
    // Get top ports (returns count of ports)
    SNIFFER_API int Sniffer_GetTopPorts(void* sniffer, NativePortStats* stats, int maxCount);
    
    // Clear statistics
    SNIFFER_API void Sniffer_ClearStatistics(void* sniffer);
    
    // Get flow count
    SNIFFER_API uint64_t Sniffer_GetFlowCount(void* sniffer);
}

#endif 
