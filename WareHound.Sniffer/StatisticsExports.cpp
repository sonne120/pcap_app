#define WAREHOUND_SNIFFER_EXPORTS
#define _CRT_SECURE_NO_WARNINGS
#include "StatisticsExports.h"
#include "FlowTracker.h"
#include <unordered_map>
#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <cstring>
#include <ws2tcpip.h>

using namespace WareHound;

// GLOBAL FLOW TRACKER INSTANCE
static std::unique_ptr<FlowTracker> g_flowTracker;
static std::shared_mutex g_flowTrackerMutex;  // Shared mutex for concurrent reads
static bool g_nativeStatsEnabled = false;

// IP address counters
static std::unordered_map<uint32_t, uint64_t> g_sourceIPCounts;
static std::unordered_map<uint32_t, uint64_t> g_destIPCounts;
static std::unordered_map<uint16_t, uint64_t> g_portCounts;
static std::shared_mutex g_ipStatsMutex;  // Shared mutex for concurrent reads

// CACHED STATISTICS - Avoid re-sorting on every poll
struct CachedTopStats {
    std::vector<std::pair<uint32_t, uint64_t>> topSourceIPs;
    std::vector<std::pair<uint32_t, uint64_t>> topDestIPs;
    std::vector<std::pair<uint16_t, uint64_t>> topPorts;
    uint64_t lastUpdateCount = 0;  // Packet count when last updated
    bool dirty = true;  // Invalidated when data changes
    static constexpr uint64_t UPDATE_THRESHOLD = 100;  // Re-cache every N packets
    
    void Invalidate() { dirty = true; }
    bool NeedsUpdate(uint64_t currentCount) const {
        return dirty || (currentCount - lastUpdateCount) >= UPDATE_THRESHOLD;
    }
};
static CachedTopStats g_cachedStats;
static std::mutex g_cacheMutex;

// HELPER FUNCTIONS
static void IP4ToString(uint32_t ip, char* buffer, size_t bufferSize) {
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buffer, static_cast<socklen_t>(bufferSize));
}

static const char* GetServiceName(uint16_t port) {
    switch (port) {
        case 20: return "FTP-DATA";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "TELNET";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67: case 68: return "DHCP";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 123: return "NTP";
        case 143: return "IMAP";
        case 161: case 162: return "SNMP";
        case 389: return "LDAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 6379: return "Redis";
        case 8080: return "HTTP-ALT";
        case 8443: return "HTTPS-ALT";
        case 27017: return "MongoDB";
        default: return "";
    }
}

// CACHE UPDATE HELPER - Rebuilds cached top stats if needed
static void UpdateCacheIfNeeded(size_t maxSourceIPs, size_t maxDestIPs, size_t maxPorts) {
    uint64_t currentCount = g_flowTracker ? g_flowTracker->GetPacketsProcessed() : 0;
    
    std::lock_guard<std::mutex> cacheLock(g_cacheMutex);
    
    if (!g_cachedStats.NeedsUpdate(currentCount)) {
        return;  // Cache is still valid
    }
    
    // Rebuild cache from current data (already holding shared lock on g_ipStatsMutex from caller)
    // Note: This is called while holding a shared lock, so we only read
    
    // Top source IPs
    g_cachedStats.topSourceIPs.assign(g_sourceIPCounts.begin(), g_sourceIPCounts.end());
    size_t nSrc = (std::min)(maxSourceIPs, g_cachedStats.topSourceIPs.size());
    if (nSrc > 0) {
        std::partial_sort(g_cachedStats.topSourceIPs.begin(), 
                          g_cachedStats.topSourceIPs.begin() + nSrc, 
                          g_cachedStats.topSourceIPs.end(),
                          [](const auto& a, const auto& b) { return a.second > b.second; });
    }
    
    // Top dest IPs
    g_cachedStats.topDestIPs.assign(g_destIPCounts.begin(), g_destIPCounts.end());
    size_t nDst = (std::min)(maxDestIPs, g_cachedStats.topDestIPs.size());
    if (nDst > 0) {
        std::partial_sort(g_cachedStats.topDestIPs.begin(), 
                          g_cachedStats.topDestIPs.begin() + nDst, 
                          g_cachedStats.topDestIPs.end(),
                          [](const auto& a, const auto& b) { return a.second > b.second; });
    }
    
    // Top ports
    g_cachedStats.topPorts.assign(g_portCounts.begin(), g_portCounts.end());
    size_t nPorts = (std::min)(maxPorts, g_cachedStats.topPorts.size());
    if (nPorts > 0) {
        std::partial_sort(g_cachedStats.topPorts.begin(), 
                          g_cachedStats.topPorts.begin() + nPorts, 
                          g_cachedStats.topPorts.end(),
                          [](const auto& a, const auto& b) { return a.second > b.second; });
    }
    
    g_cachedStats.lastUpdateCount = currentCount;
    g_cachedStats.dirty = false;
}

// INITIALIZATION

void InitFlowTracker() {
    std::unique_lock<std::shared_mutex> lock(g_flowTrackerMutex);  // Exclusive lock for write
    if (!g_flowTracker) {
        FlowTracker::Config config;
        config.table_size = 65536;
        config.max_flows = 100000;
        config.flow_timeout_us = 300 * 1000000ULL;  // 5 minutes
        g_flowTracker = std::make_unique<FlowTracker>(config);
    }
}

void ProcessPacketForStats(const uint8_t* data, uint32_t len, uint64_t timestamp_us) {
    if (!g_nativeStatsEnabled) return;
    
    InitFlowTracker();
    
    std::unique_lock<std::shared_mutex> lock(g_flowTrackerMutex);  // Exclusive lock for write
    FlowEntry* flow = g_flowTracker->ProcessPacket(data, len, timestamp_us);
    
    if (flow) {
        // Update IP/port statistics
        std::unique_lock<std::shared_mutex> ipLock(g_ipStatsMutex);  // Exclusive lock for write
        g_sourceIPCounts[flow->key.src_ip]++;
        g_destIPCounts[flow->key.dst_ip]++;
        if (flow->key.src_port > 0) g_portCounts[flow->key.src_port]++;
        if (flow->key.dst_port > 0) g_portCounts[flow->key.dst_port]++;
        
        // Mark cache as dirty (but don't invalidate immediately for performance)
        // Cache will be rebuilt on next query after threshold is reached
    }
}

// EXPORTS IMPLEMENTATION

extern "C" {

SNIFFER_API void Sniffer_EnableNativeStats(void* sniffer, bool enable) {
    g_nativeStatsEnabled = enable;
    if (enable) {
        InitFlowTracker();
    }
}

SNIFFER_API bool Sniffer_IsNativeStatsEnabled(void* sniffer) {
    return g_nativeStatsEnabled;
}

SNIFFER_API bool Sniffer_GetCaptureStatistics(void* sniffer, NativeCaptureStatistics* stats) {
    if (!stats || !g_flowTracker) {
        if (stats) memset(stats, 0, sizeof(NativeCaptureStatistics));
        return false;
    }
    
    std::shared_lock<std::shared_mutex> lock(g_flowTrackerMutex);  // Shared lock for read
    
    stats->totalPackets = g_flowTracker->GetPacketsProcessed();
    stats->totalBytes = g_flowTracker->GetBytesProcessed();
    stats->activeFlows = g_flowTracker->GetFlowCount();
    stats->captureDurationSeconds = g_flowTracker->GetCaptureDurationSeconds();
    
    if (stats->captureDurationSeconds > 0) {
        stats->packetsPerSecond = static_cast<double>(stats->totalPackets) / stats->captureDurationSeconds;
        stats->bytesPerSecond = static_cast<double>(stats->totalBytes) / stats->captureDurationSeconds;
    } else {
        stats->packetsPerSecond = 0;
        stats->bytesPerSecond = 0;
    }
    
    // Use pre-computed unique protocol count instead of iterating all flows
    stats->uniqueProtocols = static_cast<int>(g_flowTracker->GetUniqueProtocolCount());
    
    std::shared_lock<std::shared_mutex> ipLock(g_ipStatsMutex);  // Shared lock for read
    stats->uniqueSourceIPs = static_cast<int>(g_sourceIPCounts.size());
    stats->uniqueDestIPs = static_cast<int>(g_destIPCounts.size());
    
    return true;
}

SNIFFER_API int Sniffer_GetProtocolStats(void* sniffer, NativeProtocolStats* stats, int maxCount) {
    if (!stats || !g_flowTracker || maxCount <= 0) return 0;
    
    std::shared_lock<std::shared_mutex> lock(g_flowTrackerMutex);  // Shared lock for read
    
    // Use GetAggregatedStats() to avoid full flow copy
    auto aggStats = g_flowTracker->GetFlowTable().GetAggregatedStats();
    uint64_t totalPackets = aggStats.total_packets;
    
    // Convert to vector for sorting
    std::vector<std::pair<int, std::pair<uint64_t, uint64_t>>> sorted;
    sorted.reserve(aggStats.protocol_counts.size());
    for (const auto& p : aggStats.protocol_counts) {
        uint64_t bytes = aggStats.protocol_bytes.count(p.first) ? aggStats.protocol_bytes.at(p.first) : 0;
        sorted.emplace_back(p.first, std::make_pair(p.second, bytes));
    }
    
    // Partial sort to get top N only
    size_t n = (std::min)(static_cast<size_t>(maxCount), sorted.size());
    std::partial_sort(sorted.begin(), sorted.begin() + n, sorted.end(),
        [](const auto& a, const auto& b) { return a.second.first > b.second.first; });
    
    int count = static_cast<int>(n);
    for (int i = 0; i < count; i++) {
        strncpy(stats[i].protocolName, ProtocolDetector::GetProtocolName(static_cast<AppProtocol>(sorted[i].first)), 31);
        stats[i].protocolName[31] = '\0';
        stats[i].packetCount = sorted[i].second.first;
        stats[i].byteCount = sorted[i].second.second;
        stats[i].percentage = totalPackets > 0 
            ? (static_cast<double>(sorted[i].second.first) / totalPackets) * 100.0 
            : 0.0;
    }
    
    return count;
}

SNIFFER_API int Sniffer_GetTopSourceIPs(void* sniffer, NativeTalkerStats* stats, int maxCount) {
    if (!stats || maxCount <= 0) return 0;
    
    std::shared_lock<std::shared_mutex> lock(g_ipStatsMutex);  // Shared lock for read
    
    // Update cache if needed (uses cached sorted results to avoid re-sorting)
    UpdateCacheIfNeeded(static_cast<size_t>(maxCount), 10, 10);
    
    std::lock_guard<std::mutex> cacheLock(g_cacheMutex);
    size_t n = (std::min)(static_cast<size_t>(maxCount), g_cachedStats.topSourceIPs.size());
    
    int count = static_cast<int>(n);
    for (int i = 0; i < count; i++) {
        IP4ToString(g_cachedStats.topSourceIPs[i].first, stats[i].ipAddress, 64);
        stats[i].packetCount = g_cachedStats.topSourceIPs[i].second;
        stats[i].byteCount = 0;  // Not tracked per-IP currently
    }
    
    return count;
}

SNIFFER_API int Sniffer_GetTopDestIPs(void* sniffer, NativeTalkerStats* stats, int maxCount) {
    if (!stats || maxCount <= 0) return 0;
    
    std::shared_lock<std::shared_mutex> lock(g_ipStatsMutex);  // Shared lock for read
    
    // Update cache if needed
    UpdateCacheIfNeeded(10, static_cast<size_t>(maxCount), 10);
    
    std::lock_guard<std::mutex> cacheLock(g_cacheMutex);
    size_t n = (std::min)(static_cast<size_t>(maxCount), g_cachedStats.topDestIPs.size());
    
    int count = static_cast<int>(n);
    for (int i = 0; i < count; i++) {
        IP4ToString(g_cachedStats.topDestIPs[i].first, stats[i].ipAddress, 64);
        stats[i].packetCount = g_cachedStats.topDestIPs[i].second;
        stats[i].byteCount = 0;
    }
    
    return count;
}

SNIFFER_API int Sniffer_GetTopPorts(void* sniffer, NativePortStats* stats, int maxCount) {
    if (!stats || maxCount <= 0) return 0;
    
    std::shared_lock<std::shared_mutex> lock(g_ipStatsMutex);  // Shared lock for read
    
    // Update cache if needed
    UpdateCacheIfNeeded(10, 10, static_cast<size_t>(maxCount));
    
    std::lock_guard<std::mutex> cacheLock(g_cacheMutex);
    size_t n = (std::min)(static_cast<size_t>(maxCount), g_cachedStats.topPorts.size());
    
    int count = static_cast<int>(n);
    for (int i = 0; i < count; i++) {
        stats[i].port = g_cachedStats.topPorts[i].first;
        strncpy(stats[i].serviceName, GetServiceName(g_cachedStats.topPorts[i].first), 31);
        stats[i].serviceName[31] = '\0';
        stats[i].packetCount = g_cachedStats.topPorts[i].second;
    }
    
    return count;
}

SNIFFER_API void Sniffer_ClearStatistics(void* sniffer) {
    {
        std::unique_lock<std::shared_mutex> lock(g_flowTrackerMutex);  // Exclusive lock for write
        if (g_flowTracker) {
            g_flowTracker->Clear();
        }
    }
    
    {
        std::unique_lock<std::shared_mutex> lock(g_ipStatsMutex);  // Exclusive lock for write
        g_sourceIPCounts.clear();
        g_destIPCounts.clear();
        g_portCounts.clear();
        
        // Invalidate cache
        std::lock_guard<std::mutex> cacheLock(g_cacheMutex);
        g_cachedStats.Invalidate();
        g_cachedStats.topSourceIPs.clear();
        g_cachedStats.topDestIPs.clear();
        g_cachedStats.topPorts.clear();
    }
}

SNIFFER_API uint64_t Sniffer_GetFlowCount(void* sniffer) {
    std::shared_lock<std::shared_mutex> lock(g_flowTrackerMutex);  // Shared lock for read
    return g_flowTracker ? g_flowTracker->GetFlowCount() : 0;
}

} // extern "C"
