#include <atomic>
#include <cstring>

#ifdef SNIFFER_PCAP_DISABLED
// Stub implementation for platforms without WinPcap/Npcap (e.g., Windows ARM64)

#ifdef _WIN32
  #define IPC_EXPORT extern "C" __declspec(dllexport)
  #define STDCALL __stdcall
#else
  #define IPC_EXPORT extern "C"
  #define STDCALL
#endif

static std::atomic<bool> g_running{false};

// Device enumeration stub – returns zero devices
IPC_EXPORT void fnDevCPPDLL(char** data, int* sizes, int* count)
{
    if(count) *count = 0; // no devices
}

// Start capture stub – just flips a flag
IPC_EXPORT void STDCALL fnCPPDLL(int d)
{
    (void)d;
    g_running.store(true, std::memory_order_release);
}

// Set / put device stub – no-op
IPC_EXPORT void STDCALL fnPutdevCPPDLL(int dev)
{
    (void)dev;
}

#endif // SNIFFER_PCAP_DISABLED
