#pragma once

#ifdef _WIN32
    #define IPC_EXPORT __declspec(dllexport)
    #include <windows.h>
#else
    typedef void* HANDLE;
#endif

#include <pcap.h>
#include <atomic>
#include <mutex>
#include <condition_variable>

// Global variables declared in ipc.cpp
extern std::atomic_bool quit_flag;
extern std::atomic<int> d1;
extern std::mutex m;
extern std::condition_variable cv;
extern pcap_t* _adhandle1;
#ifdef _WIN32
extern HANDLE hPipe;
#endif

extern "C" {
    IPC_EXPORT void fnDevCPPDLL(char** data, int* sizes, int* count);
    IPC_EXPORT void __stdcall fnCPPDLL(int d);
    IPC_EXPORT void __stdcall fnPutdevCPPDLL(int dev);
    IPC_EXPORT void __stdcall fnStartCapture();
    IPC_EXPORT void __stdcall fnStopCapture();
    IPC_EXPORT void __stdcall fnCloseApp();
}

int mainFunc(HANDLE eventHandle, int d);
