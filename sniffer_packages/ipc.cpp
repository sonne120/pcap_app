#include "ipc.h"
#include <iostream>
#include <cstring>
#include "builderDevice.h"

// Platform specific:
#ifdef _WIN32
// Windows architecture 
#if defined(_M_ARM64)
  #ifndef SNIFFER_WIN_ARCH_ARM64
    #define SNIFFER_WIN_ARCH_ARM64 1
  #endif
  #pragma message("[sniffer_packages] Building Windows ARM64 implementation")
#elif defined(_M_ARM)
  #ifndef SNIFFER_WIN_ARCH_ARM
    #define SNIFFER_WIN_ARCH_ARM 1
  #endif
  #pragma message("[sniffer_packages] Building Windows ARM (32-bit) implementation")
#elif defined(_M_X64)
  #ifndef SNIFFER_WIN_ARCH_X64
    #define SNIFFER_WIN_ARCH_X64 1
  #endif
  #pragma message("[sniffer_packages] Building Windows x64 implementation")
#elif defined(_M_IX86)
  #ifndef SNIFFER_WIN_ARCH_X86
    #define SNIFFER_WIN_ARCH_X86 1
  #endif
  #pragma message("[sniffer_packages] Building Windows Win32 (x86) implementation")
#else
  #pragma message("[sniffer_packages] Unknown Windows architecture")
#endif

#include <atlsafe.h>
#include <tchar.h>
#include <windows.h>
#include <thread>
#include <stop_token>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <chrono>

std::atomic_bool quit_flag(false);
std::atomic<int> d1;
std::mutex m;
std::condition_variable cv;
pcap_t* _adhandle1 = nullptr;
HANDLE hPipe = INVALID_HANDLE_VALUE;

static std::jthread mainThread;
HANDLE eventHandle = NULL;

static bool ConnectPipeServer() {
    const wchar_t* pipeName = L"\\\\.\\pipe\\testpipe";
    hPipe = CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::wcerr << L"CreateNamedPipeW failed. GLE=" << GetLastError() << std::endl;
        return false;
    }
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr)) {
        std::wcerr << L"SetNamedPipeHandleState failed. GLE=" << GetLastError() << std::endl;
    }
    return true;
}

IPC_EXPORT void fnDevCPPDLL(char** data, int* sizes, int* count) {
    std::vector<std::string> listdev = builderDevice::Builder(0).ListDevices().Build().getDevices();
    *count = static_cast<int>(listdev.size());
    if (data) {
        for (int i = 0; i < *count; ++i) {
            sizes[i] = static_cast<int>(listdev[i].size());
            data[i] = new char[sizes[i] + 1];
            std::strcpy(data[i], listdev[i].c_str());
        }
    }
}

IPC_EXPORT void __stdcall fnCPPDLL(int d) {   
    const WCHAR* name = L"Global\\sniffer";
    int attempt = 0;
    int maxAttempts = 30; 

    while ((eventHandle = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, name)) == NULL && attempt < maxAttempts) {
        Sleep(1000);
        ++attempt;
        if (attempt % 5 == 0) {
            std::cout << "fnCPPDLL Still waiting for event, attempt: " << attempt << "/" << maxAttempts << std::endl;
        }
    }
    
    if (eventHandle == NULL) {
        std::cout << "fnCPPDLL GetLastError=" << GetLastError() << std::endl;
        return;
    }
   
    if (ConnectPipeServer()) {

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cout << "fnCPPDLL ERROR: Pipe invalid after creation" << std::endl;
        } else {
            BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
            if (!connected) {
                DWORD err = GetLastError();
                std::cout << "fnCPPDLL ConnectNamedPipe failed. GLE=" << err << std::endl;
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
            } else {
                std::cout << "fnCPPDLL Named pipe connected to client successfully" << std::endl;
            }
        }

        DWORD waitResult = WaitForSingleObject(eventHandle, 30000); // 30 second timeout instead of INFINITE
        
        if (waitResult == WAIT_TIMEOUT) {
            std::cout << "fnCPPDLL WARNING: Event wait timed out after 30 seconds!" << std::endl;
        } else if (waitResult == WAIT_FAILED) {
            std::cout << "fnCPPDLL ERROR: Event wait failed, GLE=" << GetLastError() << std::endl;
            return;
        } else {
            std::cout << "fnCPPDLL Event signaled! Starting main capture thread..." << std::endl;
        }
        
        try {
            mainThread = std::jthread(
                [](std::stop_token st, HANDLE eventHandle, int d) {
                    while (!st.stop_requested()) {
                        mainFunc(eventHandle, d);
                    }
                },
                eventHandle,
                d
            );

            std::cout << "main thread started" << std::endl;
        }
        catch (const std::exception& e) {
            std::cout << "Failed to start main thread : "
                << e.what() << std::endl;
        }
        catch (...) {
            std::cout << "Failed to start main thread" << std::endl;
        }
        

    } 
}

IPC_EXPORT void __stdcall fnPutdevCPPDLL(int dev) {
    d1 = dev; _adhandle1 = nullptr;
    builderDevice::Builder builder(dev);
    if (quit_flag) quit_flag = false;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    try {
        _adhandle1 = builder.FindDevices()
            .SelectDevice()
            .OpenSelectedDevice()
            .Build()
            .getHandler();
    } catch (const std::exception& e) {
        std::cout << "[fnPutdevCPPDLL] Error opening device: " << e.what() << std::endl;
        _adhandle1 = nullptr;
    }

    {
        std::unique_lock<std::mutex> lock(m);
        quit_flag = true;
    }
    cv.notify_one();
}

IPC_EXPORT void __stdcall fnStopCapture() {
    std::cout << "[fnStopCapture] Stopping capture..." << std::endl;
    
    {
        std::unique_lock<std::mutex> lock(m);
        quit_flag = false;
    }
    cv.notify_all();
}

IPC_EXPORT void __stdcall fnCloseApp() {
    std::cout << "[fnCloseApp] Closing application..." << std::endl;
    if (mainThread.joinable()) {
        mainThread.request_stop();
        
        if (eventHandle) {
            SetEvent(eventHandle);
        }
        
        {
            std::unique_lock<std::mutex> lock(m);
            quit_flag = false; 
        }
        cv.notify_all();
    }
    
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
    }
    
    if (eventHandle) {
        CloseHandle(eventHandle);
        eventHandle = NULL;
    }
}

IPC_EXPORT void __stdcall fnStartCapture() {
    std::cout << "[fnStartCapture] Starting capture..." << std::endl;
    {
        std::unique_lock<std::mutex> lock(m);
        quit_flag = true;
    }
    cv.notify_all();
}

#else // Non-Windows 

#include <atomic>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <thread>
#include <chrono>

std::atomic_bool quit_flag(false);
std::atomic<int> d1;
std::mutex m;
std::condition_variable cv;
pcap_t* _adhandle1 = nullptr;

IPC_EXPORT void fnDevCPPDLL(char** data, int* sizes, int* count) {
    std::vector<std::string> listdev = builderDevice::Builder(0).ListDevices().Build().getDevices();
    *count = static_cast<int>(listdev.size());
    if (data) {
        for (int i = 0; i < *count; ++i) {
            sizes[i] = static_cast<int>(listdev[i].size());
            data[i] = new char[sizes[i] + 1];
            std::strcpy(data[i], listdev[i].c_str());
        }
    }
}

IPC_EXPORT void fnCPPDLL(int d) {
    std::thread t([d]() {
        while (!quit_flag) {
            mainFunc(nullptr, d);
        }
    });
    t.detach();
    std::cout << "main thread started (stub non-Windows)" << std::endl;
}

IPC_EXPORT void fnPutdevCPPDLL(int dev) {
    d1 = dev; _adhandle1 = nullptr;
    builderDevice::Builder builder(dev);
    if (quit_flag) quit_flag = false;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    _adhandle1 = builder.FindDevices().SelectDevice().OpenSelectedDevice().Build().getHandler();
    {
        std::unique_lock<std::mutex> lock(m);
        quit_flag = true;
    }
    cv.notify_one();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
}

IPC_EXPORT void fnStop() {
    quit_flag = true;
}

#endif // _WIN32
