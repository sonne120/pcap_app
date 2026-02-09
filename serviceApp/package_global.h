#pragma once
#ifndef PACKAGE_GLOBAL_H
#define PACKAGE_GLOBAL_H
#include <windows.h>
#include <mutex>
#include <fstream>
#include <string>

extern HANDLE hEvent;

// Import from WareHound.Sniffer.dll (formerly sniffer_packages.dll)
extern "C" __declspec(dllimport) void __stdcall fnCPPDLL(int dev);
extern "C" __declspec(dllimport) void __stdcall fnPutdevCPPDLL(int dev);
extern "C" __declspec(dllimport) void __stdcall fnStartCapture();
extern "C" __declspec(dllimport) void __stdcall fnStopCapture();
extern "C" __declspec(dllimport) void __stdcall fnCloseApp();
#endif
