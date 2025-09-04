#pragma once
#ifndef PACKAGE_GLOBAL_H
#define PACKAGE_GLOBAL_H
#include <windows.h>
#include <mutex>
#include <fstream>
#include <string>

extern HANDLE hEvent;

extern "C" __declspec(dllimport) void __stdcall fnCPPDLL(int dev);
extern "C" __declspec(dllimport) void __stdcall fnPutdevCPPDLL(int dev);
#endif
