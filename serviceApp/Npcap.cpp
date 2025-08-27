#include "Npcap.h"
#include <pcap.h>
#include <windows.h>
#include <iostream>

HANDLE hPipe = CreateFileW(
    L"\\\\.\\pipe\\MyPipe",              
    GENERIC_READ | GENERIC_WRITE,       
    0,                                  
    NULL,                               
    OPEN_EXISTING,                     
    0,                                
    NULL);

void StartCapture() {
  
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::wcerr << L"CreateFileW failed: " << GetLastError() << std::endl;
        //return 1;
    }
    char buffer[128] = {};
    DWORD bytesRead;
    if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        std::cout << "Received from server: " << buffer << std::endl;
    }

    CloseHandle(hPipe);
  //  return 0;
}
