#include "package_global.h"
#include <windows.h> 

HANDLE hEvent = CreateEventW(
    nullptr,
    TRUE,   
    FALSE,  
    L"Global\\sniffer"
);