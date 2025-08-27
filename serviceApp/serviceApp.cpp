#include <windows.h>
#include "Npcap.h"

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
void WINAPI ServiceCtrlHandler(DWORD ctrlCode);

int main() {
    SERVICE_TABLE_ENTRY serviceTable[] = {
        { (LPSTR)"PacketCaptureService", ServiceMain },
        { NULL, NULL }
    };
    StartServiceCtrlDispatcher(serviceTable);
    return 0;
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    serviceStatusHandle = RegisterServiceCtrlHandler("PacketCaptureService", ServiceCtrlHandler);
    serviceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    // Start packet capture here
    StartCapture();
}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    if (ctrlCode == SERVICE_CONTROL_STOP) {
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
    }
}