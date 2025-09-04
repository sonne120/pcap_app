#include <thread>
#include <windows.h>
#include "package_global.h"
#include "FileLogger.h"
#include <memory>
#include <vector>
#include "StreamSession.h"
#include "NpcapCommands.h"

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;


void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
void WINAPI ServiceCtrlHandler(DWORD ctrlCode);

int main() {
    FileLogger::Instance().Info("main() entered; starting service control dispatcher");
    TCHAR serviceName[] = TEXT("PacketCaptureService");
    SERVICE_TABLE_ENTRY serviceTable[] = {
        { serviceName, ServiceMain },
        { nullptr, nullptr }
    };
    StartServiceCtrlDispatcher(serviceTable);
    FileLogger::Instance().Info("StartServiceCtrlDispatcher returned; process exiting");
    FileLogger::Instance().Info("Service status set to RUNNING");

    return 0;
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    FileLogger::Instance().Info("ServiceMain entered");
    serviceStatusHandle = RegisterServiceCtrlHandler(TEXT("PacketCaptureService"), ServiceCtrlHandler);
    
    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwCurrentState = SERVICE_RUNNING;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    serviceStatus.dwWin32ExitCode = 0;
    serviceStatus.dwServiceSpecificExitCode = 0;
    serviceStatus.dwCheckPoint = 0;
    serviceStatus.dwWaitHint = 0;
    
    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    FileLogger::Instance().Info("Service status set to RUNNING");
    StreamSession::Builder builder(1);
    builder.WithEvent(hEvent)
        .WithDevice(3)
        .Start()
        .PutDev(3);

    StreamSession session = builder.Build();

    NpcapContext ctx;
    ctx.session = &session;

    CommandInvoker invoker;
    invoker.Add(std::make_unique<ConnectPipeCommand>());
    invoker.Add(std::make_unique<ReadSnapshotsCommand>());
    session.SignalAndJoin();

    if (!invoker.ExecuteAll(ctx)) {
        FileLogger::Instance().Warn("Command sequence failed");
        if (ctx.hPipe != INVALID_HANDLE_VALUE) CloseHandle(ctx.hPipe);
        CloseHandle(hEvent);
    }

   
    FileLogger::Instance().Info("ServiceMain exiting");

}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    if (ctrlCode == SERVICE_CONTROL_STOP) {
        FileLogger::Instance().Info("SERVICE_CONTROL_STOP received");
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
        FileLogger::Instance().Info("Service status set to STOPPED");
    }
}