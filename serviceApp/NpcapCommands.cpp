#include "NpcapCommands.h"
#include "FileLogger.h"
#include "struct.h"
#include "package_global.h"

#define buff_max 3
Snapshot buffer[buff_max];

bool ConnectPipeCommand::Execute(NpcapContext& ctx) {
    FileLogger::Instance().Info("ConnectPipeCommand.Execute()");
    return ConnectPipeClient(ctx.hPipe);
}

//Command
bool ConnectPipeCommand::ConnectPipeClient(HANDLE& hPipe) {
	const wchar_t* pipeName = L"\\\\.\\pipe\\testpipe";

	for (int attempt = 0; attempt < 60; ++attempt) {
		if (WaitNamedPipeW(pipeName, 1000) || GetLastError() == ERROR_SEM_TIMEOUT) {
		hPipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
				OPEN_EXISTING, 0, nullptr);
			if (hPipe != INVALID_HANDLE_VALUE) {
				DWORD mode = PIPE_READMODE_MESSAGE;
				if (!SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr)) {
				}
				return true;
			}
		}
		Sleep(100);
	}
	std::wcerr << L"Failed to open pipe. GLE=" << GetLastError() << std::endl;
	return false;
}

bool ReadSnapshotsCommand::Execute(NpcapContext& ctx) {
    FileLogger::Instance().Info("ReadSnapshotsCommand.Execute()");
    if (ctx.hPipe == INVALID_HANDLE_VALUE) return false;
    ReadSnapshots(ctx.hPipe);
    return true;
}

void ReadSnapshotsCommand::ReadSnapshots(HANDLE hPipe) {
    constexpr size_t snap_size = sizeof(Snapshot);
    DWORD bytesRead = 0;
    size_t filled = 0;

    while (true) {

        DWORD avail = 0, msgBytes = 0, msgCount = 0;
        if (!PeekNamedPipe(hPipe, nullptr, 0, nullptr, &avail, &msgBytes)) {
            std::wcerr << L"PeekNamedPipe failed. GLE=" << GetLastError() << L"\n";
            break;
        }
        if (avail == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            continue;
        }

        DWORD toRead = static_cast<DWORD>(snap_size - filled);
        BOOL ok = ReadFile(hPipe, buffer + filled, toRead, &bytesRead, nullptr);
        if (!ok) {
            DWORD le = GetLastError();
            if (le == ERROR_BROKEN_PIPE) {
                std::wcout << L"Server closed the pipe\n";
                break;
            }
            if (le == ERROR_MORE_DATA) {

                continue;
            }
            std::wcerr << L"ReadFile failed. GLE=" << le << L" (filled=" << filled
                << L" bytes, requested=" << toRead << L", avail=" << avail
                << L", msgBytes=" << msgBytes << L")\n";
            break;
        }

        if (bytesRead == 0) {
            break;
        }

        filled += bytesRead;
        while (filled >= snap_size) {
            Snapshot snap{};
            memcpy(&snap, buffer, snap_size);

            std::ostringstream oss;
            oss << "Received id=" << snap.id
                << " src=" << snap.source_ip << ":" << snap.source_port
                << " dst=" << snap.dest_ip << ":" << snap.dest_port
                << " proto=" << snap.proto
                << " smac=" << snap.source_mac
                << " dmac=" << snap.dest_mac
                << " host=" << snap.host_name << std::endl;

            FileLogger::Instance().Info(oss.str());

            size_t remain = filled - snap_size;
            if (remain > 0) memmove(buffer, buffer + snap_size, remain);
            filled = remain;
        }
    }
}

