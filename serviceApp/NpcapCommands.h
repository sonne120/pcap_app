#include <windows.h>
#include <memory>
#include <vector>
#include "StreamSession.h"

struct NpcapContext {
    HANDLE hPipe { INVALID_HANDLE_VALUE };
    StreamSession* session { nullptr }; 
};

class INpcapCommand {
public:
    virtual ~INpcapCommand() = default;
    virtual bool Execute(NpcapContext& ctx) = 0;
};

class ConnectPipeCommand : public INpcapCommand {
public:
    bool Execute(NpcapContext& ctx) override;
    bool ConnectPipeClient(HANDLE& hPipe);
};

class ReadSnapshotsCommand : public INpcapCommand {
public:
    bool Execute(NpcapContext& ctx) override;
    void ReadSnapshots(HANDLE hPipe);
};

class CommandInvoker {
public:
    void Add(std::unique_ptr<INpcapCommand> cmd) { cmds_.emplace_back(std::move(cmd)); }
    bool ExecuteAll(NpcapContext& ctx) {
        for (auto& c : cmds_) {
            if (!c->Execute(ctx)) return false;
        }
        return true;
    }
private:
    std::vector<std::unique_ptr<INpcapCommand>> cmds_;
};

