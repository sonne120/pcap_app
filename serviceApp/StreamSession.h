#pragma once
#include <windows.h>
#include <thread>

struct StreamSessionConfig {
    HANDLE hEvent { nullptr };
    int deviceId { 1 };
};

class StreamSession {
public:
    class Builder {
    public:
        explicit Builder(int devIndex);
        ~Builder();

        Builder& WithEvent(HANDLE h);
        Builder& WithDevice(int dev);
        Builder& Start();           
        Builder& PutDev(int dev);
   
        StreamSession Build();

    private:
        StreamSessionConfig cfg_{};
        std::thread worker_{}; 

        friend class StreamSession;
    };

    HANDLE Event() const;

public:
    void SignalAndJoin();
private:
    StreamSessionConfig cfg_{};
    StreamSession(const Builder& b);
    StreamSession(Builder&& b);
    std::thread worker_{}; 
};
