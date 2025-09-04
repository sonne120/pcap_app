#include "StreamSession.h"
#include <windows.h>
#include <thread>
#include "package_global.h"
#include "FileLogger.h"

// Builder
StreamSession::Builder::Builder(int devIndex) {
    cfg_.deviceId = devIndex;
}

StreamSession::Builder::~Builder() {
    if (worker_.joinable()) {
        worker_.detach();
    }
}

StreamSession::Builder& StreamSession::Builder::WithEvent(HANDLE h) {
    cfg_.hEvent = h; return *this;
}

StreamSession::Builder& StreamSession::Builder::WithDevice(int dev) {
    cfg_.deviceId = dev; return *this;
}

StreamSession::Builder& StreamSession::Builder::Start() {
    FileLogger::Instance().Info("StreamSession::Builder.Start()");
    worker_ = std::thread([dev = cfg_.deviceId]() {
        fnCPPDLL(dev);
    });
    worker_.detach();
    return *this;
}

StreamSession::Builder& StreamSession::Builder::PutDev(int dev) {
    FileLogger::Instance().Info("StreamSession::Builder.PutDev()");
    fnPutdevCPPDLL(dev);
    return *this;
}

void StreamSession::SignalAndJoin()     
{
    if (!SetEvent(cfg_.hEvent)) {
        FileLogger::Instance().Warn("SetEvent failed in StreamSession::SignalAndJoin");
    }
}

StreamSession StreamSession::Builder::Build() {
    return StreamSession(*this);
}
StreamSession::StreamSession(const Builder& b)
    : cfg_(b.cfg_) {}
StreamSession::StreamSession(Builder&& b):worker_(std::move(b.worker_))
{
  if (b.worker_.joinable()) {
   b.worker_.detach();
  }
}


HANDLE StreamSession::Event() const { return cfg_.hEvent; }

