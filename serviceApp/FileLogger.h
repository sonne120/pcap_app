#ifndef FILELOGGEER_H
#define FILELOGGEER_H
#include <mutex>
#include <chrono>
#include <iomanip>
#include <string>
#include <fstream>
#include <filesystem>
#include <iostream>

class FileLogger {
public:
    static FileLogger& Instance() {
        static FileLogger inst;
        return inst;
    }

    void Info(const std::string& msg) { Log("INFO", msg); }
    void Warn(const std::string& msg) { Log("WARN", msg); }
    void Error(const std::string& msg) { Log("ERROR", msg); }

    void  Log(const char* level, const std::string& msg) {
        std::lock_guard<std::mutex> lock(mutex);
        if (!ofstream.is_open()) return;

        const auto now = std::chrono::system_clock::now();
        const auto tt = std::chrono::system_clock::to_time_t(now);
        tm tmLocal{};
        (void)localtime_s(&tmLocal, &tt);

        ofstream << std::put_time(&tmLocal, "%Y-%m-%d %H:%M:%S")
            << " [" << level << "] " << msg << "\n";
        ofstream.flush();
    }

private:
    FileLogger() {
        try {
            std::filesystem::path dir = "C:\\ProgramData\\pcap_app\\logs";
            std::error_code ec;
            std::filesystem::create_directories(dir, ec);
            ofstream.open(dir / "serviceApp.log", std::ios::app);
        }
        catch (const std::exception& ex) {
            std::cerr << "FileLogger init failed: " << ex.what() << '\n';
        }
        catch (...) {
            std::cerr << "FileLogger init failed: unknown error\n";
        }
    }

    std::mutex mutex;
    std::ofstream ofstream;

    FileLogger(const FileLogger&) = delete;
    FileLogger& operator=(const FileLogger&) = delete;
    FileLogger(FileLogger&&) = delete;
    FileLogger& operator=(FileLogger&&) = delete;
};
#endif