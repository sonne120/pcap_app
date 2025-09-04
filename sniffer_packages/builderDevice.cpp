#include "builderDevice.h"

builderDevice::Builder::Builder(int devIndex)
    : inum(devIndex), deviceCount(0), alldevs(nullptr),
    selectedDev(nullptr), handle(nullptr) {}

builderDevice::Builder::~Builder() {
    if (alldevs) {
        pcap_freealldevs(alldevs);
        alldevs = nullptr;
    }
}

builderDevice::Builder& builderDevice::Builder::FindDevices() {

    if (alldevs) {
        pcap_freealldevs(alldevs);
        alldevs = nullptr;
    }
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) {
        throw std::runtime_error("Failed to find devices: " + std::string(errbuf));
    }
    deviceCount = 0;
    for (selectedDev = alldevs; selectedDev; selectedDev = selectedDev->next) {
        ++deviceCount;
        std::cout << deviceCount << ". " << selectedDev->name << "\n"
            << (selectedDev->description ? selectedDev->description : "No description available") << "\n";
    }
    return *this;
}

builderDevice::Builder& builderDevice::Builder::SelectDevice() {
    if (!alldevs) {
        FindDevices();
    }
    if (inum < 1 || inum > deviceCount) {
        throw std::out_of_range("Interface number out of range");
    }
    selectedDev = alldevs;
    for (int idx = 1; idx < inum; ++idx) {
        selectedDev = selectedDev->next;
    }
    return *this;
}

builderDevice::Builder& builderDevice::Builder::OpenSelectedDevice() {
    if (inum < 1 || inum > deviceCount) {
        throw std::logic_error("No valid device selected. Call SelectDevice() first.");
    }

    handle = pcap_open(selectedDev->name,
        65536,
        PCAP_OPENFLAG_PROMISCUOUS,
        1000,
        NULL,
        errbuf);
    if (!handle) {
        throw std::runtime_error("Failed to open device: " + std::string(errbuf));
    }
    return *this;
}

builderDevice::Builder& builderDevice::Builder::ListDevices() {
    deviceList.clear();
    if (!alldevs) {
        FindDevices();
    }
    int idx = 0;
    for (pcap_if_t* it = alldevs; it; it = it->next) {
        ++idx;
        if (it->description) {
            std::string desc = std::to_string(idx) + "_" + it->description;
            if (desc.size() > 53) desc.resize(53);
            size_t lastWhitespace = desc.find_last_of(" \t\n\r");
            if (lastWhitespace != std::string::npos) {
                desc.erase(lastWhitespace);
            }
            deviceList.push_back(desc);
        }
    }
    return *this;
}

builderDevice::Builder& builderDevice::Builder::OpenFromFile(const std::string& filePath) {
    handle = pcap_open_offline(filePath.c_str(), errbuf);
    if (!handle) {
        throw std::runtime_error("Failed to open file: " + std::string(errbuf));
    }
    return *this;
}

builderDevice builderDevice::Builder::Build() {
    return builderDevice(*this);
}

pcap_t* builderDevice::getHandler() const {
    return adhandle;
}

const std::vector<std::string>& builderDevice::getDevices() const {
    return list;
}

builderDevice::builderDevice(const Builder& builder)
    : inum(builder.inum), adhandle(builder.handle), list(builder.deviceList) {}