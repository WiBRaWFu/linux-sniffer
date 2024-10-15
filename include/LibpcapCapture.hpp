#ifndef LIBPCAP_CAPTURE_HPP
#define LIBPCAP_CAPTURE_HPP

#include "PacketCapture.hpp"
#include <atomic>
#include <mutex>
#include <pcap.h>
#include <thread>

class LibpcapCapture : public PacketCapture {
public:
    LibpcapCapture();
    ~LibpcapCapture();

    void startCapture() override;
    void stopCapture() override;
    std::vector<Packet> getCapturedPackets() override;
    void setFilter(const std::string &filter) override;

private:
    void captureLoop();

    pcap_if_t *devices;
    pcap_t *handle;

    std::thread captureThread;
    std::mutex packetMutex;
    std::atomic<bool> capturing;
    std::vector<Packet> packetBuffer;
    std::string filterExpression;
};

#endif
