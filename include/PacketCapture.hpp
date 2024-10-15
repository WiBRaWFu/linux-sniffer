#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include <string>
#include <vector>

struct Packet {
    std::string timestamp;
    std::string sourceIP;
    std::string destIP;
    int protocol;
    std::vector<uint8_t> data;
};

class PacketCapture {
public:
    virtual void startCapture() = 0;

    virtual void stopCapture() = 0;

    virtual std::vector<Packet> getCapturedPackets() = 0;

    virtual void setFilter(const std::string &filter) = 0;

    virtual ~PacketCapture() {}
};

#endif
