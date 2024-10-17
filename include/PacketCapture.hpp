#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include "PacketProcessor.hpp"
#include <memory>
#include <string>

class PacketCapture {
public:
    virtual ~PacketCapture() {}

    virtual void startCapture() = 0;
    virtual void stopCapture() = 0;
    virtual void setFilter(const std::string &filter) = 0;

    static std::shared_ptr<PacketProcessor> processor;
};

#endif
