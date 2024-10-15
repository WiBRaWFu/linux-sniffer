#ifndef PACKET_PROCESSOR_HPP
#define PACKET_PROCESSOR_HPP

#include "PacketCapture.hpp"
#include <string>

class PacketProcessor {
public:
    // 解析数据包，返回可读的解析结果
    std::string processPacket(const Packet &packet);

    // 判断数据包是否匹配某些条件（如IP、协议等）
    bool filterPacket(const Packet &packet, const std::string &filter);

    ~PacketProcessor() {}
};

#endif
