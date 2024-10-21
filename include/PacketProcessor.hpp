#ifndef PACKET_PROCESSOR_HPP
#define PACKET_PROCESSOR_HPP

#include "PacketDefine.hpp"
#include <mutex>
#include <string>
#include <vector>

class PacketProcessor {
public:
    PacketProcessor();
    ~PacketProcessor();

    void process();
    std::vector<std::vector<std::pair<std::string, std::string>>> getInfo() {
        return info_cache;
    };

    std::mutex packet_mtx;
    std::vector<Packet> packet_cache;

    std::mutex info_mtx;
    std::vector<std::vector<std::pair<std::string, std::string>>> info_cache;
};

#endif