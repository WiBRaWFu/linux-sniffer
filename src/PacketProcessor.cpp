#include "PacketProcessor.hpp"
#include <mutex>
#include <string>

std::vector<std::string> PacketProcessor::getInfo() {
    std::vector<std::string> info;
    std::lock_guard<std::mutex> lock(mtx);

    for (auto &packet: packet_list) {
        char src_mac[18], dst_mac[18];
        sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                packet.eth_header.src_mac[0], packet.eth_header.src_mac[1],
                packet.eth_header.src_mac[2], packet.eth_header.src_mac[3],
                packet.eth_header.src_mac[4], packet.eth_header.src_mac[5]);
        sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                packet.eth_header.dst_mac[0], packet.eth_header.dst_mac[1],
                packet.eth_header.dst_mac[2], packet.eth_header.dst_mac[3],
                packet.eth_header.dst_mac[4], packet.eth_header.dst_mac[5]);
        std::string message = std::string(src_mac) + "<><><>" + std::string(dst_mac);
        info.push_back(message);
    }

    return info;
}