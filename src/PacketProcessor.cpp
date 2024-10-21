#include "PacketProcessor.hpp"
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string>
#include <thread>
#include <utility>

std::vector<std::string> parse_http_payload(const char *payload, int payload_size) {
    std::string data(payload, payload_size);
    std::vector<std::string> res;

    // 查找HTTP头部结束的位置
    size_t header_end_pos = data.find("\r\n\r\n");

    if (header_end_pos == std::string::npos) {
        return {};
    }

    // 提取HTTP头部
    std::string header = data.substr(0, header_end_pos);
    res.push_back(header);

    // 提取HTTP正文
    size_t body_start_pos = header_end_pos + 4;// 跳过 "\r\n\r\n"
    std::string body = data.substr(body_start_pos);
    res.push_back(body);

    return res;
}

PacketProcessor::PacketProcessor() {
    std::thread pt([&]() {
        process();
    });
    pt.detach();
}

PacketProcessor::~PacketProcessor() {}

void PacketProcessor::process() {
    while (true) {
        info_mtx.lock();
        int len = info_cache.size();

        packet_mtx.lock();
        for (int i = len; i < packet_cache.size(); i++) {
            Packet &packet = packet_cache[i];
            std::vector<std::pair<std::string, std::string>> packet_info;

            packet_info.emplace_back(std::make_pair("<Captured Length>", std::to_string(packet.cap_size)));
            packet_info.emplace_back(std::make_pair("<Original Length>", std::to_string(packet.cap_size)));

            char src_mac[18], dst_mac[18];
            sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    packet.eth_header.src_mac[0], packet.eth_header.src_mac[1],
                    packet.eth_header.src_mac[2], packet.eth_header.src_mac[3],
                    packet.eth_header.src_mac[4], packet.eth_header.src_mac[5]);
            sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    packet.eth_header.dst_mac[0], packet.eth_header.dst_mac[1],
                    packet.eth_header.dst_mac[2], packet.eth_header.dst_mac[3],
                    packet.eth_header.dst_mac[4], packet.eth_header.dst_mac[5]);

            packet_info.emplace_back(std::make_pair("<Source MAC>", std::string(src_mac)));
            packet_info.emplace_back(std::make_pair("<Destination MAC>", std::string(dst_mac)));

            if (ntohs(packet.eth_header.ethertype) == ETHERTYPE_IP) {
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(packet.ip_header.src_ip), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(packet.ip_header.dest_ip), dst_ip, INET_ADDRSTRLEN);

                packet_info.emplace_back(std::make_pair("<Source IP>", std::string(src_ip)));
                packet_info.emplace_back(std::make_pair("<Destination IP>", std::string(dst_ip)));

                // check for TCP or UDP packets
                if (packet.ip_header.protocol == IPPROTO_TCP) {
                    int src_port = ntohs(packet.tcp_header.src_port);
                    int dst_port = ntohs(packet.tcp_header.dest_port);

                    if (src_port == 80 || dst_port == 80) {
                        packet_info.emplace_back(std::make_pair("<Protocol>", "http"));
                        if (packet.payload_size) {
                            auto res = parse_http_payload(packet.payload, packet.payload_size);
                            if (res.size() == 2) {
                                packet_info.emplace_back(std::make_pair("<HTTP Header>", res[0]));
                            }
                        }
                    } else if (src_port == 443 || dst_port == 443)
                        packet_info.emplace_back(std::make_pair("<Protocol>", "https"));
                    else {
                        packet_info.emplace_back(std::make_pair("<Protocol>", "tcp"));
                    }

                    packet_info.emplace_back(std::make_pair("<Source Port>", std::to_string(src_port)));
                    packet_info.emplace_back(std::make_pair("<Destination Port>", std::to_string(dst_port)));
                } else if (packet.ip_header.protocol == IPPROTO_UDP) {
                    packet_info.emplace_back(std::make_pair("<Protocol>", "udp"));

                    int src_port = ntohs(packet.udp_header.src_port);
                    int dst_port = ntohs(packet.udp_header.dest_port);

                    packet_info.emplace_back(std::make_pair("<Source Port>", std::to_string(src_port)));
                    packet_info.emplace_back(std::make_pair("<Destination Port>", std::to_string(dst_port)));
                } else if (packet.ip_header.protocol == IPPROTO_ICMP) {
                    packet_info.emplace_back(std::make_pair("<Protocol>", "icmp"));

                    if (packet.icmp_header.type == ICMP_ECHO) {
                        packet_info.emplace_back(std::make_pair("<ICMP Type>", "echo"));
                    } else if (packet.icmp_header.type == ICMP_ECHOREPLY) {
                        packet_info.emplace_back(std::make_pair("<ICMP Type>", "echo reply"));
                    }
                }
            } else if (ntohs(packet.eth_header.ethertype) == ETHERTYPE_ARP) {
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(packet.arp_header.sender_ip), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(packet.arp_header.target_ip), dst_ip, INET_ADDRSTRLEN);

                packet_info.emplace_back(std::make_pair("<Source IP>", std::string(src_ip)));
                packet_info.emplace_back(std::make_pair("<Destination IP>", std::string(dst_ip)));
                packet_info.emplace_back(std::make_pair("<Protocol>", "arp"));
            }

            info_cache.push_back(packet_info);
        }
        packet_mtx.unlock();

        info_mtx.unlock();
    }
}
