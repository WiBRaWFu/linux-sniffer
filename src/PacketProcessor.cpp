#include "PacketProcessor.hpp"
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <regex>
#include <sstream>
#include <thread>
#include <utility>

std::vector<std::pair<std::string, std::string>> parse_http(const char *payload, int payload_size) {
    std::string data(payload, payload_size);
    std::vector<std::pair<std::string, std::string>> res;

    // find header ending
    size_t header_end_pos = data.find("\r\n\r\n");

    if (header_end_pos == std::string::npos) {
        return {};
    }

    // get header
    std::string header = data.substr(0, header_end_pos);
    res.push_back({"<HTTP Header>", header});

    // get body
    size_t body_start_pos = header_end_pos + 4;// 跳过 "\r\n\r\n"
    std::string body = data.substr(body_start_pos);
    // resolve conflicts between HTML and CDK string attribute commands
    // IMPROVE: currently it is a simple replacement
    auto processed_body = std::regex_replace(body, std::regex("</"), "< /");
    res.push_back({"<HTTP Body>", processed_body});

    return res;
}

uint64_t ntohll(uint64_t value) {
    return (((uint64_t) ntohl(value & 0xFFFFFFFF)) << 32) | ntohl(value >> 32);
}

std::string timestamp_to_string(uint64_t timestamp) {
    std::ostringstream oss;
    oss << timestamp;
    return oss.str();
}

std::vector<std::pair<std::string, std::string>> parse_ntp(const char *packet_body) {
    NTPPacket ntp_packet;
    std::vector<std::pair<std::string, std::string>> result;

    // LI, VN, Mode
    ntp_packet.li_vn_mode = packet_body[0];
    int li = (ntp_packet.li_vn_mode >> 6) & 0x03;
    int vn = (ntp_packet.li_vn_mode >> 3) & 0x07;
    int mode = ntp_packet.li_vn_mode & 0x07;
    result.push_back({"<Leap Indicator>", std::to_string(li)});
    result.push_back({"<Version Number>", std::to_string(vn)});
    result.push_back({"<Mode>", std::to_string(mode)});

    // Stratum
    ntp_packet.stratum = packet_body[1];
    result.push_back({"<Stratum>", std::to_string(ntp_packet.stratum)});

    // Poll
    ntp_packet.poll = packet_body[2];
    result.push_back({"<Poll Interval>", std::to_string(ntp_packet.poll)});

    // Precision
    ntp_packet.precision = packet_body[3];
    result.push_back({"<Precision>", std::to_string(ntp_packet.precision)});

    // Root Delay
    ntp_packet.root_delay = ntohl(*(uint32_t *) (packet_body + 4));
    result.push_back({"<Root Delay>", std::to_string(ntp_packet.root_delay)});

    // Root Dispersion
    ntp_packet.root_dispersion = ntohl(*(uint32_t *) (packet_body + 8));
    result.push_back({"<Root Dispersion>", std::to_string(ntp_packet.root_dispersion)});

    // Reference ID
    ntp_packet.reference_id = ntohl(*(uint32_t *) (packet_body + 12));
    result.push_back({"<Reference ID>", std::to_string(ntp_packet.reference_id)});

    // Reference Timestamp
    ntp_packet.reference_timestamp = ntohll(*(uint64_t *) (packet_body + 16));
    result.push_back({"<Reference Timestamp>", timestamp_to_string(ntp_packet.reference_timestamp)});

    // Originate Timestamp
    ntp_packet.originate_timestamp = ntohll(*(uint64_t *) (packet_body + 24));
    result.push_back({"<Originate Timestamp>", timestamp_to_string(ntp_packet.originate_timestamp)});

    // Receive Timestamp
    ntp_packet.receive_timestamp = ntohll(*(uint64_t *) (packet_body + 32));
    result.push_back({"<Receive Timestamp>", timestamp_to_string(ntp_packet.receive_timestamp)});

    // Transmit Timestamp
    ntp_packet.transmit_timestamp = ntohll(*(uint64_t *) (packet_body + 40));
    result.push_back({"<Transmit Timestamp>", timestamp_to_string(ntp_packet.transmit_timestamp)});

    return result;
}

std::vector<std::pair<std::string, std::string>> parse_dns(const char *data) {
    std::vector<std::pair<std::string, std::string>> result;

    // DNS header
    const uint16_t *header = reinterpret_cast<const uint16_t *>(data);

    uint16_t id = ntohs(header[0]);// Identification
    result.push_back({"<ID>", std::to_string(id)});

    uint16_t flags = ntohs(header[1]);// Flags
    result.push_back({"<Flags>", std::to_string(flags)});

    uint16_t qdCount = ntohs(header[2]);// Number of questions
    result.push_back({"<QDCOUNT>", std::to_string(qdCount)});

    uint16_t anCount = ntohs(header[3]);// Number of answers
    result.push_back({"<ANCOUNT>", std::to_string(anCount)});

    uint16_t nsCount = ntohs(header[4]);// Number of authority records
    result.push_back({"<NSCOUNT>", std::to_string(nsCount)});

    uint16_t arCount = ntohs(header[5]);// Number of additional records
    result.push_back({"<ARCOUNT>", std::to_string(arCount)});

    // DNS Question
    const char *ptr = data + 12;// skip header (12 bytes)

    // QNAME
    std::stringstream qnameStream;
    while (true) {
        uint8_t labelLen = *ptr++;
        if (labelLen == 0) break;// end
        qnameStream << std::string(ptr, labelLen) << ".";
        ptr += labelLen;
    }
    std::string qname = qnameStream.str();
    if (!qname.empty() && qname.back() == '.') {
        qname.pop_back();// remove last '.'
    }
    result.push_back({"<QNAME>", qname});

    // QTYPE and QCLASS
    uint16_t qtype = ntohs(*reinterpret_cast<const uint16_t *>(ptr));
    ptr += 2;
    uint16_t qclass = ntohs(*reinterpret_cast<const uint16_t *>(ptr));
    ptr += 2;

    result.push_back({"<QTYPE>", std::to_string(qtype)});
    result.push_back({"<QCLASS>", std::to_string(qclass)});

    // NAME、TYPE、CLASS、TTL、RDLENGTH、RDATA
    for (int i = 0; i < anCount; ++i) {
        // skip NAME
        while (true) {
            uint8_t labelLen = *ptr++;
            if (labelLen == 0) break;// domain name end
            if ((labelLen & 0xC0) == 0xC0) {
                // skip compression pointer (11)
                ptr++;
                break;
            }
            ptr += labelLen;
        }

        // TYPE
        uint16_t rrType = ntohs(*reinterpret_cast<const uint16_t *>(ptr));
        ptr += 2;
        result.push_back({"<TYPE>", std::to_string(rrType)});

        // CLASS
        uint16_t rrClass = ntohs(*reinterpret_cast<const uint16_t *>(ptr));
        ptr += 2;
        result.push_back({"<CLASS>", std::to_string(rrClass)});

        // TTL
        uint32_t rrTTL = ntohl(*reinterpret_cast<const uint32_t *>(ptr));
        ptr += 4;
        result.push_back({"<TTL>", std::to_string(rrTTL)});

        // RDLENGTH
        uint16_t rdLength = ntohs(*reinterpret_cast<const uint16_t *>(ptr));
        ptr += 2;

        // RDATA
        std::stringstream rdataStream;
        for (int j = 0; j < rdLength; ++j) {
            rdataStream << std::to_string(static_cast<uint8_t>(*ptr++)) << ".";
        }
        std::string rdata = rdataStream.str();
        if (!rdata.empty() && rdata.back() == '.') {
            rdata.pop_back();// remove last '.'
        }
        result.push_back({"<RDATA>", rdata});
    }

    return result;
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

            // packet size
            packet_info.emplace_back(std::make_pair("<Captured Length>", std::to_string(packet.cap_size)));
            packet_info.emplace_back(std::make_pair("<Original Length>", std::to_string(packet.cap_size)));

            // MAC
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
                // IPv4
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
                    packet_info.emplace_back(std::make_pair("<Source Port>", std::to_string(src_port)));
                    packet_info.emplace_back(std::make_pair("<Destination Port>", std::to_string(dst_port)));

                    if (src_port == 80 || dst_port == 80) {
                        packet_info.emplace_back(std::make_pair("<Protocol>", "http"));
                        if (packet.payload_size) {
                            auto res = parse_http(packet.payload, packet.payload_size);
                            for (auto &r: res) {
                                packet_info.emplace_back(r);
                            }
                        }
                    } else if (src_port == 443 || dst_port == 443) {
                        packet_info.emplace_back(std::make_pair("<Protocol>", "https"));
                    } else {
                        packet_info.emplace_back(std::make_pair("<Protocol>", "tcp"));
                    }
                } else if (packet.ip_header.protocol == IPPROTO_UDP) {
                    int src_port = ntohs(packet.udp_header.src_port);
                    int dst_port = ntohs(packet.udp_header.dest_port);
                    packet_info.emplace_back(std::make_pair("<Source Port>", std::to_string(src_port)));
                    packet_info.emplace_back(std::make_pair("<Destination Port>", std::to_string(dst_port)));

                    if (src_port == 123 || dst_port == 123) {
                        packet_info.emplace_back(std::make_pair("<Protocol>", "ntp"));
                        if (packet.payload_size) {
                            auto res = parse_ntp(packet.payload);
                            for (auto &r: res) {
                                packet_info.emplace_back(r);
                            }
                        }
                    } else if (src_port == 53 || dst_port == 53) {
                        packet_info.emplace_back(std::make_pair("<Protocol>", "dns"));
                        if (packet.payload_size) {
                            auto res = parse_dns(packet.payload);
                            for (auto &r: res) {
                                packet_info.emplace_back(r);
                            }
                        }
                    } else {
                        packet_info.emplace_back(std::make_pair("<Protocol>", "udp"));
                    }
                } else if (packet.ip_header.protocol == IPPROTO_ICMP) {
                    // ICMP
                    packet_info.emplace_back(std::make_pair("<Protocol>", "icmp"));
                    if (packet.icmp_header.type == ICMP_ECHO) {
                        packet_info.emplace_back(std::make_pair("<ICMP Type>", "echo"));
                    } else if (packet.icmp_header.type == ICMP_ECHOREPLY) {
                        packet_info.emplace_back(std::make_pair("<ICMP Type>", "echo reply"));
                    }
                }
            } else if (ntohs(packet.eth_header.ethertype) == ETHERTYPE_ARP) {
                // ARP
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
