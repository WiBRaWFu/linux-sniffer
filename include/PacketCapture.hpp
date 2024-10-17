#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include <mutex>
#include <string>
#include <vector>

struct Packet {
    std::string src_mac;
    std::string dst_mac;
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;  // "TCP", "UDP", "ICMP", "ARP", etc.
    int src_port;          // For TCP/UDP
    int dst_port;          // For TCP/UDP
    unsigned int icmp_type;// For ICMP
    unsigned int icmp_code;// For ICMP
};

class PacketCapture {
public:
    virtual void startCapture() = 0;

    virtual void stopCapture() = 0;

    virtual void setFilter(const std::string &filter) = 0;

    virtual ~PacketCapture() {}

    // static void push(Packet packet) {
    //     std::lock_guard<std::mutex> lock(mtx);
    //     packets.push(packet);
    // }

    // static bool pop(Packet &packet) {
    //     std::lock_guard<std::mutex> lock(mtx);
    //     if (!packets.empty()) {
    //         packet = packets.front();
    //         packets.pop();
    //         return true;
    //     }
    //     return false;
    // }

    static std::vector<Packet> packets;
    static std::mutex mtx;
};

#endif
