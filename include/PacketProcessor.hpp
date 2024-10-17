#ifndef PACKET_PROCESSOR_HPP
#define PACKET_PROCESSOR_HPP

#include <cstdint>
#include <mutex>
#include <vector>

struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

struct IPv4Header {
    uint8_t version_ihl;    // 版本和头长度
    uint8_t tos;            // 服务类型
    uint16_t total_length;  // 总长度
    uint16_t identification;// 标识
    uint16_t flags_offset;  // 标志和片偏移
    uint8_t ttl;            // 生存时间
    uint8_t protocol;       // 协议（TCP: 6, UDP: 17）
    uint16_t checksum;      // 头部校验和
    uint32_t src_ip;        // 源IP地址
    uint32_t dest_ip;       // 目标IP地址
};

struct TCPHeader {
    uint16_t src_port;  // 源端口
    uint16_t dest_port; // 目标端口
    uint32_t seq_num;   // 序列号
    uint32_t ack_num;   // 确认号
    uint8_t data_offset;// 数据偏移（TCP头长度）
    uint8_t flags;      // 标志位
    uint16_t window;    // 窗口大小
    uint16_t checksum;  // 校验和
    uint16_t urgent_ptr;// 紧急指针
};

struct UDPHeader {
    uint16_t src_port; // 源端口
    uint16_t dest_port;// 目标端口
    uint16_t length;   // 长度
    uint16_t checksum; // 校验和
};

struct ARPHeader {
    uint16_t hardware_type;// 硬件类型（通常为1表示以太网）
    uint16_t protocol_type;// 协议类型（例如 0x0800 表示 IPv4）
    uint8_t hardware_size; // 硬件地址长度（通常为6，表示MAC地址长度）
    uint8_t protocol_size; // 协议地址长度（通常为4，表示IPv4地址长度）
    uint16_t opcode;       // 操作码（1表示ARP请求，2表示ARP回复）
    uint8_t sender_mac[6]; // 发送方硬件地址（MAC地址）
    uint32_t sender_ip;    // 发送方协议地址（IP地址）
    uint8_t target_mac[6]; // 接收方硬件地址（MAC地址）
    uint32_t target_ip;    // 接收方协议地址（IP地址）
};

struct Packet_ex {
    uint32_t size;
    EthernetHeader eth_header;// 以太网头
    union {
        IPv4Header ip_header;// IPv4头
        ARPHeader arp_header;// ARP头
    };
    union {
        TCPHeader tcp_header;// TCP头
        UDPHeader udp_header;// UDP头
    } transport_layer;       // 传输层协议
};

class PacketProcessor {
public:
    std::vector<std::string> getInfo();

    std::mutex mtx;
    std::vector<Packet_ex> packet_list;
};

#endif