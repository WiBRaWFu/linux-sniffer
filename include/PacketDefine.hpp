#ifndef PACKET_DEFINE_HPP
#define PACKET_DEFINE_HPP

#include <cstdint>

struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
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

struct ICMPHeader {
    uint8_t type;     // ICMP 消息类型 (如 8 表示回显请求, 0 表示回显应答)
    uint8_t code;     // ICMP 代码 (与类型结合使用)
    uint16_t checksum;// ICMP 校验和
    union {
        struct {
            uint16_t identifier;// 标识符 (通常用于区分回显请求和应答)
            uint16_t sequence;  // 序列号 (通常用于区分回显请求和应答)
        } echo;                 // 回显请求和应答
        uint32_t gateway;       // 网关地址 (用于重定向消息)
        uint32_t unused;        // 通用的未使用字段
    } data;                     // 根据类型的不同，数据字段可能有所不同
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

struct Packet {
    EthernetHeader eth_header;// 以太网头
    union {
        IPv4Header ip_header;// IPv4头
        ARPHeader arp_header;// ARP头
    };
    union {
        ICMPHeader icmp_header;//ICMP头
        TCPHeader tcp_header;  // TCP头
        UDPHeader udp_header;  // UDP头
    };
    char *payload;
    uint32_t payload_size;
    uint32_t cap_size;
    uint32_t origin_size;
};

struct NTPPacket {
    uint8_t li_vn_mode;          // LI, VN, Mode
    uint8_t stratum;             // Stratum level
    uint8_t poll;                // Poll interval
    int8_t precision;            // Precision
    uint32_t root_delay;         // Root Delay
    uint32_t root_dispersion;    // Root Dispersion
    uint32_t reference_id;       // Reference ID
    uint64_t reference_timestamp;// Reference timestamp (64 bits)
    uint64_t originate_timestamp;// Originate timestamp (64 bits)
    uint64_t receive_timestamp;  // Receive timestamp (64 bits)
    uint64_t transmit_timestamp; // Transmit timestamp (64 bits)
};

#endif