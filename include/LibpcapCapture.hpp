#ifndef LIBPCAP_CAPTURE_HPP
#define LIBPCAP_CAPTURE_HPP

#include "PacketCapture.hpp"
#include <pcap/pcap.h>
#include <thread>
#include <unordered_map>

class LibpcapCapture : public PacketCapture {
public:
    LibpcapCapture();
    ~LibpcapCapture();

    void startCapture() override;
    void stopCapture() override;
    void setFilter(const std::string &filter) override;

private:
    friend void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet_body);

    pcap_if_t *devices;
    pcap_t *handle;

    std::unordered_map<int, pcap_if_t *> device_list;
    std::thread captureThread;
};

#endif
