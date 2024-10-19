#ifndef LIBPCAP_CAPTURE_HPP
#define LIBPCAP_CAPTURE_HPP

#include "PacketCapture.hpp"
#include <pcap/pcap.h>

class LibpcapCapture : public PacketCapture {
public:
    friend void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet_body);

    LibpcapCapture();
    ~LibpcapCapture();

    void startCapture() override;
    void stopCapture() override;
    void setFilter(const std::string &filter) override;

    void findDevices();
    void openDevice(std::string &name);
    std::vector<std::string> getAllDeviceName();

private:
    pcap_if_t *devices;
    pcap_t *handle;

    std::vector<pcap_if_t *> device_list;
};

#endif
