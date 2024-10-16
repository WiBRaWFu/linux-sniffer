#include "LibpcapCapture.hpp"

int main(int argc, char *argv[]) {

    LibpcapCapture libpcapCapture;

    // libpcapCapture.setFilter("tcp or udp");

    libpcapCapture.startCapture();

    return 0;
}
