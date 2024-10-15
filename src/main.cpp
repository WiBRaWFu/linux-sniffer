#include "LibpcapCapture.hpp"

int main(int argc, char *argv[]) {

    LibpcapCapture libpcapCapture;

    libpcapCapture.setFilter("tcp");

    libpcapCapture.startCapture();

    return 0;
}
