#include "LibpcapCapture.hpp"
#include "TuiDisplay.hpp"

TuiDisplay::TuiDisplay() {
    cap = std::make_unique<LibpcapCapture>();

    // cap.setFilter("tcp or udp");

    cap->startCapture();
}

TuiDisplay::~TuiDisplay() {}

void TuiDisplay::init() {}

void TuiDisplay::update() {}

void TuiDisplay::close() {}

void TuiDisplay::drawHeader() {}

void TuiDisplay::drawPacketList() {}