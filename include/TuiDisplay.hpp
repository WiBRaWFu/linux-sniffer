#ifndef TUI_DISPLAY_HPP
#define TUI_DISPLAY_HPP

#include "PacketCapture.hpp"
#include <cdk/cdk.h>
#include <memory>
#include <ncurses.h>

class TuiDisplay {
public:
    TuiDisplay();
    ~TuiDisplay();

    void init();
    void update();
    void close();

private:
    std::unique_ptr<PacketCapture> cap;

    void drawHeader();
    void drawPacketList();

    WINDOW *headerWin;
    WINDOW *packetWin;

    int winHeight, winWidth;
};

#endif
