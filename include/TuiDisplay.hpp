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
    void draw();

    std::shared_ptr<PacketCapture> capture;
    WINDOW *packetWin;
    int winHeight, winWidth;
};

#endif
