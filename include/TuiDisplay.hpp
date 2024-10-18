#ifndef TUI_DISPLAY_HPP
#define TUI_DISPLAY_HPP

#include "PacketCapture.hpp"
#include <cdk/cdk.h>
#include <entry.h>
#include <memory>
#include <ncurses.h>
#include <scroll.h>

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
    CDKSCREEN *cdk_screen;
    CDKENTRY *cdk_filter_input;
    CDKSCROLL *cdk_scroll_list;
};

#endif
