#ifndef TUI_DISPLAY_HPP
#define TUI_DISPLAY_HPP

#include "LibpcapCapture.hpp"
#include <cdk/cdk.h>
#include <entry.h>
#include <itemlist.h>
#include <memory>
#include <ncurses.h>
#include <scroll.h>
#include <swindow.h>

#define KEY_INFO_WIDTH 20
#define DETAIL_KEY_WIDTH 25

class TuiDisplay {
public:
    TuiDisplay();
    ~TuiDisplay();

    void init();
    void update();
    void close();

private:
    void draw();

    char **vectorToCharArray(const std::vector<std::string> &vec);
    void freeCharArray(char **charArray, size_t size);

    std::shared_ptr<LibpcapCapture> capture;

    CDKSCREEN *cdk_screen;
    CDKITEMLIST *cdk_interface_list;
    CDKENTRY *cdk_filter_input;
    CDKSCROLL *cdk_scroll_list;
    CDKSWINDOW *cdk_scroll_window;
};

#endif
