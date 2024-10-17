#include "LibpcapCapture.hpp"
#include "TuiDisplay.hpp"
#include "scroll.h"
#include <memory>
#include <ncurses.h>
#include <string>

TuiDisplay::TuiDisplay() : headerWin(nullptr), packetWin(nullptr) {
    capture = std::make_shared<LibpcapCapture>();
}

TuiDisplay::~TuiDisplay() {
    close();
}

void TuiDisplay::init() {
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);
    getmaxyx(stdscr, winHeight, winWidth);

    // create WINDOW
    headerWin = newwin(3, winWidth, 0, 0);
    box(headerWin, 0, 0);

    packetWin = newwin(winHeight - 3, winWidth, 3, 0);
    box(packetWin, 0, 0);

    drawHeader();
    wrefresh(headerWin);
    wrefresh(packetWin);

    // cap.setFilter("tcp or udp");
    capture->startCapture();
}

void TuiDisplay::update() {
    drawPacketList();
}

void TuiDisplay::close() {
    if (headerWin) {
        delwin(headerWin);
    }
    if (packetWin) {
        delwin(packetWin);
    }
    endwin();
}

void TuiDisplay::drawHeader() {
    std::string title = "Packet Sniffer";
    mvwprintw(headerWin, 1, (winWidth - title.size()) / 2, "%s", title.c_str());
}

void TuiDisplay::drawPacketList() {
    CDKSCREEN *cdkScreen = initCDKScreen(packetWin);
    initCDKColor();
    cdkScreen->window->_notimeout = true;
    nodelay(cdkScreen->window, true);
    keypad(cdkScreen->window, TRUE);

    CDKSCROLL *scrollList = newCDKScroll(
            cdkScreen,
            LEFT,
            TOP,
            RIGHT,
            0,
            0,
            "SRC-MAC    DST-MAC    SRC-IP    DST-IP    PROTOCOL",
            nullptr,
            0,
            TRUE,
            A_BOLD,
            TRUE,
            FALSE);

    while (true) {
        auto info = capture->processor->getInfo();

        std::vector<char *> chlist;
        for (auto &str: info) {
            chlist.push_back((char *) str.c_str());
        }

        setCDKScrollItems(scrollList, (CDK_CSTRING2) chlist.data(), chlist.size(), TRUE);
        activateCDKScroll(scrollList, nullptr);
    }
}
