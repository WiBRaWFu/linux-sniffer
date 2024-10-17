#include "LibpcapCapture.hpp"
#include "PacketCapture.hpp"
#include "TuiDisplay.hpp"
#include "scroll.h"
#include <mutex>
#include <ncurses.h>
#include <string>

TuiDisplay::TuiDisplay() {
    headerWin = nullptr;
    packetWin = nullptr;

    cap = std::make_unique<LibpcapCapture>();
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
    cap->startCapture();
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
    std::string title = "Packet Capture";
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
        cap->mtx.lock();
        // 收集所有包的信息
        std::vector<std::string> info_list;
        for (auto &pkt: cap->packets) {
            std::string info;
            info += pkt.src_mac + " ";
            info += pkt.dst_mac + " ";
            info += pkt.src_ip + " ";
            info += pkt.dst_ip + " ";
            info += pkt.protocol + " ";
            if (pkt.protocol == "tcp" || pkt.protocol == "udp") {
                info += "[SRC-PORT]" + std::to_string(pkt.src_port) + " ";
                info += "[DST_PORT]" + std::to_string(pkt.dst_port) + " ";
            } else if (pkt.protocol == "icmp") {
                info += "[TYPE]" + std::to_string(pkt.icmp_type) + " ";
                info += "[CODE]" + std::to_string(pkt.icmp_code) + " ";
            }
            info_list.push_back(info);
        }
        cap->mtx.unlock();

        std::vector<char *> chlist;
        for (auto &str: info_list) {
            chlist.push_back((char *) str.c_str());
        }

        setCDKScrollItems(scrollList, (CDK_CSTRING2) chlist.data(), chlist.size(), TRUE);
        drawCDKScroll(scrollList, TRUE);
        // activateCDKScroll(scrollList, nullptr);
        usleep(500000);
    }
}
