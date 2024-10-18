#include "LibpcapCapture.hpp"
#include "TuiDisplay.hpp"
#include <cdk.h>
#include <cstdio>
#include <entry.h>
#include <memory>
#include <ncurses.h>
#include <scroll.h>

TuiDisplay::TuiDisplay() : packetWin(nullptr) {
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
    packetWin = newwin(winHeight, winWidth, 0, 0);

    // cap.setFilter("tcp or udp");
    capture->startCapture();
}

void TuiDisplay::update() {
    draw();
}

void TuiDisplay::close() {
    if (packetWin) {
        delwin(packetWin);
    }
    endwin();
}

void TuiDisplay::draw() {
    CDKSCREEN *cdkScreen = initCDKScreen(packetWin);
    initCDKColor();
    cdkScreen->window->_notimeout = true;
    nodelay(cdkScreen->window, true);
    keypad(cdkScreen->window, TRUE);

    // filter input example
    // CDKENTRY *input = newCDKEntry(
    //         cdkScreen, LEFT, TOP,
    //         "<C>filter", "expression:",
    //         A_BOLD, ' ',
    //         vLMIXED,
    //         0,
    //         0, 10,
    //         TRUE, TRUE);
    // activateCDKEntry(input, nullptr);

    // packet list
    CDKSCROLL *scrollList = newCDKScroll(
            cdkScreen,
            LEFT,
            TOP,
            RIGHT,
            0,
            0,
            "<C></B/31>[ Packet Sniffer ]<!31>",
            nullptr,
            0,
            TRUE,
            A_STANDOUT,
            TRUE,
            FALSE);

    while (true) {
        capture->processor->info_mtx.lock();
        auto info_cache = capture->processor->getInfo();
        capture->processor->info_mtx.unlock();

        std::vector<char *> short_info = {};
        for (auto &info: info_cache) {
            std::string key;
            for (int i = 0; i < 5; i++) {
                char *buffer = new char[32];
                auto &p = info[i];
                sprintf(buffer, "%-20s", p.second.c_str());
                key += std::string(buffer);
                delete[] buffer;
            }
            char *temp = new char[128];
            sprintf(temp, "%s", key.c_str());
            short_info.push_back(temp);
        }

        setCDKScrollItems(scrollList, (CDK_CSTRING2) short_info.data(), short_info.size(), TRUE);
        setCDKScrollHorizontalChar(scrollList, '-');
        setCDKScrollULChar(scrollList, '+');
        setCDKScrollURChar(scrollList, '+');
        setCDKScrollLLChar(scrollList, '+');
        setCDKScrollLRChar(scrollList, '+');
        setCDKScrollBackgroundColor(scrollList, "</26>");
        int idx = activateCDKScroll(scrollList, nullptr);

        if (scrollList->exitType == vNORMAL && !short_info.empty()) {
            auto &info = info_cache[idx];
            int n = info.size();
            char **lines = new char *[n];

            for (int i = 0; i < n; i++) {
                char *line = new char[128];
                std::string str = std::string("<#DI>") + info[i].first + " " + info[i].second;
                sprintf(line, "%s", str.c_str());
                lines[i] = line;
            }

            popupLabel(cdkScreen, lines, n);

            // free
            for (int i = 0; i < short_info.size(); i++) {
                delete[] short_info[i];
            }
            for (int i = 0; i < n; i++) {
                delete[] lines[i];
            }
            delete[] lines;
        }
    }
}
