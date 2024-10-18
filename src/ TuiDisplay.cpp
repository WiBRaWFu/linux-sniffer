#include "LibpcapCapture.hpp"
#include "TuiDisplay.hpp"

TuiDisplay::TuiDisplay() {
    capture = std::make_shared<LibpcapCapture>();
}

TuiDisplay::~TuiDisplay() {
    close();
}

void TuiDisplay::init() {
    cdk_screen = initCDKScreen(nullptr);
    initCDKColor();

    noecho();
    cbreak();
    curs_set(0);
    cdk_screen->window->_notimeout = true;
    nodelay(cdk_screen->window, true);
    keypad(cdk_screen->window, TRUE);
}

void TuiDisplay::update() {
    draw();
}

void TuiDisplay::close() {
    destroyCDKScreen(cdk_screen);
    endCDK();
}

void TuiDisplay::draw() {
    // input filter
    cdk_filter_input = newCDKEntry(
            cdk_screen, LEFT, TOP,
            "<C></B/31>[SET FILTER]<!31>", "</B>Expression:",
            A_DIM, ' ',
            vLMIXED,
            0,
            0, 20,
            TRUE, TRUE);

    setCDKEntryHorizontalChar(cdk_filter_input, '-');
    setCDKEntryULChar(cdk_filter_input, '+');
    setCDKEntryURChar(cdk_filter_input, '+');
    setCDKEntryLLChar(cdk_filter_input, '+');
    setCDKEntryLRChar(cdk_filter_input, '+');

    // set filter
    char *filter = activateCDKEntry(cdk_filter_input, nullptr);
    if (filter)
        capture->setFilter(std::string(filter));
    capture->startCapture();

    // destroy
    destroyCDKEntry(cdk_filter_input);

    // list packets
    cdk_scroll_list = newCDKScroll(
            cdk_screen, LEFT, TOP, RIGHT,
            0, 0,
            "<C></B/31>[PACKET SNIFFER]<!31>",
            nullptr, 0,
            TRUE,
            A_STANDOUT,
            TRUE, FALSE);

    setCDKScrollHorizontalChar(cdk_scroll_list, '-');
    setCDKScrollULChar(cdk_scroll_list, '+');
    setCDKScrollURChar(cdk_scroll_list, '+');
    setCDKScrollLLChar(cdk_scroll_list, '+');
    setCDKScrollLRChar(cdk_scroll_list, '+');
    setCDKScrollBackgroundColor(cdk_scroll_list, "</26>");

    while (true) {
        // get info cache
        capture->processor->info_mtx.lock();
        auto info_cache = capture->processor->getInfo();
        capture->processor->info_mtx.unlock();

        // format the short info
        std::vector<char *> short_info = {};
        for (auto &info: info_cache) {
            std::string key;
            for (int i = 0; i < 5; i++) {
                auto &p = info[i];
                p.second.resize(20, ' ');
                key += p.second;
            }
            char *key_ptr = new char[128];
            sprintf(key_ptr, "%s", key.c_str());
            short_info.push_back(key_ptr);
        }

        // show list
        setCDKScrollItems(cdk_scroll_list, (CDK_CSTRING2) short_info.data(), short_info.size(), TRUE);
        int idx = activateCDKScroll(cdk_scroll_list, nullptr);

        if (cdk_scroll_list->exitType == vNORMAL && !short_info.empty()) {
            // show the detail
            auto &info = info_cache[idx];
            int n = info.size();
            char **lines = new char *[n];

            for (int i = 0; i < n; i++) {
                char *line = new char[128];
                std::string str = std::string("<#DI>") + info[i].first + " " + info[i].second;
                sprintf(line, "%s", str.c_str());
                lines[i] = line;
            }

            popupLabel(cdk_screen, lines, n);

            // free
            for (int i = 0; i < short_info.size(); i++) {
                delete[] short_info[i];
            }
            for (int i = 0; i < n; i++) {
                delete[] lines[i];
            }
            delete[] lines;
        } else if (cdk_scroll_list->exitType == vESCAPE_HIT) {
            break;
        }
    }
    destroyCDKScroll(cdk_scroll_list);
}
