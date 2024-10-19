#include "LibpcapCapture.hpp"
#include "TuiDisplay.hpp"
#include <cstring>

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
    // interface list
    std::vector<std::string> interfaces = capture->getAllDeviceName();
    auto name_list = vectorToCharArray(interfaces);

    cdk_interface_list = newCDKItemlist(
            cdk_screen, CENTER, CENTER,
            "<C></B/31>[ Interface ]<!31>", nullptr,
            name_list, interfaces.size(), 0,
            TRUE, TRUE);
    setCDKItemlistHorizontalChar(cdk_interface_list, '-');
    setCDKItemlistULChar(cdk_interface_list, '+');
    setCDKItemlistURChar(cdk_interface_list, '+');
    setCDKItemlistLLChar(cdk_interface_list, '+');
    setCDKItemlistLRChar(cdk_interface_list, '+');

    int idx_interface = activateCDKItemlist(cdk_interface_list, nullptr);
    capture->openDevice(interfaces[idx_interface]);

    // input filter
    cdk_filter_input = newCDKEntry(
            cdk_screen, CENTER, BOTTOM,
            nullptr, "</B>Filter Expression:",
            A_DIM, ' ',
            vLMIXED,
            0,
            0, 25,
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
    freeCharArray(name_list, interfaces.size());
    destroyCDKItemlist(cdk_interface_list);
    destroyCDKEntry(cdk_filter_input);

    // list packets
    cdk_scroll_list = newCDKScroll(
            cdk_screen, LEFT, TOP, RIGHT,
            0, 0,
            "<C></B/31>[ Packet Sniffer ]<!31>",
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
        std::vector<std::string> key_info_list;
        for (auto &info: info_cache) {
            std::string key_info;
            for (int i = 1; i < 6; i++) {
                auto str = info[i].second;
                str.resize(20, ' ');
                key_info += str;
            }
            key_info_list.push_back(key_info);
        }
        auto item_list_1 = vectorToCharArray(key_info_list);
        setCDKScrollItems(cdk_scroll_list, item_list_1, key_info_list.size(), TRUE);
        int idx = activateCDKScroll(cdk_scroll_list, nullptr);

        if (cdk_scroll_list->exitType == vNORMAL && !key_info_list.empty()) {
            // show the detail
            auto &info = info_cache[idx];
            std::vector<std::string> detail_info_list;
            for (auto &p: info) {
                auto key = p.first;
                key.resize(15, ' ');
                auto value = p.second;
                value.resize(20, ' ');
                std::string detail_info = std::string("<#DI>") + key + value;
                detail_info_list.push_back(detail_info);
            }
            auto item_list_2 = vectorToCharArray(detail_info_list);
            popupLabel(cdk_screen, item_list_2, detail_info_list.size());

            // free
            freeCharArray(item_list_1, key_info_list.size());
            freeCharArray(item_list_2, detail_info_list.size());
        } else if (cdk_scroll_list->exitType == vESCAPE_HIT) {
            break;
        }
    }
    destroyCDKScroll(cdk_scroll_list);
}

char **TuiDisplay::vectorToCharArray(const std::vector<std::string> &vec) {
    // 分配char*数组的空间
    char **charArray = new char *[vec.size()];

    // 将vector中的每个字符串转换为C风格的字符串
    for (size_t i = 0; i < vec.size(); ++i) {
        // 为每个字符串分配空间，包含结尾的 '\0'
        charArray[i] = new char[vec[i].size() + 1];
        std::strcpy(charArray[i], vec[i].c_str());// 复制字符串内容
    }

    return charArray;
}

void TuiDisplay::freeCharArray(char **charArray, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        delete[] charArray[i];// 释放每个字符串的内存
    }
    delete[] charArray;// 释放数组本身的内存
}