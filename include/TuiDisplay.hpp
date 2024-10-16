#ifndef TUI_DISPLAY_HPP
#define TUI_DISPLAY_HPP

#include "PacketCapture.hpp"
#include <memory>
#include <ncurses.h>

class TuiDisplay {
public:
    TuiDisplay();
    ~TuiDisplay();

    // 初始化界面
    void init();

    // 更新并显示数据包信息
    void update();

    // 关闭界面
    void close();

private:
    std::unique_ptr<PacketCapture> cap;

    void drawHeader();    // 绘制界面头部
    void drawPacketList();// 绘制包列表

    WINDOW *headerWin;// 头部窗口
    WINDOW *packetWin;// 数据包窗口
};

#endif
