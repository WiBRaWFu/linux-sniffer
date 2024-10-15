#ifndef TUI_DISPLAY_HPP
#define TUI_DISPLAY_HPP

#include "PacketCapture.hpp"
#include <ncurses.h>
#include <vector>

class TuiDisplay {
public:
    TuiDisplay();
    ~TuiDisplay();

    // 初始化界面
    void init();

    // 更新并显示数据包信息
    void update(const std::vector<Packet> &packets);

    // 关闭界面
    void close();

private:
    void drawHeader();                                      // 绘制界面头部
    void drawPacketList(const std::vector<Packet> &packets);// 绘制包列表

    WINDOW *headerWin;// 头部窗口
    WINDOW *packetWin;// 数据包窗口
};

#endif
