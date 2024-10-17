#include "TuiDisplay.hpp"

int main(int argc, char *argv[]) {

    TuiDisplay tui;
    tui.init();

    tui.update();

    tui.close();
    return 0;
}
