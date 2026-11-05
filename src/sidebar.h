#pragma once
#include "common.h"

#define WM_APP_SIDEBAR (WM_APP + 3)

struct SidebarRow {
    bool header = false;
    int tab = -1;
    int stockIcon = 0;
    std::wstring label;
};

HWND CreateSidebar(HWND parent, HINSTANCE instance, const std::vector<SidebarRow>& rows, int dpi);
void SidebarSelect(HWND sidebar, int tab);
void SidebarLayout(HWND sidebar, int x, int y, int width, int height);
