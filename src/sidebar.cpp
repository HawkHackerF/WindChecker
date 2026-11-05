#include "sidebar.h"

#include <shellapi.h>
#include <windowsx.h>
#include <cwctype>

namespace {

constexpr int kBrandHeight = 58;
constexpr int kHeaderHeight = 26;
constexpr int kItemHeight = 34;
constexpr int kFooterHeight = 30;

constexpr COLORREF kPanelTop = RGB(0xFF, 0xFF, 0xFF);
constexpr COLORREF kPanelBottom = RGB(0xEF, 0xF2, 0xF7);
constexpr COLORREF kBandTop = RGB(0xEC, 0xF1, 0xF9);
constexpr COLORREF kBandBottom = RGB(0xD3, 0xDF, 0xEF);
constexpr COLORREF kBandEdge = RGB(0xA5, 0xB4, 0xC9);
constexpr COLORREF kGroupText = RGB(0x3A, 0x59, 0x80);
constexpr COLORREF kGroupRule = RGB(0xC4, 0xCF, 0xDE);
constexpr COLORREF kItemText = RGB(0x1B, 0x1B, 0x1F);
constexpr COLORREF kHoverFill = RGB(0xEA, 0xF2, 0xFD);
constexpr COLORREF kHoverEdge = RGB(0xB8, 0xCF, 0xEE);
constexpr COLORREF kSelectFill = RGB(0x31, 0x6A, 0xC5);
constexpr COLORREF kSelectText = RGB(0xFF, 0xFF, 0xFF);
constexpr COLORREF kEdgeShadow = RGB(0xA9, 0xB3, 0xC0);
constexpr COLORREF kEdgeLight = RGB(0xFF, 0xFF, 0xFF);

struct SidebarState {
    std::vector<SidebarRow> rows;
    std::vector<HICON> icons;
    HICON brandIcon = nullptr;
    int selected = 0;
    int hover = -1;
    int scroll = 0;
    int dpi = 96;
    HFONT itemFont = nullptr;
    HFONT headerFont = nullptr;
    HFONT selectedFont = nullptr;
    HFONT brandFont = nullptr;
    HFONT taglineFont = nullptr;
    HFONT footerFont = nullptr;
    std::wstring footerText;
    bool trackingLeave = false;
};

int Scale(const SidebarState* state, int value) {
    return MulDiv(value, state->dpi, 96);
}

bool ProcessElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    bool elevated = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) &&
                    elevation.TokenIsElevated != 0;
    CloseHandle(token);
    return elevated;
}

SidebarState* StateOf(HWND hwnd) {
    return reinterpret_cast<SidebarState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

void FillGradient(HDC dc, const RECT& area, COLORREF top, COLORREF bottom) {
    int height = area.bottom - area.top;
    if (height <= 0) return;
    int red = GetRValue(top), green = GetGValue(top), blue = GetBValue(top);
    int redEnd = GetRValue(bottom), greenEnd = GetGValue(bottom), blueEnd = GetBValue(bottom);
    for (int y = 0; y < height; ++y) {
        int t = height > 1 ? y * 255 / (height - 1) : 0;
        HBRUSH brush = CreateSolidBrush(RGB(red + (redEnd - red) * t / 255,
                                            green + (greenEnd - green) * t / 255,
                                            blue + (blueEnd - blue) * t / 255));
        RECT line{area.left, area.top + y, area.right, area.top + y + 1};
        FillRect(dc, &line, brush);
        DeleteObject(brush);
    }
}

void FillSolid(HDC dc, const RECT& area, COLORREF color) {
    HBRUSH brush = CreateSolidBrush(color);
    FillRect(dc, &area, brush);
    DeleteObject(brush);
}

int ScrollTop(const SidebarState* state) { return Scale(state, kBrandHeight); }

int ScrollBottom(const SidebarState* state, const RECT& rc) {
    int bottom = rc.bottom - Scale(state, kFooterHeight);
    return bottom > ScrollTop(state) ? bottom : ScrollTop(state);
}

int ContentHeight(const SidebarState* state) {
    int height = 0;
    for (const SidebarRow& row : state->rows) {
        height += row.header ? Scale(state, kHeaderHeight) : Scale(state, kItemHeight);
    }
    return height + Scale(state, 10);
}

int RowTop(const SidebarState* state, size_t index) {
    int y = ScrollTop(state) + Scale(state, 4) - state->scroll;
    for (size_t i = 0; i < index && i < state->rows.size(); ++i) {
        y += state->rows[i].header ? Scale(state, kHeaderHeight) : Scale(state, kItemHeight);
    }
    return y;
}

int RowHeight(const SidebarState* state, size_t index) {
    if (index >= state->rows.size()) return 0;
    return state->rows[index].header ? Scale(state, kHeaderHeight) : Scale(state, kItemHeight);
}

int HitTest(HWND hwnd, POINT point) {
    SidebarState* state = StateOf(hwnd);
    if (!state) return -1;
    RECT rc{};
    GetClientRect(hwnd, &rc);
    if (point.y < ScrollTop(state) || point.y >= ScrollBottom(state, rc)) return -1;
    for (size_t i = 0; i < state->rows.size(); ++i) {
        int top = RowTop(state, i);
        int height = RowHeight(state, i);
        if (point.y >= top && point.y < top + height) {
            return state->rows[i].header ? -1 : static_cast<int>(i);
        }
    }
    return -1;
}

void ClampScroll(HWND hwnd) {
    SidebarState* state = StateOf(hwnd);
    if (!state) return;
    RECT rc{};
    GetClientRect(hwnd, &rc);
    int viewport = ScrollBottom(state, rc) - ScrollTop(state);
    int maxScroll = ContentHeight(state) - viewport;
    if (maxScroll < 0) maxScroll = 0;
    if (state->scroll > maxScroll) state->scroll = maxScroll;
    if (state->scroll < 0) state->scroll = 0;
}

void UpdateScrollbar(HWND hwnd) {
    SidebarState* state = StateOf(hwnd);
    if (!state) return;
    RECT rc{};
    GetClientRect(hwnd, &rc);
    int viewport = ScrollBottom(state, rc) - ScrollTop(state);
    int content = ContentHeight(state);
    bool needed = content > viewport && viewport > 0;
    ShowScrollBar(hwnd, SB_VERT, needed ? TRUE : FALSE);
    SCROLLINFO si{};
    si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin = 0;
    si.nMax = content;
    si.nPage = viewport > 0 ? viewport : 1;
    si.nPos = state->scroll;
    SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
}

void PaintBrand(HDC mem, SidebarState* state, const RECT& rc) {
    RECT band{0, 0, rc.right, Scale(state, kBrandHeight)};
    FillGradient(mem, band, kBandTop, kBandBottom);

    RECT light{0, band.bottom - 2, rc.right, band.bottom - 1};
    FillSolid(mem, light, kEdgeLight);
    RECT shadow{0, band.bottom - 1, rc.right, band.bottom};
    FillSolid(mem, shadow, kBandEdge);

    int pad = Scale(state, 10);
    int iconSize = Scale(state, 28);
    if (state->brandIcon) {
        int oldStretch = SetStretchBltMode(mem, HALFTONE);
        SetBrushOrgEx(mem, 0, 0, nullptr);
        DrawIconEx(mem, pad, Scale(state, 12), state->brandIcon, iconSize, iconSize, 0, nullptr,
                   DI_NORMAL);
        SetStretchBltMode(mem, oldStretch);
    }

    SetBkMode(mem, TRANSPARENT);
    int textLeft = pad + iconSize + Scale(state, 9);
    SelectObject(mem, state->brandFont);
    SetTextColor(mem, RGB(0x14, 0x31, 0x5C));
    RECT title{textLeft, Scale(state, 10), rc.right - pad, Scale(state, 34)};
    DrawTextW(mem, L"WindChecker", -1, &title, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    SelectObject(mem, state->taglineFont);
    SetTextColor(mem, RGB(0x55, 0x67, 0x82));
    RECT tagline{textLeft, Scale(state, 32), rc.right - pad, Scale(state, 48)};
    DrawTextW(mem, L"Forensic inspection toolkit", -1, &tagline,
              DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
}

void PaintFooter(HDC mem, SidebarState* state, const RECT& rc) {
    int top = rc.bottom - Scale(state, kFooterHeight);
    RECT area{0, top, rc.right, rc.bottom};
    FillSolid(mem, area, RGB(0xF4, 0xF6, 0xF9));

    RECT light{0, top, rc.right, top + 1};
    FillSolid(mem, light, kEdgeLight);
    RECT shadow{0, top + 1, rc.right, top + 2};
    FillSolid(mem, shadow, kEdgeShadow);

    SetBkMode(mem, TRANSPARENT);
    SelectObject(mem, state->footerFont);
    SetTextColor(mem, RGB(0x4C, 0x5A, 0x6E));
    int pad = Scale(state, 10);
    RECT text{pad, top + Scale(state, 2), rc.right - pad, rc.bottom};
    DrawTextW(mem, state->footerText.c_str(), -1, &text,
              DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
}

void PaintSidebar(HWND hwnd) {
    SidebarState* state = StateOf(hwnd);
    if (!state) return;

    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(hwnd, &ps);
    RECT rc{};
    GetClientRect(hwnd, &rc);
    if (rc.right <= 0 || rc.bottom <= 0) {
        EndPaint(hwnd, &ps);
        return;
    }

    HDC mem = CreateCompatibleDC(dc);
    HBITMAP bitmap = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
    HGDIOBJ oldBitmap = SelectObject(mem, bitmap);

    FillGradient(mem, rc, kPanelTop, kPanelBottom);

    int pad = Scale(state, 8);
    int scrollBottom = ScrollBottom(state, rc);

    int saved = SaveDC(mem);
    IntersectClipRect(mem, 0, ScrollTop(state), rc.right, scrollBottom);
    SetBkMode(mem, TRANSPARENT);

    for (size_t i = 0; i < state->rows.size(); ++i) {
        const SidebarRow& row = state->rows[i];
        int top = RowTop(state, i);
        int height = RowHeight(state, i);
        if (top + height < ScrollTop(state) || top > scrollBottom) continue;

        if (row.header) {
            SelectObject(mem, state->headerFont);
            SetTextColor(mem, kGroupText);
            std::wstring label = row.label;
            for (wchar_t& ch : label) ch = static_cast<wchar_t>(towupper(ch));
            RECT text{pad + Scale(state, 4), top + Scale(state, 7), rc.right - pad, top + height};
            DrawTextW(mem, label.c_str(), -1, &text, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

            RECT rule{pad, top + height - Scale(state, 5), rc.right - pad, top + height - Scale(state, 4)};
            FillSolid(mem, rule, kGroupRule);
            RECT ruleLight{pad, top + height - Scale(state, 4), rc.right - pad, top + height - Scale(state, 3)};
            FillSolid(mem, ruleLight, kEdgeLight);
            continue;
        }

        bool selected = row.tab == state->selected;
        bool hovered = static_cast<int>(i) == state->hover;
        int left = Scale(state, 6);
        int right = rc.right - Scale(state, 7);
        RECT item{left, top, right, top + height};

        if (selected) {
            RECT grad{item.left, item.top, item.right, item.top + height / 2};
            FillGradient(mem, grad, RGB(0x4F, 0x8D, 0xE0), kSelectFill);
            RECT grad2{item.left, item.top + height / 2, item.right, item.bottom};
            FillGradient(mem, grad2, kSelectFill, RGB(0x1F, 0x4E, 0x9E));
            HBRUSH accent = CreateSolidBrush(RGB(0x16, 0x3E, 0x7E));
            FrameRect(mem, &item, accent);
            DeleteObject(accent);
        } else if (hovered) {
            FillSolid(mem, item, kHoverFill);
            HBRUSH edge = CreateSolidBrush(kHoverEdge);
            FrameRect(mem, &item, edge);
            DeleteObject(edge);
        } else {

            FillSolid(mem, RECT{item.left, item.bottom - 1, item.right, item.bottom},
                      RGB(0xE4, 0xEA, 0xF2));
        }

        int iconSize = Scale(state, 22);
        int iconX = left + Scale(state, 10);
        int iconY = top + (height - iconSize) / 2;

        if (i < state->icons.size() && state->icons[i]) {

            int oldStretch = SetStretchBltMode(mem, HALFTONE);
            SetBrushOrgEx(mem, 0, 0, nullptr);
            DrawIconEx(mem, iconX, iconY, state->icons[i], iconSize, iconSize, 0, nullptr, DI_NORMAL);
            SetStretchBltMode(mem, oldStretch);
        }

        SelectObject(mem, selected ? state->selectedFont : state->itemFont);
        SetTextColor(mem, selected ? kSelectText : kItemText);
        RECT text{iconX + iconSize + Scale(state, 10), top, right - Scale(state, 6), top + height};
        DrawTextW(mem, row.label.c_str(), -1, &text,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }

    RestoreDC(mem, saved);

    PaintBrand(mem, state, rc);
    PaintFooter(mem, state, rc);

    RECT edgeLight{rc.right - 2, 0, rc.right - 1, rc.bottom};
    FillSolid(mem, edgeLight, kEdgeLight);
    RECT edgeShadow{rc.right - 1, 0, rc.right, rc.bottom};
    FillSolid(mem, edgeShadow, kEdgeShadow);

    BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldBitmap);
    DeleteObject(bitmap);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

LRESULT CALLBACK SidebarProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    SidebarState* state = StateOf(hwnd);
    switch (message) {
    case WM_CREATE: {
        auto* created = new SidebarState();
        created->dpi = static_cast<int>(reinterpret_cast<LONG_PTR>(
            reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams));
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(created));
        return 0;
    }
    case WM_PAINT:
        PaintSidebar(hwnd);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_MOUSEMOVE: {
        if (!state) return 0;
        POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        int hit = HitTest(hwnd, point);
        if (hit != state->hover) {
            state->hover = hit;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        if (!state->trackingLeave) {
            TRACKMOUSEEVENT track{};
            track.cbSize = sizeof(track);
            track.dwFlags = TME_LEAVE;
            track.hwndTrack = hwnd;
            TrackMouseEvent(&track);
            state->trackingLeave = true;
        }
        return 0;
    }
    case WM_MOUSELEAVE:
        if (state) {
            state->hover = -1;
            state->trackingLeave = false;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    case WM_LBUTTONDOWN: {
        if (!state) return 0;
        POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        int hit = HitTest(hwnd, point);
        if (hit >= 0 && state->rows[hit].tab >= 0) {
            PostMessageW(GetParent(hwnd), WM_APP_SIDEBAR, static_cast<WPARAM>(state->rows[hit].tab), 0);
        }
        return 0;
    }
    case WM_MOUSEWHEEL: {
        if (!state) return 0;
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        state->scroll -= delta > 0 ? Scale(state, 48) : -Scale(state, 48);
        ClampScroll(hwnd);
        UpdateScrollbar(hwnd);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_VSCROLL: {
        if (!state) return 0;
        RECT rc{};
        GetClientRect(hwnd, &rc);
        int viewport = ScrollBottom(state, rc) - ScrollTop(state);
        int line = Scale(state, kItemHeight);
        int pos = state->scroll;
        switch (LOWORD(wParam)) {
        case SB_TOP: pos = 0; break;
        case SB_BOTTOM: pos = ContentHeight(state); break;
        case SB_LINEUP: pos -= line; break;
        case SB_LINEDOWN: pos += line; break;
        case SB_PAGEUP: pos -= viewport; break;
        case SB_PAGEDOWN: pos += viewport; break;
        case SB_THUMBTRACK:
        case SB_THUMBPOSITION: {
            SCROLLINFO si{};
            si.cbSize = sizeof(si);
            si.fMask = SIF_TRACKPOS;
            GetScrollInfo(hwnd, SB_VERT, &si);
            pos = si.nTrackPos;
            break;
        }
        }
        state->scroll = pos;
        ClampScroll(hwnd);
        UpdateScrollbar(hwnd);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_SETCURSOR:
        if (LOWORD(lParam) == HTCLIENT) {
            POINT cursor{};
            GetCursorPos(&cursor);
            ScreenToClient(hwnd, &cursor);
            SetCursor(LoadCursorW(nullptr, HitTest(hwnd, cursor) >= 0 ? IDC_HAND : IDC_ARROW));
            return TRUE;
        }
        break;
    case WM_DESTROY:
        if (state) {
            for (HICON icon : state->icons) {
                if (icon) DestroyIcon(icon);
            }
            if (state->brandIcon) DestroyIcon(state->brandIcon);
            if (state->itemFont) DeleteObject(state->itemFont);
            if (state->headerFont) DeleteObject(state->headerFont);
            if (state->selectedFont) DeleteObject(state->selectedFont);
            if (state->brandFont) DeleteObject(state->brandFont);
            if (state->taglineFont) DeleteObject(state->taglineFont);
            if (state->footerFont) DeleteObject(state->footerFont);
            delete state;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

}

HWND CreateSidebar(HWND parent, HINSTANCE instance, const std::vector<SidebarRow>& rows, int dpi) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW cls{};
        cls.cbSize = sizeof(cls);
        cls.style = CS_HREDRAW | CS_VREDRAW;
        cls.lpfnWndProc = SidebarProc;
        cls.hInstance = instance;
        cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        cls.lpszClassName = L"WindCheckerSidebar";
        RegisterClassExW(&cls);
        registered = true;
    }

    HWND sidebar = CreateWindowExW(0, L"WindCheckerSidebar", L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_VSCROLL,
                                   0, 0, 10, 10, parent,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(1)),
                                   instance, reinterpret_cast<LPVOID>(static_cast<LONG_PTR>(dpi)));
    if (!sidebar) return nullptr;

    SidebarState* state = StateOf(sidebar);
    if (!state) return sidebar;
    state->rows = rows;

    state->itemFont = CreateFontW(-MulDiv(9, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    state->selectedFont = CreateFontW(-MulDiv(9, dpi, 72), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                      DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                      CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    state->headerFont = CreateFontW(-MulDiv(7, dpi, 72), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    state->brandFont = CreateFontW(-MulDiv(12, dpi, 72), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                   CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    state->taglineFont = CreateFontW(-MulDiv(7, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                     DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                     CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    state->footerFont = CreateFontW(-MulDiv(7, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

    state->footerText = ProcessElevated() ? L"Administrator session" : L"Standard user session";

    state->brandIcon = nullptr;
    SHSTOCKICONINFO brand{};
    brand.cbSize = sizeof(brand);
    if (SUCCEEDED(SHGetStockIconInfo(SIID_FIND, SHGSI_ICON | SHGSI_LARGEICON, &brand))) {
        state->brandIcon = brand.hIcon;
    }
    if (!state->brandIcon) {
        state->brandIcon = static_cast<HICON>(LoadImageW(GetModuleHandleW(nullptr),
                                                         MAKEINTRESOURCEW(101), IMAGE_ICON,
                                                         64, 64, LR_DEFAULTCOLOR));
    }

    state->icons.resize(rows.size(), nullptr);
    for (size_t i = 0; i < rows.size(); ++i) {
        if (rows[i].header) continue;
        if (rows[i].stockIcon == -2) {

            wchar_t windows[MAX_PATH] = {};
            GetWindowsDirectoryW(windows, MAX_PATH);
            std::wstring regedit = std::wstring(windows) + L"\\regedit.exe";
            SHFILEINFOW fileInfo{};
            if (SHGetFileInfoW(regedit.c_str(), 0, &fileInfo, sizeof(fileInfo),
                               SHGFI_ICON | SHGFI_LARGEICON) && fileInfo.hIcon) {
                state->icons[i] = fileInfo.hIcon;
            }
            if (!state->icons[i]) {
                SHSTOCKICONINFO fallback{};
                fallback.cbSize = sizeof(fallback);
                if (SUCCEEDED(SHGetStockIconInfo(SIID_DOCNOASSOC, SHGSI_ICON | SHGSI_LARGEICON, &fallback))) {
                    state->icons[i] = fallback.hIcon;
                }
            }
            continue;
        }
        SHSTOCKICONINFO info{};
        info.cbSize = sizeof(info);
        if (SUCCEEDED(SHGetStockIconInfo(static_cast<SHSTOCKICONID>(rows[i].stockIcon),
                                         SHGSI_ICON | SHGSI_LARGEICON, &info)) &&
            info.hIcon) {
            state->icons[i] = info.hIcon;
        } else {
            SHSTOCKICONINFO fallback{};
            fallback.cbSize = sizeof(fallback);
            if (SUCCEEDED(SHGetStockIconInfo(SIID_APPLICATION, SHGSI_ICON | SHGSI_LARGEICON, &fallback))) {
                state->icons[i] = fallback.hIcon;
            }
        }
    }
    return sidebar;
}

void SidebarSelect(HWND sidebar, int tab) {
    SidebarState* state = StateOf(sidebar);
    if (!state) return;
    if (state->selected == tab) {
        InvalidateRect(sidebar, nullptr, FALSE);
        return;
    }
    state->selected = tab;
    InvalidateRect(sidebar, nullptr, FALSE);
}

void SidebarLayout(HWND sidebar, int x, int y, int width, int height) {
    if (!sidebar) return;
    MoveWindow(sidebar, x, y, width, height, TRUE);
    ClampScroll(sidebar);
    UpdateScrollbar(sidebar);
}
