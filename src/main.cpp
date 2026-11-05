#include "common.h"
#include "network.h"
#include "capture.h"
#include "carve.h"
#include "search.h"
#include "artifacts.h"
#include "sidebar.h"
#include "forensics.h"

#include <commctrl.h>
#include <uxtheme.h>
#include <windowsx.h>
#include <commdlg.h>
#include <shobjidl.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <psapi.h>
#include <wincodec.h>
#include <winioctl.h>

#ifndef LVM_GETCOLUMNCOUNT
#define LVM_GETCOLUMNCOUNT (LVM_FIRST + 95)
#endif

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <optional>
#include <regex>
#include <set>

#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "windowscodecs.lib")

namespace {

constexpr wchar_t APP_TITLE[] = L"WindChecker";

enum {
    TAB_VOLUME = 0, TAB_SEARCH = 1, TAB_USN = 2, TAB_MFT = 3, TAB_EVENTS = 4,
    TAB_NFAT = 5, TAB_PACKET = 6, TAB_PREFETCH = 7, TAB_STRINGS = 8,
    TAB_POWERSHELL = 9, TAB_PROCESS = 10, TAB_PERSISTENCE = 11, TAB_EXECUTION = 12,
    TAB_SIGNATURES = 13,
    TAB_MEMORY = 14, TAB_REGISTRY = 15, TAB_CLIPBOARD = 16, TAB_THUMBNAIL = 17,
    TAB_HIDDEN = 18, TAB_STARTUP = 19, TAB_CARVE = 20, TAB_SERVICES = 21,
    TAB_COMPUTERINFO = 22, TAB_SRUM = 23, TAB_AMCACHE = 24,
    TAB_USB = 25, TAB_BAMDAM = 26, TAB_USERASSIST = 27,
    TAB_RECENTDOCS = 28, TAB_MRU = 29,
    TAB_WMI = 30, TAB_NETART = 31, TAB_DEFENDER = 32, TAB_RDP = 33,
    TAB_ACTIVITIES = 34, TAB_CRASH = 35, TAB_WPN = 36,
    TAB_EVENTVIEWER = 37, TAB_FILEHASH = 38, TAB_EXIF = 39,
    TAB_COUNT = 40
};

enum LocalId {
    L_START = 1, L_STOP, L_REFRESH,
    L_SEARCH, L_MODE, L_FROM, L_TO, L_CLEAR,
    L_TARGET, L_PATTERN, L_MIN, L_MAX, L_ALLDRIVES, L_REGEX, L_CASE,
    L_TCP, L_UDP, L_DNS, L_ARP, L_ADAPTERS, L_TRAFFIC, L_REALTIME, L_INTERVAL, L_FULL,
    L_PAYLOAD, L_PACKETFULL,
    L_LIMIT, L_CHANNEL, L_ALLEVENTS, L_FOLDER, L_MAXFILES, L_DETAILS, L_RECENT,
    L_MINLEN, L_LIMITMB, L_UTF16, L_ASCII, L_FULLDISK,
    L_ALLUSERS, L_SYSTEMPROFILE, L_MODULES, L_SERVICES,
    L_REGKEYS, L_SVCAUTO, L_TASKS, L_FOLDERS, L_SHIMCACHE, L_USB, L_RECYCLE,
    L_SIGNPROC, L_SIGNMODULES, L_SIGNSERVICES,
    L_OPEN, L_SAVE, L_BROWSE, L_DUMP, L_TABLE, L_HIVE,
    L_MEMMODULES, L_MEMTHREADS, L_MEMHANDLES, L_MEMHEAPS, L_MEMMAP,
    L_PROCDETAILS, L_PROCMEMORY, L_MEMALL, L_MEMDUMP,
    L_REGSEARCH, L_REGCLEAR,
    L_HIDDENMODE, L_CARVEDFILES, L_MFTRECOVER,
    L_VIEWFILES, L_VIEWMEDIA, L_GALLERY, L_SVCDRIVERS, L_SVCRUNNING, L_SVCSIGN,
    L_HEXVIEW,
    L_EVLEVEL, L_EVLOGON, L_EVFAIL, L_EVACCT, L_EVPROC, L_EVALL,
    L_RECURSE, L_HASHCONTENT, L_VERIFYSIGN
};

constexpr UINT_PTR TIMER_FILTER_BASE = 0x4100;
constexpr UINT_PTR TIMER_REGSEARCH = 0x4200;

#define WM_APP_REGSEARCH (WM_APP + 4)

int IdFor(int tab, int local) { return 1000 + tab * 100 + local; }
int TabOf(int id) { return (id - 1000) / 100; }
int LocalOf(int id) { return (id - 1000) % 100; }

enum FilterKind { FM_ALL = 0, FM_NAME = 1, FM_ACTION = 2, FM_DATE = 3, FM_PRIV = 4 };

struct HeaderCtrl {
    HWND hwnd = nullptr;
    int x = 0;
    int w = 0;
    int h = 0;
    int row = 0; // 0,1,2... = extra header rows after the description; <0 = button row
};

struct Tab {
    int key = 0;
    int headerButtonY = 86;
    int headerFilterY = 118;
    bool buttonsCustom = false; // tab supplies its own button-row layout via headerCtrls (row < 0)
    std::vector<HeaderCtrl> headerCtrls; // controls between description and the button row
    HWND page = nullptr;
    HWND title = nullptr;
    HWND desc = nullptr;
    HWND list = nullptr;
    HWND startBtn = nullptr;
    HWND stopBtn = nullptr;
    HWND refreshBtn = nullptr;
    HWND statusLabel = nullptr;
    HWND countLabel = nullptr;

    HWND searchLabel = nullptr;
    HWND searchIcon = nullptr;
    HWND searchEdit = nullptr;
    HWND modeLabel = nullptr;
    HWND modeCombo = nullptr;
    HWND fromLabel = nullptr;
    HWND fromEdit = nullptr;
    HWND toLabel = nullptr;
    HWND toEdit = nullptr;
    HWND clearBtn = nullptr;

    std::vector<FilterKind> modeKinds;
    std::vector<int> nameColumns;
    std::vector<int> actionColumns;
    int dateColumn = -1;

    std::vector<std::wstring> headers;
    std::vector<int> baseWidths;
    std::vector<Row> records;
    std::vector<std::wstring> details;
    std::vector<size_t> displayed;
    std::shared_ptr<std::atomic<bool>> stopFlag = std::make_shared<std::atomic<bool>>(false);
    uint64_t generation = 1;
    bool running = false;
    int shown = 0;
    int matched = 0;
    std::wstring countCache;

    HWND targetCombo = nullptr;
    HWND patternEdit = nullptr;
    HWND minEdit = nullptr;
    HWND maxEdit = nullptr;
    HWND allDrivesCheck = nullptr;
    HWND regexCheck = nullptr;
    HWND caseCheck = nullptr;

    HWND chkTcp = nullptr;
    HWND chkUdp = nullptr;
    HWND chkDns = nullptr;
    HWND chkArp = nullptr;
    HWND chkAdapters = nullptr;
    HWND chkTraffic = nullptr;
    HWND chkRealtime = nullptr;
    HWND intervalCombo = nullptr;
    HWND chkFull = nullptr;

    HWND chkPayload = nullptr;
    HWND chkPacketFull = nullptr;

    HWND limitEdit = nullptr;
    HWND channelCombo = nullptr;
    HWND allChannelsCheck = nullptr;

    HWND folderEdit = nullptr;
    HWND hashContentCheck = nullptr;
    HWND verifySignCheck = nullptr;
    HWND maxFilesEdit = nullptr;
    HWND detailsCheck = nullptr;
    HWND recentCheck = nullptr;

    HWND minLengthEdit = nullptr;
    HWND limitMbEdit = nullptr;

    HWND recurseCheck = nullptr;
    HWND utf16Check = nullptr;
    HWND asciiCheck = nullptr;
    HWND fullDiskCheck = nullptr;

    HWND allUsersCheck = nullptr;
    HWND systemProfileCheck = nullptr;

    HWND modulesCheck = nullptr;
    HWND servicesCheck = nullptr;
    HWND svcDriversCheck = nullptr;
    HWND svcRunningCheck = nullptr;

    HWND regKeysCheck = nullptr;
    HWND svcAutoCheck = nullptr;
    HWND tasksCheck = nullptr;
    HWND foldersCheck = nullptr;

    HWND shimCacheCheck = nullptr;
    HWND usbCheck = nullptr;
    HWND recycleCheck = nullptr;

    HWND signProcCheck = nullptr;
    HWND signModulesCheck = nullptr;
    HWND signServicesCheck = nullptr;

    HWND tree = nullptr;
    HWND detailPane = nullptr;
    HWND headerEdit = nullptr;
    std::unordered_map<unsigned long, void*> treeNodes;
    HTREEITEM driverRoot = nullptr;

    int sortColumn = -1;
    bool sortAscending = true;

    HWND volumeStatus = nullptr;
};

HINSTANCE g_instance = nullptr;
HWND g_hwnd = nullptr;
HWND g_sidebar = nullptr;
HWND g_status = nullptr;
HWND g_progressText = nullptr;
HWND g_progress = nullptr;
HFONT g_fontUI = nullptr;
HFONT g_fontSmall = nullptr;
HFONT g_fontTitle = nullptr;
HFONT g_fontMono = nullptr;
HBRUSH g_bgBrush = nullptr;

struct CarveMediaView {
    HWND list = nullptr;
    HWND filesBtn = nullptr;
    HWND mediaBtn = nullptr;
    HIMAGELIST images = nullptr;
    bool visible = false;
    int imageSize = 192;
    std::wstring tempDir;
    std::wstring lastStatus;
    std::map<std::wstring, int> thumbs;
};
CarveMediaView g_carveMedia;

struct ThumbPreview {
    HWND preview = nullptr;
    HBITMAP bitmap = nullptr;
    std::wstring folder;
};
ThumbPreview g_thumb;

constexpr COLORREF kCanvas = RGB(0xF3, 0xF3, 0xF5);
int g_dpi = 96;
Tab g_tabs[TAB_COUNT];
const wchar_t* kTabTitles[TAB_COUNT] = {
    L"Volumes", L"File Search", L"USN Journal", L"MFT", L"Event Logs",
    L"Connections", L"Packet Capture", L"Prefetch && Recent", L"Disk Strings",
    L"PowerShell History", L"Processes", L"Persistence", L"Execution Evidence",
    L"Code Signing",
    L"Memory", L"Registry", L"Clipboard", L"Thumbcache",
    L"Hidden Files", L"Startup Apps", L"Carving", L"Services",
    L"Computer Info", L"SRUM", L"AmCache",
    L"USB Device History", L"BAM / DAM", L"UserAssist",
    L"RecentDocs", L"MRU",
    L"WMI Event Subscriptions", L"Network Artifacts", L"Defender Logs",
    L"Remote Access (RDP)", L"Activities Cache",
    L"Crash Dumps", L"Notifications",
    L"Event Viewer", L"Hash & Signature", L"Image Metadata"
};

const SidebarRow kSidebarRows[] = {
    {true, -1, 0, L"System"},
    {false, TAB_COMPUTERINFO, SIID_DESKTOPPC, L"Computer Info"},
    {false, TAB_VOLUME, SIID_DRIVEFIXED, L"Volumes"},
    {false, TAB_PROCESS, SIID_SOFTWARE, L"Processes"},
    {false, TAB_SERVICES, SIID_SERVER, L"Services"},
    {false, TAB_EVENTS, SIID_AUTOLIST, L"Event Logs"},
    {false, TAB_EVENTVIEWER, SIID_AUTOLIST, L"Event Viewer"},
    {false, TAB_PREFETCH, SIID_DOCASSOC, L"Prefetch && Recent"},

    {true, -1, 0, L"File system"},
    {false, TAB_SEARCH, SIID_FIND, L"File Search"},
    {false, TAB_HIDDEN, SIID_FOLDEROPEN, L"Hidden Files"},
    {false, TAB_USN, SIID_DOCNOASSOC, L"USN Journal"},
    {false, TAB_MFT, SIID_STACK, L"MFT"},
    {false, TAB_STRINGS, SIID_DRIVEUNKNOWN, L"Disk Strings"},
    {false, TAB_CARVE, SIID_DRIVEFIXED, L"Carving"},
    {false, TAB_FILEHASH, SIID_LOCK, L"Hash && Signature"},
    {false, TAB_EXIF, SIID_IMAGEFILES, L"Image Metadata"},
    {false, TAB_RECENTDOCS, SIID_DOCASSOC, L"RecentDocs"},

    {true, -1, 0, L"Network"},
    {false, TAB_NFAT, SIID_NETWORKCONNECT, L"Connections"},
    {false, TAB_PACKET, SIID_WORLD, L"Packet Capture"},
    {false, TAB_NETART, SIID_NETWORKCONNECT, L"Network Artifacts"},

    {true, -1, 0, L"Security"},
    {false, TAB_POWERSHELL, SIID_KEY, L"PowerShell History"},
    {false, TAB_STARTUP, SIID_SHIELD, L"Startup Apps"},
    {false, TAB_PERSISTENCE, SIID_SHIELD, L"Persistence"},
    {false, TAB_EXECUTION, SIID_USERS, L"Execution Evidence"},
    {false, TAB_SRUM, SIID_CLUSTEREDDRIVE, L"SRUM"},
    {false, TAB_AMCACHE, SIID_APPLICATION, L"AmCache"},
    {false, TAB_SIGNATURES, SIID_LOCK, L"Code Signing"},
    {false, TAB_USB, SIID_SERVER, L"USB Device History"},
    {false, TAB_BAMDAM, SIID_APPLICATION, L"BAM / DAM"},
    {false, TAB_USERASSIST, SIID_USERS, L"UserAssist"},
    {false, TAB_MRU, SIID_AUTOLIST, L"MRU"},
    {false, TAB_WMI, SIID_SERVER, L"WMI Event Subscriptions"},
    {false, TAB_DEFENDER, SIID_SHIELD, L"Defender Logs"},
    {false, TAB_RDP, SIID_NETWORKCONNECT, L"Remote Access (RDP)"},

    {true, -1, 0, L"Artifacts"},
    {false, TAB_ACTIVITIES, SIID_CLUSTEREDDRIVE, L"Activities Cache"},
    {false, TAB_CRASH, SIID_DRIVEFIXED, L"Crash Dumps"},
    {false, TAB_WPN, SIID_DOCNOASSOC, L"Notifications"},

    {true, -1, 0, L"Viewers"},
    {false, TAB_REGISTRY, -2, L"Registry"},
    {false, TAB_CLIPBOARD, SIID_DOCNOASSOC, L"Clipboard"},
    {false, TAB_THUMBNAIL, SIID_IMAGEFILES, L"Thumbcache"},
};
std::vector<std::wstring> g_eventChannels;

struct EventViewerState {
    HWND tree = nullptr;
    std::vector<std::wstring> channels;  // leaf channel names, indexed by the tree item lParam
    std::wstring selectedChannel;
    HWND idsEdit = nullptr;
    HWND levelCombo = nullptr;
    HWND providerEdit = nullptr;
    HWND limitEdit = nullptr;
    HWND allCheck = nullptr;
};
EventViewerState g_ev;

struct MemoryViewer {
    HWND list = nullptr;
    HWND info = nullptr;
    bool showingRegions = false;
    bool allStates = false;
    DWORD selectedPid = 0;
    std::wstring selectedName;
    HANDLE process = INVALID_HANDLE_VALUE;
    std::vector<uintptr_t> regionBases;
    std::vector<uintptr_t> regionSizes;
};
MemoryViewer g_memory;

struct RegistryViewer {
    HWND tree = nullptr;
    HWND header = nullptr;
    HWND list = nullptr;
    HWND valueDetail = nullptr;
    HWND hint = nullptr;
    HWND searchIcon = nullptr;
    HWND searchEdit = nullptr;
    HWND clearBtn = nullptr;
    HIMAGELIST icons = nullptr;
    int rootIcon = 0;
    int keyIcon = 1;
    int textIcon = 2;
    int numberIcon = 3;
    int binaryIcon = 4;
    bool searchActive = false;
    uint64_t searchGeneration = 0;
    std::wstring lastQuery;
    std::list<std::wstring> paths;
    std::vector<std::wstring> valueNames;
    std::vector<std::wstring> valueTypes;
    std::vector<std::wstring> valueData;
    std::vector<std::wstring> valuePaths;
    std::vector<std::wstring> valueDetails;
    std::vector<int> valueKinds;
};
RegistryViewer g_reg;

HWND g_procDetailsBtn = nullptr;
HWND g_procMemoryBtn = nullptr;
HWND g_procMemAllCheck = nullptr;
HWND g_procMemButtons[6] = {};
bool g_procMemoryMode = false;

int S(int value) { return MulDiv(value, g_dpi, 96); }

std::wstring GetText(HWND control) {
    int length = GetWindowTextLengthW(control);
    if (length <= 0) return L"";
    std::wstring text(static_cast<size_t>(length), L'\0');
    GetWindowTextW(control, text.data(), length + 1);
    return text;
}

void SetText(HWND control, const std::wstring& text) {
    SetWindowTextW(control, text.c_str());
}

bool IsChecked(HWND control) {
    return SendMessageW(control, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void ComboAdd(HWND combo, const std::wstring& text) {
    SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text.c_str()));
}

int ComboSelection(HWND combo) {
    return static_cast<int>(SendMessageW(combo, CB_GETCURSEL, 0, 0));
}

std::wstring ComboText(HWND combo) {
    int index = ComboSelection(combo);
    if (index < 0) return L"";
    wchar_t buffer[512] = {};
    SendMessageW(combo, CB_GETLBTEXT, index, reinterpret_cast<LPARAM>(buffer));
    return buffer;
}

HFONT MakeFont(int points, int weight) {
    return CreateFontW(-MulDiv(points, g_dpi, 72), 0, 0, 0, weight, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
}

HWND MakeLabel(HWND parent, const std::wstring& text, HFONT font, bool transparent = false) {
    HWND control = CreateWindowExW(0, L"STATIC", text.c_str(),
                                   WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                                   0, 0, 10, 10, parent, nullptr, g_instance, nullptr);
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    if (transparent) SetWindowLongPtrW(control, GWL_EXSTYLE, GetWindowLongPtrW(control, GWL_EXSTYLE));
    return control;
}

HWND MakeButton(HWND parent, const std::wstring& text, int id) {
    HWND control = CreateWindowExW(0, L"BUTTON", text.c_str(),
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   0, 0, 10, 10, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                   g_instance, nullptr);
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontUI), TRUE);
    return control;
}

HWND MakeCheck(HWND parent, const std::wstring& text, int id, bool checked) {
    HWND control = CreateWindowExW(0, L"BUTTON", text.c_str(),
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                   0, 0, 10, 10, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                   g_instance, nullptr);
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
    SendMessageW(control, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
    return control;
}

HWND MakeEdit(HWND parent, const std::wstring& text, int id) {
    HWND control = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", text.c_str(),
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                   0, 0, 10, 10, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                   g_instance, nullptr);
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontUI), TRUE);
    return control;
}

HWND MakeCombo(HWND parent, int id) {
    HWND control = CreateWindowExW(0, L"COMBOBOX", L"",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL |
                                       CBS_DROPDOWNLIST,
                                   0, 0, 10, 200, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                   g_instance, nullptr);
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
    return control;
}

void Place(HWND control, int x, int y, int width, int height) {
    if (!control) return;
    MoveWindow(control, S(x), S(y), S(width), S(height), TRUE);
}

// Register a header control that lives between the description and the button row.
// The y argument is only used as the initial (pre-layout) position; LayoutTab
// repositions every registered control so the header follows the description.
void PlaceHeader(Tab& tab, HWND control, int x, int y, int width, int height, int row) {
    if (!control) return;
    Place(control, x, y, width, height);
    tab.headerCtrls.push_back({control, x, width, height, row});
}

void ShowRowDetail(Tab& tab, int item);
void ShowTextDialog(const std::wstring& caption, const std::wstring& headerText, const std::wstring& text);
void ShowHexView(const std::wstring& path);
void ShowHexVolume(const std::wstring& volume, uint64_t offset);
void CarveMediaRebuild();
void CarveMediaReset();
Tab* TabFromList(HWND list);
void ShowListMenu(HWND list, Tab& tab, int item, POINT screenPoint);
void ProcessSelectNode(Tab& tab, size_t index);
void UpdateServiceDetail(int item);
void UpdateComputerInfoDetail(int item);
void UpdateStoredDetail(Tab& tab, int item);
void SetProcessMemoryMode(bool memory);
void MemoryReloadSelected();
void MemoryDumpSelected();

int PathColumnForTab(int key) {
    if (key == TAB_SEARCH) return 0;
    if (key == TAB_PROCESS) return 5;
    if (key == TAB_SERVICES) return 8;
    return -1;
}

void CopyToClipboard(HWND owner, const std::wstring& text) {
    if (text.empty() || !OpenClipboard(owner)) return;
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (memory) {
        if (void* target = GlobalLock(memory)) {
            memcpy(target, text.c_str(), bytes);
            GlobalUnlock(memory);
            SetClipboardData(CF_UNICODETEXT, memory);
        } else {
            GlobalFree(memory);
        }
    }
    CloseClipboard();
}

LRESULT CALLBACK ListSubclassProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam,
                                  UINT_PTR, DWORD_PTR) {
    if (message == WM_MOUSEWHEEL && (GET_KEYSTATE_WPARAM(wParam) & MK_SHIFT)) {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        int direction = delta > 0 ? -1 : 1;
        ListView_Scroll(hwnd, direction * S(80), 0);
        return 0;
    }
    if (message == WM_RBUTTONUP) {
        POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        LVHITTESTINFO hit{};
        hit.pt = point;
        int item = ListView_SubItemHitTest(hwnd, &hit);
        Tab* tab = TabFromList(hwnd);
        if (tab && item >= 0) {
            ListView_SetItemState(hwnd, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(hwnd, item, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
            POINT screen = point;
            ClientToScreen(hwnd, &screen);
            ShowListMenu(hwnd, *tab, item, screen);
            return 0;
        }
    }
    if (message == WM_LBUTTONDBLCLK) {
        POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        LVHITTESTINFO hit{};
        hit.pt = point;
        int item = ListView_SubItemHitTest(hwnd, &hit);
        Tab* tab = TabFromList(hwnd);
        if (tab && item >= 0) {
            ListView_SetItemState(hwnd, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(hwnd, item, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
            ShowRowDetail(*tab, item);
            return 0;
        }
    }
    if (message == WM_CONTEXTMENU) {
        POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        if (point.x != -1 || point.y != -1) return 0;
        int item = ListView_GetNextItem(hwnd, -1, LVNI_SELECTED);
        if (item < 0) return 0;
        RECT bounds{};
        ListView_GetItemRect(hwnd, item, &bounds, LVIR_BOUNDS);
        point.x = bounds.left + 40;
        point.y = bounds.bottom;
        ClientToScreen(hwnd, &point);
        Tab* tab = TabFromList(hwnd);
        if (tab) ShowListMenu(hwnd, *tab, item, point);
        return 0;
    }
    return DefSubclassProc(hwnd, message, wParam, lParam);
}

void ShowListMenu(HWND list, Tab& tab, int item, POINT screenPoint) {
    if (item < 0 || static_cast<size_t>(item) >= tab.displayed.size()) return;
    size_t recordIndex = tab.displayed[static_cast<size_t>(item)];
    if (recordIndex >= tab.records.size()) return;

    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, 1, L"Show more detail\u2026");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, 2, L"Copy row");
    AppendMenuW(menu, MF_STRING, 3, L"Copy cell");

    int pathColumn = PathColumnForTab(tab.key);
    std::wstring path;
    if (pathColumn >= 0) {
        const Row& source = tab.records[recordIndex];
        if (static_cast<size_t>(pathColumn) < source.size()) path = source[pathColumn];
        const DWORD attributes = path.empty() ? INVALID_FILE_ATTRIBUTES : GetFileAttributesW(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(menu, MF_STRING, 4, L"Hash file (SHA-256 / MD5)\u2026");
            AppendMenuW(menu, MF_STRING, 6, L"View hex\u2026");
            if (tab.key == TAB_SEARCH) {
                AppendMenuW(menu, MF_STRING, 5, L"Alternate data streams\u2026");
            }
        } else {
            path.clear();
        }
    }

    int command = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_LEFTALIGN,
                                 screenPoint.x, screenPoint.y, 0, list, nullptr);
    DestroyMenu(menu);
    if (command == 1) {
        ShowRowDetail(tab, item);
    } else if (command == 4 && !path.empty()) {
        ShowTextDialog(L"Hash \u2014 " + PathFileName(path),
                       L"Digests are computed locally from the file content; nothing is uploaded.",
                       HashFileReport(path));
    } else if (command == 6 && !path.empty()) {
        ShowHexView(path);
    } else if (command == 5 && !path.empty()) {
        ShowTextDialog(L"Alternate data streams \u2014 " + PathFileName(path),
                       L"Every stream attached to this file, plus the mark-of-the-web content when present.",
                       AlternateStreamsReport(path));
    } else if (command == 2) {
        const Row& row = tab.records[recordIndex];
        std::wstring text;
        for (const std::wstring& cell : row) {
            if (!text.empty()) text += L"\t";
            text += cell;
        }
        CopyToClipboard(g_hwnd, text);
    } else if (command == 3) {
        POINT client = screenPoint;
        ScreenToClient(list, &client);
        LVHITTESTINFO hit{};
        hit.pt = client;
        ListView_SubItemHitTest(list, &hit);
        const Row& row = tab.records[recordIndex];
        if (hit.iSubItem >= 0 && static_cast<size_t>(hit.iSubItem) < row.size()) {
            CopyToClipboard(g_hwnd, row[static_cast<size_t>(hit.iSubItem)]);
        }
    }
}

HWND MakeList(HWND parent, Tab& tab, const std::vector<std::wstring>& headers,
              const std::vector<int>& widths) {
    HWND list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL |
                                    LVS_SHOWSELALWAYS | WS_HSCROLL | WS_VSCROLL | WS_TABSTOP,
                                0, 0, 10, 10, parent, nullptr, g_instance, nullptr);
    SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
    ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
                                                 LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    SetWindowTheme(list, L"Explorer", nullptr);
    SetWindowSubclass(list, ListSubclassProc, 1, 0);

    tab.headers = headers;
    tab.baseWidths = widths;
    for (size_t i = 0; i < headers.size(); ++i) {
        LVCOLUMNW column{};
        column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        column.fmt = LVCFMT_LEFT;
        column.cx = S(widths[i]);
        column.pszText = const_cast<LPWSTR>(headers[i].c_str());
        ListView_InsertColumn(list, static_cast<int>(i), &column);
    }
    return list;
}

Tab* TabFromList(HWND list) {
    for (Tab& tab : g_tabs) {
        if (tab.list == list) return &tab;
    }
    return nullptr;
}

struct DetailWindow {
    HWND window = nullptr;
    HWND header = nullptr;
    HWND edit = nullptr;
    HWND copy = nullptr;
    HWND close = nullptr;
    bool closed = false;
    std::wstring text;
};

void LayoutDetail(DetailWindow& detail) {
    RECT rc{};
    GetClientRect(detail.window, &rc);
    int pad = S(12);
    int headerHeight = S(38);
    int buttonHeight = S(28);
    int buttonWidth = S(96);
    int buttonTop = rc.bottom - pad - buttonHeight;
    MoveWindow(detail.header, pad, pad, rc.right - pad * 2, headerHeight, TRUE);
    MoveWindow(detail.edit, pad, pad + headerHeight + S(6),
               rc.right - pad * 2, buttonTop - (pad + headerHeight + S(6)) - S(10), TRUE);
    MoveWindow(detail.copy, rc.right - pad - buttonWidth * 2 - S(8), buttonTop,
               buttonWidth, buttonHeight, TRUE);
    MoveWindow(detail.close, rc.right - pad - buttonWidth, buttonTop,
               buttonWidth, buttonHeight, TRUE);
}

LRESULT CALLBACK DetailProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* detail = reinterpret_cast<DetailWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (message) {
    case WM_SIZE:
        if (detail) LayoutDetail(*detail);
        return 0;
    case WM_COMMAND:
        if (detail && LOWORD(wParam) == 100) {
            CopyToClipboard(hwnd, detail->text);
            return 0;
        }
        if (LOWORD(wParam) == IDCANCEL) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (detail) detail->closed = true;
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

std::wstring DetailTitle(int tabKey) {
    std::wstring title = kTabTitles[tabKey];
    size_t at = 0;
    while ((at = title.find(L"&&", at)) != std::wstring::npos) title.erase(at, 1);
    return title;
}

std::wstring BuildRowDetailAt(const Tab& tab, size_t index, int position) {
    if (index >= tab.records.size()) return L"";
    const Row& row = tab.records[index];

    std::wstring text;
    text += L"Tab      : " + DetailTitle(tab.key) + L"\r\n";
    text += Format(L"Position : row %s of %s shown \u00B7 record %s of %s collected\r\n",
                   CommaNumber(static_cast<unsigned long long>(position) + 1).c_str(),
                   CommaNumber(static_cast<unsigned long long>(tab.shown)).c_str(),
                   CommaNumber(index + 1).c_str(),
                   CommaNumber(tab.records.size()).c_str());
    text += L"\r\n";

    size_t labelWidth = 0;
    for (const std::wstring& header : tab.headers) labelWidth = std::max(labelWidth, header.size());
    for (size_t i = 0; i < tab.headers.size(); ++i) {
        const std::wstring& value = i < row.size() ? row[i] : L"";
        text += tab.headers[i];
        text.append(labelWidth - tab.headers[i].size(), L' ');
        text += L" : ";
        text += value.empty() ? L"-" : value;
        text += L"\r\n";
    }

    if (index < tab.details.size() && !tab.details[index].empty()) {
        text += L"\r\n--- raw detail ---\r\n";
        text += tab.details[index];
        if (text.size() < 2 || text[text.size() - 1] != L'\n') text += L"\r\n";
    }
    return text;
}

std::wstring BuildRowDetail(const Tab& tab, int item) {
    if (item < 0 || static_cast<size_t>(item) >= tab.displayed.size()) return L"";
    return BuildRowDetailAt(tab, tab.displayed[static_cast<size_t>(item)], item);
}

void ShowTextDialog(const std::wstring& caption, const std::wstring& headerText,
                    const std::wstring& text) {
    if (text.empty()) return;

    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW cls{};
        cls.cbSize = sizeof(cls);
        cls.lpfnWndProc = DetailProc;
        cls.hInstance = g_instance;
        cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        cls.lpszClassName = L"WindCheckerDetail";
        RegisterClassExW(&cls);
        registered = true;
    }

    DetailWindow detail;
    detail.text = text;

    RECT owner{};
    GetWindowRect(g_hwnd, &owner);
    int width = S(920);
    int height = S(680);
    int x = owner.left + ((owner.right - owner.left) - width) / 2;
    int y = owner.top + ((owner.bottom - owner.top) - height) / 2;
    detail.window = CreateWindowExW(WS_EX_DLGMODALFRAME, L"WindCheckerDetail", caption.c_str(),
                                    WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_CLIPCHILDREN,
                                    x, y, width, height, g_hwnd, nullptr, g_instance, nullptr);
    if (!detail.window) return;
    SetWindowLongPtrW(detail.window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&detail));

    detail.header = CreateWindowExW(0, L"STATIC", headerText.c_str(),
                                    WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0,
                                    detail.window, nullptr, g_instance, nullptr);
    detail.edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", detail.text.c_str(),
                                  WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                      ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                  0, 0, 0, 0, detail.window,
                                  reinterpret_cast<HMENU>(static_cast<INT_PTR>(200)),
                                  g_instance, nullptr);
    detail.copy = CreateWindowExW(0, L"BUTTON", L"Copy all",
                                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0,
                                  detail.window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(100)),
                                  g_instance, nullptr);
    detail.close = CreateWindowExW(0, L"BUTTON", L"Close",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0,
                                   detail.window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDCANCEL)),
                                   g_instance, nullptr);

    SendMessageW(detail.header, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
    SendMessageW(detail.copy, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontUI), TRUE);
    SendMessageW(detail.close, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontUI), TRUE);
    HFONT mono = CreateFontW(-MulDiv(9, g_dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    SendMessageW(detail.edit, WM_SETFONT, reinterpret_cast<WPARAM>(mono ? mono : g_fontSmall), TRUE);

    LayoutDetail(detail);
    EnableWindow(g_hwnd, FALSE);
    ShowWindow(detail.window, SW_SHOW);
    UpdateWindow(detail.window);
    SetFocus(detail.edit);
    SendMessageW(detail.edit, EM_SETSEL, 0, 0);

    MSG msg{};
    while (!detail.closed && GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(detail.window, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    if (msg.message == WM_QUIT) PostQuitMessage(static_cast<int>(msg.wParam));
    if (IsWindow(detail.window)) DestroyWindow(detail.window);
    if (mono) DeleteObject(mono);
    EnableWindow(g_hwnd, TRUE);
    SetForegroundWindow(g_hwnd);
}

void ShowRowDetail(Tab& tab, int item) {
    std::wstring text = BuildRowDetail(tab, item);
    if (text.empty()) return;
    std::wstring headerText = Format(
        L"%s \u00B7 row %d \u00B7 full value of every column, plus any raw detail kept for this record.",
        DetailTitle(tab.key).c_str(), item + 1);
    ShowTextDialog(L"Detail \u2014 " + DetailTitle(tab.key), headerText, text);
}

void InsertRow(HWND list, const Row& row) {
    if (!list || row.empty()) return;
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = ListView_GetItemCount(list);
    item.pszText = const_cast<LPWSTR>(row[0].c_str());
    int index = ListView_InsertItem(list, &item);
    for (size_t i = 1; i < row.size(); ++i) {
        if (row[i].empty()) continue;
        ListView_SetItemText(list, index, static_cast<int>(i), const_cast<LPWSTR>(row[i].c_str()));
    }
}

void ClearList(Tab& tab) {
    if (tab.list) ListView_DeleteAllItems(tab.list);
    if (tab.tree) {
        TreeView_DeleteAllItems(tab.tree);
        tab.treeNodes.clear();
        tab.driverRoot = nullptr;
    }
    tab.displayed.clear();
    tab.shown = 0;
    tab.matched = 0;
}

bool ParseTimeValue(const std::wstring& raw, bool endOfDay, unsigned long long& value) {
    std::wstring text = Trim(raw);
    if (text.empty()) return false;
    size_t dot = text.find(L'.');
    if (dot != std::wstring::npos) text = text.substr(0, dot);
    size_t utc = text.find(L" UTC");
    if (utc != std::wstring::npos) text = Trim(text.substr(0, utc));

    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    int count = 0;
    if (text.find(L'/') != std::wstring::npos) {
        count = swscanf_s(text.c_str(), L"%d/%d/%d %d:%d:%d", &mo, &d, &y, &h, &mi, &s);
    } else {
        count = swscanf_s(text.c_str(), L"%d-%d-%d %d:%d:%d", &y, &mo, &d, &h, &mi, &s);
    }
    if (count < 3) return false;
    bool hasTime = count >= 5;
    if (!hasTime) {
        h = 0;
        mi = 0;
        s = 0;
        if (endOfDay) {
            h = 23;
            mi = 59;
            s = 59;
        }
    }
    if (y < 1601 || y > 9999 || mo < 1 || mo > 12 || d < 1 || d > 31 ||
        h < 0 || h > 23 || mi < 0 || mi > 59 || s < 0 || s > 59) {
        return false;
    }
    SYSTEMTIME st{};
    st.wYear = static_cast<WORD>(y);
    st.wMonth = static_cast<WORD>(mo);
    st.wDay = static_cast<WORD>(d);
    st.wHour = static_cast<WORD>(h);
    st.wMinute = static_cast<WORD>(mi);
    st.wSecond = static_cast<WORD>(s);
    FILETIME ft{};
    if (!SystemTimeToFileTime(&st, &ft)) return false;
    ULARGE_INTEGER large{};
    large.LowPart = ft.dwLowDateTime;
    large.HighPart = ft.dwHighDateTime;
    value = large.QuadPart;
    return true;
}

FilterKind CurrentMode(const Tab& tab) {
    int index = tab.modeCombo ? ComboSelection(tab.modeCombo) : -1;
    if (index < 0 || static_cast<size_t>(index) >= tab.modeKinds.size()) return FM_ALL;
    return tab.modeKinds[index];
}

bool CellHas(const std::wstring& cell, const std::wstring& term) {
    if (term.empty()) return true;
    return StrStrIW(cell.c_str(), term.c_str()) != nullptr;
}

bool RowMatches(Tab& tab, const Row& row) {
    if (!tab.countLabel) return true;
    FilterKind mode = CurrentMode(tab);
    if (mode == FM_DATE) {
        if (tab.dateColumn < 0 || static_cast<size_t>(tab.dateColumn) >= row.size()) return true;
        unsigned long long lower = 0, upper = 0;
        bool hasLower = ParseTimeValue(GetText(tab.fromEdit), false, lower);
        bool hasUpper = ParseTimeValue(GetText(tab.toEdit), true, upper);
        if (!hasLower && !hasUpper) return true;
        unsigned long long stamp = 0;
        if (!ParseTimeValue(row[tab.dateColumn], false, stamp)) return false;
        if (hasLower && stamp < lower) return false;
        if (hasUpper && stamp > upper) return false;
        return true;
    }

    std::wstring term = GetText(tab.searchEdit);
    if (term.empty()) return true;
    if (mode == FM_NAME) {
        for (int column : tab.nameColumns) {
            if (column >= 0 && static_cast<size_t>(column) < row.size() && CellHas(row[column], term)) return true;
        }
        return false;
    }
    if (mode == FM_ACTION) {
        for (int column : tab.actionColumns) {
            if (column >= 0 && static_cast<size_t>(column) < row.size() && CellHas(row[column], term)) return true;
        }
        return false;
    }
    if (mode == FM_PRIV) {
        return row.size() > 8 && CellHas(row[8], term);
    }
    for (const std::wstring& cell : row) {
        if (CellHas(cell, term)) return true;
    }
    return false;
}

void UpdateCount(Tab& tab) {
    if (!tab.countLabel) return;
    std::wstring text = Format(L"%s shown \u00B7 %s matched \u00B7 %s collected",
                               CommaNumber(tab.shown).c_str(), CommaNumber(tab.matched).c_str(),
                               CommaNumber(tab.records.size()).c_str());
    if (tab.matched > tab.shown) {
        text += Format(L" \u00B7 display limit %s", CommaNumber(DISPLAY_LIMIT).c_str());
    }
    if (text != tab.countCache) {
        tab.countCache = text;
        SetText(tab.countLabel, text);
    }
}

void RebuildProcessTree(Tab& tab);
void RebuildCarveTree(Tab& tab);

void RefreshList(Tab& tab) {
    if (tab.tree) {
        if (tab.key == TAB_CARVE) RebuildCarveTree(tab);
        else RebuildProcessTree(tab);
        return;
    }
    if (!tab.list) return;
    SendMessageW(tab.list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(tab.list);
    tab.displayed.clear();
    tab.shown = 0;
    tab.matched = 0;
    for (size_t i = 0; i < tab.records.size(); ++i) {
        if (!RowMatches(tab, tab.records[i])) continue;
        ++tab.matched;
        if (tab.shown < static_cast<int>(DISPLAY_LIMIT)) {
            InsertRow(tab.list, tab.records[i]);
            tab.displayed.push_back(i);
            ++tab.shown;
        }
    }
    SendMessageW(tab.list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(tab.list, nullptr, TRUE);
    UpdateCount(tab);
    if (tab.key == TAB_CARVE && g_carveMedia.visible) CarveMediaRebuild();
}

std::wstring ProcessDisplayName(const Row& row) {
    std::wstring name = row.size() > 2 ? row[2] : L"(unknown)";
    size_t start = 0;
    while (start < name.size()) {
        wchar_t ch = name[start];
        if (ch == L' ' || ch == L'\u2502' || ch == L'\u251C' || ch == L'\u2514' || ch == L'\u2500') {
            ++start;
        } else {
            break;
        }
    }
    return name.substr(start);
}

int ProcessIconIndex(const Row& row) {
    if (row.size() <= 5) return 0;
    const std::wstring& path = row[5];
    if (path.empty() || path == L"-") return 0;
    SHFILEINFOW info{};
    if (SHGetFileInfoW(path.c_str(), FILE_ATTRIBUTE_NORMAL, &info, sizeof(info),
                       SHGFI_SYSICONINDEX | SHGFI_SMALLICON)) {
        return info.iIcon;
    }
    return 0;
}

bool IsProcessChildRow(const Row& row) { return row.size() == 6; }

int StockIconIndex(SHSTOCKICONID id) {
    SHSTOCKICONINFO info{};
    info.cbSize = sizeof(info);
    if (SUCCEEDED(SHGetStockIconInfo(id, SHGSI_SYSICONINDEX, &info))) return info.iSysImageIndex;
    return 0;
}

int ProcessChildIcon(const Row& row) {
    if (row.size() < 6) return 0;
    if (row[1] == L"Group") return StockIconIndex(SIID_DRIVEFIXED);
    if (row[1] == L"Service") return StockIconIndex(SIID_SERVER);
    const std::wstring& path = row[5];
    if (!path.empty() && path != L"-") {
        SHFILEINFOW info{};
        if (SHGetFileInfoW(path.c_str(), FILE_ATTRIBUTE_NORMAL, &info, sizeof(info),
                           SHGFI_SYSICONINDEX | SHGFI_SMALLICON)) {
            return info.iIcon;
        }
    }
    return 0;
}

bool InsertProcessItem(Tab& tab, size_t recordIndex) {
    if (!tab.tree || recordIndex >= tab.records.size()) return false;
    const Row& row = tab.records[recordIndex];
    unsigned long pid = row.empty() ? 0 : wcstoul(row[0].c_str(), nullptr, 10);
    unsigned long ppid = 0;
    if (row.size() > 1) ppid = wcstoul(row[1].c_str(), nullptr, 10);

    HTREEITEM parent = TVI_ROOT;
    auto found = tab.treeNodes.find(ppid);
    if (ppid != pid && found != tab.treeNodes.end()) {
        parent = reinterpret_cast<HTREEITEM>(found->second);
    }

    std::wstring text = ProcessDisplayName(row);
    text += L"  (" + row[0] + L")";
    if (row.size() > 8 && !row[8].empty()) text += L"  \u00B7 " + row[8];
    if (row.size() > 3 && !row[3].empty() && row[3] != L"-") text += L"  \u00B7 " + row[3];
    if (row.size() > 7 && !row[7].empty()) text += L"  \u00B7 " + row[7];

    int icon = ProcessIconIndex(row);
    TVINSERTSTRUCTW insert{};
    insert.hParent = parent;
    insert.hInsertAfter = TVI_LAST;
    insert.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
    insert.item.pszText = const_cast<LPWSTR>(text.c_str());
    insert.item.lParam = static_cast<LPARAM>(recordIndex);
    insert.item.iImage = icon;
    insert.item.iSelectedImage = icon;
    HTREEITEM item = TreeView_InsertItem(tab.tree, &insert);
    if (item) tab.treeNodes[pid] = item;
    return item != nullptr;
}

bool InsertProcessChild(Tab& tab, size_t recordIndex) {
    if (!tab.tree || recordIndex >= tab.records.size()) return false;
    const Row& row = tab.records[recordIndex];
    if (!IsProcessChildRow(row)) return false;

    HTREEITEM parent = TVI_ROOT;
    if (row[0] == L"drivers") {
        if (!tab.driverRoot) return false;
        parent = tab.driverRoot;
    } else if (row[0] != L"-") {
        unsigned long pid = wcstoul(row[0].c_str(), nullptr, 10);
        auto found = tab.treeNodes.find(pid);
        if (found == tab.treeNodes.end()) return false;
        parent = reinterpret_cast<HTREEITEM>(found->second);
    }

    std::wstring text;
    if (row[1] == L"Group") {
        text = row[2];
        if (!row[3].empty()) text += L"  \u00B7 " + row[3];
    } else {
        text = L"[" + row[1] + L"]  " + row[2];
        if (!row[3].empty()) text += L"  \u00B7 " + row[3];
    }

    int icon = ProcessChildIcon(row);
    TVINSERTSTRUCTW insert{};
    insert.hParent = parent;
    insert.hInsertAfter = TVI_LAST;
    insert.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
    insert.item.pszText = const_cast<LPWSTR>(text.c_str());
    insert.item.lParam = static_cast<LPARAM>(recordIndex);
    insert.item.iImage = icon;
    insert.item.iSelectedImage = icon;
    HTREEITEM item = TreeView_InsertItem(tab.tree, &insert);
    if (item && row[1] == L"Group") tab.driverRoot = item;
    return item != nullptr;
}

void UpdateProcessDetail(Tab& tab, size_t recordIndex) {
    if (!tab.detailPane) return;
    if (recordIndex >= tab.records.size()) return;
    std::wstring text = recordIndex < tab.details.size() ? tab.details[recordIndex] : L"";
    if (text.empty()) text = BuildRowDetailAt(tab, recordIndex, static_cast<int>(recordIndex));
    SetWindowTextW(tab.detailPane, text.c_str());
    SendMessageW(tab.detailPane, EM_SETSEL, 0, 0);
    SendMessageW(tab.detailPane, EM_SCROLLCARET, 0, 0);
}

void RebuildProcessTree(Tab& tab) {
    if (!tab.tree) return;
    SendMessageW(tab.tree, WM_SETREDRAW, FALSE, 0);
    TreeView_DeleteAllItems(tab.tree);
    tab.treeNodes.clear();
    tab.driverRoot = nullptr;
    tab.displayed.clear();
    tab.shown = 0;
    tab.matched = 0;
    for (size_t i = 0; i < tab.records.size(); ++i) {
        if (!RowMatches(tab, tab.records[i])) continue;
        ++tab.matched;
        if (tab.shown >= static_cast<int>(DISPLAY_LIMIT)) continue;
        bool inserted = IsProcessChildRow(tab.records[i]) ? InsertProcessChild(tab, i)
                                                          : InsertProcessItem(tab, i);
        if (!inserted) continue;
        tab.displayed.push_back(i);
        ++tab.shown;
    }
    SendMessageW(tab.tree, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(tab.tree, nullptr, TRUE);
    UpdateCount(tab);
    HTREEITEM first = TreeView_GetRoot(tab.tree);
    if (first) TreeView_SelectItem(tab.tree, first);
}

Tab* TabFromTree(HWND tree) {
    for (Tab& tab : g_tabs) {
        if (tab.tree == tree) return &tab;
    }
    return nullptr;
}

size_t TreeRecordIndex(HWND tree, HTREEITEM item) {
    if (!item) return static_cast<size_t>(-1);
    TVITEMW info{};
    info.mask = TVIF_PARAM;
    info.hItem = item;
    if (!TreeView_GetItem(tree, &info)) return static_cast<size_t>(-1);
    return static_cast<size_t>(info.lParam);
}

void ShowProcessMenu(HWND tree, bool openDetail) {
    Tab* tab = TabFromTree(tree);
    if (!tab) return;

    HTREEITEM item = nullptr;
    POINT screen{};
    if (openDetail) {
        item = TreeView_GetSelection(tree);
        GetCursorPos(&screen);
    } else {
        GetCursorPos(&screen);
        POINT client = screen;
        ScreenToClient(tree, &client);
        TVHITTESTINFO hit{};
        hit.pt = client;
        item = TreeView_HitTest(tree, &hit);
        if (!item) return;
        TreeView_SelectItem(tree, item);
    }

    size_t index = TreeRecordIndex(tree, item);
    if (index == static_cast<size_t>(-1) || index >= tab->records.size()) return;
    const Row& row = tab->records[index];
    std::wstring path = row.size() > 5 ? row[5] : L"";
    bool realFile = !path.empty() && path != L"-" &&
                    GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
    std::wstring detailText =
        IsProcessChildRow(row) && index < tab->details.size()
            ? tab->details[index]
            : BuildRowDetailAt(*tab, index, static_cast<int>(index));

    if (openDetail) {
        ShowTextDialog(L"Detail \u2014 " + DetailTitle(tab->key),
                       L"Every column of this row, plus the full dump kept for it.",
                       detailText);
        return;
    }

    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, 1, L"Show more detail\u2026");
    AppendMenuW(menu, MF_STRING, 2, L"Copy row");
    if (realFile) {
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, 4, L"Hash file (SHA-256 / MD5)\u2026");
        AppendMenuW(menu, MF_STRING, 5, L"Certificate and signature\u2026");
    }

    int command = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_LEFTALIGN,
                                 screen.x, screen.y, 0, tree, nullptr);
    DestroyMenu(menu);

    if (command == 1) {
        ShowTextDialog(L"Detail \u2014 " + DetailTitle(tab->key),
                       L"Every column of this row, plus the full dump kept for it.",
                       detailText);
    } else if (command == 2) {
        std::wstring text;
        for (const std::wstring& cell : row) {
            if (!text.empty()) text += L"\t";
            text += cell;
        }
        CopyToClipboard(g_hwnd, text);
    } else if (command == 4 && realFile) {
        ShowTextDialog(L"Hash \u2014 " + PathFileName(path),
                       L"Digests are computed locally from the file content; nothing is uploaded.",
                       HashFileReport(path));
    } else if (command == 5 && realFile) {
        ShowTextDialog(L"Signature \u2014 " + PathFileName(path),
                       L"Embedded Authenticode and catalog signatures are both checked, including the full certificate chain.",
                       CertificateReport(path));
    }
}

bool LooksNumeric(const std::wstring& text) {
    if (text.empty()) return false;
    size_t index = text[0] == L'-' ? 1 : 0;
    if (index >= text.size()) return false;
    for (; index < text.size(); ++index) {
        if (!iswdigit(text[index])) return false;
    }
    return true;
}

void UpdateSortIndicator(Tab& tab) {
    if (!tab.list) return;
    HWND header = ListView_GetHeader(tab.list);
    if (!header) return;
    int count = Header_GetItemCount(header);
    for (int i = 0; i < count; ++i) {
        HDITEMW item{};
        item.mask = HDI_FORMAT;
        if (!Header_GetItem(header, i, &item)) continue;
        item.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (i == tab.sortColumn) item.fmt |= tab.sortAscending ? HDF_SORTUP : HDF_SORTDOWN;
        Header_SetItem(header, i, &item);
    }
}

void SortTab(Tab& tab, int column, bool ascending) {
    if (!tab.list || column < 0 || tab.records.empty()) return;
    std::vector<size_t> order(tab.records.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;

    std::stable_sort(order.begin(), order.end(), [&](size_t left, size_t right) {
        const Row& a = tab.records[left];
        const Row& b = tab.records[right];
        static const std::wstring kEmpty;
        const std::wstring& first =
            static_cast<size_t>(column) < a.size() ? a[static_cast<size_t>(column)] : kEmpty;
        const std::wstring& second =
            static_cast<size_t>(column) < b.size() ? b[static_cast<size_t>(column)] : kEmpty;
        int compare;
        if (LooksNumeric(first) && LooksNumeric(second)) {
            long long na = _wtoi64(first.c_str());
            long long nb = _wtoi64(second.c_str());
            compare = na < nb ? -1 : (na > nb ? 1 : 0);
        } else {
            compare = _wcsicmp(first.c_str(), second.c_str());
        }
        return ascending ? compare < 0 : compare > 0;
    });

    std::vector<Row> rows;
    std::vector<std::wstring> details;
    rows.reserve(order.size());
    details.reserve(order.size());
    for (size_t index : order) {
        rows.push_back(std::move(tab.records[index]));
        details.push_back(index < tab.details.size() ? std::move(tab.details[index]) : std::wstring());
    }
    tab.records = std::move(rows);
    tab.details = std::move(details);
    tab.sortColumn = column;
    tab.sortAscending = ascending;
    RefreshList(tab);
    UpdateSortIndicator(tab);
}

void AdjustFillerColumn(Tab& tab) {
    if (!tab.list || tab.baseWidths.empty()) return;
    RECT rc{};
    GetClientRect(tab.list, &rc);
    int total = 0;
    for (int width : tab.baseWidths) total += S(width);
    int last = static_cast<int>(tab.baseWidths.size()) - 1;
    int width = S(tab.baseWidths[static_cast<size_t>(last)]);
    if (total <= rc.right) width += (rc.right - total) + S(40);
    ListView_SetColumnWidth(tab.list, last, width);
}

void EnsureDetailPane(Tab& tab) {
    if (tab.detailPane || !tab.page) return;
    tab.detailPane = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                         ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tab.detailPane, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontMono ? g_fontMono : g_fontSmall), TRUE);
    SetWindowTextW(tab.detailPane, L"Select a record to inspect every field of it.");
}

// Positions every filter control (search, mode, optional date range, Clear and the
// result count) on a single horizontal row at y. When the date mode is not active the
// From/To fields are hidden and Clear + count sit right after the mode combo instead of
// leaving an empty gap where those fields would be.
static void PositionFilterRow(Tab& tab, int y) {
    if (!tab.countLabel) return;
    bool date = CurrentMode(tab) == FM_DATE;
    RECT rc{};
    GetClientRect(tab.page, &rc);
    int pageW = rc.right;
    if (tab.searchIcon)   Place(tab.searchIcon, 8, y, 20, 24);
    if (tab.searchEdit)   Place(tab.searchEdit, 32, y, 244, 24);
    if (tab.modeLabel)    Place(tab.modeLabel, 286, y + 2, 48, 20);
    if (tab.modeCombo)    Place(tab.modeCombo, 338, y, 96, 200);
    if (tab.fromLabel)    Place(tab.fromLabel, 444, y + 2, 36, 20);
    if (tab.fromEdit)     Place(tab.fromEdit, 482, y, 110, 24);
    if (tab.toLabel)      Place(tab.toLabel, 598, y + 2, 20, 20);
    if (tab.toEdit)       Place(tab.toEdit, 620, y, 110, 24);
    int clearX = date ? 740 : 444;
    int countX = clearX + 66;
    int countW = pageW - countX - 16;
    if (countW < 120) countW = 120;
    if (tab.clearBtn)    Place(tab.clearBtn, clearX, y, 60, 24);
    if (tab.countLabel)  Place(tab.countLabel, countX, y + 2, countW, 20);
}

void LayoutTab(Tab& tab) {
    if (!tab.page) return;
    RECT rc{};
    GetClientRect(tab.page, &rc);
    int pageW = rc.right;

    // ---- header: title + description (description wraps and sizes to its content) ----
    MoveWindow(tab.title, S(8), S(4), pageW - S(16), S(24), TRUE);
    int descTop = S(28);
    int descW = pageW - S(16);
    int descH = S(18);
    if (tab.desc) {
        HDC dc = GetDC(tab.desc);
        HFONT f = reinterpret_cast<HFONT>(SendMessageW(tab.desc, WM_GETFONT, 0, 0));
        HGDIOBJ old = f ? SelectObject(dc, f) : nullptr;
        int n = GetWindowTextLengthW(tab.desc) + 1;
        std::wstring buf(static_cast<size_t>(n > 1 ? n : 1), L'\0');
        GetWindowTextW(tab.desc, &buf[0], n);
        RECT mr = {0, 0, descW, 1};
        DrawTextW(dc, buf.c_str(), -1, &mr, DT_CALCRECT | DT_WORDBREAK | DT_LEFT | DT_NOPREFIX);
        if (old) SelectObject(dc, old);
        ReleaseDC(tab.desc, dc);
        descH = mr.bottom;
        if (descH < S(18)) descH = S(18);
    }
    if (tab.desc) MoveWindow(tab.desc, S(8), descTop, descW, descH, TRUE);

    // ---- extra header rows (registered in the build functions) follow the description ----
    // Controls sharing the same row index sit on one horizontal line; y only advances
    // when the row index changes. Registration order is ascending by row.
    int y = descTop + descH + S(6);
    int lastRow = -999;
    int rowAdvance = S(26) + S(6);
    for (auto& c : tab.headerCtrls) {
        if (c.row < 0) continue;
        if (c.row != lastRow) {
            if (lastRow != -999) y += rowAdvance;
            lastRow = c.row;
        }
        MoveWindow(c.hwnd, S(c.x), y, S(c.w), S(c.h), TRUE);
    }
    if (lastRow != -999) y += rowAdvance;
    int btnY = y;
    tab.headerButtonY = btnY;
    if (tab.buttonsCustom) {
        // The build function registered start/stop/status (and any extras) in headerCtrls
        // as row < 0; the loop below positions them at their design x coordinates.
    } else {
        if (tab.startBtn)    MoveWindow(tab.startBtn, S(8), btnY, S(90), S(26), TRUE);
        if (tab.stopBtn)     MoveWindow(tab.stopBtn, S(103), btnY, S(80), S(26), TRUE);
        if (tab.statusLabel) MoveWindow(tab.statusLabel, S(205), btnY + S(4), pageW - S(220), S(20), TRUE);
    }
    for (auto& c : tab.headerCtrls) {
        if (c.row < 0) {
            MoveWindow(c.hwnd, S(c.x), btnY, S(c.w), S(c.h), TRUE);
        }
    }
    tab.headerFilterY = btnY + S(32);
    PositionFilterRow(tab, tab.headerFilterY);
    int listY = tab.headerFilterY + S(30);
    if (tab.key == TAB_PROCESS) {
        int top = S(listY);
        int height = rc.bottom - top - S(10);
        if (height < S(160)) height = S(160);
        int treeWidth = (rc.right - S(24)) * 42 / 100;
        if (treeWidth < S(320)) treeWidth = S(320);
        if (treeWidth > rc.right - S(280)) treeWidth = rc.right - S(280);
        MoveWindow(tab.tree, S(8), top, treeWidth, height, TRUE);
        int detailX = S(8) + treeWidth + S(8);
        int rightWidth = rc.right - detailX - S(8);
        if (g_procMemoryMode) {
            MoveWindow(g_memory.info, detailX, top, rightWidth, S(20), TRUE);
            MoveWindow(g_memory.list, detailX, top + S(24), rightWidth, height - S(24), TRUE);
        } else {
            MoveWindow(tab.detailPane, detailX, top, rightWidth, height, TRUE);
        }
        return;
    }
    if (tab.key == TAB_REGISTRY) {
        int top = S(90);
        int height = rc.bottom - top - S(10);
        if (height < S(160)) height = S(160);
        int treeWidth = (rc.right - S(24)) * 38 / 100;
        if (treeWidth < S(300)) treeWidth = S(300);
        if (treeWidth > rc.right - S(300)) treeWidth = rc.right - S(300);
        MoveWindow(tab.tree, S(8), top, treeWidth, height, TRUE);
        int detailX = S(8) + treeWidth + S(8);
        int rightWidth = rc.right - detailX - S(8);
        MoveWindow(g_reg.header, detailX, top, rightWidth, S(20), TRUE);
        int listTop = top + S(26);
        int listHeight = (height - S(26)) * 58 / 100;
        if (listHeight < S(120)) listHeight = S(120);
        MoveWindow(g_reg.list, detailX, listTop, rightWidth, listHeight, TRUE);
        int valueTop = listTop + listHeight + S(6);
        MoveWindow(g_reg.valueDetail, detailX, valueTop, rightWidth,
                   top + height - valueTop, TRUE);
        return;
    }
    if (tab.key == TAB_SERVICES || tab.key == TAB_COMPUTERINFO || tab.key == TAB_SRUM ||
        tab.key == TAB_AMCACHE ||
        (tab.key >= TAB_USB && tab.key <= TAB_WPN)) {        int top = S(listY);
        int height = rc.bottom - top - S(10);
        if (height < S(160)) height = S(160);
        int listWidth = (rc.right - S(24)) * 62 / 100;
        if (listWidth < S(420)) listWidth = S(420);
        if (listWidth > rc.right - S(320)) listWidth = rc.right - S(320);
        MoveWindow(tab.list, S(8), top, listWidth, height, TRUE);
        int detailX = S(8) + listWidth + S(8);
        MoveWindow(tab.detailPane, detailX, top, rc.right - detailX - S(8), height, TRUE);
        return;
    }
    if (tab.key == TAB_THUMBNAIL) {
        int top = S(listY);
        int height = rc.bottom - top - S(10);
        if (height < S(200)) height = S(200);
        int listWidth = (rc.right - S(24)) * 62 / 100;
        if (listWidth < S(420)) listWidth = S(420);
        if (listWidth > rc.right - S(320)) listWidth = rc.right - S(320);
        MoveWindow(tab.list, S(8), top, listWidth, height, TRUE);
        int detailX = S(8) + listWidth + S(8);
        int rightWidth = rc.right - detailX - S(8);
        int previewHeight = height * 45 / 100;
        if (previewHeight < S(180)) previewHeight = S(180);
        if (previewHeight > height - S(120)) previewHeight = height - S(120);
        MoveWindow(g_thumb.preview, detailX, top, rightWidth, previewHeight, TRUE);
        MoveWindow(tab.detailPane, detailX, top + previewHeight + S(6), rightWidth,
                   height - previewHeight - S(6), TRUE);
        return;
    }
    if (tab.key == TAB_CARVE) {
        int top = S(listY);
        int height = rc.bottom - top - S(10);
        if (height < S(160)) height = S(160);
        int treeWidth = (rc.right - S(24)) * 46 / 100;
        if (treeWidth < S(320)) treeWidth = S(320);
        if (treeWidth > rc.right - S(300)) treeWidth = rc.right - S(300);
        MoveWindow(tab.tree, S(8), top, treeWidth, height, TRUE);
        int detailX = S(8) + treeWidth + S(8);
        MoveWindow(tab.detailPane, detailX, top, rc.right - detailX - S(8), height, TRUE);
        if (g_carveMedia.list) {
            MoveWindow(g_carveMedia.list, S(8), top, rc.right - S(16), height, TRUE);
        }
        return;
    }
    if (tab.key == TAB_EVENTVIEWER) {
        int top = S(listY);
        int height = rc.bottom - top - S(10);
        if (height < S(200)) height = S(200);
        int treeWidth = (rc.right - S(24)) * 24 / 100;
        if (treeWidth < S(220)) treeWidth = S(220);
        if (treeWidth > rc.right - S(460)) treeWidth = rc.right - S(460);
        MoveWindow(g_ev.tree, S(8), top, treeWidth, height, TRUE);
        int rightX = S(8) + treeWidth + S(8);
        int rightW = rc.right - rightX - S(8);
        int listHeight = height * 56 / 100;
        if (listHeight < S(140)) listHeight = S(140);
        MoveWindow(tab.list, rightX, top, rightW, listHeight, TRUE);
        MoveWindow(tab.detailPane, rightX, top + listHeight + S(6), rightW,
                   height - listHeight - S(6), TRUE);
        return;
    }
    if (tab.tree) {
        int top = S(listY);
        int height = rc.bottom - top - S(10);
        if (height < S(120)) height = S(120);
        int treeWidth = (rc.right - S(24)) * 46 / 100;
        if (treeWidth < S(300)) treeWidth = S(300);
        if (treeWidth > rc.right - S(240)) treeWidth = rc.right - S(240);
        MoveWindow(tab.tree, S(8), top, treeWidth, height, TRUE);
        int detailX = S(8) + treeWidth + S(8);
        MoveWindow(tab.detailPane, detailX, top, rc.right - detailX - S(8), height, TRUE);
        return;
    }

    if (tab.key == TAB_NFAT) {
        // listY already 176 from the header
    } else if (!tab.countLabel) {
        listY = tab.headerButtonY + S(30);
    }
    if (tab.headerEdit) {
        int headerH = S(58);
        MoveWindow(tab.headerEdit, S(8), S(54), rc.right - S(16), headerH, TRUE);
        listY = 54 + 58 + 8;
    }
    if (tab.list) {
        int listWidth = rc.right - S(16);
        if (tab.detailPane) {
            listWidth = (rc.right - S(24)) * 58 / 100;
            if (listWidth < S(420)) listWidth = S(420);
            if (listWidth > rc.right - S(300)) listWidth = rc.right - S(300);
            int detailX = S(8) + listWidth + S(8);
            MoveWindow(tab.detailPane, detailX, S(listY), rc.right - detailX - S(8),
                       rc.bottom - S(listY + 8), TRUE);
        }
        MoveWindow(tab.list, S(8), S(listY), listWidth, rc.bottom - S(listY + 8), TRUE);
    }
    if (tab.key == TAB_CARVE && g_carveMedia.list) {
        MoveWindow(g_carveMedia.list, S(8), S(listY), rc.right - S(16),
                   rc.bottom - S(listY + 8), TRUE);
    }
    AdjustFillerColumn(tab);
}

int SidebarWidth() { return S(214); }

void LayoutAll() {
    if (!g_hwnd) return;
    RECT rc{};
    GetClientRect(g_hwnd, &rc);
    int statusHeight = S(30);
    SidebarLayout(g_sidebar, 0, 0, SidebarWidth(), rc.bottom - statusHeight);

    int left = SidebarWidth() + S(10);
    int top = S(8);
    int width = rc.right - left - S(10);
    int height = rc.bottom - statusHeight - top - S(8);
    if (width < S(200)) width = S(200);
    if (height < S(200)) height = S(200);
    for (Tab& tab : g_tabs) {
        MoveWindow(tab.page, left, top, width, height, TRUE);
        LayoutTab(tab);
    }

    int barY = rc.bottom - statusHeight + S(5);
    MoveWindow(g_status, S(14), barY, rc.right - S(464), S(20), TRUE);
    MoveWindow(g_progressText, rc.right - S(440), barY, S(230), S(20), TRUE);
    MoveWindow(g_progress, rc.right - S(198), barY + S(2), S(186), S(16), TRUE);
}

static void StartForensicScan(int tabKey);
static void ThumbSelect(int item);
static void ThumbSetBitmap(HBITMAP bitmap);

void ShowPage(int index) {
    if (index < 0 || index >= TAB_COUNT) index = 0;
    for (int i = 0; i < TAB_COUNT; ++i) {
        if (!g_tabs[i].page) continue;
        ShowWindow(g_tabs[i].page, i == index ? SW_SHOW : SW_HIDE);
    }
    SidebarSelect(g_sidebar, index);
    LayoutAll();
    if (g_tabs[index].page) {
        SetWindowPos(g_tabs[index].page, HWND_TOP, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
}

void SetMarquee(bool active) {
    if (!g_progress) return;
    SendMessageW(g_progress, PBM_SETMARQUEE, active ? TRUE : FALSE, 28);
    if (!active) SendMessageW(g_progress, PBM_SETPOS, 0, 0);
}

void SetRunning(Tab& tab, bool running) {
    tab.running = running;
    if (tab.startBtn) EnableWindow(tab.startBtn, running ? FALSE : TRUE);
    if (tab.stopBtn) EnableWindow(tab.stopBtn, running ? TRUE : FALSE);
}

void SetFilterVisibility(Tab& tab) {
    if (!tab.countLabel) return;
    bool date = CurrentMode(tab) == FM_DATE;
    ShowWindow(tab.searchIcon, date ? SW_HIDE : SW_SHOW);
    ShowWindow(tab.searchEdit, date ? SW_HIDE : SW_SHOW);
    ShowWindow(tab.fromLabel, date ? SW_SHOW : SW_HIDE);
    ShowWindow(tab.fromEdit, date ? SW_SHOW : SW_HIDE);
    ShowWindow(tab.toLabel, date ? SW_SHOW : SW_HIDE);
    ShowWindow(tab.toEdit, date ? SW_SHOW : SW_HIDE);
    PositionFilterRow(tab, tab.headerFilterY);
}

void ScheduleFilter(Tab& tab) {
    SetTimer(g_hwnd, TIMER_FILTER_BASE + static_cast<UINT_PTR>(tab.key), 220, nullptr);
}

void ClearFilter(Tab& tab) {
    if (!tab.countLabel) return;
    SetText(tab.searchEdit, L"");
    SetText(tab.fromEdit, L"");
    SetText(tab.toEdit, L"");
    RefreshList(tab);
}

void StartWork(Tab& tab, std::function<void(const Sink&, std::atomic<bool>&)> work) {
    if (tab.running) return;
    if (tab.key == TAB_CARVE) CarveMediaReset();
    tab.generation += 1;

    auto stopFlag = std::make_shared<std::atomic<bool>>(false);
    tab.stopFlag = stopFlag;
    tab.records.clear();
    tab.sortColumn = -1;
    tab.sortAscending = true;
    ClearList(tab);
    UpdateSortIndicator(tab);
    SetText(tab.countLabel, L"Working\u2026");
    tab.countCache.clear();
    SetText(tab.statusLabel, L"Working\u2026");
    SetText(g_status, L"Working\u2026");
    SetText(g_progressText, L"Working\u2026");
    SetMarquee(true);
    SetRunning(tab, true);
    if (tab.list) InvalidateRect(tab.list, nullptr, TRUE);
    if (tab.tree) InvalidateRect(tab.tree, nullptr, TRUE);

    Sink sink;
    sink.hwnd = g_hwnd;
    sink.tab = tab.key;
    sink.generation = tab.generation;
    std::thread([sink, work = std::move(work), stopFlag]() mutable {
        try {
            work(sink, *stopFlag);
        } catch (const std::exception& error) {
            sink.Error(Utf8ToWide(error.what()));
        } catch (...) {
            sink.Error(L"Unexpected error while collecting data.");
        }
    }).detach();
}

void StopWork(Tab& tab) {
    if (!tab.running) return;
    if (tab.stopFlag) tab.stopFlag->store(true);
    tab.generation += 1;
    SetRunning(tab, false);
    SetMarquee(false);
    std::wstring message;
    if (tab.key == TAB_NFAT) message = L"Stopped. The last network snapshot is kept.";
    else if (tab.key == TAB_PACKET) message = L"Stopped. Captured packets already displayed are kept.";
    else message = L"Stopped. Remaining work was cancelled; results already displayed are kept.";
    SetText(tab.statusLabel, message);
    SetText(g_status, message);
    SetText(g_progressText, L"Stopped");
    UpdateCount(tab);
}

bool IsElevated() {
    BOOL admin = FALSE;
    PSID sid = nullptr;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid)) {
        CheckTokenMembership(nullptr, sid, &admin);
        FreeSid(sid);
    }
    return admin != FALSE;
}

void RebuildTargetCombo() {
    HWND combos[] = {
        g_tabs[TAB_SEARCH].targetCombo,
        g_tabs[TAB_USN].targetCombo,
        g_tabs[TAB_MFT].targetCombo,
        g_tabs[TAB_STRINGS].targetCombo,
    };
    for (HWND combo : combos) {
        if (!combo) continue;
        std::wstring previous = ComboText(combo);
        SendMessageW(combo, CB_RESETCONTENT, 0, 0);
        ComboAdd(combo, L"All NTFS volumes");
        for (const std::wstring& drive : NtfsDrives()) ComboAdd(combo, drive);
        int index = 0;
        if (!previous.empty()) {
            int found = static_cast<int>(SendMessageW(combo, CB_FINDSTRINGEXACT,
                                                      static_cast<WPARAM>(-1),
                                                      reinterpret_cast<LPARAM>(previous.c_str())));
            if (found >= 0) index = found;
        }
        SendMessageW(combo, CB_SETCURSEL, index, 0);
    }
}

std::vector<std::wstring> SelectedVolumes(HWND combo) {
    std::wstring target = ComboText(combo);
    if (target.empty() || target == L"All NTFS volumes") return NtfsDrives();
    return {target};
}

void RefreshVolumes() {
    Tab& tab = g_tabs[TAB_VOLUME];
    tab.records = CollectVolumes();
    tab.details.assign(tab.records.size(), std::wstring());
    RefreshList(tab);
    bool admin = IsElevated();
    std::wstring text = Format(L"%s mounted volume(s) detected \u00B7 %s session",
                               CommaNumber(tab.records.size()).c_str(),
                               admin ? L"Administrator" : L"standard user");
    if (tab.volumeStatus) SetText(tab.volumeStatus, text);
    SetText(g_status, text);
    RebuildTargetCombo();
}

void StartSearch() {
    Tab& tab = g_tabs[TAB_SEARCH];
    if (tab.running) return;
    SearchConfig config;
    config.pattern = GetText(tab.patternEdit);
    if (config.pattern.empty()) config.pattern = L"*";
    config.regex = IsChecked(tab.regexCheck);
    config.caseSensitive = IsChecked(tab.caseCheck);

    double minimumMb = _wtof(GetText(tab.minEdit).c_str());
    double maximumMb = _wtof(GetText(tab.maxEdit).c_str());
    if (minimumMb < 0) minimumMb = 0;
    if (maximumMb < 0) maximumMb = 0;
    config.minBytes = static_cast<unsigned long long>(minimumMb * 1048576.0);
    config.maxBytes = static_cast<unsigned long long>(maximumMb * 1048576.0);

    if (config.regex) {
        try {
            auto flags = std::regex::ECMAScript | std::regex::optimize;
            if (!config.caseSensitive) flags |= std::regex::icase;
            std::wregex check(config.pattern, flags);
        } catch (const std::regex_error& error) {
            MessageBoxW(g_hwnd, (L"Invalid regular expression: " + Utf8ToWide(error.what())).c_str(),
                        APP_TITLE, MB_ICONWARNING);
            return;
        }
    }

    std::vector<std::wstring> roots;
    if (IsChecked(tab.allDrivesCheck)) {
        roots = LogicalDrives();
    } else {
        std::wstring target = ComboText(tab.targetCombo);
        if (target.empty() || target == L"All NTFS volumes") {
            for (const std::wstring& drive : NtfsDrives()) roots.push_back(drive + L"\\");
        } else {
            roots.push_back(target + L"\\");
        }
    }
    if (roots.empty()) {
        MessageBoxW(g_hwnd, L"No mounted drive was selected.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    config.roots = std::move(roots);

    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunFileSearch(sink, stop, config);
    });
}

void StartUsn() {
    Tab& tab = g_tabs[TAB_USN];
    if (tab.running) return;
    UsnConfig config;
    config.volumes = SelectedVolumes(tab.targetCombo);
    config.limit = _wcstoui64(GetText(tab.limitEdit).c_str(), nullptr, 10);
    if (config.volumes.empty()) {
        MessageBoxW(g_hwnd, L"No NTFS volume was selected.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunUsnJournal(sink, stop, config);
    });
}

void StartMft() {
    Tab& tab = g_tabs[TAB_MFT];
    if (tab.running) return;
    MftConfig config;
    config.volumes = SelectedVolumes(tab.targetCombo);
    config.limit = _wcstoui64(GetText(tab.limitEdit).c_str(), nullptr, 10);
    if (config.volumes.empty()) {
        MessageBoxW(g_hwnd, L"No NTFS volume was selected.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunMftScan(sink, stop, config);
    });
}

void StartEvents() {
    Tab& tab = g_tabs[TAB_EVENTS];
    if (tab.running) return;
    EventsConfig config;
    if (IsChecked(tab.allChannelsCheck)) {
        config.channels = g_eventChannels;
    } else {
        std::wstring channel = ComboText(tab.channelCombo);
        if (!channel.empty()) config.channels.push_back(channel);
    }
    config.limitPerChannel = _wtoi(GetText(tab.limitEdit).c_str());
    if (config.limitPerChannel <= 0) config.limitPerChannel = 1000;
    if (config.channels.empty()) {
        MessageBoxW(g_hwnd, L"No Windows event log channel was selected.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunEventLogs(sink, stop, config);
    });
}

std::vector<int> ParseEventIds(const std::wstring& text) {
    std::vector<int> ids;
    std::wstring token;
    auto flush = [&]() {
        if (!token.empty()) {
            int value = _wtoi(token.c_str());
            if (value > 0) ids.push_back(value);
            token.clear();
        }
    };
    for (wchar_t c : text) {
        if (c >= L'0' && c <= L'9') token += c;
        else flush();
    }
    flush();
    return ids;
}

void StartEventViewer() {
    Tab& tab = g_tabs[TAB_EVENTVIEWER];
    if (tab.running) return;
    EventViewerConfig config;
    if (IsChecked(g_ev.allCheck)) {
        config.channels = g_eventChannels;
    } else {
        if (g_ev.selectedChannel.empty()) {
            MessageBoxW(g_hwnd, L"Pick a channel in the tree on the left, or tick All channels.",
                        APP_TITLE, MB_ICONWARNING);
            return;
        }
        config.channels.push_back(g_ev.selectedChannel);
    }
    config.eventIds = ParseEventIds(GetText(g_ev.idsEdit));
    config.level = ComboSelection(g_ev.levelCombo);
    if (config.level < 0) config.level = 0;
    config.provider = Trim(GetText(g_ev.providerEdit));
    config.limitPerChannel = _wtoi(GetText(g_ev.limitEdit).c_str());
    if (config.limitPerChannel <= 0) config.limitPerChannel = 2000;
    if (config.channels.empty()) {
        MessageBoxW(g_hwnd, L"No event channel is available to read.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunEventViewer(sink, stop, config);
    });
}

void StartPrefetch() {
    Tab& tab = g_tabs[TAB_PREFETCH];
    if (tab.running) return;
    PrefetchConfig config;
    config.folder = Trim(GetText(tab.folderEdit));
    config.maxFiles = _wtoi(GetText(tab.maxFilesEdit).c_str());
    if (config.maxFiles < 0) config.maxFiles = 0;
    config.details = IsChecked(tab.detailsCheck);
    config.recent = IsChecked(tab.recentCheck);
    if (!config.details && !config.recent) {
        MessageBoxW(g_hwnd, L"Select Prefetch details, Recent shortcuts and Jump Lists, or both.",
                    APP_TITLE, MB_ICONWARNING);
        return;
    }
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunPrefetchRecent(sink, stop, config);
    });
}

void StartStrings() {
    Tab& tab = g_tabs[TAB_STRINGS];
    if (tab.running) return;
    StringsConfig config;
    config.volumes = SelectedVolumes(tab.targetCombo);
    config.minLength = _wtoi(GetText(tab.minLengthEdit).c_str());
    if (config.minLength < 3) config.minLength = 3;
    config.utf16 = IsChecked(tab.utf16Check);
    config.ascii = IsChecked(tab.asciiCheck);
    if (!config.utf16 && !config.ascii) {
        MessageBoxW(g_hwnd, L"Select UTF-16, ASCII, or both.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    if (!IsChecked(tab.fullDiskCheck)) {
        double megabytes = _wtof(GetText(tab.limitMbEdit).c_str());
        if (megabytes < 0) megabytes = 0;
        config.limitBytes = static_cast<unsigned long long>(megabytes * 1048576.0);
    }
    if (config.volumes.empty()) {
        MessageBoxW(g_hwnd, L"No NTFS volume was selected.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunDiskStrings(sink, stop, config);
    });
}

void StartPowerShell() {
    Tab& tab = g_tabs[TAB_POWERSHELL];
    if (tab.running) return;
    PowerShellConfig config;
    config.allUsers = IsChecked(tab.allUsersCheck);
    config.systemProfile = IsChecked(tab.systemProfileCheck);
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunPowerShellHistory(sink, stop, config);
    });
}

void StartProcess() {
    Tab& tab = g_tabs[TAB_PROCESS];
    if (tab.running) return;
    ProcessConfig config;
    config.modules = IsChecked(tab.modulesCheck);
    config.services = IsChecked(tab.servicesCheck);
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunProcessExplorer(sink, stop, config);
    });
}

void StartStartup() {
    Tab& tab = g_tabs[TAB_STARTUP];
    if (tab.running) return;
    StartWork(tab, [](const Sink& sink, std::atomic<bool>& stop) {
        RunStartupInventory(sink, stop);
    });
}

void StartPersistence() {
    Tab& tab = g_tabs[TAB_PERSISTENCE];
    if (tab.running) return;
    PersistenceConfig config;
    config.registry = IsChecked(tab.regKeysCheck);
    config.services = IsChecked(tab.svcAutoCheck);
    config.tasks = IsChecked(tab.tasksCheck);
    config.folders = IsChecked(tab.foldersCheck);
    if (!config.registry && !config.services && !config.tasks && !config.folders) {
        MessageBoxW(g_hwnd, L"Select at least one persistence source.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunPersistenceAudit(sink, stop, config);
    });
}

void StartExecution() {
    Tab& tab = g_tabs[TAB_EXECUTION];
    if (tab.running) return;
    ExecConfig config;
    config.shimcache = IsChecked(tab.shimCacheCheck);
    config.usb = IsChecked(tab.usbCheck);
    config.recycle = IsChecked(tab.recycleCheck);
    if (!config.shimcache && !config.usb && !config.recycle) {
        MessageBoxW(g_hwnd, L"Select at least one source.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunExecutionDevices(sink, stop, config);
    });
}

void StartSignatures() {
    Tab& tab = g_tabs[TAB_SIGNATURES];
    if (tab.running) return;
    SignatureConfig config;
    config.processes = IsChecked(tab.signProcCheck);
    config.modules = IsChecked(tab.signModulesCheck);
    config.services = IsChecked(tab.signServicesCheck);
    if (!config.processes && !config.modules && !config.services) {
        MessageBoxW(g_hwnd, L"Select at least one file source.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunSignatureScan(sink, stop, config);
    });
}

void StartNfat() {
    Tab& tab = g_tabs[TAB_NFAT];
    if (tab.running) return;
    NfatConfig config;
    config.tcp = IsChecked(tab.chkTcp);
    config.udp = IsChecked(tab.chkUdp);
    config.dns = IsChecked(tab.chkDns);
    config.arp = IsChecked(tab.chkArp);
    config.adapters = IsChecked(tab.chkAdapters);
    config.traffic = IsChecked(tab.chkTraffic);
    config.full = IsChecked(tab.chkFull);
    config.realtime = IsChecked(tab.chkRealtime);
    std::wstring intervalText = ComboText(tab.intervalCombo);
    int seconds = _wtoi(intervalText.c_str());
    config.interval = seconds > 0 ? static_cast<double>(seconds) : 2.0;

    if (!config.tcp && !config.udp && !config.dns && !config.arp && !config.adapters && !config.traffic) {
        MessageBoxW(g_hwnd, L"Select at least one network source.", APP_TITLE, MB_ICONWARNING);
        return;
    }

    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        NetworkCollector collector(config);
        if (!config.realtime) {
            sink.Status(L"Collecting network snapshot\u2026");
            NetSnapshot snapshot = collector.Collect();
            Batch batch;
            batch.reset = true;
            batch.rows = std::move(snapshot.rows);
            batch.status = Format(L"Snapshot \u00B7 %s records",
                                  CommaNumber(batch.rows.size()).c_str());
            sink.Post(std::move(batch));
            sink.Done(L"Completed. Network snapshot collected.");
            return;
        }
        int cycle = 0;
        while (!stop.load()) {
            NetSnapshot snapshot = collector.Collect();
            ++cycle;
            std::wstring status = Format(L"Live \u00B7 cycle %d \u00B7 %s records",
                                         cycle, CommaNumber(snapshot.rows.size()).c_str());
            if (config.traffic) {
                status += Format(L" \u00B7 In %s/s \u00B7 Out %s/s",
                                 SizeText(static_cast<unsigned long long>(snapshot.inRate)).c_str(),
                                 SizeText(static_cast<unsigned long long>(snapshot.outRate)).c_str());
            }
            Batch batch;
            batch.reset = true;
            batch.rows = std::move(snapshot.rows);
            batch.status = status;
            sink.Post(std::move(batch));

            auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(static_cast<int>(config.interval * 1000.0));
            while (!stop.load() && std::chrono::steady_clock::now() < deadline) {
                Sleep(50);
            }
        }
        sink.Done(Format(L"Stopped after %d update(s). The last network snapshot is kept.", cycle));
    });
}

void StartPacket() {
    Tab& tab = g_tabs[TAB_PACKET];
    if (tab.running) return;
    PacketConfig config;
    config.payloadOnly = IsChecked(tab.chkPayload);
    config.fullLookup = IsChecked(tab.chkPacketFull);
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunPacketCapture(sink, stop, config);
    });
}

void HandleBatch(Batch* raw) {
    std::unique_ptr<Batch> batch(raw);
    if (!batch) return;
    if (batch->tab < 0 || batch->tab >= TAB_COUNT) return;
    Tab& tab = g_tabs[batch->tab];
    if (batch->generation != tab.generation) return;

    if (batch->reset) {
        tab.records.clear();
        tab.details.clear();
        ClearList(tab);
    }

    if (!batch->rows.empty()) {
        HWND target = tab.tree ? tab.tree : tab.list;
        if (target) SendMessageW(target, WM_SETREDRAW, FALSE, 0);
        for (size_t i = 0; i < batch->rows.size(); ++i) {
            if (tab.records.size() >= COLLECT_LIMIT) {
                if (tab.stopFlag) tab.stopFlag->store(true);
                SetText(tab.statusLabel, Format(L"Collection limit of %s rows reached; stopping.",
                                                CommaNumber(COLLECT_LIMIT).c_str()));
                break;
            }
            tab.records.push_back(std::move(batch->rows[i]));

            if (i < batch->details.size() && tab.details.size() < DISPLAY_LIMIT) {
                tab.details.push_back(std::move(batch->details[i]));
            } else {
                tab.details.emplace_back();
            }
            const Row& stored = tab.records.back();
            if (RowMatches(tab, stored)) {
                ++tab.matched;
                if (tab.shown < static_cast<int>(DISPLAY_LIMIT)) {
                    bool inserted = true;
                    if (tab.tree && tab.key == TAB_CARVE) {
                        inserted = false;
                    } else if (tab.tree) {
                        inserted = IsProcessChildRow(stored)
                                       ? InsertProcessChild(tab, tab.records.size() - 1)
                                       : InsertProcessItem(tab, tab.records.size() - 1);
                    } else {
                        InsertRow(tab.list, stored);
                    }
                    if (inserted) {
                        tab.displayed.push_back(tab.records.size() - 1);
                        ++tab.shown;
                        if (tab.shown == static_cast<int>(DISPLAY_LIMIT)) {
                            SetText(g_status, Format(L"Display limit of %s rows reached for this tab; use the filter to narrow the result.",
                                                     CommaNumber(DISPLAY_LIMIT).c_str()));
                        }
                    }
                }
            }
        }
        if (target) {
            SendMessageW(target, WM_SETREDRAW, TRUE, 0);
            InvalidateRect(target, nullptr, TRUE);
        }
        UpdateCount(tab);
    }

    if (!tab.detailPane && !tab.details.empty() && tab.list && !tab.tree) {
        EnsureDetailPane(tab);
        LayoutTab(tab);
    }

    if (!batch->status.empty()) {
        SetText(tab.statusLabel, batch->status);
        SetText(g_status, batch->status);
    }
    if (batch->progress >= 0) {
        SetMarquee(false);
        SendMessageW(g_progress, PBM_SETPOS, static_cast<WPARAM>(batch->progress), 0);
    }

    if (batch->done || batch->error) {
        SetRunning(tab, false);
        SetMarquee(false);
        SetText(g_progressText, batch->error ? L"Error" : L"Completed");
        if (batch->done && !batch->error) {
            if (tab.tree || tab.sortColumn >= 0) RefreshList(tab);
        }
        if (batch->done && !batch->error && tab.list && tab.detailPane && !tab.tree) {
            if (ListView_GetItemCount(tab.list) > 0) {
                ListView_SetItemState(tab.list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
                ListView_SetItemState(tab.list, 0, LVIS_SELECTED | LVIS_FOCUSED,
                                      LVIS_SELECTED | LVIS_FOCUSED);
                if (tab.key == TAB_SERVICES) UpdateServiceDetail(0);
                else if (tab.key == TAB_COMPUTERINFO) UpdateComputerInfoDetail(0);
                else if (tab.key == TAB_THUMBNAIL) ThumbSelect(0);
                else UpdateStoredDetail(tab, 0);
            }
        }
        if (batch->error) {
            MessageBoxW(g_hwnd, batch->status.c_str(), APP_TITLE, MB_ICONWARNING);
        }
        if (batch->error) SetText(g_progressText, L"Error");
        else if (batch->status.rfind(L"Stopped", 0) == 0) SetText(g_progressText, L"Stopped");
        else SetText(g_progressText, L"Completed");
    }
}

HICON WindowsSearchIcon() {
    static HICON icon = nullptr;
    if (!icon) {
        SHSTOCKICONINFO info{};
        info.cbSize = sizeof(info);
        if (SUCCEEDED(SHGetStockIconInfo(SIID_FIND, SHGSI_ICON | SHGSI_SMALLICON, &info))) {
            icon = info.hIcon;
        }
    }
    return icon;
}

void BuildFilter(Tab& tab, int dateColumn, std::vector<int> nameColumns,
                 std::vector<int> actionColumns,
                 const std::vector<std::pair<std::wstring, FilterKind>>& modes) {
    tab.dateColumn = dateColumn;
    tab.nameColumns = std::move(nameColumns);
    tab.actionColumns = std::move(actionColumns);
    tab.modeKinds.clear();
    for (const auto& mode : modes) tab.modeKinds.push_back(mode.second);

    tab.searchIcon = CreateWindowExW(0, L"STATIC", L"",
                                     WS_CHILD | WS_VISIBLE | SS_ICON | SS_CENTERIMAGE,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    if (HICON icon = WindowsSearchIcon()) {
        SendMessageW(tab.searchIcon, STM_SETICON, reinterpret_cast<WPARAM>(icon), 0);
    }
    tab.searchEdit = MakeEdit(tab.page, L"", IdFor(tab.key, L_SEARCH));
    SendMessageW(tab.searchEdit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"Search"));
    tab.modeLabel = MakeLabel(tab.page, L"Filter by", g_fontSmall);
    tab.modeCombo = MakeCombo(tab.page, IdFor(tab.key, L_MODE));
    for (const auto& mode : modes) ComboAdd(tab.modeCombo, mode.first);
    SendMessageW(tab.modeCombo, CB_SETCURSEL, 0, 0);

    tab.fromLabel = MakeLabel(tab.page, L"From", g_fontSmall);
    tab.fromEdit = MakeEdit(tab.page, L"", IdFor(tab.key, L_FROM));
    tab.toLabel = MakeLabel(tab.page, L"To", g_fontSmall);
    tab.toEdit = MakeEdit(tab.page, L"", IdFor(tab.key, L_TO));
    tab.clearBtn = MakeButton(tab.page, L"Clear", IdFor(tab.key, L_CLEAR));
    tab.countLabel = MakeLabel(tab.page, L"No results", g_fontSmall);

    int y = tab.key == TAB_NFAT ? 146 : 82;
    Place(tab.searchIcon, 8, y, 20, 24);
    Place(tab.searchEdit, 32, y, 244, 24);
    Place(tab.modeLabel, 286, y + 2, 48, 20);
    Place(tab.modeCombo, 338, y, 96, 200);
    Place(tab.fromLabel, 444, y + 2, 36, 20);
    Place(tab.fromEdit, 482, y, 110, 24);
    Place(tab.toLabel, 598, y + 2, 20, 20);
    Place(tab.toEdit, 620, y, 110, 24);
    Place(tab.clearBtn, 740, y, 60, 24);
    Place(tab.countLabel, 808, y + 2, 220, 20);

    SetFilterVisibility(tab);
}

void BuildVolumePage() {
    Tab& tab = g_tabs[TAB_VOLUME];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_VOLUME)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Volumes", g_fontTitle);
    tab.desc = MakeLabel(tab.page, L"Mounted Windows volumes. NTFS scanners default to all eligible mounted volumes.", g_fontSmall);
    tab.refreshBtn = MakeButton(tab.page, L"Refresh", IdFor(TAB_VOLUME, L_REFRESH));
    tab.volumeStatus = MakeLabel(tab.page, L"", g_fontSmall);
    tab.list = MakeList(tab.page, tab,
                        {L"Drive", L"Label", L"File system", L"Capacity", L"Free space", L"Status"},
                        {160, 300, 200, 250, 250, 240});
    BuildFilter(tab, -1, {0, 1}, {},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}});
    PlaceHeader(tab, tab.refreshBtn, 8, 54, 90, 26, -1);
    PlaceHeader(tab, tab.volumeStatus, 110, 58, 640, 20, -1);
}

void BuildSearchPage() {
    Tab& tab = g_tabs[TAB_SEARCH];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_SEARCH)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"File Search", g_fontTitle);
    tab.desc = MakeLabel(tab.page, L"Search selected or all mounted drives. Results remain in the application.", g_fontSmall);

    HWND targetLabel = MakeLabel(tab.page, L"Target", g_fontSmall);
    tab.targetCombo = MakeCombo(tab.page, IdFor(TAB_SEARCH, L_TARGET));
    ComboAdd(tab.targetCombo, L"All NTFS volumes");
    SendMessageW(tab.targetCombo, CB_SETCURSEL, 0, 0);
    HWND patternLabel = MakeLabel(tab.page, L"Name pattern", g_fontSmall);
    tab.patternEdit = MakeEdit(tab.page, L"*", IdFor(TAB_SEARCH, L_PATTERN));
    HWND minLabel = MakeLabel(tab.page, L"Min MB", g_fontSmall);
    tab.minEdit = MakeEdit(tab.page, L"0", IdFor(TAB_SEARCH, L_MIN));
    HWND maxLabel = MakeLabel(tab.page, L"Max MB", g_fontSmall);
    tab.maxEdit = MakeEdit(tab.page, L"0", IdFor(TAB_SEARCH, L_MAX));
    tab.allDrivesCheck = MakeCheck(tab.page, L"All drives", IdFor(TAB_SEARCH, L_ALLDRIVES), true);
    tab.regexCheck = MakeCheck(tab.page, L"Regex", IdFor(TAB_SEARCH, L_REGEX), false);
    tab.caseCheck = MakeCheck(tab.page, L"Case", IdFor(TAB_SEARCH, L_CASE), false);

    PlaceHeader(tab, targetLabel, 8, 56, 42, 20, 0);
    PlaceHeader(tab, tab.targetCombo, 52, 54, 150, 200, 0);
    PlaceHeader(tab, patternLabel, 214, 56, 78, 20, 0);
    PlaceHeader(tab, tab.patternEdit, 294, 54, 210, 24, 0);
    PlaceHeader(tab, minLabel, 516, 56, 44, 20, 0);
    PlaceHeader(tab, tab.minEdit, 562, 54, 56, 24, 0);
    PlaceHeader(tab, maxLabel, 630, 56, 44, 20, 0);
    PlaceHeader(tab, tab.maxEdit, 676, 54, 56, 24, 0);
    PlaceHeader(tab, tab.allDrivesCheck, 744, 56, 74, 20, 0);
    PlaceHeader(tab, tab.regexCheck, 824, 56, 56, 20, 0);
    PlaceHeader(tab, tab.caseCheck, 886, 56, 52, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_SEARCH, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_SEARCH, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 700, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 2, {0}, {}, {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"Path", L"Size", L"Modified", L"Attributes"},
                        {700, 110, 165, 180});
}

void BuildUsnPage() {
    Tab& tab = g_tabs[TAB_USN];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_USN)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"USN Journal", g_fontTitle);
    tab.desc = MakeLabel(tab.page, L"Reads the NTFS USN change journal natively through the supported volume control path.", g_fontSmall);

    HWND volumeLabel = MakeLabel(tab.page, L"Volume", g_fontSmall);
    tab.targetCombo = MakeCombo(tab.page, IdFor(TAB_USN, L_TARGET));
    ComboAdd(tab.targetCombo, L"All NTFS volumes");
    SendMessageW(tab.targetCombo, CB_SETCURSEL, 0, 0);
    HWND limitLabel = MakeLabel(tab.page, L"Max records", g_fontSmall);
    tab.limitEdit = MakeEdit(tab.page, L"100000", IdFor(TAB_USN, L_LIMIT));

    PlaceHeader(tab, volumeLabel, 8, 56, 48, 20, 0);
    PlaceHeader(tab, tab.targetCombo, 58, 54, 170, 200, 0);
    PlaceHeader(tab, limitLabel, 242, 56, 82, 20, 0);
    PlaceHeader(tab, tab.limitEdit, 326, 54, 100, 24, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_USN, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_USN, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 820, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 1, {2}, {3},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Action", FM_ACTION}, {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"Volume", L"Timestamp", L"Name", L"Reason", L"File reference",
                         L"Parent reference", L"Attributes", L"USN"},
                        {75, 160, 260, 260, 160, 160, 130, 120});
}

void BuildMftPage() {
    Tab& tab = g_tabs[TAB_MFT];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_MFT)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"MFT", g_fontTitle);
    tab.desc = MakeLabel(tab.page, L"Reads NTFS FILE records directly from the raw volume, including deleted records.", g_fontSmall);

    HWND volumeLabel = MakeLabel(tab.page, L"Volume", g_fontSmall);
    tab.targetCombo = MakeCombo(tab.page, IdFor(TAB_MFT, L_TARGET));
    ComboAdd(tab.targetCombo, L"All NTFS volumes");
    SendMessageW(tab.targetCombo, CB_SETCURSEL, 0, 0);
    HWND limitLabel = MakeLabel(tab.page, L"Record limit", g_fontSmall);
    tab.limitEdit = MakeEdit(tab.page, L"250000", IdFor(TAB_MFT, L_LIMIT));

    PlaceHeader(tab, volumeLabel, 8, 56, 48, 20, 0);
    PlaceHeader(tab, tab.targetCombo, 58, 54, 170, 200, 0);
    PlaceHeader(tab, limitLabel, 242, 56, 82, 20, 0);
    PlaceHeader(tab, tab.limitEdit, 326, 54, 100, 24, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_MFT, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_MFT, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 820, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 5, {2}, {4},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Action", FM_ACTION}, {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"Volume", L"Record", L"Name", L"Type", L"State", L"Created",
                         L"Modified", L"Metadata changed / accessed"},
                        {75, 90, 300, 100, 125, 165, 165, 200});
}

void BuildEventsPage() {
    Tab& tab = g_tabs[TAB_EVENTS];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_EVENTS)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Event Logs", g_fontTitle);
    tab.desc = MakeLabel(tab.page, L"Reads a selected channel or all registered Windows Event Log channels natively.", g_fontSmall);

    HWND channelLabel = MakeLabel(tab.page, L"Channel", g_fontSmall);
    tab.channelCombo = MakeCombo(tab.page, IdFor(TAB_EVENTS, L_CHANNEL));
    if (g_eventChannels.empty()) {
        g_eventChannels = {L"Application", L"Security", L"System"};
    }
    for (const std::wstring& channel : g_eventChannels) ComboAdd(tab.channelCombo, channel);
    int systemIndex = static_cast<int>(SendMessageW(tab.channelCombo, CB_FINDSTRINGEXACT,
                                                    static_cast<WPARAM>(-1),
                                                    reinterpret_cast<LPARAM>(L"System")));
    SendMessageW(tab.channelCombo, CB_SETCURSEL, systemIndex >= 0 ? systemIndex : 0, 0);

    HWND limitLabel = MakeLabel(tab.page, L"Limit / channel", g_fontSmall);
    tab.limitEdit = MakeEdit(tab.page, L"1000", IdFor(TAB_EVENTS, L_LIMIT));
    tab.allChannelsCheck = MakeCheck(tab.page, L"All registered channels",
                                      IdFor(TAB_EVENTS, L_ALLEVENTS), false);

    PlaceHeader(tab, channelLabel, 8, 56, 52, 20, 0);
    PlaceHeader(tab, tab.channelCombo, 62, 54, 300, 240, 0);
    PlaceHeader(tab, limitLabel, 376, 56, 94, 20, 0);
    PlaceHeader(tab, tab.limitEdit, 472, 54, 70, 24, 0);
    PlaceHeader(tab, tab.allChannelsCheck, 556, 56, 190, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_EVENTS, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_EVENTS, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 820, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 0, {3}, {},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"Timestamp", L"Channel", L"Event ID", L"Provider", L"Level",
                         L"Event data / computer"},
                        {170, 260, 80, 260, 80, 500});
}

void BuildEventChannelTree() {
    if (!g_ev.tree) return;
    TreeView_DeleteAllItems(g_ev.tree);
    g_ev.channels.clear();
    g_ev.selectedChannel.clear();

    const wchar_t* kWindowsLogs[] = {L"Application", L"Security", L"System", L"Setup",
                                     L"ForwardedEvents"};
    auto exists = [](const std::wstring& name) {
        for (const std::wstring& channel : g_eventChannels) {
            if (_wcsicmp(channel.c_str(), name.c_str()) == 0) return true;
        }
        return false;
    };
    auto isWindowsLog = [&](const std::wstring& name) {
        for (const wchar_t* known : kWindowsLogs) {
            if (_wcsicmp(known, name.c_str()) == 0) return true;
        }
        return false;
    };

    TVINSERTSTRUCTW insert{};
    insert.hInsertAfter = TVI_LAST;
    insert.item.mask = TVIF_TEXT | TVIF_PARAM;

    std::wstring groupWindows = L"Windows Logs";
    insert.hParent = TVI_ROOT;
    insert.item.pszText = groupWindows.data();
    insert.item.lParam = -1;
    HTREEITEM windowsRoot = TreeView_InsertItem(g_ev.tree, &insert);
    for (const wchar_t* name : kWindowsLogs) {
        if (!exists(name)) continue;
        g_ev.channels.emplace_back(name);
        std::wstring label = name;
        insert.hParent = windowsRoot;
        insert.item.pszText = label.data();
        insert.item.lParam = static_cast<LPARAM>(g_ev.channels.size() - 1);
        TreeView_InsertItem(g_ev.tree, &insert);
    }

    std::wstring groupApps = L"Applications and Services Logs";
    insert.hParent = TVI_ROOT;
    insert.item.pszText = groupApps.data();
    insert.item.lParam = -1;
    HTREEITEM appsRoot = TreeView_InsertItem(g_ev.tree, &insert);
    for (const std::wstring& name : g_eventChannels) {
        if (isWindowsLog(name)) continue;
        g_ev.channels.push_back(name);
        std::wstring label = name;
        insert.hParent = appsRoot;
        insert.item.pszText = label.data();
        insert.item.lParam = static_cast<LPARAM>(g_ev.channels.size() - 1);
        TreeView_InsertItem(g_ev.tree, &insert);
    }

    TreeView_Expand(g_ev.tree, windowsRoot, TVE_EXPAND);
    HTREEITEM first = TreeView_GetChild(g_ev.tree, windowsRoot);
    if (first) TreeView_SelectItem(g_ev.tree, first);
}

void EventViewerOnTreeSelect() {
    if (!g_ev.tree) return;
    HTREEITEM item = TreeView_GetSelection(g_ev.tree);
    if (!item) return;
    TVITEMW info{};
    info.mask = TVIF_PARAM;
    info.hItem = item;
    if (!TreeView_GetItem(g_ev.tree, &info)) return;
    if (info.lParam < 0 || static_cast<size_t>(info.lParam) >= g_ev.channels.size()) return;
    g_ev.selectedChannel = g_ev.channels[static_cast<size_t>(info.lParam)];
    if (g_tabs[TAB_EVENTVIEWER].statusLabel) {
        SetText(g_tabs[TAB_EVENTVIEWER].statusLabel, L"Channel: " + g_ev.selectedChannel);
    }
}

void EventViewerPreset(int which) {
    const wchar_t* ids = L"";
    switch (which) {
    case 0: ids = L"4624,4625,4634,4647,4648,4672,4776"; break;             // logon / logoff
    case 1: ids = L"4625,4771,4776,4740"; break;                            // logon failures
    case 2: ids = L"4720,4722,4723,4724,4725,4726,4728,4732,4738,4740,4756,4767"; break;
    case 3: ids = L"4688,4689"; break;                                      // process creation
    default: ids = L""; break;                                              // all events
    }
    if (g_ev.idsEdit) SetText(g_ev.idsEdit, ids);
    StartEventViewer();
}

void BuildEventViewerPage() {
    Tab& tab = g_tabs[TAB_EVENTVIEWER];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_EVENTVIEWER)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Event Viewer", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"Complete Windows Event Viewer: browse every registered channel on the left, filter by "
        L"Event ID, level and provider, then read each record in full. Presets cover logon / logoff, "
        L"failed logons, account changes and process creation; the detail pane shows every event-data "
        L"field plus the raw XML.", g_fontSmall);

    HWND idsLabel = MakeLabel(tab.page, L"Event IDs", g_fontSmall);
    g_ev.idsEdit = MakeEdit(tab.page, L"", IdFor(TAB_EVENTVIEWER, L_PATTERN));
    SendMessageW(g_ev.idsEdit, EM_SETCUEBANNER, TRUE,
                 reinterpret_cast<LPARAM>(L"e.g. 4624,4625,4634  (blank = all)"));
    HWND levelLabel = MakeLabel(tab.page, L"Level", g_fontSmall);
    g_ev.levelCombo = MakeCombo(tab.page, IdFor(TAB_EVENTVIEWER, L_EVLEVEL));
    const wchar_t* levels[] = {L"All levels", L"Critical", L"Error", L"Warning",
                               L"Information", L"Verbose"};
    for (const wchar_t* level : levels) ComboAdd(g_ev.levelCombo, level);
    SendMessageW(g_ev.levelCombo, CB_SETCURSEL, 0, 0);
    HWND providerLabel = MakeLabel(tab.page, L"Provider", g_fontSmall);
    g_ev.providerEdit = MakeEdit(tab.page, L"", IdFor(TAB_EVENTVIEWER, L_TARGET));
    SendMessageW(g_ev.providerEdit, EM_SETCUEBANNER, TRUE,
                 reinterpret_cast<LPARAM>(L"e.g. Microsoft-Windows-Security-Auditing"));
    HWND limitLabel = MakeLabel(tab.page, L"Limit / channel", g_fontSmall);
    g_ev.limitEdit = MakeEdit(tab.page, L"2000", IdFor(TAB_EVENTVIEWER, L_LIMIT));

    PlaceHeader(tab, idsLabel, 8, 56, 66, 20, 0);
    PlaceHeader(tab, g_ev.idsEdit, 76, 54, 210, 24, 0);
    PlaceHeader(tab, levelLabel, 296, 56, 40, 20, 0);
    PlaceHeader(tab, g_ev.levelCombo, 338, 54, 120, 200, 0);
    PlaceHeader(tab, providerLabel, 468, 56, 60, 20, 0);
    PlaceHeader(tab, g_ev.providerEdit, 530, 54, 250, 24, 0);
    PlaceHeader(tab, limitLabel, 790, 56, 96, 20, 0);
    PlaceHeader(tab, g_ev.limitEdit, 888, 54, 70, 24, 0);

    HWND logonBtn = MakeButton(tab.page, L"Logon / Logoff", IdFor(TAB_EVENTVIEWER, L_EVLOGON));
    HWND failBtn = MakeButton(tab.page, L"Logon failures", IdFor(TAB_EVENTVIEWER, L_EVFAIL));
    HWND accountBtn = MakeButton(tab.page, L"Account changes", IdFor(TAB_EVENTVIEWER, L_EVACCT));
    HWND processBtn = MakeButton(tab.page, L"Process creation", IdFor(TAB_EVENTVIEWER, L_EVPROC));
    HWND allBtn = MakeButton(tab.page, L"All events", IdFor(TAB_EVENTVIEWER, L_EVALL));
    g_ev.allCheck = MakeCheck(tab.page, L"All channels", IdFor(TAB_EVENTVIEWER, L_ALLEVENTS), false);
    PlaceHeader(tab, logonBtn, 8, 86, 120, 26, 1);
    PlaceHeader(tab, failBtn, 134, 86, 120, 26, 1);
    PlaceHeader(tab, accountBtn, 260, 86, 130, 26, 1);
    PlaceHeader(tab, processBtn, 396, 86, 130, 26, 1);
    PlaceHeader(tab, allBtn, 532, 86, 100, 26, 1);
    PlaceHeader(tab, g_ev.allCheck, 642, 90, 110, 20, 1);

    tab.startBtn = MakeButton(tab.page, L"Load", IdFor(TAB_EVENTVIEWER, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_EVENTVIEWER, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 0, {2, 5, 6}, {3, 4},
                {{L"All fields", FM_ALL}, {L"Event ID / user", FM_NAME},
                 {L"Level / provider", FM_ACTION}, {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"Timestamp", L"Channel", L"Event ID", L"Level", L"Provider", L"User",
                         L"Message / summary"},
                        {160, 180, 70, 80, 180, 160, 520});

    g_ev.tree = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | TVS_HASLINES | TVS_LINESATROOT |
                                    TVS_HASBUTTONS | TVS_SHOWSELALWAYS,
                                0, 0, 10, 10, tab.page,
                                reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdFor(TAB_EVENTVIEWER, 91))),
                                g_instance, nullptr);
    if (g_ev.tree) {
        SendMessageW(g_ev.tree, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
        TreeView_SetExtendedStyle(g_ev.tree, TVS_EX_DOUBLEBUFFER, TVS_EX_DOUBLEBUFFER);
        SetWindowTheme(g_ev.tree, L"Explorer", nullptr);
        BuildEventChannelTree();
    }

    tab.detailPane = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                         ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tab.detailPane, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontMono ? g_fontMono : g_fontSmall), TRUE);
    SetWindowTextW(tab.detailPane,
                   L"Pick a channel on the left, then click Load. Use the presets for logon / "
                   L"logoff, failed logons, account changes and process creation. Select a record "
                   L"to read every field and the raw XML.");
}

void BuildNfatPage() {
    Tab& tab = g_tabs[TAB_NFAT];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_NFAT)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Connections", g_fontTitle);
    tab.desc = MakeLabel(tab.page, L"Network Forensic Analysis Tool: connections, DNS cache, ARP neighbors and interface configuration.", g_fontSmall);

    HWND collectLabel = MakeLabel(tab.page, L"Collect", g_fontSmall);
    tab.chkTcp = MakeCheck(tab.page, L"TCP", IdFor(TAB_NFAT, L_TCP), true);
    tab.chkUdp = MakeCheck(tab.page, L"UDP", IdFor(TAB_NFAT, L_UDP), true);
    tab.chkDns = MakeCheck(tab.page, L"DNS cache", IdFor(TAB_NFAT, L_DNS), true);
    tab.chkArp = MakeCheck(tab.page, L"ARP / neighbors", IdFor(TAB_NFAT, L_ARP), true);
    tab.chkAdapters = MakeCheck(tab.page, L"Interfaces", IdFor(TAB_NFAT, L_ADAPTERS), true);
    tab.chkTraffic = MakeCheck(tab.page, L"Traffic", IdFor(TAB_NFAT, L_TRAFFIC), true);
    PlaceHeader(tab, collectLabel, 8, 56, 48, 20, 0);
    PlaceHeader(tab, tab.chkTcp, 60, 56, 58, 20, 0);
    PlaceHeader(tab, tab.chkUdp, 122, 56, 58, 20, 0);
    PlaceHeader(tab, tab.chkDns, 184, 56, 88, 20, 0);
    PlaceHeader(tab, tab.chkArp, 276, 56, 112, 20, 0);
    PlaceHeader(tab, tab.chkAdapters, 392, 56, 82, 20, 0);
    PlaceHeader(tab, tab.chkTraffic, 478, 56, 68, 20, 0);

    tab.chkRealtime = MakeCheck(tab.page, L"Realtime", IdFor(TAB_NFAT, L_REALTIME), true);
    HWND refreshLabel = MakeLabel(tab.page, L"Refresh every", g_fontSmall);
    tab.intervalCombo = MakeCombo(tab.page, IdFor(TAB_NFAT, L_INTERVAL));
    ComboAdd(tab.intervalCombo, L"1s");
    ComboAdd(tab.intervalCombo, L"2s");
    ComboAdd(tab.intervalCombo, L"5s");
    ComboAdd(tab.intervalCombo, L"10s");
    SendMessageW(tab.intervalCombo, CB_SETCURSEL, 1, 0);
    tab.chkFull = MakeCheck(tab.page,
                            L"Full lookup (reverse DNS, ASN/org, process path, user, command line, service ports)",
                            IdFor(TAB_NFAT, L_FULL), true);
    PlaceHeader(tab, tab.chkRealtime, 8, 84, 76, 20, 1);
    PlaceHeader(tab, refreshLabel, 90, 84, 88, 20, 1);
    PlaceHeader(tab, tab.intervalCombo, 180, 82, 64, 200, 1);
    PlaceHeader(tab, tab.chkFull, 258, 84, 700, 20, 1);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_NFAT, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_NFAT, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 114, 90, 26);
    Place(tab.stopBtn, 103, 114, 90, 26);
    Place(tab.statusLabel, 205, 118, 820, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 0, {2, 5}, {1},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Action", FM_ACTION}, {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"Observed", L"Layer", L"Local / host", L"Remote / address", L"State",
                         L"Process / PID", L"Detail"},
                        {140, 80, 170, 180, 95, 170, 420});
}

struct ImageViewerState {
    HWND window = nullptr;
    UINT width = 0;
    UINT height = 0;
    std::vector<BYTE> pixels;
    bool closed = false;
};

LRESULT CALLBACK ImageViewerProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<ImageViewerState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (message) {
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc{};
        GetClientRect(hwnd, &rc);
        FillRect(dc, &rc, reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
        if (state && state->width && state->height && !state->pixels.empty()) {
            BITMAPINFO bmi{};
            bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
            bmi.bmiHeader.biWidth = static_cast<LONG>(state->width);
            bmi.bmiHeader.biHeight = -static_cast<LONG>(state->height);
            bmi.bmiHeader.biPlanes = 1;
            bmi.bmiHeader.biBitCount = 32;
            bmi.bmiHeader.biCompression = BI_RGB;
            const int dw = rc.right;
            const int dh = rc.bottom;
            const double scale = std::min(static_cast<double>(dw) / state->width,
                                          static_cast<double>(dh) / state->height);
            const int w = std::max(1, static_cast<int>(state->width * scale));
            const int h = std::max(1, static_cast<int>(state->height * scale));
            SetStretchBltMode(dc, HALFTONE);
            StretchDIBits(dc, (dw - w) / 2, (dh - h) / 2, w, h, 0, 0,
                          static_cast<int>(state->width), static_cast<int>(state->height),
                          state->pixels.data(), &bmi, DIB_RGB_COLORS, SRCCOPY);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_CLOSE:
        if (state) state->closed = true;
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

bool DecodeImageWic(const std::vector<BYTE>& data, UINT& width, UINT& height,
                    std::vector<BYTE>& pixels) {
    if (data.empty()) return false;
    IWICImagingFactory* factory = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&factory)))) {
        return false;
    }
    IStream* stream = SHCreateMemStream(data.data(), static_cast<UINT>(data.size()));
    if (!stream) { factory->Release(); return false; }
    IWICBitmapDecoder* decoder = nullptr;
    IWICBitmapFrameDecode* frame = nullptr;
    IWICFormatConverter* converter = nullptr;
    bool ok = false;
    if (SUCCEEDED(factory->CreateDecoderFromStream(stream, nullptr, WICDecodeMetadataCacheOnLoad,
                                                   &decoder)) &&
        SUCCEEDED(decoder->GetFrame(0, &frame)) &&
        SUCCEEDED(factory->CreateFormatConverter(&converter)) &&
        SUCCEEDED(converter->Initialize(frame, GUID_WICPixelFormat32bppBGRA, WICBitmapDitherTypeNone,
                                        nullptr, 0.0, WICBitmapPaletteTypeCustom))) {
        UINT w = 0, h = 0;
        if (SUCCEEDED(converter->GetSize(&w, &h)) && w && h) {
            const UINT stride = w * 4;
            const UINT size = stride * h;
            pixels.resize(size);
            if (SUCCEEDED(converter->CopyPixels(nullptr, stride, size, pixels.data()))) {
                width = w;
                height = h;
                ok = true;
            }
        }
    }
    if (converter) converter->Release();
    if (frame) frame->Release();
    if (decoder) decoder->Release();
    stream->Release();
    factory->Release();
    return ok;
}

bool ShowImageViewer(const CarvedFile& file, HWND owner) {
    UINT width = 0, height = 0;
    std::vector<BYTE> pixels;
    if (!DecodeImageWic(file.data, width, height, pixels)) return false;

    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW cls{};
        cls.cbSize = sizeof(cls);
        cls.lpfnWndProc = ImageViewerProc;
        cls.hInstance = g_instance;
        cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        cls.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
        cls.lpszClassName = L"WindCheckerImage";
        RegisterClassExW(&cls);
        registered = true;
    }

    ImageViewerState state;
    state.width = width;
    state.height = height;
    state.pixels = std::move(pixels);

    RECT ownerRect{};
    GetWindowRect(owner ? owner : g_hwnd, &ownerRect);
    const int maxW = S(1000), maxH = S(760);
    const double scale = std::min(1.0, std::min(static_cast<double>(maxW) / width,
                                             static_cast<double>(maxH) / height));
    int winW = static_cast<int>(width * scale) + S(16);
    int winH = static_cast<int>(height * scale) + S(48);
    if (winW < S(320)) winW = S(320);
    if (winH < S(240)) winH = S(240);
    const int x = ownerRect.left + ((ownerRect.right - ownerRect.left) - winW) / 2;
    const int y = ownerRect.top + ((ownerRect.bottom - ownerRect.top) - winH) / 2;

    state.window = CreateWindowExW(WS_EX_DLGMODALFRAME, L"WindCheckerImage",
                                   (file.name + L"  \u00B7  " + file.type).c_str(),
                                   WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME, x, y, winW,
                                   winH, owner ? owner : g_hwnd, nullptr, g_instance, nullptr);
    if (!state.window) return false;
    SetWindowLongPtrW(state.window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&state));

    HWND disable = owner ? owner : g_hwnd;
    const bool wasEnabled = IsWindowEnabled(disable) != FALSE;
    if (wasEnabled) EnableWindow(disable, FALSE);
    ShowWindow(state.window, SW_SHOW);
    UpdateWindow(state.window);

    MSG msg{};
    while (!state.closed && GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(state.window, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    if (msg.message == WM_QUIT) PostQuitMessage(static_cast<int>(msg.wParam));
    if (IsWindow(state.window)) DestroyWindow(state.window);
    if (wasEnabled) EnableWindow(disable, TRUE);
    SetForegroundWindow(disable);
    return true;
}

struct CarvedDialogState {
    HWND window = nullptr;
    HWND list = nullptr;
    HWND status = nullptr;
    HIMAGELIST icons = nullptr;
    std::vector<CarvedFile> files;
    std::map<std::wstring, int> iconCache;
    bool closed = false;
};

std::wstring TempPathForName(const std::wstring& name) {
    wchar_t dir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, dir);
    std::wstring safe = name;
    for (wchar_t& c : safe) {
        if (c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?' || c == L'"' ||
            c == L'<' || c == L'>' || c == L'|') {
            c = L'_';
        }
    }
    if (safe.empty()) safe = L"captured.bin";
    return std::wstring(dir) + L"WindChecker_" + safe;
}

bool WriteBytesToFile(const std::wstring& path, const std::vector<BYTE>& data) {
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const BOOL ok = WriteFile(handle, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
    CloseHandle(handle);
    return ok && written == data.size();
}

bool IsImageExtension(const std::wstring& ext) {
    return ext == L".jpg" || ext == L".jpeg" || ext == L".png" || ext == L".gif" ||
           ext == L".bmp" || ext == L".webp" || ext == L".tif" || ext == L".tiff";
}

void OpenCarvedFile(const CarvedFile& file, HWND owner) {
    if (file.data.empty()) return;
    if (IsImageExtension(ToLower(file.ext)) && ShowImageViewer(file, owner)) return;
    const std::wstring temp = TempPathForName(file.name);
    if (WriteBytesToFile(temp, file.data)) {
        ShellExecuteW(owner ? owner : g_hwnd, L"open", temp.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    } else {
        MessageBoxW(g_hwnd, L"Could not stage the file for viewing.", APP_TITLE, MB_ICONERROR);
    }
}

void SaveCarvedFile(const CarvedFile& file) {
    wchar_t path[MAX_PATH] = {};
    wcsncpy_s(path, file.name.c_str(), _TRUNCATE);
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"All files\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    const std::wstring defExt = file.ext.size() > 1 ? file.ext.substr(1) : std::wstring();
    ofn.lpstrDefExt = defExt.empty() ? nullptr : defExt.c_str();
    if (!GetSaveFileNameW(&ofn)) return;
    if (WriteBytesToFile(path, file.data)) {
        MessageBoxW(g_hwnd, (L"Saved to:\n" + std::wstring(path)).c_str(), APP_TITLE,
                    MB_ICONINFORMATION);
    } else {
        MessageBoxW(g_hwnd, L"Could not write the file.", APP_TITLE, MB_ICONERROR);
    }
}

int CarvedIconIndex(CarvedDialogState& state, const std::wstring& ext) {
    auto it = state.iconCache.find(ext);
    if (it != state.iconCache.end()) return it->second;
    SHFILEINFOW info{};
    const std::wstring fake = L"file" + ext;
    int index = -1;
    if (SHGetFileInfoW(fake.c_str(), FILE_ATTRIBUTE_NORMAL, &info, sizeof(info),
                       SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES)) {
        index = ImageList_AddIcon(state.icons, info.hIcon);
        DestroyIcon(info.hIcon);
    }
    state.iconCache[ext] = index;
    return index;
}

void CarvedRefresh(CarvedDialogState& state) {
    state.files = CarvedSnapshot();
    ListView_DeleteAllItems(state.list);
    for (size_t i = 0; i < state.files.size(); ++i) {
        const CarvedFile& file = state.files[i];
        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_IMAGE;
        item.iItem = static_cast<int>(i);
        item.iImage = CarvedIconIndex(state, file.ext);
        item.pszText = const_cast<LPWSTR>(file.name.c_str());
        const int row = ListView_InsertItem(state.list, &item);
        ListView_SetItemText(state.list, row, 1, const_cast<LPWSTR>(file.type.c_str()));
        const std::wstring size = SizeText(file.size);
        ListView_SetItemText(state.list, row, 2, const_cast<LPWSTR>(size.c_str()));
        const std::wstring origin = file.origin.empty() ? L"\u2014" : file.origin;
        ListView_SetItemText(state.list, row, 3, const_cast<LPWSTR>(origin.c_str()));
        ListView_SetItemText(state.list, row, 4, const_cast<LPWSTR>(file.source.c_str()));
        const std::wstring captured = file.captured.empty() ? L"\u2014" : file.captured;
        ListView_SetItemText(state.list, row, 5, const_cast<LPWSTR>(captured.c_str()));
        ListView_SetItemText(state.list, row, 6,
                             const_cast<LPWSTR>(file.complete ? L"complete" : L"partial"));
    }
    if (state.status) {
        SetText(state.status,
                state.files.empty()
                    ? std::wstring(L"No files carved yet. Start a capture, send or receive a photo/video, "
                                   L"then press Refresh.")
                    : Format(L"%s file(s) carved from captured traffic. Double-click to open.",
                             CommaNumber(state.files.size()).c_str()));
    }
}

void LayoutCarvedDialog(CarvedDialogState& state) {
    RECT rc{};
    GetClientRect(state.window, &rc);
    const int pad = S(10);
    const int btnH = S(28);
    const int statusH = S(22);
    const int listH = rc.bottom - pad * 2 - btnH - statusH - S(8);
    MoveWindow(state.list, pad, pad, rc.right - pad * 2, listH, TRUE);
    const int y = pad + listH + S(8);
    MoveWindow(GetDlgItem(state.window, 100), pad, y, S(90), btnH, TRUE);
    MoveWindow(GetDlgItem(state.window, 101), pad + S(98), y, S(104), btnH, TRUE);
    MoveWindow(GetDlgItem(state.window, 102), pad + S(210), y, S(90), btnH, TRUE);
    MoveWindow(GetDlgItem(state.window, IDCANCEL), rc.right - pad - S(90), y, S(90), btnH, TRUE);
    MoveWindow(state.status, pad, y + btnH + S(4), rc.right - pad * 2, statusH, TRUE);
}

void AddCarvedColumn(HWND list, int index, const wchar_t* text, int width) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    column.fmt = LVCFMT_LEFT;
    column.cx = S(width);
    column.pszText = const_cast<LPWSTR>(text);
    ListView_InsertColumn(list, index, &column);
}

LRESULT CALLBACK CarvedDialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<CarvedDialogState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (message) {
    case WM_SIZE:
        if (state) LayoutCarvedDialog(*state);
        return 0;
    case WM_COMMAND: {
        const int id = LOWORD(wParam);
        if (id == IDCANCEL) {
            if (state) state->closed = true;
            return 0;
        }
        if (!state) return 0;
        const int sel = ListView_GetNextItem(state->list, -1, LVNI_SELECTED);
        if (id == 100) {
            if (sel >= 0 && sel < static_cast<int>(state->files.size()))
                OpenCarvedFile(state->files[sel], state->window);
        } else if (id == 101) {
            if (sel >= 0 && sel < static_cast<int>(state->files.size()))
                SaveCarvedFile(state->files[sel]);
        } else if (id == 102) {
            CarvedRefresh(*state);
        }
        return 0;
    }
    case WM_NOTIFY: {
        auto* header = reinterpret_cast<NMHDR*>(lParam);
        if (state && header->idFrom == 200 && header->code == NM_DBLCLK) {
            const int sel = ListView_GetNextItem(state->list, -1, LVNI_SELECTED);
            if (sel >= 0 && sel < static_cast<int>(state->files.size()))
                OpenCarvedFile(state->files[sel], state->window);
        }
        return 0;
    }
    case WM_CLOSE:
        if (state) state->closed = true;
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

void ShowCarvedFilesDialog() {
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW cls{};
        cls.cbSize = sizeof(cls);
        cls.lpfnWndProc = CarvedDialogProc;
        cls.hInstance = g_instance;
        cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        cls.lpszClassName = L"WindCheckerCarved";
        RegisterClassExW(&cls);
        registered = true;
    }

    CarvedDialogState state;
    state.files = CarvedSnapshot();

    RECT owner{};
    GetWindowRect(g_hwnd, &owner);
    const int width = S(1150);
    const int height = S(600);
    const int x = owner.left + ((owner.right - owner.left) - width) / 2;
    const int y = owner.top + ((owner.bottom - owner.top) - height) / 2;

    state.window = CreateWindowExW(
        WS_EX_DLGMODALFRAME, L"WindCheckerCarved", L"Files extracted from captured traffic",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_CLIPCHILDREN, x, y, width, height,
        g_hwnd, nullptr, g_instance, nullptr);
    if (!state.window) return;
    SetWindowLongPtrW(state.window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&state));

    state.icons = ImageList_Create(S(16), S(16), ILC_COLOR32, 8, 8);
    state.list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                 WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL |
                                     LVS_SHOWSELALWAYS,
                                 0, 0, 0, 0, state.window,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(200)), g_instance,
                                 nullptr);
    SendMessageW(state.list, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
    ListView_SetExtendedListViewStyle(state.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    ListView_SetImageList(state.list, state.icons, LVSIL_SMALL);
    SetWindowTheme(state.list, L"Explorer", nullptr);
    AddCarvedColumn(state.list, 0, L"File name", 190);
    AddCarvedColumn(state.list, 1, L"Type", 105);
    AddCarvedColumn(state.list, 2, L"Size", 70);
    AddCarvedColumn(state.list, 3, L"Origin (request / host)", 290);
    AddCarvedColumn(state.list, 4, L"Source flow", 300);
    AddCarvedColumn(state.list, 5, L"Captured", 75);
    AddCarvedColumn(state.list, 6, L"State", 70);

    const struct { int id; const wchar_t* text; } buttons[] = {
        {100, L"Open"}, {101, L"Save as\u2026"}, {102, L"Refresh"}};
    for (const auto& spec : buttons) {
        HWND button = CreateWindowExW(0, L"BUTTON", spec.text,
                                      WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0,
                                      state.window,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(spec.id)),
                                      g_instance, nullptr);
        SendMessageW(button, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontUI), TRUE);
    }
    HWND close = CreateWindowExW(0, L"BUTTON", L"Close",
                                 WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, state.window,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDCANCEL)),
                                 g_instance, nullptr);
    SendMessageW(close, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontUI), TRUE);
    state.status = MakeLabel(state.window, L"", g_fontSmall);

    CarvedRefresh(state);
    LayoutCarvedDialog(state);

    EnableWindow(g_hwnd, FALSE);
    ShowWindow(state.window, SW_SHOW);
    UpdateWindow(state.window);
    SetFocus(state.list);

    MSG msg{};
    while (!state.closed && GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(state.window, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    if (msg.message == WM_QUIT) PostQuitMessage(static_cast<int>(msg.wParam));
    if (IsWindow(state.window)) DestroyWindow(state.window);
    if (state.icons) ImageList_Destroy(state.icons);
    EnableWindow(g_hwnd, TRUE);
    SetForegroundWindow(g_hwnd);
}

void BuildPacketPage() {
    Tab& tab = g_tabs[TAB_PACKET];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_PACKET)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Packet Capture", g_fontTitle);
    tab.desc = MakeLabel(tab.page, L"Live IPv4 traffic on every adapter and loopback, captured with built-in Windows raw sockets: TCP, UDP, ICMP, ESP, fragments and full payloads. No driver and no Npcap.", g_fontSmall);

    HWND captureLabel = MakeLabel(tab.page, L"Capture", g_fontSmall);
    tab.chkPayload = MakeCheck(tab.page, L"Payload only (skip empty ACK/SYN)", IdFor(TAB_PACKET, L_PAYLOAD), true);
    tab.chkPacketFull = MakeCheck(tab.page, L"Full lookup (host, ASN, process, user)", IdFor(TAB_PACKET, L_PACKETFULL), true);
    HWND engineLabel = MakeLabel(tab.page, L"Engine: built-in raw sockets \u00B7 no Npcap \u00B7 no driver", g_fontSmall);
    PlaceHeader(tab, captureLabel, 8, 56, 52, 20, 0);
    PlaceHeader(tab, tab.chkPayload, 64, 56, 210, 20, 0);
    PlaceHeader(tab, tab.chkPacketFull, 280, 56, 230, 20, 0);
    PlaceHeader(tab, engineLabel, 520, 56, 420, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Start", IdFor(TAB_PACKET, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_PACKET, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 820, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 0, {4, 5}, {2, 3},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Action", FM_ACTION}, {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"Observed", L"Interface", L"Direction", L"Protocol / app", L"Source", L"Destination",
                         L"Size", L"Process / lookup", L"Payload (what is actually sent / received)"},
                        {145, 130, 68, 250, 175, 175, 62, 250, 600});
}

void BuildPrefetchPage() {
    Tab& tab = g_tabs[TAB_PREFETCH];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_PREFETCH)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Prefetch & Recent", g_fontTitle);
    tab.desc = MakeLabel(tab.page, L"Decompresses Prefetch files and lists Recent shortcuts and Jump Lists in one result set.", g_fontSmall);

    wchar_t systemRoot[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", systemRoot, MAX_PATH);
    std::wstring defaultFolder = std::wstring(systemRoot[0] ? systemRoot : L"C:\\Windows") + L"\\Prefetch";

    HWND folderLabel = MakeLabel(tab.page, L"Folder", g_fontSmall);
    tab.folderEdit = MakeEdit(tab.page, defaultFolder, IdFor(TAB_PREFETCH, L_FOLDER));
    HWND maxLabel = MakeLabel(tab.page, L"Max files", g_fontSmall);
    tab.maxFilesEdit = MakeEdit(tab.page, L"0", IdFor(TAB_PREFETCH, L_MAXFILES));
    HWND allLabel = MakeLabel(tab.page, L"0 = all", g_fontSmall);
    tab.detailsCheck = MakeCheck(tab.page, L"Prefetch details",
                                  IdFor(TAB_PREFETCH, L_DETAILS), true);
    tab.recentCheck = MakeCheck(tab.page, L"Recent shortcuts & Jump Lists",
                                 IdFor(TAB_PREFETCH, L_RECENT), true);

    PlaceHeader(tab, folderLabel, 8, 56, 48, 20, 0);
    PlaceHeader(tab, tab.folderEdit, 58, 54, 330, 24, 0);
    PlaceHeader(tab, maxLabel, 400, 56, 62, 20, 0);
    PlaceHeader(tab, tab.maxFilesEdit, 464, 54, 60, 24, 0);
    PlaceHeader(tab, allLabel, 532, 56, 52, 20, 0);
    PlaceHeader(tab, tab.detailsCheck, 596, 56, 122, 20, 0);
    PlaceHeader(tab, tab.recentCheck, 730, 56, 220, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_PREFETCH, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_PREFETCH, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 820, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 0, {2}, {3},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Action", FM_ACTION}, {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"Artifact modified", L"Source", L"Artifact", L"Category",
                         L"Field / detail", L"Value / path"},
                        {150, 90, 220, 140, 300, 700});
}

void StringsOpenHex() {
    Tab& tab = g_tabs[TAB_STRINGS];
    if (!tab.list) return;
    const int item = ListView_GetNextItem(tab.list, -1, LVNI_SELECTED);
    if (item < 0 || static_cast<size_t>(item) >= tab.displayed.size()) {
        SetText(g_status, L"Select a string row first.");
        return;
    }
    const size_t record = tab.displayed[static_cast<size_t>(item)];
    if (record >= tab.records.size()) return;
    const Row& row = tab.records[record];
    if (row.size() < 2) return;
    const uint64_t offset = wcstoull(row[1].c_str(), nullptr, 0);
    ShowHexVolume(row[0], offset);
}

void BuildStringsPage() {
    Tab& tab = g_tabs[TAB_STRINGS];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_STRINGS)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Disk Strings", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"Full dump of ASCII and UTF-16LE strings from raw NTFS volumes, with length and the bytes "
        L"around each hit. Double-click a row (or press Hex viewer) to jump to that offset, read the "
        L"surrounding bytes and use the automatic string table for the window.",
        g_fontSmall);

    HWND volumeLabel = MakeLabel(tab.page, L"Volume", g_fontSmall);
    tab.targetCombo = MakeCombo(tab.page, IdFor(TAB_STRINGS, L_TARGET));
    ComboAdd(tab.targetCombo, L"All NTFS volumes");
    SendMessageW(tab.targetCombo, CB_SETCURSEL, 0, 0);
    HWND minLabel = MakeLabel(tab.page, L"Min length", g_fontSmall);
    tab.minLengthEdit = MakeEdit(tab.page, L"4", IdFor(TAB_STRINGS, L_MINLEN));
    HWND limitLabel = MakeLabel(tab.page, L"Limit MB", g_fontSmall);
    tab.limitMbEdit = MakeEdit(tab.page, L"1024", IdFor(TAB_STRINGS, L_LIMITMB));
    tab.utf16Check = MakeCheck(tab.page, L"UTF-16", IdFor(TAB_STRINGS, L_UTF16), true);
    tab.asciiCheck = MakeCheck(tab.page, L"ASCII", IdFor(TAB_STRINGS, L_ASCII), true);
    tab.fullDiskCheck = MakeCheck(tab.page, L"Full disk", IdFor(TAB_STRINGS, L_FULLDISK), true);

    PlaceHeader(tab, volumeLabel, 8, 56, 48, 20, 0);
    PlaceHeader(tab, tab.targetCombo, 58, 54, 170, 200, 0);
    PlaceHeader(tab, minLabel, 242, 56, 70, 20, 0);
    PlaceHeader(tab, tab.minLengthEdit, 314, 54, 52, 24, 0);
    PlaceHeader(tab, limitLabel, 380, 56, 58, 20, 0);
    PlaceHeader(tab, tab.limitMbEdit, 440, 54, 64, 24, 0);
    PlaceHeader(tab, tab.utf16Check, 518, 56, 72, 20, 0);
    PlaceHeader(tab, tab.asciiCheck, 594, 56, 66, 20, 0);
    PlaceHeader(tab, tab.fullDiskCheck, 664, 56, 92, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_STRINGS, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_STRINGS, L_STOP));
    HWND hexBtn = MakeButton(tab.page, L"Hex viewer", IdFor(TAB_STRINGS, L_HEXVIEW));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    PlaceHeader(tab, hexBtn, 198, 86, 110, 26, -1);
    Place(tab.statusLabel, 318, 90, 740, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, -1, {4}, {2},
                {{L"All fields", FM_ALL}, {L"String", FM_NAME}, {L"Encoding", FM_ACTION}});
    tab.list = MakeList(tab.page, tab,
                        {L"Volume", L"Offset", L"Encoding", L"Length", L"String", L"Context"},
                        {70, 150, 90, 70, 620, 520});
}

void BuildPowerShellPage() {
    Tab& tab = g_tabs[TAB_POWERSHELL];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_POWERSHELL)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"PowerShell History", g_fontTitle);
    tab.desc = MakeLabel(tab.page, L"Every command previously typed into Windows PowerShell and PowerShell 7, read from the PSReadLine ConsoleHost_history.txt files.", g_fontSmall);

    HWND scopeLabel = MakeLabel(tab.page, L"Scope", g_fontSmall);
    tab.allUsersCheck = MakeCheck(tab.page, L"All local user profiles",
                                  IdFor(TAB_POWERSHELL, L_ALLUSERS), true);
    tab.systemProfileCheck = MakeCheck(tab.page, L"SYSTEM profile",
                                       IdFor(TAB_POWERSHELL, L_SYSTEMPROFILE), true);
    HWND noteLabel = MakeLabel(tab.page, L"One row per command, oldest first within each history file.",
                               g_fontSmall);

    PlaceHeader(tab, scopeLabel, 8, 56, 44, 20, 0);
    PlaceHeader(tab, tab.allUsersCheck, 56, 56, 180, 20, 0);
    PlaceHeader(tab, tab.systemProfileCheck, 246, 56, 150, 20, 0);
    PlaceHeader(tab, noteLabel, 410, 56, 560, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_POWERSHELL, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_POWERSHELL, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 820, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 0, {1, 2, 4}, {2},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Action", FM_ACTION}, {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"File modified", L"User", L"Shell", L"Line", L"Command"},
                        {150, 150, 160, 60, 1100});
}

void BuildProcessPage() {
    Tab& tab = g_tabs[TAB_PROCESS];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_PROCESS)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Processes", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"Live process tree with the integrity level and elevation state of every process. Expand a process to see its running scripts, hosted services and loaded DLLs; kernel drivers sit in their own group at the bottom. Filter by privilege to isolate elevated or low-integrity processes.",
        g_fontSmall);

    HWND detailLabel = MakeLabel(tab.page, L"Include", g_fontSmall);
    tab.modulesCheck = MakeCheck(tab.page, L"Loaded DLLs", IdFor(TAB_PROCESS, L_MODULES), true);
    tab.servicesCheck = MakeCheck(tab.page, L"Hosted services", IdFor(TAB_PROCESS, L_SERVICES), true);
    g_procDetailsBtn = CreateWindowExW(0, L"BUTTON", L"Details",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                           BS_AUTOCHECKBOX | BS_PUSHLIKE,
                                       0, 0, 10, 10, tab.page,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(
                                           IdFor(TAB_PROCESS, L_PROCDETAILS))),
                                       g_instance, nullptr);
    SendMessageW(g_procDetailsBtn, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontUI), TRUE);
    g_procMemoryBtn = CreateWindowExW(0, L"BUTTON", L"Memory",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                          BS_AUTOCHECKBOX | BS_PUSHLIKE,
                                      0, 0, 10, 10, tab.page,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(
                                          IdFor(TAB_PROCESS, L_PROCMEMORY))),
                                      g_instance, nullptr);
    SendMessageW(g_procMemoryBtn, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontUI), TRUE);
    g_procMemAllCheck = MakeCheck(tab.page, L"Include reserved", IdFor(TAB_PROCESS, L_MEMALL), false);

    PlaceHeader(tab, detailLabel, 8, 56, 50, 20, 0);
    PlaceHeader(tab, tab.modulesCheck, 62, 56, 120, 20, 0);
    PlaceHeader(tab, tab.servicesCheck, 186, 56, 150, 20, 0);
    PlaceHeader(tab, g_procDetailsBtn, 348, 54, 80, 26, 0);
    PlaceHeader(tab, g_procMemoryBtn, 432, 54, 90, 26, 0);
    PlaceHeader(tab, g_procMemAllCheck, 530, 56, 150, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_PROCESS, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_PROCESS, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 900, 20);
    EnableWindow(tab.stopBtn, FALSE);

    static const wchar_t* kMemoryButtons[6] = {L"Modules", L"Threads", L"Handles",
                                               L"Heaps", L"Map", L"Dump"};
    for (int i = 0; i < 6; ++i) {
        int local = i == 0 ? L_MEMMODULES : i == 1 ? L_MEMTHREADS : i == 2 ? L_MEMHANDLES
                  : i == 3 ? L_MEMHEAPS : i == 4 ? L_MEMMAP : L_MEMDUMP;
        g_procMemButtons[i] = MakeButton(tab.page, kMemoryButtons[i], IdFor(TAB_PROCESS, local));
        PlaceHeader(tab, g_procMemButtons[i], 535 + i * 68, 86, 64, 26, -1);
    }

    BuildFilter(tab, 4, {2, 5, 6, 8}, {3, 2},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Action", FM_ACTION},
                 {L"Privilege", FM_PRIV}, {L"Date", FM_DATE}});

    tab.tree = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_HSCROLL | TVS_HASLINES |
                                   TVS_LINESATROOT | TVS_HASBUTTONS | TVS_SHOWSELALWAYS,
                               0, 0, 10, 10, tab.page,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdFor(TAB_PROCESS, 90))),
                               g_instance, nullptr);
    SendMessageW(tab.tree, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
    SendMessageW(tab.tree, TVM_SETEXTENDEDSTYLE, TVS_EX_DOUBLEBUFFER, TVS_EX_DOUBLEBUFFER);
    SetWindowTheme(tab.tree, L"Explorer", nullptr);
    SHFILEINFOW shellInfo{};
    HIMAGELIST images = reinterpret_cast<HIMAGELIST>(
        SHGetFileInfoW(L"C:\\", 0, &shellInfo, sizeof(shellInfo),
                       SHGFI_SYSICONINDEX | SHGFI_SMALLICON));
    if (images) TreeView_SetImageList(tab.tree, images, TVSIL_NORMAL);

    tab.detailPane = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                         ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tab.detailPane, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontMono ? g_fontMono : g_fontSmall), TRUE);
    SetWindowTextW(tab.detailPane, L"Run a scan, then select a process in the tree to inspect it.");

    g_memory.info = MakeLabel(tab.page, L"Select a process to walk its memory.", g_fontSmall);
    g_memory.list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                    WS_CHILD | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP,
                                    0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(g_memory.list, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
    ListView_SetExtendedListViewStyle(g_memory.list,
                                      LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    SetWindowTheme(g_memory.list, L"Explorer", nullptr);

    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    column.fmt = LVCFMT_LEFT;
    auto appendColumn = [&](const wchar_t* name, int width) {
        column.pszText = const_cast<LPWSTR>(name);
        column.cx = S(width);
        int index = Header_GetItemCount(ListView_GetHeader(g_memory.list));
        ListView_InsertColumn(g_memory.list, index, &column);
    };
    appendColumn(L"Base address", 94);
    appendColumn(L"Size", 64);
    appendColumn(L"Type", 58);
    appendColumn(L"State", 58);
    appendColumn(L"Protect", 128);
    appendColumn(L"Alloc base", 86);
    appendColumn(L"Module", 114);

    tab.headers = {L"PID", L"Parent", L"Tree (process)", L"User", L"Started",
                   L"Executable path", L"Command line", L"Working set", L"Privilege"};
    tab.baseWidths = {62, 160, 340, 170, 150, 430, 620, 110, 130};

    SetProcessMemoryMode(false);
}

void UpdateServiceDetail(int item) {
    Tab& tab = g_tabs[TAB_SERVICES];
    if (!tab.detailPane) return;
    if (item < 0 || static_cast<size_t>(item) >= tab.displayed.size()) return;
    const size_t record = tab.displayed[static_cast<size_t>(item)];
    if (record >= tab.records.size()) return;
    std::wstring text = record < tab.details.size() ? tab.details[record] : L"";
    if (text.empty()) text = BuildRowDetailAt(tab, record, item);
    SetWindowTextW(tab.detailPane, text.c_str());
    SendMessageW(tab.detailPane, EM_SETSEL, 0, 0);
    SendMessageW(tab.detailPane, EM_SCROLLCARET, 0, 0);
}

void ServiceSignature() {
    Tab& tab = g_tabs[TAB_SERVICES];
    int item = ListView_GetNextItem(tab.list, -1, LVNI_SELECTED);
    if (item < 0 || static_cast<size_t>(item) >= tab.displayed.size()) {
        MessageBoxW(g_hwnd, L"Select a service first.", APP_TITLE, MB_ICONINFORMATION);
        return;
    }
    const size_t record = tab.displayed[static_cast<size_t>(item)];
    if (record >= tab.records.size()) return;
    const Row& row = tab.records[record];
    std::wstring path = row.size() > 8 ? row[8] : L"";
    if (path.empty() || path == L"-" || GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(g_hwnd, L"The service binary could not be located on disk.",
                    APP_TITLE, MB_ICONINFORMATION);
        return;
    }
    ShowTextDialog(L"Signature \u2014 " + PathFileName(path),
                   L"Embedded Authenticode and catalog signatures are both checked, including the full certificate chain.",
                   CertificateReport(path));
}

void StartServices() {
    Tab& tab = g_tabs[TAB_SERVICES];
    if (tab.running) return;
    ServiceConfig config;
    config.drivers = IsChecked(tab.svcDriversCheck);
    config.runningOnly = IsChecked(tab.svcRunningCheck);
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunServiceViewer(sink, stop, config);
    });
}

void BuildServicesPage() {
    Tab& tab = g_tabs[TAB_SERVICES];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_SERVICES)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Services", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"Every service and driver in the Service Control Manager. Select one for its configuration, hosting process, dependencies, recovery actions, hardening, triggers and security descriptor.",
        g_fontSmall);

    HWND includeLabel = MakeLabel(tab.page, L"Include", g_fontSmall);
    tab.svcDriversCheck = MakeCheck(tab.page, L"Drivers", IdFor(TAB_SERVICES, L_SVCDRIVERS), true);
    tab.svcRunningCheck = MakeCheck(tab.page, L"Running only", IdFor(TAB_SERVICES, L_SVCRUNNING), false);
    HWND signBtn = MakeButton(tab.page, L"Signature\u2026", IdFor(TAB_SERVICES, L_SVCSIGN));

    PlaceHeader(tab, includeLabel, 8, 56, 50, 20, 0);
    PlaceHeader(tab, tab.svcDriversCheck, 62, 56, 90, 20, 0);
    PlaceHeader(tab, tab.svcRunningCheck, 158, 56, 120, 20, 0);
    PlaceHeader(tab, signBtn, 288, 54, 110, 26, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_SERVICES, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_SERVICES, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 560, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, -1, {0, 1, 8}, {3, 4},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"State", FM_ACTION}});
    tab.list = MakeList(tab.page, tab,
                        {L"Service name", L"Display name", L"Type", L"State", L"Start",
                         L"Account", L"PID", L"Process", L"Image path", L"Description"},
                        {150, 200, 130, 70, 60, 130, 50, 110, 280, 320});

    tab.detailPane = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                         ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tab.detailPane, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontMono ? g_fontMono : g_fontSmall), TRUE);
    SetWindowTextW(tab.detailPane, L"Run a scan, then select a service to inspect it.");
}

void UpdateComputerInfoDetail(int item) {
    Tab& tab = g_tabs[TAB_COMPUTERINFO];
    if (!tab.detailPane) return;
    if (item < 0 || static_cast<size_t>(item) >= tab.displayed.size()) return;
    const size_t record = tab.displayed[static_cast<size_t>(item)];
    if (record >= tab.records.size()) return;
    std::wstring text = record < tab.details.size() ? tab.details[record] : L"";
    if (text.empty()) text = BuildRowDetailAt(tab, record, item);
    SetWindowTextW(tab.detailPane, text.c_str());
    SendMessageW(tab.detailPane, EM_SETSEL, 0, 0);
    SendMessageW(tab.detailPane, EM_SCROLLCARET, 0, 0);
}

void StartComputerInfo() {
    Tab& tab = g_tabs[TAB_COMPUTERINFO];
    if (tab.running) return;
    StartWork(tab, [](const Sink& sink, std::atomic<bool>& stop) {
        RunComputerInfo(sink, stop);
    });
}

void BuildComputerInfoPage() {
    Tab& tab = g_tabs[TAB_COMPUTERINFO];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_COMPUTERINFO)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Computer Info", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"Deep inventory of this machine: identity and HWID, Windows build, firmware and SMBIOS, processor and memory modules, storage, graphics, network, security posture, accounts, environment and installed software. Select any item for its full detail.",
        g_fontSmall);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_COMPUTERINFO, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_COMPUTERINFO, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 780, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, -1, {0, 1}, {2},
                {{L"All fields", FM_ALL}, {L"Section or property", FM_NAME}, {L"Value", FM_ACTION}});
    tab.list = MakeList(tab.page, tab, {L"Section", L"Property", L"Value"}, {150, 260, 720});

    tab.detailPane = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                         ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tab.detailPane, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontMono ? g_fontMono : g_fontSmall), TRUE);
    SetWindowTextW(tab.detailPane, L"Run a scan, then select an item to inspect it.");
}

void UpdateStoredDetail(Tab& tab, int item) {
    if (!tab.detailPane) return;
    if (item < 0 || static_cast<size_t>(item) >= tab.displayed.size()) return;
    const size_t record = tab.displayed[static_cast<size_t>(item)];
    if (record >= tab.records.size()) return;
    std::wstring text = record < tab.details.size() ? tab.details[record] : L"";
    if (text.empty()) text = BuildRowDetailAt(tab, record, item);
    SetWindowTextW(tab.detailPane, text.c_str());
    SendMessageW(tab.detailPane, EM_SETSEL, 0, 0);
    SendMessageW(tab.detailPane, EM_SCROLLCARET, 0, 0);
}

void StartSrum() {
    Tab& tab = g_tabs[TAB_SRUM];
    if (tab.running) return;
    StartWork(tab, [](const Sink& sink, std::atomic<bool>& stop) {
        RunSrumExplorer(sink, stop);
    });
}

void BuildSrumPage() {
    Tab& tab = g_tabs[TAB_SRUM];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_SRUM)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"SRUM", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"System Resource Usage Monitor: the SRUM provider list from the registry plus every table and "
        L"record inside srudb.dat, with application, user, byte counts and per-record column dumps.",
        g_fontSmall);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_SRUM, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_SRUM, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 780, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, -1, {0, 2, 3}, {4},
                {{L"All fields", FM_ALL}, {L"Table or application", FM_NAME}, {L"Record", FM_ACTION}});
    tab.list = MakeList(tab.page, tab,
                        {L"Table", L"Time", L"Application", L"User", L"Record"},
                        {190, 150, 380, 200, 420});

    tab.detailPane = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                         ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tab.detailPane, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontMono ? g_fontMono : g_fontSmall), TRUE);
    SetWindowTextW(tab.detailPane, L"Run a scan, then select a record to inspect every column.");
}

void StartAmCache() {
    Tab& tab = g_tabs[TAB_AMCACHE];
    if (tab.running) return;
    StartWork(tab, [](const Sink& sink, std::atomic<bool>& stop) {
        RunAmCacheViewer(sink, stop);
    });
}

void BuildAmCachePage() {
    Tab& tab = g_tabs[TAB_AMCACHE];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_AMCACHE)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"AmCache", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"Amcache.hve and RecentFileCache.bcf: every inventory category with file name, version, publisher, "
        L"full path, install timestamp and file hash, plus the raw values behind each entry.",
        g_fontSmall);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_AMCACHE, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_AMCACHE, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 780, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, -1, {0, 1, 3, 4}, {6},
                {{L"All fields", FM_ALL}, {L"Category, name or path", FM_NAME}, {L"SHA-1", FM_ACTION}});
    tab.list = MakeList(tab.page, tab,
                        {L"Category", L"Name", L"Version", L"Publisher", L"Path", L"Timestamp", L"Hash / file id"},
                        {150, 260, 120, 200, 420, 140, 260});

    tab.detailPane = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                         ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tab.detailPane, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontMono ? g_fontMono : g_fontSmall), TRUE);
    SetWindowTextW(tab.detailPane, L"Run a scan, then select an entry to inspect all of its values.");
}


static fc::RegView ForensicLiveView(int tabKey) {
    fc::RegView view;
    if (tabKey == TAB_USB || tabKey == TAB_BAMDAM) {
        view = fc::LiveHklm();
        view.prefix = L"SYSTEM";
        view.rootLabel = L"HKLM\\SYSTEM (live)";
    } else {
        view = fc::LiveHkcu();
        view.prefix = L"";
        view.rootLabel = L"HKCU (live)";
    }
    return view;
}

static void BuildForensicPage(int tabKey, const wchar_t* title, const wchar_t* desc,
                             const std::vector<std::wstring>& headers,
                             const std::vector<int>& widths,
                             const std::vector<std::pair<std::wstring, FilterKind>>& modes,
                             const std::vector<int>& nameColumns,
                             const std::vector<int>& actionColumns, int dateColumn) {
    Tab& tab = g_tabs[tabKey];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(tabKey)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, title, g_fontTitle);
    tab.desc = MakeLabel(tab.page, desc, g_fontSmall);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(tabKey, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(tabKey, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 80, 26);
    Place(tab.statusLabel, 205, 90, 700, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, dateColumn, nameColumns, actionColumns, modes);
    tab.list = MakeList(tab.page, tab, headers, widths);

    tab.detailPane = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                         ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tab.detailPane, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontMono ? g_fontMono : g_fontSmall), TRUE);
    SetWindowTextW(tab.detailPane, L"Click Scan to read this artifact from the live system, then select a record to inspect every field.");
}

void BuildUsbPage() {
    BuildForensicPage(TAB_USB, L"USB Device History",
        L"Every USB device ever attached (storage, hubs and peripherals): friendly name, vendor and "
        L"product, VID/PID, serial, assigned drive letter, the first-install / last-connect / last-"
        L"removal timestamps from the device properties, and whether the device is currently present. "
        L"Modelled on USBDeview.",
        {L"Device", L"Vendor", L"Product", L"VID", L"PID", L"Serial", L"Rev", L"Drive / Vol",
         L"First install", L"Last connect", L"Last removal", L"Connected"},
        {260, 150, 170, 70, 70, 140, 70, 120, 180, 180, 180, 80},
        {{L"All fields", FM_ALL}, {L"Device", FM_NAME},
         {L"Vendor / product / serial / IDs", FM_ACTION}, {L"Date", FM_DATE}},
        {0}, {1, 2, 3, 4, 5, 7}, 9);
}

void BuildBamDamPage() {
    BuildForensicPage(TAB_BAMDAM, L"BAM / DAM",
        L"Background Activity Moderator and Desktop Activity Moderator: every executable per user with "
        L"the last-run timestamp decoded from the 8-byte FILETIME blob, plus the account SID.",
        {L"Executable", L"Account", L"Last run", L"Source", L""},
        {420, 200, 200, 80, 40},
        {{L"All fields", FM_ALL}, {L"Executable", FM_NAME}, {L"Account", FM_ACTION}},
        {0, 1}, {}, -1);
}

void BuildUserAssistPage() {
    BuildForensicPage(TAB_USERASSIST, L"UserAssist",
        L"NTUSER.DAT Explorer\\UserAssist: program names ROT-13 decoded, run count and last-execution "
        L"timestamp per GUID bag. Scans the live HKCU UserAssist keys.",
        {L"Program", L"Run count", L"Last exec", L"GUID", L""},
        {420, 100, 200, 260, 40},
        {{L"All fields", FM_ALL}, {L"Program", FM_NAME}, {L"GUID", FM_ACTION}},
        {0, 3}, {}, -1);
}

void BuildRecentDocsPage() {
    BuildForensicPage(TAB_RECENTDOCS, L"RecentDocs",
        L"Explorer\\RecentDocs: the most-recently-used documents per extension, ordered by the MRUListEx "
        L"binary index and resolved from their PIDL blobs. Scans the live HKCU RecentDocs keys.",
        {L"Type", L"Path", L"MRU", L"", L""},
        {120, 600, 80, 40, 40},
        {{L"All fields", FM_ALL}, {L"Type or path", FM_NAME}},
        {0, 1}, {}, -1);
}

void BuildMruPage() {
    BuildForensicPage(TAB_MRU, L"MRU",
        L"Explorer RunMRU plus ComDlg32 OpenSavePidlMRU / LastVisitedPidlMRU: most-recently-used commands "
        L"and file-dialog paths, ordered by MRUList(MRUListEx) and resolved from PIDL blobs.",
        {L"Type", L"Extension", L"Path / command", L"MRU", L""},
        {120, 120, 560, 80, 40},
        {{L"All fields", FM_ALL}, {L"Type or path", FM_NAME}},
        {0, 1, 2}, {}, -1);
}

static void StartForensicScan(int tabKey) {
    Tab& tab = g_tabs[tabKey];
    if (tab.running) return;
    fc::RegView view = ForensicLiveView(tabKey);
    StartWork(tab, [tabKey, view](const Sink& sink, std::atomic<bool>& stop) {
        switch (tabKey) {
        case TAB_USB: fc::RunUsbHistory(sink, stop, view); break;
        case TAB_BAMDAM: fc::RunBamDam(sink, stop, view); break;
        case TAB_USERASSIST: fc::RunUserAssist(sink, stop, view); break;
        case TAB_RECENTDOCS: fc::RunRecentDocs(sink, stop, view); break;
        case TAB_MRU: fc::RunMru(sink, stop, view); break;
        default: break;
        }
    });
}

void BuildWmiPage() {
    BuildForensicPage(TAB_WMI, L"WMI Event Subscriptions",
        L"Permanent WMI subscriptions from ROOT\\SUBSCRIPTION: event filters, the consumers they feed "
        L"(command line, ActiveScript, log file, NT event log, SMTP) and every filter-to-consumer "
        L"binding. This is a classic fileless persistence mechanism.",
        {L"Kind", L"Name", L"Filter / consumer detail", L"Namespace / scope", L"Source"},
        {150, 190, 330, 240, 260},
        {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Kind or detail", FM_ACTION}},
        {1}, {0, 2}, -1);
}

void BuildNetworkArtifactsPage() {
    BuildForensicPage(TAB_NETART, L"Network Artifacts",
        L"Network history that survives a reboot: the DNS client cache, the ARP / neighbour table, "
        L"WLAN profiles stored by WlanSvc under ProgramData, and the NetworkList connection history "
        L"with first and last connect timestamps.",
        {L"Type", L"Name", L"Detail", L"Address / value", L"Last seen"},
        {150, 280, 240, 320, 180},
        {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Type or detail", FM_ACTION}},
        {1}, {0, 2}, -1);
}

void BuildDefenderPage() {
    BuildForensicPage(TAB_DEFENDER, L"Defender Logs",
        L"Windows Defender activity: detections and actions from the Defender operational event log, "
        L"plus the support logs and trace files in ProgramData\\Microsoft\\Windows Defender\\Support.",
        {L"Time", L"Source", L"Event", L"Threat / what happened", L"Action / target"},
        {150, 150, 100, 320, 360},
        {{L"All fields", FM_ALL}, {L"Threat or message", FM_NAME}, {L"Kind", FM_ACTION},
         {L"Date", FM_DATE}},
        {3}, {2}, 0);
}

void BuildRdpPage() {
    BuildForensicPage(TAB_RDP, L"Remote Access (RDP)",
        L"Terminal Services event logs: LocalSessionManager and RemoteConnectionManager operational "
        L"channels. Shows every RDP logon, reconnect, disconnect and session state change.",
        {L"Time", L"Channel", L"Event ID", L"Provider", L"Level",
         L"What happened \u00B7 user \u00B7 address"},
        {170, 220, 80, 240, 70, 620},
        {{L"All fields", FM_ALL}, {L"Channel or provider", FM_NAME}, {L"Event ID", FM_ACTION},
         {L"Date", FM_DATE}},
        {1, 3}, {2}, 0);
}

void BuildActivitiesPage() {
    BuildForensicPage(TAB_ACTIVITIES, L"Activities Cache",
        L"Windows Timeline database (%LocalAppData%\\ConnectedDevicesPlatform\\*\\ActivitiesCache.db). "
        L"Every recorded user activity with its application, activity type, start and end time and the "
        L"JSON payload that carries the displayed title and description.",
        {L"Start", L"Application", L"Detail", L"End", L"Type", L"Source"},
        {140, 200, 300, 140, 60, 140},
        {{L"All fields", FM_ALL}, {L"Application or detail", FM_NAME}, {L"Activity type", FM_ACTION},
         {L"Date", FM_DATE}},
        {1, 2}, {4}, 0);
}

void BuildCrashPage() {
    BuildForensicPage(TAB_CRASH, L"Crash Dumps",
        L"Crash and kernel dumps: Windows\\Minidump, Windows\\MEMORY.DMP, per-user CrashDumps and "
        L"LiveKernelReports. Each minidump header is parsed for its crash timestamp and primary module.",
        {L"Dump file", L"Size", L"Written", L"Kind", L"Crash time", L"Primary module"},
        {220, 90, 140, 110, 140, 200},
        {{L"All fields", FM_ALL}, {L"File or module", FM_NAME}, {L"Dump kind", FM_ACTION},
         {L"Date", FM_DATE}},
        {0, 5}, {3}, 2);
}

void BuildWpnPage() {
    BuildForensicPage(TAB_WPN, L"Notifications",
        L"The Windows notification store for this user (wpndatabase.db): every toast notification "
        L"with the app that posted it, its title and body text, payload type and whether it is still "
        L"active or has expired, followed by every app registered to raise notifications. Select a "
        L"row for the full payload, buttons and raw database columns.",
        {L"Time", L"App", L"Title", L"Body", L"Type", L"Status"},
        {150, 220, 280, 460, 150, 90},
        {{L"All fields", FM_ALL}, {L"App or title", FM_NAME}, {L"Type", FM_ACTION},
         {L"Date", FM_DATE}},
        {1, 2}, {4}, 0);
}

void StartThumbcache() {
    Tab& tab = g_tabs[TAB_THUMBNAIL];
    if (tab.running) return;
    ThumbSetBitmap(nullptr);
    StartWork(tab, [](const Sink& sink, std::atomic<bool>& stop) {
        RunThumbcacheScan(sink, stop);
    });
}

void StartWmiSubscriptions() {
    Tab& tab = g_tabs[TAB_WMI];
    if (tab.running) return;
    StartWork(tab, [](const Sink& sink, std::atomic<bool>& stop) {
        RunWmiSubscriptions(sink, stop);
    });
}

void StartNetworkArtifacts() {
    Tab& tab = g_tabs[TAB_NETART];
    if (tab.running) return;
    StartWork(tab, [](const Sink& sink, std::atomic<bool>& stop) {
        RunNetworkArtifacts(sink, stop);
    });
}

void StartDefenderLogs() {
    Tab& tab = g_tabs[TAB_DEFENDER];
    if (tab.running) return;
    StartWork(tab, [](const Sink& sink, std::atomic<bool>& stop) {
        RunDefenderLogs(sink, stop);
    });
}

void StartActivitiesCache() {
    Tab& tab = g_tabs[TAB_ACTIVITIES];
    if (tab.running) return;
    StartWork(tab, [](const Sink& sink, std::atomic<bool>& stop) {
        RunActivitiesCache(sink, stop);
    });
}

void StartCrashDumps() {
    Tab& tab = g_tabs[TAB_CRASH];
    if (tab.running) return;
    StartWork(tab, [](const Sink& sink, std::atomic<bool>& stop) {
        RunCrashDumps(sink, stop);
    });
}

void StartNotificationDatabase() {
    Tab& tab = g_tabs[TAB_WPN];
    if (tab.running) return;
    StartWork(tab, [](const Sink& sink, std::atomic<bool>& stop) {
        RunNotificationDatabase(sink, stop);
    });
}

void StartEventTab(int tabKey) {
    Tab& tab = g_tabs[tabKey];
    if (tab.running) return;
    EventsConfig config;
    config.channels = {
        L"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        L"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"};
    config.limitPerChannel = 3000;
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunEventLogs(sink, stop, config);
    });
}

void BuildStartupPage() {
    Tab& tab = g_tabs[TAB_STARTUP];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_STARTUP)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Startup Apps", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
                         L"Everything that starts on its own: Run and RunOnce keys, Winlogon, Active Setup, "
                         L"shell hooks, auto-start services and drivers, scheduled tasks, and startup folders.",
                         g_fontSmall);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_STARTUP, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_STARTUP, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 820, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, -1, {1, 2}, {0, 5},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Action", FM_ACTION}});
    tab.list = MakeList(tab.page, tab,
                        {L"Startup source", L"Name", L"Command / target", L"Account", L"Enabled",
                         L"Signature"},
                        {200, 230, 620, 150, 70, 150});
}

std::wstring UniqueCarvePath(const std::wstring& folder, const std::wstring& name);
bool WriteCarvedFile(const CarvedFile& file, const std::wstring& folder, std::wstring& saved);

bool IsMediaFile(const std::wstring& name) {
    static const std::set<std::wstring> exts = {
        L".jpg", L".jpeg", L".png", L".bmp", L".gif", L".tif", L".tiff", L".ico",
        L".webp", L".psd", L".dds", L".jp2", L".heic", L".avif",
        L".mp4", L".m4v", L".avi", L".mkv", L".mov", L".wmv", L".asf", L".flv",
        L".mpg", L".mpeg", L".3gp", L".webm",
        L".txt", L".log", L".csv", L".tsv", L".json", L".xml", L".html", L".htm",
        L".md", L".ini", L".cfg", L".yml", L".yaml",
        L".pdf", L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx",
        L".rtf", L".odt", L".ods", L".eml", L".msg"};
    const size_t dot = name.find_last_of(L'.');
    if (dot == std::wstring::npos) return false;
    return exts.find(ToLower(name.substr(dot))) != exts.end();
}

bool CarveMediaThumb(const std::wstring& name, int& image) {
    auto cached = g_carveMedia.thumbs.find(name);
    if (cached != g_carveMedia.thumbs.end()) {
        image = cached->second;
        return image >= 0;
    }
    image = -1;
    if (!g_carveMedia.images) return false;

    CarvedFile file;
    if (!CarvedCopy(name, file)) return false;

    if (g_carveMedia.tempDir.empty()) {
        wchar_t temp[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, temp);
        const std::wstring base = std::wstring(temp) + L"WindChecker";
        CreateDirectoryW(base.c_str(), nullptr);
        g_carveMedia.tempDir = base + L"\\media";
        CreateDirectoryW(g_carveMedia.tempDir.c_str(), nullptr);
    }
    const std::wstring path = UniqueCarvePath(g_carveMedia.tempDir, name);

    HANDLE handle = CreateFileW(path.c_str(), GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    WriteFile(handle, file.data.data(), static_cast<DWORD>(file.data.size()), &written, nullptr);
    FlushFileBuffers(handle);
    CloseHandle(handle);

    HBITMAP bitmap = nullptr;
    IShellItem* item = nullptr;
    if (SUCCEEDED(SHCreateItemFromParsingName(path.c_str(), nullptr, IID_PPV_ARGS(&item)))) {
        IShellItemImageFactory* factory = nullptr;
        if (SUCCEEDED(item->QueryInterface(IID_PPV_ARGS(&factory)))) {
            SIZE size{g_carveMedia.imageSize, g_carveMedia.imageSize};

            factory->GetImage(size, SIIGBF_THUMBNAILONLY | SIIGBF_SCALEUP, &bitmap);
            if (!bitmap) factory->GetImage(size, SIIGBF_ICONONLY | SIIGBF_SCALEUP, &bitmap);
            factory->Release();
        }
        item->Release();
    }
    DeleteFileW(path.c_str());
    if (bitmap) {
        image = ImageList_Add(g_carveMedia.images, bitmap, nullptr);
        DeleteObject(bitmap);
    }
    g_carveMedia.thumbs[name] = image;
    return image >= 0;
}

void CarveMediaRebuild() {
    if (!g_carveMedia.list) return;
    Tab& tab = g_tabs[TAB_CARVE];
    const std::wstring term = tab.searchEdit ? Trim(GetText(tab.searchEdit)) : std::wstring();

    SendMessageW(g_carveMedia.list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_carveMedia.list);
    int shown = 0;
    int previews = 0;
    for (const std::wstring& name : CarvedNames()) {
        if (!IsMediaFile(name)) continue;
        if (!term.empty() && StrStrIW(name.c_str(), term.c_str()) == nullptr) continue;
        int image = -1;
        CarveMediaThumb(name, image);
        if (image >= 0) ++previews;
        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_IMAGE;
        item.iItem = shown;
        item.iImage = image;
        item.pszText = const_cast<LPWSTR>(name.c_str());
        ListView_InsertItem(g_carveMedia.list, &item);
        ++shown;
        if (shown >= 120) break;
    }
    SendMessageW(g_carveMedia.list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_carveMedia.list, nullptr, TRUE);
    if (tab.statusLabel) {
        SetText(tab.statusLabel, Format(L"%s previewable file(s) \u00B7 %s with a thumbnail%s",
                                        CommaNumber(shown).c_str(),
                                        CommaNumber(previews).c_str(),
                                        term.empty() ? L"" : L" \u00B7 filtered"));
    }
}

void CarveMediaReset() {
    g_carveMedia.thumbs.clear();
    if (!g_carveMedia.list) return;
    ListView_SetImageList(g_carveMedia.list, nullptr, LVSIL_NORMAL);
    if (g_carveMedia.images) ImageList_Destroy(g_carveMedia.images);
    g_carveMedia.images = ImageList_Create(g_carveMedia.imageSize, g_carveMedia.imageSize,
                                           ILC_COLOR32 | ILC_MASK, 32, 32);
    ListView_SetImageList(g_carveMedia.list, g_carveMedia.images, LVSIL_NORMAL);
}

void CarveMediaSetView(bool media) {
    Tab& tab = g_tabs[TAB_CARVE];
    if (!g_carveMedia.list) return;
    if (media && !g_carveMedia.visible) g_carveMedia.lastStatus = GetText(tab.statusLabel);
    g_carveMedia.visible = media;
    if (tab.tree) ShowWindow(tab.tree, media ? SW_HIDE : SW_SHOW);
    if (tab.detailPane) ShowWindow(tab.detailPane, media ? SW_HIDE : SW_SHOW);
    ShowWindow(g_carveMedia.list, media ? SW_SHOW : SW_HIDE);
    if (g_carveMedia.filesBtn) EnableWindow(g_carveMedia.filesBtn, media);
    if (g_carveMedia.mediaBtn) EnableWindow(g_carveMedia.mediaBtn, !media);
    if (media) CarveMediaRebuild();
    else if (tab.statusLabel) SetText(tab.statusLabel, g_carveMedia.lastStatus);
}

void CarveMediaOpenSelected() {
    if (!g_carveMedia.list) return;
    const int item = ListView_GetNextItem(g_carveMedia.list, -1, LVNI_SELECTED);
    if (item < 0) return;
    wchar_t text[512] = {};
    ListView_GetItemText(g_carveMedia.list, item, 0, text, 512);
    if (text[0] == 0) return;

    CarvedFile file;
    if (!CarvedCopy(text, file)) return;
    wchar_t temp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp);
    const std::wstring folder = std::wstring(temp) + L"WindChecker";
    CreateDirectoryW(folder.c_str(), nullptr);
    std::wstring target;
    if (WriteCarvedFile(file, folder, target)) {
        ShellExecuteW(g_hwnd, L"open", target.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }
}

void StartCarve();
void StartMftRecover();
void CarveSaveAll();
void CarveOpenSelected();


int CarveIconIndex(const std::wstring& name, bool folder) {
    if (folder) return StockIconIndex(SIID_FOLDER);
    std::wstring leaf = name;
    const size_t slash = leaf.find_last_of(L"\\/");
    if (slash != std::wstring::npos) leaf = leaf.substr(slash + 1);
    if (leaf.empty()) leaf = L"file";
    SHFILEINFOW info{};
    if (SHGetFileInfoW(leaf.c_str(), FILE_ATTRIBUTE_NORMAL, &info, sizeof(info),
                       SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES)) {
        return info.iIcon;
    }
    return StockIconIndex(SIID_APPLICATION);
}

std::wstring CarveVolumeOf(const std::wstring& source) {
    const size_t dot = source.find(L" \u00B7 ");
    return dot == std::wstring::npos ? source : source.substr(0, dot);
}

HTREEITEM InsertCarveNode(Tab& tab, HTREEITEM parent, const std::wstring& text, int icon,
                          size_t record) {
    TVINSERTSTRUCTW insert{};
    insert.hParent = parent;
    insert.hInsertAfter = TVI_LAST;
    insert.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
    insert.item.pszText = const_cast<LPWSTR>(text.c_str());
    insert.item.lParam = record == static_cast<size_t>(-1)
                             ? static_cast<LPARAM>(-1)
                             : static_cast<LPARAM>(record);
    insert.item.iImage = icon;
    insert.item.iSelectedImage = icon;
    return TreeView_InsertItem(tab.tree, &insert);
}

void RebuildCarveTree(Tab& tab) {
    if (!tab.tree) return;
    SendMessageW(tab.tree, WM_SETREDRAW, FALSE, 0);
    TreeView_DeleteAllItems(tab.tree);
    tab.displayed.clear();
    tab.shown = 0;
    tab.matched = 0;

    std::unordered_map<std::wstring, HTREEITEM> nodes;
    HTREEITEM root = nullptr;
    HTREEITEM firstLeaf = nullptr;

    for (size_t i = 0; i < tab.records.size(); ++i) {
        const Row& row = tab.records[i];
        if (!RowMatches(tab, row)) continue;
        ++tab.matched;
        if (tab.shown >= static_cast<int>(DISPLAY_LIMIT)) continue;

        const std::wstring path = row.empty() ? L"" : row[0];
        if (path.empty()) continue;
        const std::wstring type = row.size() > 1 ? row[1] : L"";
        const bool folder = type == L"Folder";
        const std::wstring size = row.size() > 2 ? row[2] : L"";
        const std::wstring state = row.size() > 4 ? row[4] : L"";

        if (!root) {
            const std::wstring volume = CarveVolumeOf(row.size() > 3 ? row[3] : L"");
            const std::wstring label = volume.empty() ? L"Recovered items"
                                                      : volume + L" \u00B7 recovered items";
            root = InsertCarveNode(tab, TVI_ROOT, label, StockIconIndex(SIID_DRIVEFIXED),
                                   static_cast<size_t>(-1));
            if (!root) break;
            TreeView_SetItemState(tab.tree, root, TVIS_BOLD, TVIS_BOLD);
        }

        HTREEITEM parent = root;
        std::wstring key;
        size_t start = 0;
        while (start < path.size()) {
            const size_t separator = path.find_first_of(L"\\/", start);
            std::wstring part = separator == std::wstring::npos
                                    ? path.substr(start)
                                    : path.substr(start, separator - start);
            const bool last = separator == std::wstring::npos;
            if (!part.empty() && part != L"." && part != L"..") {
                key += part;
                if (!last) {
                    auto found = nodes.find(key);
                    if (found != nodes.end()) {
                        parent = found->second;
                    } else {
                        HTREEITEM made = InsertCarveNode(
                            tab, parent, part + L"  \u00B7  folder",
                            CarveIconIndex(part, true), static_cast<size_t>(-1));
                        if (!made) break;
                        nodes[key] = made;
                        parent = made;
                    }
                    key += L'\\';
                } else {
                    std::wstring text = part;
                    if (folder) {
                        text += L"  \u00B7  folder";
                    } else {
                        if (!size.empty()) text += L"  \u00B7  " + size;
                        if (!state.empty()) text += L"  \u00B7  " + state;
                    }
                    HTREEITEM leaf = InsertCarveNode(tab, parent, text,
                                                     CarveIconIndex(part, folder), i);
                    if (!leaf) break;
                    if (!folder && !firstLeaf) firstLeaf = leaf;
                    tab.displayed.push_back(i);
                    ++tab.shown;
                }
            }
            if (last) break;
            start = separator + 1;
        }
    }

    SendMessageW(tab.tree, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(tab.tree, nullptr, TRUE);
    UpdateCount(tab);
    {
        HANDLE dbg = CreateFileW(L"C:\\carve_debug.log", GENERIC_WRITE, 0, nullptr,
                                 OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (dbg != INVALID_HANDLE_VALUE) {
            SetFilePointer(dbg, 0, nullptr, FILE_END);
            std::wstring msg = Format(L"[rebuild] tree=%p root=%p displayed=%d nodes=%d records=%d firstPath=%s\n",
                                      static_cast<void*>(tab.tree), static_cast<void*>(root),
                                      static_cast<int>(tab.shown), static_cast<int>(nodes.size()),
                                      static_cast<int>(tab.records.size()),
                                      tab.records.empty() ? L"(none)" : tab.records[0].empty() ? L"(empty)"
                                                                                              : tab.records[0][0].c_str());
            DWORD wrote = 0;
            WriteFile(dbg, msg.c_str(), static_cast<DWORD>(msg.size() * 2), &wrote, nullptr);
            CloseHandle(dbg);
        }
    }
    if (root) TreeView_Expand(tab.tree, root, TVE_EXPAND);
    if (firstLeaf) {
        TreeView_SelectItem(tab.tree, firstLeaf);
        TreeView_EnsureVisible(tab.tree, firstLeaf);
    }
}

void CarveShowDetail(Tab& tab, size_t record) {
    if (!tab.detailPane) return;
    if (record >= tab.records.size()) return;
    std::wstring text = BuildRowDetailAt(tab, record, static_cast<int>(record));
    if (text.empty()) return;
    SetWindowTextW(tab.detailPane, text.c_str());
    SendMessageW(tab.detailPane, EM_SETSEL, 0, 0);
    SendMessageW(tab.detailPane, EM_SCROLLCARET, 0, 0);
}

bool CarveOpenRecord(size_t record) {
    Tab& tab = g_tabs[TAB_CARVE];
    if (record >= tab.records.size() || tab.records[record].empty()) return false;
    const std::wstring name = tab.records[record][0];

    const std::vector<CarvedFile> files = CarvedSnapshot();
    for (const CarvedFile& file : files) {
        if (file.name != name) continue;
        wchar_t temp[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, temp);
        const std::wstring folder = std::wstring(temp) + L"WindChecker";
        CreateDirectoryW(folder.c_str(), nullptr);
        std::wstring target;
        if (WriteCarvedFile(file, folder, target)) {
            if (file.type == L"Folder") {
                ShellExecuteW(g_hwnd, L"open", target.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            } else {
                ShellExecuteW(g_hwnd, L"open", target.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
        } else {
            SetText(g_status, Format(L"%s has no captured content \u00B7 it is listed from $MFT "
                                     L"metadata only.", name.c_str()));
        }
        return true;
    }
    SetText(g_status, Format(L"%s is no longer in the recovered set.", name.c_str()));
    return false;
}

void CarveTreeDoubleClick(HWND tree) {
    HTREEITEM item = TreeView_GetSelection(tree);
    if (!item) return;
    const size_t record = TreeRecordIndex(tree, item);
    if (record == static_cast<size_t>(-1)) {
        UINT expanded = TreeView_GetItemState(tree, item, TVIS_EXPANDED);
        TreeView_Expand(tree, item, expanded ? TVE_COLLAPSE : TVE_EXPAND);
        return;
    }
    CarveOpenRecord(record);
}


void BuildCarvePage() {
    Tab& tab = g_tabs[TAB_CARVE];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_CARVE)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Carving", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"One pass over the volume: files and folders are rebuilt by name from the $MFT (including "
        L"files inside deleted folders), then file signatures are carved from raw disk space. "
        L"Results open as a folder tree, exactly where each item lived; select a node for every "
        L"field of that record, double-click to open it, or switch to Media for previews.",
        g_fontSmall);

    HWND volumeLabel = MakeLabel(tab.page, L"Volume", g_fontSmall);
    tab.targetCombo = MakeCombo(tab.page, IdFor(TAB_CARVE, L_TARGET));
    for (wchar_t drive = L'C'; drive <= L'Z'; ++drive) {
        const std::wstring root = std::wstring(1, drive) + L":\\";
        const UINT type = GetDriveTypeW(root.c_str());

        if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE && type != DRIVE_RAMDISK) continue;
        if (GetFileAttributesW(root.c_str()) == INVALID_FILE_ATTRIBUTES) continue;

        std::wstring label = std::wstring(1, drive) + L":";
        ULARGE_INTEGER total{};
        if (GetDiskFreeSpaceExW(root.c_str(), nullptr, &total, nullptr) && total.QuadPart) {
            label += L" (" + SizeText(total.QuadPart);
            if (type == DRIVE_REMOVABLE) label += L" \u00B7 USB";
            else if (type == DRIVE_RAMDISK) label += L" \u00B7 RAM";
            label += L")";
        } else if (type == DRIVE_REMOVABLE) {
            label += L" (USB)";
        }
        ComboAdd(tab.targetCombo, label);
    }
    if (SendMessageW(tab.targetCombo, CB_GETCOUNT, 0, 0) > 0) {
        SendMessageW(tab.targetCombo, CB_SETCURSEL, 0, 0);
    }

    HWND limitLabel = MakeLabel(tab.page, L"Limit (MB)", g_fontSmall);
    tab.limitEdit = MakeEdit(tab.page, L"1024", IdFor(TAB_CARVE, L_LIMITMB));

    g_carveMedia.filesBtn = MakeButton(tab.page, L"Files", IdFor(TAB_CARVE, L_VIEWFILES));
    g_carveMedia.mediaBtn = MakeButton(tab.page, L"Media", IdFor(TAB_CARVE, L_VIEWMEDIA));

    tab.startBtn = MakeButton(tab.page, L"Scan volume", IdFor(TAB_CARVE, L_START));
    HWND mftBtn = MakeButton(tab.page, L"MFT only", IdFor(TAB_CARVE, L_MFTRECOVER));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_CARVE, L_STOP));
    HWND saveBtn = MakeButton(tab.page, L"Extract all\u2026", IdFor(TAB_CARVE, L_SAVE));
    HWND openBtn = MakeButton(tab.page, L"Open", IdFor(TAB_CARVE, L_OPEN));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);

    PlaceHeader(tab, volumeLabel, 8, 56, 48, 20, 0);
    PlaceHeader(tab, tab.targetCombo, 58, 54, 150, 200, 0);
    PlaceHeader(tab, limitLabel, 218, 56, 70, 20, 0);
    PlaceHeader(tab, tab.limitEdit, 290, 54, 80, 24, 0);
    PlaceHeader(tab, g_carveMedia.filesBtn, 388, 52, 66, 26, 0);
    PlaceHeader(tab, g_carveMedia.mediaBtn, 458, 52, 66, 26, 0);
    tab.buttonsCustom = true;
    PlaceHeader(tab, tab.startBtn, 8, 86, 100, 26, -1);
    PlaceHeader(tab, mftBtn, 113, 86, 110, 26, -1);
    PlaceHeader(tab, tab.stopBtn, 228, 86, 80, 26, -1);
    PlaceHeader(tab, saveBtn, 313, 86, 100, 26, -1);
    PlaceHeader(tab, openBtn, 418, 86, 80, 26, -1);
    PlaceHeader(tab, tab.statusLabel, 506, 90, 420, 20, -1);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, -1, {0}, {1},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Type", FM_ACTION}});
    tab.headers = {L"Path", L"Type", L"Size", L"Source", L"State", L"Modified", L"Created"};

    tab.tree = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_HSCROLL | TVS_HASLINES |
                                   TVS_LINESATROOT | TVS_HASBUTTONS | TVS_SHOWSELALWAYS,
                               0, 0, 10, 10, tab.page,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdFor(TAB_CARVE, 91))),
                               g_instance, nullptr);
    if (tab.tree) {
        SendMessageW(tab.tree, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
        SendMessageW(tab.tree, TVM_SETEXTENDEDSTYLE, TVS_EX_DOUBLEBUFFER, TVS_EX_DOUBLEBUFFER);
        SetWindowTheme(tab.tree, L"Explorer", nullptr);
        SHFILEINFOW shellInfo{};
        HIMAGELIST images = reinterpret_cast<HIMAGELIST>(
            SHGetFileInfoW(L"C:\\", 0, &shellInfo, sizeof(shellInfo),
                           SHGFI_SYSICONINDEX | SHGFI_SMALLICON));
        if (images) TreeView_SetImageList(tab.tree, images, TVSIL_NORMAL);
    }

    tab.detailPane = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                         ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tab.detailPane, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontMono ? g_fontMono : g_fontSmall), TRUE);
    SetWindowTextW(tab.detailPane,
                   L"Run a scan to rebuild the folder tree from the $MFT. Select any node to see "
                   L"every field of the underlying record.");

    g_carveMedia.imageSize = S(192);
    g_carveMedia.images = ImageList_Create(g_carveMedia.imageSize, g_carveMedia.imageSize,
                                           ILC_COLOR32 | ILC_MASK, 32, 32);
    g_carveMedia.list = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_ICON | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_AUTOARRANGE,
        0, 0, 0, 0, tab.page,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdFor(TAB_CARVE, L_GALLERY))),
        g_instance, nullptr);
    if (g_carveMedia.list) {
        SendMessageW(g_carveMedia.list, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
        ListView_SetImageList(g_carveMedia.list, g_carveMedia.images, LVSIL_NORMAL);
        ListView_SetExtendedListViewStyle(g_carveMedia.list, LVS_EX_DOUBLEBUFFER);
        ListView_SetIconSpacing(g_carveMedia.list, S(214), S(246));
        SetWindowTheme(g_carveMedia.list, L"Explorer", nullptr);
    }
    EnableWindow(g_carveMedia.filesBtn, FALSE);
}

void StartCarve() {
    Tab& tab = g_tabs[TAB_CARVE];
    if (tab.running) return;
    CarveConfig config;
    CarveSource src;
    std::wstring drive = ComboText(tab.targetCombo);
    if (drive.size() > 2) drive = drive.substr(0, 2);
    if (drive.size() < 2) {
        SetText(g_status, L"Choose a volume first.");
        return;
    }
    src.path = L"\\\\.\\" + drive;
    src.label = drive + L" (raw)";
    src.raw = true;
    config.sources.push_back(src);
    const int mb = _wtoi(GetText(tab.limitEdit).c_str());
    config.limitBytes = mb > 0 ? (static_cast<uint64_t>(mb) << 20) : 0;

    MftRecoverConfig mft;
    mft.volume = drive;
    mft.deletedOnly = true;
    mft.limitRecords = 0;
    StartWork(tab, [config, mft](const Sink& sink, std::atomic<bool>& stop) {
        RunCarvingScan(sink, stop, config, mft);
    });
}

void StartMftRecover() {
    Tab& tab = g_tabs[TAB_CARVE];
    if (tab.running) return;
    std::wstring drive = ComboText(tab.targetCombo);
    if (drive.size() > 2) drive = drive.substr(0, 2);
    if (drive.size() < 2) {
        SetText(g_status, L"Choose a volume first.");
        return;
    }
    MftRecoverConfig config;
    config.volume = drive;
    config.deletedOnly = true;
    config.limitRecords = 0;
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunMftRecover(sink, stop, config);
    });
}


std::wstring UniqueCarvePath(const std::wstring& folder, const std::wstring& name) {
    std::wstring candidate = folder + L"\\" + name;
    if (GetFileAttributesW(candidate.c_str()) == INVALID_FILE_ATTRIBUTES) return candidate;
    const size_t dot = name.find_last_of(L'.');
    const std::wstring stem = dot == std::wstring::npos ? name : name.substr(0, dot);
    const std::wstring ext = dot == std::wstring::npos ? L"" : name.substr(dot);
    for (int i = 2; i < 10000; ++i) {
        candidate = folder + L"\\" + stem + Format(L"_%d", i) + ext;
        if (GetFileAttributesW(candidate.c_str()) == INVALID_FILE_ATTRIBUTES) return candidate;
    }
    return folder + L"\\" + name;
}

void CreateFolderTree(const std::wstring& path) {
    std::wstring current;
    for (size_t i = 0; i < path.size(); ++i) {
        current += path[i];
        if ((path[i] == L'\\' || i + 1 == path.size()) && current.size() > 3) {
            CreateDirectoryW(current.c_str(), nullptr);
        }
    }
}

std::wstring SafePathComponent(const std::wstring& name) {
    std::wstring out = name;
    for (wchar_t& ch : out) {
        if (ch < 0x20 || wcschr(L"<>:\"/\\|?*", ch) != nullptr) ch = L'_';
    }
    while (!out.empty() && (out.back() == L'.' || out.back() == L' ')) out.pop_back();
    if (out.empty()) out = L"recovered";
    return out;
}

bool WriteCarvedFile(const CarvedFile& file, const std::wstring& folder, std::wstring& saved) {
    std::wstring relative;
    size_t start = 0;
    while (start <= file.name.size()) {
        const size_t separator = file.name.find_first_of(L"\\/", start);
        std::wstring part = separator == std::wstring::npos
                                ? file.name.substr(start)
                                : file.name.substr(start, separator - start);
        if (!part.empty() && part != L"." && part != L"..") {
            if (!relative.empty()) relative += L'\\';
            relative += SafePathComponent(part);
        }
        if (separator == std::wstring::npos) break;
        start = separator + 1;
    }
    if (relative.empty()) return false;

    const std::wstring target = folder + L'\\' + relative;
    const size_t slash = target.find_last_of(L'\\');
    const std::wstring parent = slash == std::wstring::npos ? folder : target.substr(0, slash);
    const std::wstring leaf = slash == std::wstring::npos ? relative : target.substr(slash + 1);
    CreateFolderTree(parent);

    if (file.type == L"Folder") {
        saved = target;
        CreateDirectoryW(saved.c_str(), nullptr);
        return true;
    }

    saved = UniqueCarvePath(parent, leaf);
    HANDLE handle = CreateFileW(saved.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool ok = !file.data.empty() &&
                    WriteFile(handle, file.data.data(), static_cast<DWORD>(file.data.size()),
                              &written, nullptr);
    CloseHandle(handle);
    return ok;
}

void CarveSaveAll() {
    const std::vector<CarvedFile> files = CarvedSnapshot();
    if (files.empty()) {
        SetText(g_status, L"Nothing to save yet.");
        return;
    }
    BROWSEINFO bi{};
    bi.hwndOwner = g_hwnd;
    bi.lpszTitle = L"Choose a folder for the recovered files";
    bi.ulFlags = BIF_USENEWUI;
    PIDLIST_ABSOLUTE pid = SHBrowseForFolderW(&bi);
    if (!pid) return;
    wchar_t path[MAX_PATH] = {};
    std::wstring folder;
    if (SHGetPathFromIDListW(pid, path)) folder = path;
    CoTaskMemFree(pid);
    if (folder.empty()) return;

    int saved = 0;
    for (const CarvedFile& file : files) {
        std::wstring target;
        if (WriteCarvedFile(file, folder, target)) ++saved;
    }
    SetText(g_status, Format(L"Saved %d of %d recovered file(s) to %s", saved,
                             static_cast<int>(files.size()), folder.c_str()));
}

void CarveOpenSelected() {
    Tab& tab = g_tabs[TAB_CARVE];
    if (tab.tree) {
        const size_t record = TreeRecordIndex(tab.tree, TreeView_GetSelection(tab.tree));
        if (record != static_cast<size_t>(-1)) CarveOpenRecord(record);
        return;
    }
    const int item = ListView_GetNextItem(tab.list, -1, LVNI_SELECTED);
    if (item < 0 || static_cast<size_t>(item) >= tab.displayed.size()) return;
    const size_t record = tab.displayed[static_cast<size_t>(item)];
    if (record >= tab.records.size() || tab.records[record].empty()) return;
    CarveOpenRecord(record);
}

void BuildPersistencePage() {
    Tab& tab = g_tabs[TAB_PERSISTENCE];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_PERSISTENCE)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Persistence", g_fontTitle);
    tab.desc = MakeLabel(tab.page, L"Every autostart location: Run keys, Winlogon, IFEO, AppInit, services and drivers, scheduled tasks, and startup folders.", g_fontSmall);

    HWND scopeLabel = MakeLabel(tab.page, L"Include", g_fontSmall);
    tab.regKeysCheck = MakeCheck(tab.page, L"Registry autostarts", IdFor(TAB_PERSISTENCE, L_REGKEYS), true);
    tab.svcAutoCheck = MakeCheck(tab.page, L"Services && drivers", IdFor(TAB_PERSISTENCE, L_SVCAUTO), true);
    tab.tasksCheck = MakeCheck(tab.page, L"Scheduled tasks", IdFor(TAB_PERSISTENCE, L_TASKS), true);
    tab.foldersCheck = MakeCheck(tab.page, L"Startup folders", IdFor(TAB_PERSISTENCE, L_FOLDERS), true);

    PlaceHeader(tab, scopeLabel, 8, 56, 50, 20, 0);
    PlaceHeader(tab, tab.regKeysCheck, 62, 56, 150, 20, 0);
    PlaceHeader(tab, tab.svcAutoCheck, 218, 56, 150, 20, 0);
    PlaceHeader(tab, tab.tasksCheck, 374, 56, 140, 20, 0);
    PlaceHeader(tab, tab.foldersCheck, 520, 56, 140, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_PERSISTENCE, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_PERSISTENCE, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 820, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, -1, {1, 2, 3}, {0, 4},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Action", FM_ACTION}});
    tab.list = MakeList(tab.page, tab,
                        {L"Category", L"Name", L"Location", L"Command / target", L"Signature"},
                        {120, 250, 400, 720, 170});
}

void BuildExecutionPage() {
    Tab& tab = g_tabs[TAB_EXECUTION];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_EXECUTION)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Execution Evidence", g_fontTitle);
    tab.desc = MakeLabel(tab.page, L"ShimCache execution evidence, USB storage history from the registry, and Recycle Bin index entries with their original paths.", g_fontSmall);

    HWND scopeLabel = MakeLabel(tab.page, L"Include", g_fontSmall);
    tab.shimCacheCheck = MakeCheck(tab.page, L"ShimCache", IdFor(TAB_EXECUTION, L_SHIMCACHE), true);
    tab.usbCheck = MakeCheck(tab.page, L"USB storage", IdFor(TAB_EXECUTION, L_USB), true);
    tab.recycleCheck = MakeCheck(tab.page, L"Recycle Bin", IdFor(TAB_EXECUTION, L_RECYCLE), true);

    PlaceHeader(tab, scopeLabel, 8, 56, 50, 20, 0);
    PlaceHeader(tab, tab.shimCacheCheck, 62, 56, 110, 20, 0);
    PlaceHeader(tab, tab.usbCheck, 178, 56, 120, 20, 0);
    PlaceHeader(tab, tab.recycleCheck, 304, 56, 120, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_EXECUTION, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_EXECUTION, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 820, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 1, {2, 3}, {0},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Action", FM_ACTION}, {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"Category", L"Time", L"Path / device", L"Detail", L"Source"},
                        {120, 150, 660, 460, 170});
}

void BuildSignaturePage() {
    Tab& tab = g_tabs[TAB_SIGNATURES];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_SIGNATURES)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Code Signing", g_fontTitle);
    tab.desc = MakeLabel(tab.page, L"Every executable in use is verified with WinVerifyTrust. Embedded Authenticode and catalog signatures are both checked; the signer, the certificate location and self-signed status are recorded.", g_fontSmall);

    HWND scopeLabel = MakeLabel(tab.page, L"Verify", g_fontSmall);
    tab.signProcCheck = MakeCheck(tab.page, L"Process images", IdFor(TAB_SIGNATURES, L_SIGNPROC), true);
    tab.signModulesCheck = MakeCheck(tab.page, L"Loaded DLLs", IdFor(TAB_SIGNATURES, L_SIGNMODULES), true);
    tab.signServicesCheck = MakeCheck(tab.page, L"Services && drivers", IdFor(TAB_SIGNATURES, L_SIGNSERVICES), true);

    PlaceHeader(tab, scopeLabel, 8, 56, 50, 20, 0);
    PlaceHeader(tab, tab.signProcCheck, 62, 56, 130, 20, 0);
    PlaceHeader(tab, tab.signModulesCheck, 198, 56, 130, 20, 0);
    PlaceHeader(tab, tab.signServicesCheck, 334, 56, 150, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Verify", IdFor(TAB_SIGNATURES, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_SIGNATURES, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 820, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 5, {1, 2, 3, 7}, {0, 4, 6},
                {{L"All fields", FM_ALL}, {L"File", FM_NAME}, {L"Signer", FM_ACTION}, {L"Expiry", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"Status", L"File", L"Signer", L"Issuer", L"Self-signed",
                         L"Valid to", L"Certificate location", L"Full path"},
                        {150, 240, 300, 300, 100, 150, 260, 520});
}

std::wstring DefaultScanFolder() {
    for (const KNOWNFOLDERID* id : {&FOLDERID_Downloads, &FOLDERID_Profile}) {
        PWSTR path = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(*id, 0, nullptr, &path)) && path) {
            std::wstring folder = path;
            CoTaskMemFree(path);
            if (GetFileAttributesW(folder.c_str()) != INVALID_FILE_ATTRIBUTES) return folder;
        }
    }
    return L"C:\\";
}

std::wstring BrowseForFolder(HWND owner, const wchar_t* title) {
    BROWSEINFO info{};
    info.hwndOwner = owner;
    info.lpszTitle = title;
    info.ulFlags = BIF_USENEWUI;
    PIDLIST_ABSOLUTE pid = SHBrowseForFolderW(&info);
    if (!pid) return L"";
    wchar_t path[MAX_PATH] = {};
    std::wstring folder;
    if (SHGetPathFromIDListW(pid, path)) folder = path;
    CoTaskMemFree(pid);
    return folder;
}

void BuildFileHashPage() {
    Tab& tab = g_tabs[TAB_FILEHASH];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_FILEHASH)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Hash & Signature", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"Every file under the chosen folder: MD5, SHA-1, SHA-256 and SHA-512 digests, the "
        L"Authenticode signature with its full certificate chain, version resources, owner, "
        L"timestamps, alternate data streams and, for images, the embedded metadata.",
        g_fontSmall);

    HWND folderLabel = MakeLabel(tab.page, L"Folder", g_fontSmall);
    tab.folderEdit = MakeEdit(tab.page, DefaultScanFolder(), IdFor(TAB_FILEHASH, L_FOLDER));
    HWND browseBtn = MakeButton(tab.page, L"Browse\u2026", IdFor(TAB_FILEHASH, L_BROWSE));
    tab.recurseCheck = MakeCheck(tab.page, L"Include subfolders", IdFor(TAB_FILEHASH, L_RECURSE), true);
    tab.hashContentCheck = MakeCheck(tab.page, L"Hash contents", IdFor(TAB_FILEHASH, L_HASHCONTENT), true);
    tab.verifySignCheck = MakeCheck(tab.page, L"Verify signature", IdFor(TAB_FILEHASH, L_VERIFYSIGN), true);

    PlaceHeader(tab, folderLabel, 8, 56, 44, 20, 0);
    PlaceHeader(tab, tab.folderEdit, 54, 54, 430, 25, 0);
    PlaceHeader(tab, browseBtn, 490, 54, 86, 26, 0);
    PlaceHeader(tab, tab.recurseCheck, 588, 56, 148, 20, 0);
    PlaceHeader(tab, tab.hashContentCheck, 742, 56, 128, 20, 0);
    PlaceHeader(tab, tab.verifySignCheck, 876, 56, 140, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_FILEHASH, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_FILEHASH, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 900, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 2, {0, 7}, {6},
                {{L"All fields", FM_ALL}, {L"File or signer", FM_NAME}, {L"Signature", FM_ACTION},
                 {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"Name", L"Size", L"Modified", L"SHA-256", L"SHA-1", L"MD5",
                         L"Signature", L"Signer"},
                        {230, 90, 150, 430, 300, 260, 180, 240});

    tab.detailPane = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                         ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tab.detailPane, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontMono ? g_fontMono : g_fontSmall), TRUE);
    SetWindowTextW(tab.detailPane,
                   L"Choose a folder, then click Scan. Select a file to see its hashes, signature "
                   L"chain, version resources, owner, streams and image metadata.");
}

void StartFileHash() {
    Tab& tab = g_tabs[TAB_FILEHASH];
    if (tab.running) return;
    std::wstring path = Trim(GetText(tab.folderEdit));
    if (path.empty()) {
        MessageBoxW(g_hwnd, L"Choose a folder to scan.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        MessageBoxW(g_hwnd, (L"Not a folder:\n" + path).c_str(), APP_TITLE, MB_ICONWARNING);
        return;
    }
    FileHashConfig config;
    config.folder = path;
    config.recursive = IsChecked(tab.recurseCheck);
    config.hashContents = IsChecked(tab.hashContentCheck);
    config.verifySignature = IsChecked(tab.verifySignCheck);
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunFileHashScan(sink, stop, config);
    });
}

void FileHashBrowse() {
    std::wstring folder = BrowseForFolder(g_hwnd, L"Choose a folder to hash");
    if (folder.empty()) return;
    SetText(g_tabs[TAB_FILEHASH].folderEdit, folder);
    StartFileHash();
}

void BuildImageMetaPage() {
    Tab& tab = g_tabs[TAB_EXIF];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_EXIF)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Image Metadata", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"Full metadata scrape for every image under the chosen folder: format and dimensions, "
        L"EXIF capture details (camera, lens, exposure, ISO), GPS position, orientation and the "
        L"complete metadata tree with every block and tag read from the file.",
        g_fontSmall);

    HWND folderLabel = MakeLabel(tab.page, L"Folder", g_fontSmall);
    tab.folderEdit = MakeEdit(tab.page, DefaultScanFolder(), IdFor(TAB_EXIF, L_FOLDER));
    HWND browseBtn = MakeButton(tab.page, L"Browse\u2026", IdFor(TAB_EXIF, L_BROWSE));
    tab.recurseCheck = MakeCheck(tab.page, L"Include subfolders", IdFor(TAB_EXIF, L_RECURSE), true);

    PlaceHeader(tab, folderLabel, 8, 56, 44, 20, 0);
    PlaceHeader(tab, tab.folderEdit, 54, 54, 520, 25, 0);
    PlaceHeader(tab, browseBtn, 580, 54, 86, 26, 0);
    PlaceHeader(tab, tab.recurseCheck, 678, 56, 160, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_EXIF, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_EXIF, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 900, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 4, {0, 5}, {1},
                {{L"All fields", FM_ALL}, {L"File or camera", FM_NAME}, {L"Format", FM_ACTION},
                 {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"File", L"Format", L"Dimensions", L"Size", L"Date taken", L"Camera",
                         L"Lens", L"Exposure", L"GPS"},
                        {240, 90, 110, 90, 150, 210, 180, 220, 260});

    tab.detailPane = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                         ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tab.detailPane, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontMono ? g_fontMono : g_fontSmall), TRUE);
    SetWindowTextW(tab.detailPane,
                   L"Choose a folder, then click Scan. Select an image to read every metadata block "
                   L"and tag embedded in the file.");
}

void StartImageMeta() {
    Tab& tab = g_tabs[TAB_EXIF];
    if (tab.running) return;
    std::wstring path = Trim(GetText(tab.folderEdit));
    if (path.empty()) {
        MessageBoxW(g_hwnd, L"Choose a folder to scan.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        MessageBoxW(g_hwnd, (L"Not a folder:\n" + path).c_str(), APP_TITLE, MB_ICONWARNING);
        return;
    }
    ImageMetaConfig config;
    config.folder = path;
    config.recursive = IsChecked(tab.recurseCheck);
    StartWork(tab, [config](const Sink& sink, std::atomic<bool>& stop) {
        RunImageMetadataScan(sink, stop, config);
    });
}

void ImageMetaBrowse() {
    std::wstring folder = BrowseForFolder(g_hwnd, L"Choose a folder of images");
    if (folder.empty()) return;
    SetText(g_tabs[TAB_EXIF].folderEdit, folder);
    StartImageMeta();
}

void CreateStatusBar(HWND hwnd) {
    g_status = MakeLabel(hwnd, L"Ready", g_fontSmall);
    g_progressText = MakeLabel(hwnd, L"Idle", g_fontSmall);
    g_progress = CreateWindowExW(0, PROGRESS_CLASSW, L"",
                                 WS_CHILD | WS_VISIBLE | PBS_MARQUEE,
                                 0, 0, 10, 10, hwnd, nullptr, g_instance, nullptr);
    SendMessageW(g_progress, PBM_SETMARQUEE, FALSE, 28);
}

HMENU ControlMenu(int id) { return reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)); }

std::wstring FormatByteSize(uint64_t bytes) {
    const wchar_t* units[] = {L"B", L"KB", L"MB", L"GB", L"TB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) { value /= 1024.0; ++unit; }
    wchar_t buffer[64];
    if (unit == 0) swprintf(buffer, 64, L"%llu %s", bytes, units[unit]);
    else swprintf(buffer, 64, L"%.2f %s", value, units[unit]);
    return buffer;
}

std::string ReadFileBytes(const wchar_t* path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::string();
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return data;
}

std::vector<std::string> SplitLines(const std::string& text) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start <= text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string::npos) end = text.size();
        size_t len = end - start;
        if (len > 0 && text[start + len - 1] == '\r') --len;
        lines.emplace_back(text.substr(start, len));
        if (end == text.size()) break;
        start = end + 1;
    }
    return lines;
}

std::vector<std::wstring> TokenizeMax(const std::wstring& s, wchar_t sep, size_t maxTokens) {
    std::vector<std::wstring> out;
    size_t start = 0;
    while (out.size() + 1 < maxTokens) {
        size_t pos = s.find(sep, start);
        if (pos == std::wstring::npos) { out.push_back(s.substr(start)); break; }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    if (start < s.size()) out.push_back(s.substr(start));
    return out;
}

std::vector<unsigned char> Base64Decode(const std::string& in) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::vector<unsigned char> out;
    int buf = 0, bits = 0;
    for (char c : in) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t' || c == '=') continue;
        int v = val(c);
        if (v < 0) continue;
        buf = (buf << 6) | v; bits += 6;
        if (bits >= 8) { out.push_back(static_cast<unsigned char>((buf >> (bits - 8)) & 0xFF)); bits -= 8; }
    }
    return out;
}

std::string QPDecode(const std::string& in) {
    auto hx = [](char x) -> int {
        if (x >= '0' && x <= '9') return x - '0';
        if (x >= 'A' && x <= 'F') return x - 'A' + 10;
        if (x >= 'a' && x <= 'f') return x - 'a' + 10;
        return -1;
    };
    std::string out; out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == '\r' || c == '\n') continue;
        if (c == '_') { out.push_back(' '); continue; }
        if (c == '=' && i + 2 < in.size()) {
            char h1 = in[i + 1], h2 = in[i + 2];
            int hi = hx(h1), lo = hx(h2);
            if (hi >= 0 && lo >= 0) { out.push_back(static_cast<char>((hi << 4) | lo)); i += 2; continue; }
            i += 2; continue;
        }
        out.push_back(c);
    }
    return out;
}

struct ClipboardViewer { HWND list = nullptr; HWND status = nullptr; };
ClipboardViewer g_clip;

std::wstring ClipFormatName(UINT fmt) {
    switch (fmt) {
        case CF_TEXT: return L"CF_TEXT";
        case CF_BITMAP: return L"CF_BITMAP";
        case CF_METAFILEPICT: return L"CF_METAFILEPICT";
        case CF_SYLK: return L"CF_SYLK";
        case CF_DIF: return L"CF_DIF";
        case CF_TIFF: return L"CF_TIFF";
        case CF_OEMTEXT: return L"CF_OEMTEXT";
        case CF_DIB: return L"CF_DIB";
        case CF_PALETTE: return L"CF_PALETTE";
        case CF_PENDATA: return L"CF_PENDATA";
        case CF_RIFF: return L"CF_RIFF";
        case CF_WAVE: return L"CF_WAVE";
        case CF_UNICODETEXT: return L"CF_UNICODETEXT";
        case CF_ENHMETAFILE: return L"CF_ENHMETAFILE";
        case CF_HDROP: return L"CF_HDROP";
        case CF_LOCALE: return L"CF_LOCALE";
        case CF_DIBV5: return L"CF_DIBV5";
        default: { wchar_t buf[80]; if (GetClipboardFormatNameW(fmt, buf, 80)) return std::wstring(buf); return Format(L"Format %u", fmt); }
    }
}

void ClipboardRefresh() {
    Tab& tab = g_tabs[TAB_CLIPBOARD];
    tab.records.clear(); tab.details.clear();
    if (!OpenClipboard(g_hwnd)) {
        if (g_clip.status) SetText(g_clip.status, L"Clipboard is unavailable (another application may own it).");
        return;
    }
    UINT fmt = 0; int count = 0;
    while ((fmt = EnumClipboardFormats(fmt)) != 0) {
        std::wstring name = ClipFormatName(fmt);
        std::wstring kind = L"data";
        std::wstring sizeStr = L"-";
        std::wstring preview = L"";
        HANDLE h = GetClipboardData(fmt);
        if (h) {
            if (fmt == CF_UNICODETEXT) {
                kind = L"text";
                SIZE_T bytes = GlobalSize(h);
                sizeStr = FormatByteSize(bytes);
                const wchar_t* p = static_cast<const wchar_t*>(GlobalLock(h));
                if (p) {
                    size_t chars = bytes / sizeof(wchar_t);
                    size_t length = 0;
                    while (length < chars && p[length]) ++length;
                    std::wstring full(p, length);
                    preview = full.substr(0, 120);
                    if (full.size() > 120) preview += L"\u2026";
                    GlobalUnlock(h);
                }
            } else if (fmt == CF_TEXT || fmt == CF_OEMTEXT) {
                kind = L"text";
                SIZE_T bytes = GlobalSize(h);
                sizeStr = FormatByteSize(bytes);
                const char* p = static_cast<const char*>(GlobalLock(h));
                if (p) {
                    size_t length = 0;
                    while (length < bytes && p[length]) ++length;
                    if (length) {
                        int wide = MultiByteToWideChar(CP_ACP, 0, p, static_cast<int>(length), nullptr, 0);
                        if (wide > 0) {
                            std::wstring full(static_cast<size_t>(wide), L'\0');
                            MultiByteToWideChar(CP_ACP, 0, p, static_cast<int>(length),
                                                full.data(), wide);
                            preview = full.substr(0, 120);
                            if (full.size() > 120) preview += L"\u2026";
                        }
                    }
                    GlobalUnlock(h);
                }
            } else if (fmt == CF_HDROP) {
                kind = L"files";
                HDROP drop = static_cast<HDROP>(h);
                UINT n = DragQueryFileW(drop, static_cast<UINT>(-1), nullptr, 0);
                sizeStr = Format(L"%u file(s)", n);
                std::wstring listing;
                for (UINT k = 0; k < n && k < 8; ++k) {
                    wchar_t buf[MAX_PATH];
                    if (DragQueryFileW(drop, k, buf, MAX_PATH)) { listing += buf; if (k + 1 < n) listing += L"\n"; }
                }
                preview = listing;
            } else if (fmt == CF_BITMAP) {
                kind = L"image";
                BITMAP bitmap{};
                if (GetObjectW(h, sizeof(bitmap), &bitmap)) {
                    sizeStr = Format(L"%ld x %ld", bitmap.bmWidth, bitmap.bmHeight);
                    preview = Format(L"%u-bit bitmap", bitmap.bmBitsPixel);
                }
            } else if (fmt == CF_DIB || fmt == CF_DIBV5) {
                kind = L"image";
                SIZE_T bytes = GlobalSize(h);
                BITMAPINFOHEADER* info = static_cast<BITMAPINFOHEADER*>(GlobalLock(h));
                if (info && bytes >= sizeof(BITMAPINFOHEADER) &&
                    info->biSize >= sizeof(BITMAPINFOHEADER) && info->biSize <= bytes) {
                    sizeStr = Format(L"%d x %d", info->biWidth, abs(info->biHeight));
                    preview = Format(L"%d-bit DIB", info->biBitCount);
                }
                if (info) GlobalUnlock(h);
            } else if (fmt == CF_PALETTE) {
                kind = L"palette";
                sizeStr = L"palette";
            } else if (fmt == CF_ENHMETAFILE || fmt == CF_METAFILEPICT) {
                kind = L"metafile";
                sizeStr = L"metafile";
            } else {
                SIZE_T bytes = GlobalSize(h);
                if (bytes) sizeStr = FormatByteSize(bytes);
            }
        }
        Row row; row.reserve(4);
        row.push_back(name); row.push_back(kind); row.push_back(sizeStr); row.push_back(preview);
        tab.records.push_back(row);
        tab.details.push_back(L"Format : " + name + L"\r\nKind   : " + kind + L"\r\nSize   : " + sizeStr + L"\r\n\r\n" + preview);
        ++count;
    }
    CloseClipboard();
    RefreshList(tab);
    if (g_clip.status) SetText(g_clip.status, Format(L"%d format(s) currently on the clipboard.", count));
}

void BuildClipboardPage() {
    Tab& tab = g_tabs[TAB_CLIPBOARD];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_CLIPBOARD)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Clipboard", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"Snapshot of the current clipboard. Press Refresh to re-read its formats and contents.",
        g_fontSmall);
    HWND refreshBtn = MakeButton(tab.page, L"Refresh", IdFor(TAB_CLIPBOARD, L_REFRESH));
    g_clip.status = MakeLabel(tab.page, L"Press Refresh to read the clipboard.", g_fontSmall);
    tab.list = MakeList(tab.page, tab,
        {L"Format", L"Kind", L"Size", L"Preview"},
        {200, 80, 110, 560});
    g_clip.list = tab.list;
    EnsureDetailPane(tab);
    BuildFilter(tab, -1, {0}, {1},
                {{L"All fields", FM_ALL}, {L"Format", FM_NAME}, {L"Kind", FM_ACTION}});
    PlaceHeader(tab, refreshBtn, 8, 54, 90, 26, -1);
    PlaceHeader(tab, g_clip.status, 110, 58, 700, 20, -1);
    ClipboardRefresh();
}

std::wstring HexDumpText(const unsigned char* data, size_t size, uintptr_t baseAddress = 0,
                         size_t maxRows = 4096) {
    std::wstring out;
    if (size == 0) return L"(empty / no readable bytes)";
    size_t rows = (size + 15) / 16;
    if (rows > maxRows) rows = maxRows;
    for (size_t r = 0; r < rows; ++r) {
        uint64_t off = static_cast<uint64_t>(r) * 16;
        wchar_t head[40];
        if (baseAddress)
            swprintf(head, 40, L"%016llX  ", static_cast<unsigned long long>(baseAddress + off));
        else
            swprintf(head, 40, L"%08llX  ", static_cast<unsigned long long>(off));
        std::wstring hex, ascii;
        for (int i = 0; i < 16; ++i) {
            if (off + static_cast<size_t>(i) < size) {
                unsigned char c = data[off + i];
                wchar_t b[4]; swprintf(b, 4, L"%02X ", c); hex += b;
                ascii += (c >= 0x20 && c < 0x7F) ? static_cast<wchar_t>(c) : L'.';
            } else { hex += L"   "; ascii += L' '; }
        }
        out += head;
        out += hex;
        out += L"  ";
        out += ascii;
        out += L"\r\n";
    }
    if ((size + 15) / 16 > maxRows) {
        out += L"\u2026 (truncated at ";
        out += FormatByteSize(maxRows * 16);
        out += L")\r\n";
    }
    return out;
}

struct HexState {
    HWND window = nullptr;
    HWND dump = nullptr;
    HWND strings = nullptr;
    HWND offsetEdit = nullptr;
    HWND status = nullptr;
    HWND goBtn = nullptr;
    HWND backBtn = nullptr;
    HWND forwardBtn = nullptr;
    HWND homeBtn = nullptr;
    HWND endBtn = nullptr;
    HWND prevBtn = nullptr;
    HWND nextBtn = nullptr;
    HFONT font = nullptr;
    std::wstring label;
    std::wstring path;
    bool raw = false;
    uint64_t size = 0;
    uint64_t base = 0;
    std::vector<uint64_t> stringOffsets;
};

HexState g_hex;
constexpr size_t kHexWindow = 64 * 1024;
constexpr size_t kHexStep = 4096;

bool HexPrintable(BYTE value) {
    return value == 0x09 || value == 0x0A || value == 0x0D || (value >= 0x20 && value <= 0x7E);
}

uint64_t HexDeviceSize(const std::wstring& path) {
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return 0;
    GET_LENGTH_INFORMATION info{};
    DWORD got = 0;
    uint64_t size = 0;
    if (DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0, &info, sizeof(info), &got,
                        nullptr)) {
        size = static_cast<uint64_t>(info.Length.QuadPart);
    }
    CloseHandle(handle);
    return size;
}

bool HexReadWindow(const HexState& state, uint64_t offset, size_t length, std::vector<BYTE>& out) {
    out.clear();
    if (state.size && offset >= state.size) return false;
    HANDLE handle = CreateFileW(state.path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;

    uint64_t start = offset;
    size_t skip = 0;
    size_t want = length;
    if (state.raw) {
        start = offset & ~static_cast<uint64_t>(511);
        skip = static_cast<size_t>(offset - start);
        want = ((skip + length + 511) / 512) * 512;
    }
    if (state.size) {
        if (start >= state.size) {
            CloseHandle(handle);
            return false;
        }
        const uint64_t available = state.size - start;
        if (available < want) {
            want = static_cast<size_t>(available);
            if (state.raw) want &= ~static_cast<size_t>(511);
            if (!want) {
                CloseHandle(handle);
                return false;
            }
        }
    }

    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(start);
    if (!SetFilePointerEx(handle, position, nullptr, FILE_BEGIN)) {
        CloseHandle(handle);
        return false;
    }
    std::vector<BYTE> buffer(want);
    DWORD read = 0;
    const bool ok = ReadFile(handle, buffer.data(), static_cast<DWORD>(buffer.size()), &read,
                             nullptr) != FALSE;
    CloseHandle(handle);
    if (!ok || read <= skip) return ok;
    buffer.resize(read);
    out.assign(buffer.begin() + skip, buffer.end());
    if (out.size() > length) out.resize(length);
    return true;
}

void HexCollectStrings(const std::vector<BYTE>& data, uint64_t base, std::vector<Row>& rows,
                       std::vector<uint64_t>& offsets) {
    constexpr size_t minimum = 4;
    size_t index = 0;
    while (index < data.size()) {
        if (!HexPrintable(data[index])) {
            ++index;
            continue;
        }
        const size_t start = index;
        while (index < data.size() && HexPrintable(data[index])) ++index;
        if (index - start >= minimum) {
            std::wstring text;
            for (size_t i = start; i < index; ++i) text.push_back(static_cast<wchar_t>(data[i]));
            rows.push_back(Row{Format(L"0x%012llX", static_cast<unsigned long long>(base + start)),
                               L"ASCII", Format(L"%zu", text.size()), text});
            offsets.push_back(base + start);
        }
    }

    index = 0;
    while (index + 1 < data.size()) {
        if (!HexPrintable(data[index]) || data[index + 1] != 0) {
            ++index;
            continue;
        }
        const size_t start = index;
        while (index + 1 < data.size() && HexPrintable(data[index]) && data[index + 1] == 0) {
            index += 2;
        }
        const size_t characters = (index - start) / 2;
        if (characters >= minimum) {
            std::wstring text;
            for (size_t i = start; i < index; i += 2) text.push_back(static_cast<wchar_t>(data[i]));
            rows.push_back(Row{Format(L"0x%012llX", static_cast<unsigned long long>(base + start)),
                               L"UTF-16LE", Format(L"%zu", text.size()), text});
            offsets.push_back(base + start);
        }
    }
}

void HexLayout() {
    if (!g_hex.window) return;
    RECT rc{};
    GetClientRect(g_hex.window, &rc);
    const int pad = S(8);
    const int top = S(38);
    int x = pad;
    MoveWindow(g_hex.offsetEdit, x, S(7), S(170), S(24), TRUE);
    x += S(176);
    MoveWindow(g_hex.goBtn, x, S(6), S(52), S(26), TRUE);
    x += S(58);
    MoveWindow(g_hex.backBtn, x, S(6), S(72), S(26), TRUE);
    x += S(78);
    MoveWindow(g_hex.forwardBtn, x, S(6), S(72), S(26), TRUE);
    x += S(78);
    MoveWindow(g_hex.homeBtn, x, S(6), S(64), S(26), TRUE);
    x += S(70);
    MoveWindow(g_hex.endBtn, x, S(6), S(64), S(26), TRUE);
    x += S(70);
    MoveWindow(g_hex.prevBtn, x, S(6), S(90), S(26), TRUE);
    x += S(96);
    MoveWindow(g_hex.nextBtn, x, S(6), S(90), S(26), TRUE);

    const int width = rc.right - pad * 2;
    const int bodyHeight = rc.bottom - top - S(26);
    int listWidth = width * 36 / 100;
    if (listWidth < S(280)) listWidth = S(280);
    MoveWindow(g_hex.dump, pad, top, width - listWidth - pad, bodyHeight, TRUE);
    MoveWindow(g_hex.strings, pad + width - listWidth, top, listWidth, bodyHeight, TRUE);
    MoveWindow(g_hex.status, pad, rc.bottom - S(20), width, S(18), TRUE);
}

void HexRefresh() {
    if (!g_hex.window) return;
    std::vector<BYTE> data;
    if (!HexReadWindow(g_hex, g_hex.base, kHexWindow, data) || data.empty()) {
        SetWindowTextW(g_hex.dump, L"No readable bytes at this offset.");
        SetText(g_hex.status, L"Nothing readable at this offset.");
        return;
    }
    std::wstring text = HexDumpText(data.data(), data.size(), g_hex.base, 4096);
    SetWindowTextW(g_hex.dump, text.c_str());
    SendMessageW(g_hex.dump, EM_SETSEL, 0, 0);
    SendMessageW(g_hex.dump, EM_SCROLLCARET, 0, 0);

    std::vector<Row> rows;
    std::vector<uint64_t> offsets;
    HexCollectStrings(data, g_hex.base, rows, offsets);

    SendMessageW(g_hex.strings, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_hex.strings);
    for (size_t i = 0; i < rows.size(); ++i) {
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = static_cast<int>(i);
        item.pszText = const_cast<wchar_t*>(rows[i][0].c_str());
        ListView_InsertItem(g_hex.strings, &item);
        for (int column = 1; column < 4; ++column) {
            ListView_SetItemText(g_hex.strings, static_cast<int>(i), column,
                                 const_cast<wchar_t*>(rows[i][column].c_str()));
        }
    }
    SendMessageW(g_hex.strings, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hex.strings, nullptr, TRUE);
    g_hex.stringOffsets = std::move(offsets);

    SetText(g_hex.status,
            Format(L"%s \u00B7 offset 0x%012llX \u00B7 %s shown \u00B7 %s string(s) in this window \u00B7 %s total",
                   g_hex.label.c_str(), static_cast<unsigned long long>(g_hex.base),
                   SizeText(data.size()).c_str(), CommaNumber(rows.size()).c_str(),
                   SizeText(g_hex.size).c_str()));
    SetText(g_hex.offsetEdit,
            Format(L"0x%llX", static_cast<unsigned long long>(g_hex.base)));
}

void HexGoto(uint64_t offset) {
    if (g_hex.size && offset >= g_hex.size) offset = g_hex.size > 16 ? g_hex.size - 16 : 0;
    g_hex.base = offset & ~static_cast<uint64_t>(15);
    HexRefresh();
}

uint64_t HexParseOffset(const std::wstring& text) {
    std::wstring value = Trim(text);
    if (value.empty()) return 0;
    int radix = 10;
    if (value.size() > 2 && value[0] == L'0' && (value[1] == L'x' || value[1] == L'X')) {
        value = value.substr(2);
        radix = 16;
    } else {
        for (wchar_t ch : value) {
            if (iswalpha(ch)) {
                radix = 16;
                break;
            }
        }
    }
    return wcstoull(value.c_str(), nullptr, radix);
}

void HexJumpString(int direction) {
    if (g_hex.stringOffsets.empty()) {
        HexGoto(direction > 0 ? g_hex.base + kHexStep : (g_hex.base > kHexStep ? g_hex.base - kHexStep : 0));
        return;
    }
    uint64_t target = 0;
    bool found = false;
    if (direction > 0) {
        for (uint64_t offset : g_hex.stringOffsets) {
            if (offset > g_hex.base + 15) {
                target = offset;
                found = true;
                break;
            }
        }
        if (!found) target = g_hex.base + kHexWindow;
    } else {
        for (auto it = g_hex.stringOffsets.rbegin(); it != g_hex.stringOffsets.rend(); ++it) {
            if (*it < g_hex.base) {
                target = *it;
                found = true;
                break;
            }
        }
        if (!found) target = g_hex.base > kHexWindow ? g_hex.base - kHexWindow : 0;
    }
    HexGoto(target);
}

void HexLayout();
LRESULT CALLBACK HexProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

bool HexCreate() {
    if (g_hex.window && IsWindow(g_hex.window)) return true;
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW cls{};
        cls.cbSize = sizeof(cls);
        cls.lpfnWndProc = HexProc;
        cls.hInstance = g_instance;
        cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        cls.lpszClassName = L"WindCheckerHex";
        RegisterClassExW(&cls);
        registered = true;
    }
    RECT owner{};
    GetWindowRect(g_hwnd, &owner);
    const int width = S(1180);
    const int height = S(760);
    g_hex.window = CreateWindowExW(WS_EX_DLGMODALFRAME, L"WindCheckerHex", L"Hex Viewer",
                                   WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                                   owner.left + ((owner.right - owner.left) - width) / 2,
                                   owner.top + ((owner.bottom - owner.top) - height) / 2,
                                   width, height, g_hwnd, nullptr, g_instance, nullptr);
    if (!g_hex.window) return false;

    g_hex.font = CreateFontW(-MulDiv(9, g_dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

    g_hex.offsetEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"0x0",
                                       WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 10, 10,
                                       g_hex.window,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(3)),
                                       g_instance, nullptr);
    SendMessageW(g_hex.offsetEdit, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_hex.font ? g_hex.font : g_fontSmall), TRUE);
    g_hex.goBtn = MakeButton(g_hex.window, L"Go", 4);
    g_hex.backBtn = MakeButton(g_hex.window, L"\u2212 4 KB", 5);
    g_hex.forwardBtn = MakeButton(g_hex.window, L"+ 4 KB", 6);
    g_hex.homeBtn = MakeButton(g_hex.window, L"Start", 7);
    g_hex.endBtn = MakeButton(g_hex.window, L"End", 8);
    g_hex.prevBtn = MakeButton(g_hex.window, L"\u25C0 string", 9);
    g_hex.nextBtn = MakeButton(g_hex.window, L"string \u25B6", 10);

    g_hex.dump = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                 WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                     ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                 0, 0, 10, 10, g_hex.window,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(1)), g_instance,
                                 nullptr);
    SendMessageW(g_hex.dump, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_hex.font ? g_hex.font : g_fontSmall), TRUE);

    g_hex.strings = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                    WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL |
                                        LVS_SHOWSELALWAYS,
                                    0, 0, 10, 10, g_hex.window,
                                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(2)), g_instance,
                                    nullptr);
    SendMessageW(g_hex.strings, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
    ListView_SetExtendedListViewStyle(g_hex.strings,
                                      LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER |
                                          LVS_EX_GRIDLINES);
    {
        const wchar_t* titles[4] = {L"Offset", L"Type", L"Length", L"String"};
        const int widths[4] = {S(120), S(70), S(55), S(320)};
        const int formats[4] = {LVCFMT_LEFT, LVCFMT_LEFT, LVCFMT_RIGHT, LVCFMT_LEFT};
        for (int i = 0; i < 4; ++i) {
            LVCOLUMNW column{};
            column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
            column.pszText = const_cast<wchar_t*>(titles[i]);
            column.cx = widths[i];
            column.fmt = formats[i];
            ListView_InsertColumn(g_hex.strings, i, &column);
        }
    }

    g_hex.status = MakeLabel(g_hex.window, L"", g_fontSmall);
    HexLayout();
    return true;
}

LRESULT CALLBACK HexProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_SIZE:
        HexLayout();
        return 0;
    case WM_COMMAND: {
        const int id = LOWORD(wParam);
        if (id == 3 && HIWORD(wParam) == EN_SETFOCUS) return 0;
        switch (id) {
        case 4: HexGoto(HexParseOffset(GetText(g_hex.offsetEdit))); break;
        case 5: HexGoto(g_hex.base > kHexStep ? g_hex.base - kHexStep : 0); break;
        case 6: HexGoto(g_hex.base + kHexStep); break;
        case 7: HexGoto(0); break;
        case 8: HexGoto(g_hex.size > kHexWindow ? g_hex.size - kHexWindow : 0); break;
        case 9: HexJumpString(-1); break;
        case 10: HexJumpString(1); break;
        default: break;
        }
        return 0;
    }
    case WM_NOTIFY: {
        auto* header = reinterpret_cast<LPNMHDR>(lParam);
        if (header && header->hwndFrom == g_hex.strings && header->code == NM_DBLCLK) {
            const int item = ListView_GetNextItem(g_hex.strings, -1, LVNI_SELECTED);
            if (item >= 0 && static_cast<size_t>(item) < g_hex.stringOffsets.size()) {
                HexGoto(g_hex.stringOffsets[static_cast<size_t>(item)]);
            }
        }
        return 0;
    }
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        g_hex.window = nullptr;
        g_hex.dump = nullptr;
        g_hex.strings = nullptr;
        g_hex.offsetEdit = nullptr;
        g_hex.status = nullptr;
        g_hex.stringOffsets.clear();
        if (g_hex.font) {
            DeleteObject(g_hex.font);
            g_hex.font = nullptr;
        }
        return 0;
    default:
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
}

void HexClose() {
    if (g_hex.window && IsWindow(g_hex.window)) DestroyWindow(g_hex.window);
    g_hex.window = nullptr;
}

void ShowHexView(const std::wstring& path) {
    if (!HexCreate()) return;
    g_hex.label = PathFileName(path);
    g_hex.path = path;
    g_hex.raw = false;
    WIN32_FILE_ATTRIBUTE_DATA info{};
    g_hex.size = GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &info)
                     ? (static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow
                     : 0;
    SetWindowTextW(g_hex.window, (L"Hex \u2014 " + g_hex.label).c_str());
    HexGoto(0);
    ShowWindow(g_hex.window, SW_SHOWNORMAL);
    SetForegroundWindow(g_hex.window);
}

void ShowHexVolume(const std::wstring& volume, uint64_t offset) {
    if (!HexCreate()) return;
    std::wstring name = volume;
    while (!name.empty() && (name.back() == L'\\' || name.back() == L'/')) name.pop_back();
    if (name.size() == 1) name += L":";
    g_hex.label = name + L" (raw)";
    g_hex.path = L"\\\\.\\" + name;
    g_hex.raw = true;
    g_hex.size = HexDeviceSize(g_hex.path);
    SetWindowTextW(g_hex.window, (L"Hex \u2014 " + g_hex.label).c_str());
    HexGoto(offset);
    ShowWindow(g_hex.window, SW_SHOWNORMAL);
    SetForegroundWindow(g_hex.window);
}

void MemoryClose() {
    if (g_memory.process && g_memory.process != INVALID_HANDLE_VALUE) { CloseHandle(g_memory.process); }
    g_memory.process = INVALID_HANDLE_VALUE;
    g_memory.showingRegions = false;
    g_memory.selectedPid = 0;
    g_memory.regionBases.clear();
    g_memory.regionSizes.clear();
}

std::wstring ProtectText(DWORD p) {
    std::wstring base;
    switch (p & 0xFF) {
        case PAGE_NOACCESS: base = L"NOACCESS"; break;
        case PAGE_READONLY: base = L"READONLY"; break;
        case PAGE_READWRITE: base = L"READWRITE"; break;
        case PAGE_WRITECOPY: base = L"WRITECOPY"; break;
        case PAGE_EXECUTE: base = L"EXECUTE"; break;
        case PAGE_EXECUTE_READ: base = L"EXECUTE_READ"; break;
        case PAGE_EXECUTE_READWRITE: base = L"EXECUTE_READWRITE"; break;
        case PAGE_EXECUTE_WRITECOPY: base = L"EXECUTE_WRITECOPY"; break;
        default: base = Format(L"0x%X", p & 0xFF); break;
    }
    if (p & PAGE_GUARD) base += L"+GUARD";
    if (p & PAGE_NOCACHE) base += L"+NOCACHE";
    if (p & PAGE_WRITECOMBINE) base += L"+WC";
    return base;
}

void MemoryLoadRegions(DWORD pid, const std::wstring& name) {
    MemoryClose();
    g_memory.selectedPid = pid;
    g_memory.selectedName = name;
    g_memory.allStates = g_procMemAllCheck && IsChecked(g_procMemAllCheck);
    if (!g_memory.list) return;

    SendMessageW(g_memory.list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_memory.list);

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    g_memory.process = process;
    if (!process) {
        SendMessageW(g_memory.list, WM_SETREDRAW, TRUE, 0);
        if (g_memory.info) {
            SetText(g_memory.info, Format(L"%s (%u) \u00B7 access denied or the process exited. "
                                          L"Run WindChecker elevated to read its memory.",
                                          name.c_str(), pid));
        }
        return;
    }

    MEMORY_BASIC_INFORMATION info{};
    uintptr_t address = 0;
    int committed = 0, reserved = 0;
    unsigned long long committedBytes = 0, reservedBytes = 0;
    const int rowLimit = 20000;
    while (ListView_GetItemCount(g_memory.list) < rowLimit) {
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &info, sizeof(info)) == 0) break;
        uintptr_t base = reinterpret_cast<uintptr_t>(info.BaseAddress);
        bool isCommit = info.State == MEM_COMMIT;
        bool isReserve = info.State == MEM_RESERVE;
        if (isCommit) { ++committed; committedBytes += info.RegionSize; }
        if (isReserve) { ++reserved; reservedBytes += info.RegionSize; }

        if (isCommit || (g_memory.allStates && isReserve)) {
            std::wstring module;
            if (info.Type == MEM_IMAGE || info.Type == MEM_MAPPED) {
                wchar_t mapped[MAX_PATH] = {};
                if (GetMappedFileNameW(process, reinterpret_cast<LPVOID>(base), mapped, MAX_PATH)) {
                    module = PathFileName(mapped);
                }
            }
            const wchar_t* type = info.Type == MEM_IMAGE ? L"IMAGE"
                                : info.Type == MEM_MAPPED ? L"MAPPED"
                                : info.Type == MEM_PRIVATE ? L"PRIVATE" : L"-";
            const wchar_t* state = isCommit ? L"COMMIT" : isReserve ? L"RESERVE" : L"FREE";
            std::wstring baseText = Format(L"0x%llX", static_cast<unsigned long long>(base));
            std::wstring sizeText = FormatByteSize(info.RegionSize);
            std::wstring protectText = ProtectText(info.Protect);
            std::wstring allocText = Format(L"0x%llX",
                static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(info.AllocationBase)));

            LVITEMW item{};
            item.mask = LVIF_TEXT;
            item.iItem = ListView_GetItemCount(g_memory.list);
            item.pszText = const_cast<LPWSTR>(baseText.c_str());
            int index = ListView_InsertItem(g_memory.list, &item);
            ListView_SetItemText(g_memory.list, index, 1, const_cast<LPWSTR>(sizeText.c_str()));
            ListView_SetItemText(g_memory.list, index, 2, const_cast<LPWSTR>(type));
            ListView_SetItemText(g_memory.list, index, 3, const_cast<LPWSTR>(state));
            ListView_SetItemText(g_memory.list, index, 4, const_cast<LPWSTR>(protectText.c_str()));
            ListView_SetItemText(g_memory.list, index, 5, const_cast<LPWSTR>(allocText.c_str()));
            ListView_SetItemText(g_memory.list, index, 6, const_cast<LPWSTR>(module.c_str()));

            g_memory.regionBases.push_back(base);
            g_memory.regionSizes.push_back(static_cast<uintptr_t>(info.RegionSize));
        }

        uintptr_t next = base + info.RegionSize;
        if (info.RegionSize == 0 || next <= address) break;
        address = next;
    }
    g_memory.showingRegions = true;

    SendMessageW(g_memory.list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_memory.list, nullptr, TRUE);
    if (ListView_GetItemCount(g_memory.list) > 0) {
        ListView_SetItemState(g_memory.list, 0, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (g_memory.info) {
        SetText(g_memory.info, Format(
            L"%s (%u) \u00B7 %s committed (%s) \u00B7 %s reserved (%s) \u00B7 %s row(s) shown%s",
            name.c_str(), pid, CommaNumber(committed).c_str(), FormatByteSize(committedBytes).c_str(),
            CommaNumber(reserved).c_str(), FormatByteSize(reservedBytes).c_str(),
            CommaNumber(ListView_GetItemCount(g_memory.list)).c_str(),
            ListView_GetItemCount(g_memory.list) >= rowLimit ? L" \u00B7 row limit reached" : L""));
    }
}

std::wstring MemoryModulesReport(DWORD pid, const std::wstring& name) {
    std::wstring text = Format(L"Loaded modules in %s (PID %u)\r\n\r\n", name.c_str(), pid);
    text += L"Base                Size        Module                          Path\r\n";
    text += L"------------------  ----------  ------------------------------  ------------------------------\r\n";
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        text += L"(module enumeration failed. Run WindChecker elevated; a 32-bit target is only partly visible from the 64-bit build.)\r\n";
        return text;
    }
    MODULEENTRY32W me{sizeof(me)};
    int count = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            text += Format(L"0x%016llX  %10s  %-30s  %s\r\n",
                           static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(me.modBaseAddr)),
                           FormatByteSize(me.modBaseSize).c_str(), me.szModule, me.szExePath);
            if (++count >= 2000) { text += L"\u2026 (truncated at 2000 modules)\r\n"; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    text += Format(L"\r\n%s module(s)\r\n", CommaNumber(count).c_str());
    return text;
}

std::wstring MemoryThreadsReport(DWORD pid, const std::wstring& name) {
    std::wstring text = Format(L"Threads in %s (PID %u)\r\n\r\n", name.c_str(), pid);
    text += L"TID       Prio  Base  Created               CPU time    Flags\r\n";
    text += L"--------  ----  ----  --------------------  ----------  -----\r\n";
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return text + L"(thread enumeration failed)\r\n";
    THREADENTRY32 te{sizeof(te)};
    int count = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            std::wstring created = L"-", cpu = L"-", priority = L"-";
            HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (thread) {
                FILETIME creation{}, exitTime{}, kernel{}, user{};
                if (GetThreadTimes(thread, &creation, &exitTime, &kernel, &user)) {
                    created = FileTimeText(creation);
                    ULARGE_INTEGER k{}, u{};
                    k.LowPart = kernel.dwLowDateTime; k.HighPart = kernel.dwHighDateTime;
                    u.LowPart = user.dwLowDateTime; u.HighPart = user.dwHighDateTime;
                    cpu = Format(L"%.2f s", static_cast<double>(k.QuadPart + u.QuadPart) / 10000000.0);
                }
                int value = GetThreadPriority(thread);
                if (value != THREAD_PRIORITY_ERROR_RETURN) priority = Format(L"%d", value);
                CloseHandle(thread);
            }
            text += Format(L"%-8u  %-4s  %-4u  %-20s  %-10s  0x%X\r\n",
                           te.th32ThreadID, priority.c_str(), te.tpBasePri, created.c_str(),
                           cpu.c_str(), te.dwFlags);
            if (++count >= 3000) { text += L"\u2026 (truncated at 3000 threads)\r\n"; break; }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    text += Format(L"\r\n%s thread(s)\r\n", CommaNumber(count).c_str());
    return text;
}

std::wstring MemoryHeapsReport(DWORD pid, const std::wstring& name) {
    std::wstring text = Format(L"Heaps in %s (PID %u)\r\n\r\n", name.c_str(), pid);
    text += L"Heap ID            Flags       Blocks      Bytes\r\n";
    text += L"-----------------  ----------  ----------  ----------\r\n";
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);
    if (snap == INVALID_HANDLE_VALUE) return text + L"(heap enumeration failed)\r\n";
    HEAPLIST32 list{sizeof(list)};
    int heaps = 0;
    ULONGLONG totalBytes = 0;
    while (Heap32ListNext(snap, &list)) {
        HEAPENTRY32 entry{sizeof(entry)};
        int blocks = 0;
        ULONGLONG bytes = 0;
        if (Heap32First(&entry, pid, list.th32HeapID)) {
            do {
                bytes += entry.dwSize;
                if (++blocks >= 20000) break;
            } while (Heap32Next(&entry));
        }
        totalBytes += bytes;
        text += Format(L"0x%016llX 0x%08X  %10s  %10s\r\n",
                       static_cast<unsigned long long>(list.th32HeapID), list.dwFlags,
                       CommaNumber(blocks).c_str(), FormatByteSize(bytes).c_str());
        if (++heaps >= 500) { text += L"\u2026 (truncated at 500 heaps)\r\n"; break; }
    }
    CloseHandle(snap);
    text += Format(L"\r\n%s heap(s), %s in blocks (block walks are capped at 20,000 per heap)\r\n",
                   CommaNumber(heaps).c_str(), FormatByteSize(totalBytes).c_str());
    return text;
}

struct WcUnicodeString { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };
struct WcObjectTypeInfo { WcUnicodeString TypeName; };
struct WcHandleEntry {
    void* Object;
    ULONG_PTR ProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};
struct WcHandleInfo {
    ULONG_PTR Count;
    ULONG_PTR Reserved;
    WcHandleEntry Entries[1];
};

std::wstring MemoryHandlesReport(DWORD pid, const std::wstring& name) {
    std::wstring text = Format(L"Handles in %s (PID %u)\r\n\r\n", name.c_str(), pid);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto querySystem = ntdll ? reinterpret_cast<LONG (NTAPI*)(ULONG, PVOID, ULONG, PULONG)>(
                                   GetProcAddress(ntdll, "NtQuerySystemInformation")) : nullptr;
    auto queryObject = ntdll ? reinterpret_cast<LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG)>(
                                   GetProcAddress(ntdll, "NtQueryObject")) : nullptr;
    if (!querySystem || !queryObject) return text + L"(NtQuerySystemInformation is unavailable)\r\n";

    std::vector<unsigned char> buffer(1 << 20);
    LONG status = -1;
    for (int attempt = 0; attempt < 6; ++attempt) {
        ULONG needed = 0;
        status = querySystem(64 , buffer.data(),
                             static_cast<ULONG>(buffer.size()), &needed);
        if (status >= 0) break;
        if (needed > buffer.size()) buffer.resize(needed + 65536);
        else buffer.resize(buffer.size() * 2);
    }
    if (status < 0) return text + L"(the handle table could not be read; run elevated)\r\n";

    HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    auto* info = reinterpret_cast<WcHandleInfo*>(buffer.data());
    std::map<std::wstring, int> counts;
    std::map<USHORT, std::wstring> typeNames;
    std::vector<std::wstring> lines;
    ULONG_PTR found = 0;
    for (ULONG_PTR i = 0; i < info->Count; ++i) {
        const WcHandleEntry& entry = info->Entries[i];
        if (entry.ProcessId != pid) continue;
        ++found;
        std::wstring type = L"?";
        auto cached = typeNames.find(entry.ObjectTypeIndex);
        if (cached != typeNames.end()) {
            type = cached->second;
        } else if (process) {
            HANDLE duplicate = nullptr;
            if (DuplicateHandle(process, entry.HandleValue, GetCurrentProcess(), &duplicate, 0,
                                FALSE, DUPLICATE_SAME_ACCESS)) {
                unsigned char typeBuffer[1024] = {};
                ULONG returned = 0;
                if (queryObject(duplicate, 2 , typeBuffer,
                                sizeof(typeBuffer), &returned) >= 0) {
                    auto* typeInfo = reinterpret_cast<WcObjectTypeInfo*>(typeBuffer);
                    if (typeInfo->TypeName.Buffer && typeInfo->TypeName.Length)
                        type.assign(typeInfo->TypeName.Buffer, typeInfo->TypeName.Length / 2);
                }
                CloseHandle(duplicate);
            }
            typeNames[entry.ObjectTypeIndex] = type;
        }
        counts[type] += 1;
        if (lines.size() < 3000) {
            lines.push_back(Format(L"0x%04llX  %-28s  access 0x%08X",
                                   static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(entry.HandleValue)),
                                   type.c_str(), entry.GrantedAccess));
        }
    }
    if (process) CloseHandle(process);

    std::vector<std::pair<int, std::wstring>> ordered;
    for (const auto& item : counts) ordered.push_back({item.second, item.first});
    std::sort(ordered.begin(), ordered.end(),
              [](const std::pair<int, std::wstring>& a, const std::pair<int, std::wstring>& b) {
                  return a.first > b.first;
              });
    text += L"By object type\r\n";
    for (const auto& item : ordered) {
        text += Format(L"  %-30s %s\r\n", item.second.c_str(), CommaNumber(item.first).c_str());
    }
    text += L"\r\nHandles\r\n";
    text += L"Handle  Type                          Access\r\n";
    text += L"------  ----------------------------  ------\r\n";
    for (const std::wstring& line : lines) { text += line; text += L"\r\n"; }
    if (found > lines.size()) text += L"\u2026 (list truncated; the summary above counts every handle)\r\n";
    text += Format(L"\r\n%s handle(s)\r\n", CommaNumber(found).c_str());
    return text;
}

std::wstring MemoryMapReport(DWORD pid, const std::wstring& name) {
    std::wstring text = Format(L"Memory map for %s (PID %u)\r\n\r\n", name.c_str(), pid);
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) return text + L"(could not open the process; run elevated)\r\n";

    struct Stats { uint64_t bytes = 0; unsigned count = 0; };
    Stats committed, reserved, released, image, mapped, privateBytes;
    std::map<std::wstring, Stats> byProtection;
    std::vector<std::pair<uint64_t, std::wstring>> largest;
    MEMORY_BASIC_INFORMATION info{};
    uintptr_t address = 0;
    while (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &info, sizeof(info)) == sizeof(info)) {
        uint64_t size = static_cast<uint64_t>(info.RegionSize);
        if (info.State == MEM_COMMIT) {
            committed.bytes += size;
            ++committed.count;
            if (info.Type == MEM_IMAGE) { image.bytes += size; ++image.count; }
            else if (info.Type == MEM_MAPPED) { mapped.bytes += size; ++mapped.count; }
            else { privateBytes.bytes += size; ++privateBytes.count; }
            Stats& protect = byProtection[ProtectText(info.Protect)];
            protect.bytes += size;
            ++protect.count;
            if (largest.size() < 200) {
                std::wstring module;
                wchar_t mappedName[MAX_PATH] = {};
                if (GetMappedFileNameW(process, reinterpret_cast<LPVOID>(info.BaseAddress), mappedName, MAX_PATH))
                    module = L"  " + std::wstring(PathFileName(mappedName));
                largest.push_back({size, Format(L"0x%016llX  %10s  %-18s%s",
                                                static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(info.BaseAddress)),
                                                FormatByteSize(size).c_str(), ProtectText(info.Protect).c_str(),
                                                module.c_str())});
            }
        } else if (info.State == MEM_RESERVE) {
            reserved.bytes += size;
            ++reserved.count;
        } else {
            released.bytes += size;
            ++released.count;
        }
        uintptr_t next = reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
        if (!info.RegionSize || next <= address) break;
        address = next;
    }
    CloseHandle(process);

    text += Format(L"Committed : %10s  %s region(s)\r\n", FormatByteSize(committed.bytes).c_str(), CommaNumber(committed.count).c_str());
    text += Format(L"  Image   : %10s  %s\r\n", FormatByteSize(image.bytes).c_str(), CommaNumber(image.count).c_str());
    text += Format(L"  Mapped  : %10s  %s\r\n", FormatByteSize(mapped.bytes).c_str(), CommaNumber(mapped.count).c_str());
    text += Format(L"  Private : %10s  %s\r\n", FormatByteSize(privateBytes.bytes).c_str(), CommaNumber(privateBytes.count).c_str());
    text += Format(L"Reserved  : %10s  %s region(s)\r\n", FormatByteSize(reserved.bytes).c_str(), CommaNumber(reserved.count).c_str());
    text += Format(L"Free      : %10s  %s region(s)\r\n", FormatByteSize(released.bytes).c_str(), CommaNumber(released.count).c_str());

    text += L"\r\nBy protection\r\n";
    std::vector<std::pair<uint64_t, std::wstring>> ordered;
    for (const auto& item : byProtection) ordered.push_back({item.second.bytes, item.first});
    std::sort(ordered.begin(), ordered.end(),
              [](const std::pair<uint64_t, std::wstring>& a, const std::pair<uint64_t, std::wstring>& b) {
                  return a.first > b.first;
              });
    for (const auto& item : ordered) {
        text += Format(L"  %-24s %10s  %s region(s)\r\n", item.second.c_str(),
                       FormatByteSize(item.first).c_str(), CommaNumber(byProtection[item.second].count).c_str());
    }

    std::sort(largest.begin(), largest.end(),
              [](const std::pair<uint64_t, std::wstring>& a, const std::pair<uint64_t, std::wstring>& b) {
                  return a.first > b.first;
              });
    text += L"\r\nLargest committed regions\r\n";
    text += L"Base                Size        Protection          Module\r\n";
    size_t shown = largest.size() < 15 ? largest.size() : 15;
    for (size_t i = 0; i < shown; ++i) { text += L"  "; text += largest[i].second; text += L"\r\n"; }
    return text;
}

struct MemoryDumpWindow {
    HWND window = nullptr;
    HWND edit = nullptr;
    HWND save = nullptr;
    HWND strings = nullptr;
    HWND close = nullptr;
    HFONT font = nullptr;
    std::vector<unsigned char> bytes;
    std::wstring caption;
    uintptr_t base = 0;
    DWORD pid = 0;
};
MemoryDumpWindow g_memDump;

void LayoutMemoryDump() {
    if (!g_memDump.window) return;
    RECT rc{};
    GetClientRect(g_memDump.window, &rc);
    int pad = S(10);
    int buttonHeight = S(26);
    int buttonWidth = S(96);
    int top = rc.bottom - pad - buttonHeight;
    MoveWindow(g_memDump.edit, pad, pad, rc.right - pad * 2, top - pad - S(8), TRUE);
    int x = pad;
    MoveWindow(g_memDump.save, x, top, buttonWidth, buttonHeight, TRUE);
    x += buttonWidth + S(8);
    MoveWindow(g_memDump.strings, x, top, buttonWidth, buttonHeight, TRUE);
    MoveWindow(g_memDump.close, rc.right - pad - buttonWidth, top, buttonWidth, buttonHeight, TRUE);
}

void SaveMemoryDump() {
    if (g_memDump.bytes.empty()) return;
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"dump_%u_%llX.bin", g_memDump.pid,
             static_cast<unsigned long long>(g_memDump.base));
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_memDump.window;
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Binary dump\0*.bin\0All files\0*.*\0";
    ofn.lpstrDefExt = L"bin";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        ShowTextDialog(L"Save dump", L"The dump could not be written.", L"");
        return;
    }
    DWORD written = 0;
    WriteFile(file, g_memDump.bytes.data(), static_cast<DWORD>(g_memDump.bytes.size()), &written, nullptr);
    CloseHandle(file);
    SetWindowTextW(g_memDump.window, (L"Memory dump \u2014 saved " + PathFileName(path)).c_str());
}

std::wstring MemoryStringsText(const std::vector<unsigned char>& data, size_t maxStrings) {
    std::wstring out;
    std::vector<std::wstring> ascii;
    std::wstring current;
    for (size_t i = 0; i < data.size() && ascii.size() < maxStrings; ++i) {
        unsigned char c = data[i];
        if (c >= 0x20 && c < 0x7F) {
            current.push_back(static_cast<wchar_t>(c));
        } else {
            if (current.size() >= 4) ascii.push_back(current);
            current.clear();
        }
    }
    if (current.size() >= 4 && ascii.size() < maxStrings) ascii.push_back(current);

    std::vector<std::wstring> wide;
    current.clear();
    for (size_t i = 0; i + 1 < data.size() && wide.size() < maxStrings; i += 2) {
        wchar_t c = static_cast<wchar_t>(data[i] | (data[i + 1] << 8));
        if (c >= 0x20 && c < 0x7F) {
            current.push_back(c);
        } else {
            if (current.size() >= 4) wide.push_back(current);
            current.clear();
        }
    }
    if (current.size() >= 4 && wide.size() < maxStrings) wide.push_back(current);

    out += Format(L"ASCII strings: %s\r\n", CommaNumber(ascii.size()).c_str());
    for (const std::wstring& line : ascii) { out += L"  "; out += line; out += L"\r\n"; }
    out += Format(L"\r\nUTF-16LE strings: %s\r\n", CommaNumber(wide.size()).c_str());
    for (const std::wstring& line : wide) { out += L"  "; out += line; out += L"\r\n"; }
    return out;
}

LRESULT CALLBACK MemoryDumpProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_SIZE:
        LayoutMemoryDump();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == 1) { SaveMemoryDump(); return 0; }
        if (LOWORD(wParam) == 2) {
            ShowTextDialog(L"Strings \u2014 " + g_memDump.caption,
                           L"Printable ASCII and UTF-16LE runs of four or more characters from the whole dump.",
                           MemoryStringsText(g_memDump.bytes, 4000));
            return 0;
        }
        if (LOWORD(wParam) == IDCANCEL) { DestroyWindow(hwnd); return 0; }
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (g_memDump.font) { DeleteObject(g_memDump.font); g_memDump.font = nullptr; }
        g_memDump.window = nullptr;
        g_memDump.edit = nullptr;
        g_memDump.save = nullptr;
        g_memDump.strings = nullptr;
        g_memDump.close = nullptr;
        g_memDump.bytes.clear();
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

void MemoryOpenDump(size_t ri) {
    if (!g_memory.process || g_memory.process == INVALID_HANDLE_VALUE || ri >= g_memory.regionBases.size()) return;
    uintptr_t base = g_memory.regionBases[ri];
    uint64_t size = ri < g_memory.regionSizes.size() ? g_memory.regionSizes[ri] : 0;
    const uint64_t limit = 32ull * 1024 * 1024;
    uint64_t want = size > limit ? limit : size;
    std::vector<unsigned char> bytes(static_cast<size_t>(want));
    SIZE_T read = 0;
    if (!ReadProcessMemory(g_memory.process, reinterpret_cast<LPCVOID>(base), bytes.data(),
                           static_cast<SIZE_T>(want), &read)) {
        read = 0;
    }
    bytes.resize(read);

    if (!g_memDump.window) {
        static bool registered = false;
        if (!registered) {
            WNDCLASSEXW cls{};
            cls.cbSize = sizeof(cls);
            cls.lpfnWndProc = MemoryDumpProc;
            cls.hInstance = g_instance;
            cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
            cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
            cls.lpszClassName = L"WindCheckerMemoryDump";
            RegisterClassExW(&cls);
            registered = true;
        }
        RECT owner{};
        GetWindowRect(g_hwnd, &owner);
        int width = S(1000);
        int height = S(720);
        g_memDump.window = CreateWindowExW(WS_EX_DLGMODALFRAME, L"WindCheckerMemoryDump", L"Memory dump",
                                           WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                                           owner.left + ((owner.right - owner.left) - width) / 2,
                                           owner.top + ((owner.bottom - owner.top) - height) / 2,
                                           width, height, g_hwnd, nullptr, g_instance, nullptr);
        if (!g_memDump.window) return;
        g_memDump.font = CreateFontW(-MulDiv(9, g_dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                     DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                     CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
        g_memDump.edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                         WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                             ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                         0, 0, 0, 0, g_memDump.window,
                                         reinterpret_cast<HMENU>(static_cast<INT_PTR>(3)),
                                         g_instance, nullptr);
        g_memDump.save = CreateWindowExW(0, L"BUTTON", L"Save\u2026", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                         0, 0, 0, 0, g_memDump.window,
                                         reinterpret_cast<HMENU>(static_cast<INT_PTR>(1)), g_instance, nullptr);
        g_memDump.strings = CreateWindowExW(0, L"BUTTON", L"Strings", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                            0, 0, 0, 0, g_memDump.window,
                                            reinterpret_cast<HMENU>(static_cast<INT_PTR>(2)), g_instance, nullptr);
        g_memDump.close = CreateWindowExW(0, L"BUTTON", L"Close", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                          0, 0, 0, 0, g_memDump.window,
                                          reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDCANCEL)), g_instance, nullptr);
        SendMessageW(g_memDump.edit, WM_SETFONT,
                     reinterpret_cast<WPARAM>(g_memDump.font ? g_memDump.font : g_fontMono), TRUE);
        SendMessageW(g_memDump.save, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontUI), TRUE);
        SendMessageW(g_memDump.strings, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontUI), TRUE);
        SendMessageW(g_memDump.close, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontUI), TRUE);
        LayoutMemoryDump();
    }

    g_memDump.bytes = std::move(bytes);
    g_memDump.base = base;
    g_memDump.pid = g_memory.selectedPid;
    g_memDump.caption = Format(L"%s 0x%llX", g_memory.selectedName.c_str(),
                               static_cast<unsigned long long>(base));

    const size_t shownRows = 8192;
    std::wstring text = Format(L"%s (PID %u)\r\nBase 0x%llX \u00B7 region %s \u00B7 read %s\r\n\r\n",
                               g_memory.selectedName.c_str(), g_memory.selectedPid,
                               static_cast<unsigned long long>(base), FormatByteSize(size).c_str(),
                               FormatByteSize(read).c_str());
    text += HexDumpText(g_memDump.bytes.data(), g_memDump.bytes.size(), base, shownRows);
    if (g_memDump.bytes.size() > shownRows * 16) {
        text += Format(L"\r\nShowing the first %s. Save\u2026 writes all %s read from the region.\r\n",
                       FormatByteSize(shownRows * 16).c_str(), FormatByteSize(read).c_str());
    }
    SetWindowTextW(g_memDump.window, (L"Memory dump \u2014 " + g_memDump.caption).c_str());
    SetWindowTextW(g_memDump.edit, text.c_str());
    ShowWindow(g_memDump.window, SW_SHOWNORMAL);
    SetForegroundWindow(g_memDump.window);
}

DWORD ProcessRowPid(const Row& row) {
    if (row.empty()) return 0;
    if (row[0] == L"-" || row[0] == L"drivers") return 0;
    return static_cast<DWORD>(wcstoul(row[0].c_str(), nullptr, 10));
}

std::wstring ProcessRowName(const Tab& tab, const Row& row) {
    if (!IsProcessChildRow(row)) return ProcessDisplayName(row);
    DWORD pid = ProcessRowPid(row);
    for (const Row& candidate : tab.records) {
        if (candidate.size() >= 8 && ProcessRowPid(candidate) == pid) {
            return ProcessDisplayName(candidate);
        }
    }
    return L"";
}

DWORD MemorySelectedPid(std::wstring& name) {
    Tab& tab = g_tabs[TAB_PROCESS];
    if (!tab.tree) return 0;
    HTREEITEM item = TreeView_GetSelection(tab.tree);
    size_t index = TreeRecordIndex(tab.tree, item);
    if (index >= tab.records.size()) return 0;
    const Row& row = tab.records[index];
    DWORD pid = ProcessRowPid(row);
    if (!pid) return 0;
    name = ProcessRowName(tab, row);
    return pid;
}

void MemoryShowReport(int which) {
    std::wstring name;
    DWORD pid = MemorySelectedPid(name);
    if (!pid) {
        MessageBoxW(g_hwnd, L"Select a process in the tree first.", APP_TITLE, MB_ICONINFORMATION);
        return;
    }
    std::wstring title, hint, text;
    switch (which) {
    case 0:
        title = L"Modules";
        hint = L"Every module mapped into the process, with base address, size and full path.";
        text = MemoryModulesReport(pid, name);
        break;
    case 1:
        title = L"Threads";
        hint = L"Every thread in the process with priority, creation time and CPU time.";
        text = MemoryThreadsReport(pid, name);
        break;
    case 2:
        title = L"Handles";
        hint = L"Kernel handles held by the process, grouped by object type, with granted access.";
        text = MemoryHandlesReport(pid, name);
        break;
    case 3:
        title = L"Heaps";
        hint = L"Private heaps and their blocks, walked with the toolhelp heap APIs.";
        text = MemoryHeapsReport(pid, name);
        break;
    default:
        title = L"Memory map";
        hint = L"Committed, reserved and free address space, grouped by type and protection.";
        text = MemoryMapReport(pid, name);
        break;
    }
    ShowTextDialog(title + L" \u2014 " + name + Format(L" (%u)", pid), hint, text);
}

void ProcessSelectNode(Tab& tab, size_t index) {
    if (index >= tab.records.size()) return;
    if (g_procMemoryMode) {
        const Row& row = tab.records[index];
        DWORD pid = ProcessRowPid(row);
        if (pid) MemoryLoadRegions(pid, ProcessRowName(tab, row));
    } else {
        UpdateProcessDetail(tab, index);
    }
}

void MemoryReloadSelected() {
    std::wstring name;
    DWORD pid = MemorySelectedPid(name);
    if (pid) {
        MemoryLoadRegions(pid, name);
    } else if (g_memory.info) {
        SetText(g_memory.info, L"Select a process in the tree first.");
    }
}

void MemoryDumpSelected() {
    int item = ListView_GetNextItem(g_memory.list, -1, LVNI_SELECTED);
    if (item >= 0) MemoryOpenDump(static_cast<size_t>(item));
}

void SetProcessMemoryMode(bool memory) {
    g_procMemoryMode = memory;
    Tab& tab = g_tabs[TAB_PROCESS];
    ShowWindow(tab.detailPane, memory ? SW_HIDE : SW_SHOW);
    ShowWindow(g_memory.list, memory ? SW_SHOW : SW_HIDE);
    ShowWindow(g_memory.info, memory ? SW_SHOW : SW_HIDE);
    ShowWindow(g_procMemAllCheck, memory ? SW_SHOW : SW_HIDE);
    for (HWND button : g_procMemButtons) ShowWindow(button, memory ? SW_SHOW : SW_HIDE);
    SendMessageW(g_procDetailsBtn, BM_SETCHECK, memory ? BST_UNCHECKED : BST_CHECKED, 0);
    SendMessageW(g_procMemoryBtn, BM_SETCHECK, memory ? BST_CHECKED : BST_UNCHECKED, 0);
    if (memory) {
        MemoryReloadSelected();
    } else {
        HTREEITEM selected = tab.tree ? TreeView_GetSelection(tab.tree) : nullptr;
        size_t index = TreeRecordIndex(tab.tree, selected);
        if (index != static_cast<size_t>(-1)) UpdateProcessDetail(tab, index);
    }
    LayoutAll();
}

HKEY RegRootKey(const std::wstring& root) {
    if (root == L"HKEY_CLASSES_ROOT" || root == L"HKCR") return HKEY_CLASSES_ROOT;
    if (root == L"HKEY_CURRENT_USER" || root == L"HKCU") return HKEY_CURRENT_USER;
    if (root == L"HKEY_LOCAL_MACHINE" || root == L"HKLM") return HKEY_LOCAL_MACHINE;
    if (root == L"HKEY_USERS" || root == L"HKU") return HKEY_USERS;
    if (root == L"HKEY_CURRENT_CONFIG" || root == L"HKCC") return HKEY_CURRENT_CONFIG;
    return nullptr;
}

bool RegOpenPath(const std::wstring& path, HKEY& out, bool& needClose) {
    size_t slash = path.find(L'\\');
    std::wstring root = (slash == std::wstring::npos) ? path : path.substr(0, slash);
    std::wstring sub = (slash == std::wstring::npos) ? L"" : path.substr(slash + 1);
    HKEY hkRoot = RegRootKey(root);
    if (!hkRoot) return false;
    if (sub.empty()) { out = hkRoot; needClose = false; return true; }
    LONG r = RegOpenKeyExW(hkRoot, sub.c_str(), 0, KEY_READ, &out);
    needClose = (r == ERROR_SUCCESS);
    return r == ERROR_SUCCESS;
}

const wchar_t* RegTypeName(DWORD type) {
    switch (type) {
    case REG_SZ: return L"REG_SZ";
    case REG_EXPAND_SZ: return L"REG_EXPAND_SZ";
    case REG_MULTI_SZ: return L"REG_MULTI_SZ";
    case REG_DWORD: return L"REG_DWORD";
    case REG_DWORD_BIG_ENDIAN: return L"REG_DWORD_BIG_ENDIAN";
    case REG_QWORD: return L"REG_QWORD";
    case REG_BINARY: return L"REG_BINARY";
    case REG_NONE: return L"REG_NONE";
    case REG_LINK: return L"REG_LINK";
    case REG_RESOURCE_LIST: return L"REG_RESOURCE_LIST";
    case REG_FULL_RESOURCE_DESCRIPTOR: return L"REG_FULL_RESOURCE_DESCRIPTOR";
    case REG_RESOURCE_REQUIREMENTS_LIST: return L"REG_RESOURCE_REQUIREMENTS_LIST";
    default: return L"REG_UNKNOWN";
    }
}

int RegTypeIcon(DWORD type) {
    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ || type == REG_LINK) {
        return g_reg.textIcon;
    }
    if (type == REG_DWORD || type == REG_QWORD || type == REG_DWORD_BIG_ENDIAN) {
        return g_reg.numberIcon;
    }
    return g_reg.binaryIcon;
}

std::wstring RegFormatValue(DWORD type, const BYTE* data, DWORD size) {
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        std::wstring s(reinterpret_cast<const wchar_t*>(data), size / 2);
        while (!s.empty() && s.back() == L'\0') s.pop_back();
        if (type == REG_EXPAND_SZ) return L"(expanded) " + s;
        return s;
    }
    if (type == REG_MULTI_SZ) {
        std::wstring s(reinterpret_cast<const wchar_t*>(data), size / 2);
        std::wstring out;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == L'\0') {
                if (i + 1 < s.size()) out += L" | ";
            } else {
                out += s[i];
            }
        }
        return out;
    }
    if (type == REG_DWORD && size >= sizeof(DWORD)) {
        DWORD v = *reinterpret_cast<const DWORD*>(data);
        return Format(L"%u (0x%08X)", v, v);
    }
    if (type == REG_DWORD_BIG_ENDIAN && size >= sizeof(DWORD)) {
        DWORD raw = *reinterpret_cast<const DWORD*>(data);
        DWORD v = ((raw & 0x000000FFu) << 24) | ((raw & 0x0000FF00u) << 8) |
                  ((raw & 0x00FF0000u) >> 8) | ((raw & 0xFF000000u) >> 24);
        return Format(L"%u (0x%08X, big-endian)", v, v);
    }
    if (type == REG_QWORD && size >= sizeof(uint64_t)) {
        uint64_t v = *reinterpret_cast<const uint64_t*>(data);
        return Format(L"%llu (0x%llX)", v, v);
    }
    std::wstring out = Format(L"[%s byte(s)]\r\n", CommaNumber(size).c_str());
    const DWORD limit = size > 8192 ? 8192 : size;
    for (DWORD i = 0; i < limit; ++i) {
        if (i % 16 == 0) {
            if (i) out += L"\r\n";
            out += Format(L"%08X  ", i);
        }
        out += Format(L"%02X ", data[i]);
    }
    if (limit < size) out += L"\r\n\u2026 (display capped at 8 KB)";
    return out;
}

std::wstring RegPreview(std::wstring text, size_t limit) {
    for (wchar_t& ch : text) {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t') ch = L' ';
    }
    while (text.find(L"  ") != std::wstring::npos) text.replace(text.find(L"  "), 2, L" ");
    if (text.size() > limit) text = text.substr(0, limit) + L"\u2026";
    return text;
}

void RegShowValueDetail(int item) {
    if (!g_reg.valueDetail || item < 0 || static_cast<size_t>(item) >= g_reg.valueDetails.size()) return;
    SetText(g_reg.valueDetail, g_reg.valueDetails[static_cast<size_t>(item)]);
}

void RegResetValueLists() {
    ListView_DeleteAllItems(g_reg.list);
    g_reg.valueNames.clear();
    g_reg.valueTypes.clear();
    g_reg.valueData.clear();
    g_reg.valuePaths.clear();
    g_reg.valueDetails.clear();
    g_reg.valueKinds.clear();
}

void RegListValues(const std::wstring& path) {
    if (!g_reg.list) return;
    RegResetValueLists();

    HKEY hk = nullptr;
    bool needClose = false;
    if (!RegOpenPath(path, hk, needClose)) {
        if (g_reg.header) SetText(g_reg.header, path);
        SetText(g_reg.valueDetail, L"Cannot open this key. It may be protected; run WindChecker elevated.");
        return;
    }

    DWORD index = 0;
    std::vector<wchar_t> name(16384);
    int shown = 0;
    while (true) {
        DWORD nameLength = static_cast<DWORD>(name.size()) - 1;
        DWORD type = 0;
        DWORD size = 0;
        LONG result = RegEnumValueW(hk, index, name.data(), &nameLength, nullptr, &type, nullptr, &size);
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS && result != ERROR_MORE_DATA) break;

        std::wstring valueName(name.data(), nameLength);
        std::vector<BYTE> data(size ? size : 1);
        DWORD dataSize = size;
        if (RegQueryValueExW(hk, name.data(), nullptr, &type, data.data(), &dataSize) != ERROR_SUCCESS) {
            dataSize = 0;
        }
        std::wstring formatted = RegFormatValue(type, data.data(), dataSize);
        std::wstring typeName = RegTypeName(type);

        g_reg.valueNames.push_back(valueName);
        g_reg.valueTypes.push_back(typeName);
        g_reg.valueData.push_back(formatted);
        g_reg.valuePaths.push_back(path);
        g_reg.valueDetails.push_back(
            L"Value : " + (valueName.empty() ? std::wstring(L"(Default)") : valueName) +
            L"\r\nKey   : " + path + L"\r\nType  : " + typeName + L"\r\n\r\n" + formatted);
        g_reg.valueKinds.push_back(0);

        LVITEMW entry{};
        entry.mask = LVIF_TEXT | LVIF_IMAGE;
        entry.iItem = ListView_GetItemCount(g_reg.list);
        entry.pszText = const_cast<LPWSTR>(valueName.empty() ? L"(Default)" : valueName.c_str());
        entry.iImage = RegTypeIcon(type);
        int row = ListView_InsertItem(g_reg.list, &entry);
        std::wstring preview = RegPreview(formatted, 360);
        ListView_SetItemText(g_reg.list, row, 1, const_cast<LPWSTR>(typeName.c_str()));
        ListView_SetItemText(g_reg.list, row, 2, const_cast<LPWSTR>(preview.c_str()));

        ++shown;
        ++index;
        if (shown >= 4000) break;
    }
    if (needClose) RegCloseKey(hk);

    if (g_reg.header) {
        SetText(g_reg.header, Format(L"%s  \u00B7  %s value(s)%s", path.c_str(),
                                     CommaNumber(shown).c_str(),
                                     shown >= 4000 ? L" (list capped)" : L""));
    }
    if (shown == 0) {
        SetText(g_reg.valueDetail, L"This key has no values. Expand it in the tree to browse subkeys.");
    } else {
        ListView_SetItemState(g_reg.list, 0, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
        RegShowValueDetail(0);
    }
}

void RegShowValues(HWND tree) {
    if (g_reg.searchActive) {
        g_reg.searchActive = false;
        g_reg.searchGeneration += 1;
        g_reg.lastQuery.clear();
        if (g_reg.searchEdit) SetText(g_reg.searchEdit, L"");
        if (g_reg.hint) SetText(g_reg.hint, L"Live hives \u00B7 expand a hive to enumerate its subkeys.");
    }
    HTREEITEM sel = TreeView_GetSelection(tree);
    if (!sel) {
        RegResetValueLists();
        return;
    }
    TVITEMW item{};
    item.hItem = sel;
    item.mask = TVIF_PARAM;
    TreeView_GetItem(tree, &item);
    auto* ppath = reinterpret_cast<std::wstring*>(item.lParam);
    if (!ppath) return;
    RegListValues(*ppath);
}

void RegPopulate(HWND tree, HTREEITEM parent, std::wstring* ppath) {
    std::wstring path = *ppath;
    if (TreeView_GetChild(tree, parent)) return;
    HKEY hk = nullptr;
    bool needClose = false;
    if (!RegOpenPath(path, hk, needClose)) return;
    DWORD index = 0;
    wchar_t name[512];
    DWORD nameLength = 512;
    int added = 0;
    while (RegEnumKeyExW(hk, index, name, &nameLength, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        std::wstring childPath = path + L"\\" + std::wstring(name, nameLength);
        g_reg.paths.push_back(childPath);
        TVINSERTSTRUCTW ti{};
        ti.hParent = parent;
        ti.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_CHILDREN | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
        ti.item.pszText = const_cast<LPWSTR>(name);
        ti.item.cChildren = 1;
        ti.item.lParam = reinterpret_cast<LPARAM>(&g_reg.paths.back());
        ti.item.iImage = g_reg.keyIcon;
        ti.item.iSelectedImage = g_reg.keyIcon;
        TreeView_InsertItem(tree, &ti);
        ++index;
        nameLength = 512;
        if (++added >= 2000) break;
    }
    if (added == 0) {
        TVITEMW ti{};
        ti.hItem = parent;
        ti.mask = TVIF_CHILDREN;
        ti.cChildren = 0;
        TreeView_SetItem(tree, &ti);
    }
    if (needClose) RegCloseKey(hk);
}

void RegAddRoot(HWND tree, const wchar_t* name) {
    g_reg.paths.push_back(name);
    TVINSERTSTRUCTW ti{};
    ti.hParent = TVI_ROOT;
    ti.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_CHILDREN | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
    ti.item.pszText = const_cast<LPWSTR>(name);
    ti.item.cChildren = 1;
    ti.item.lParam = reinterpret_cast<LPARAM>(&g_reg.paths.back());
    ti.item.iImage = g_reg.rootIcon;
    ti.item.iSelectedImage = g_reg.rootIcon;
    TreeView_InsertItem(tree, &ti);
}

void RegLoadHive() {
    OPENFILENAMEW ofn{};
    wchar_t file[MAX_PATH] = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Registry hive files\0*.dat;*.hiv;*\0All files\0*.*\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;
    if (RegLoadKeyW(HKEY_LOCAL_MACHINE, L"WindCheckerTemp", ofn.lpstrFile) != ERROR_SUCCESS) {
        ShowTextDialog(L"Load hive", L"", L"Could not load the hive. You may need to run WindChecker elevated.");
        return;
    }
    RegAddRoot(g_reg.tree, L"HKEY_LOCAL_MACHINE\\WindCheckerTemp");
    if (g_reg.hint) SetText(g_reg.hint, L"Loaded " + PathFileName(ofn.lpstrFile) + L" under HKEY_LOCAL_MACHINE\\WindCheckerTemp.");
}

void RegRefresh() {
    if (!g_reg.tree) return;
    TreeView_DeleteAllItems(g_reg.tree);
    g_reg.paths.clear();
    RegResetValueLists();
    g_reg.searchActive = false;
    g_reg.searchGeneration += 1;
    g_reg.lastQuery.clear();
    if (g_reg.searchEdit) SetText(g_reg.searchEdit, L"");
    RegAddRoot(g_reg.tree, L"HKEY_CLASSES_ROOT");
    RegAddRoot(g_reg.tree, L"HKEY_CURRENT_USER");
    RegAddRoot(g_reg.tree, L"HKEY_LOCAL_MACHINE");
    RegAddRoot(g_reg.tree, L"HKEY_USERS");
    RegAddRoot(g_reg.tree, L"HKEY_CURRENT_CONFIG");
    if (g_reg.header) SetText(g_reg.header, L"Select a key to list its values");
    SetText(g_reg.valueDetail, L"Expand a hive and select a key. Its values appear above with type icons; "
                               L"select one to read the complete data here.");
    if (g_reg.hint) SetText(g_reg.hint, L"Live hives \u00B7 expand a hive to enumerate its subkeys.");
}

void RegOnExpand(HWND tree, HTREEITEM h, std::wstring* ppath) {
    if (h && !TreeView_GetChild(tree, h)) RegPopulate(tree, h, ppath);
}

struct RegHit {
    std::wstring path;
    std::wstring name;
    std::wstring type;
    std::wstring preview;
    std::wstring detail;
    DWORD valueType = 0;
    int kind = 0;
};

struct RegSearchPayload {
    uint64_t generation = 0;
    std::vector<RegHit> hits;
    std::wstring query;
    std::wstring status;
    bool truncated = false;
};

std::wstring RegSearchPreview(DWORD type, const BYTE* data, DWORD size) {
    if ((type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) && size >= 2) {
        std::wstring text(reinterpret_cast<const wchar_t*>(data), size / 2);
        for (wchar_t& ch : text) {
            if (ch == L'\0' || ch == L'\r' || ch == L'\n' || ch == L'\t') ch = L' ';
        }
        text = Trim(text);
        while (text.find(L"  ") != std::wstring::npos) text.replace(text.find(L"  "), 2, L" ");
        if (text.size() > 300) text = text.substr(0, 300) + L"\u2026";
        return text;
    }
    if (type == REG_DWORD && size >= sizeof(DWORD)) {
        DWORD value = *reinterpret_cast<const DWORD*>(data);
        return Format(L"%u (0x%08X)", value, value);
    }
    if (type == REG_QWORD && size >= sizeof(uint64_t)) {
        uint64_t value = *reinterpret_cast<const uint64_t*>(data);
        return Format(L"%llu", value);
    }
    return Format(L"[%s byte(s)]", CommaNumber(size).c_str());
}

void RegSearchWalk(const std::wstring& needle, size_t maxHits, size_t maxNodes, int maxDepth,
                   double budgetSeconds, std::vector<RegHit>& hits, size_t& visitedCount,
                   bool& truncated) {
    const auto started = std::chrono::steady_clock::now();
    std::vector<std::pair<std::wstring, int>> stack;
    stack.push_back({L"HKEY_CURRENT_USER", 0});
    stack.push_back({L"HKEY_LOCAL_MACHINE", 0});
    stack.push_back({L"HKEY_USERS", 0});

    size_t visited = 0;
    while (!stack.empty()) {
        if (hits.size() >= maxHits) { truncated = true; break; }
        if (visited >= maxNodes) { truncated = true; break; }
        if ((visited & 0x3F) == 0 &&
            std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count() >
                budgetSeconds) {
            truncated = true;
            break;
        }
        std::wstring path = stack.back().first;
        int depth = stack.back().second;
        stack.pop_back();
        ++visited;

        HKEY hk = nullptr;
        bool needClose = false;
        if (!RegOpenPath(path, hk, needClose)) continue;

        DWORD index = 0;
        wchar_t childName[512];
        while (!truncated) {
            DWORD length = 512;
            if (RegEnumKeyExW(hk, index, childName, &length, nullptr, nullptr, nullptr, nullptr) !=
                ERROR_SUCCESS) {
                break;
            }
            std::wstring child(childName, length);
            std::wstring childPath = path + L"\\" + child;
            if (ToLower(child).find(needle) != std::wstring::npos) {
                RegHit hit;
                hit.kind = 1;
                hit.path = childPath;
                hit.name = child;
                hit.type = L"Key";
                hit.preview = path;
                hit.detail = L"Key    : " + childPath + L"\r\nParent : " + path +
                             L"\r\n\r\nDouble-click to open this key.";
                hits.push_back(std::move(hit));
                if (hits.size() >= maxHits) { truncated = true; break; }
            }
            if (depth < maxDepth) stack.push_back({childPath, depth + 1});
            ++index;
        }

        DWORD valueIndex = 0;
        std::vector<wchar_t> valueName(4096);
        while (!truncated) {
            DWORD length = static_cast<DWORD>(valueName.size()) - 1;
            DWORD type = 0;
            DWORD size = 0;
            LONG result = RegEnumValueW(hk, valueIndex, valueName.data(), &length, nullptr, &type,
                                        nullptr, &size);
            if (result == ERROR_NO_MORE_ITEMS) break;
            if (result != ERROR_SUCCESS && result != ERROR_MORE_DATA) break;

            std::wstring name(valueName.data(), length);
            std::wstring preview;
            if (size <= 65536) {
                std::vector<BYTE> data(size ? size : 1);
                DWORD dataSize = size;
                if (RegQueryValueExW(hk, valueName.data(), nullptr, &type, data.data(), &dataSize) ==
                    ERROR_SUCCESS) {
                    preview = RegSearchPreview(type, data.data(), dataSize);
                }
            } else {
                preview = Format(L"[%s byte(s)]", CommaNumber(size).c_str());
            }

            bool nameHit = ToLower(name).find(needle) != std::wstring::npos;
            bool dataHit = !preview.empty() && ToLower(preview).find(needle) != std::wstring::npos;
            if (nameHit || dataHit) {
                RegHit hit;
                hit.kind = 0;
                hit.path = path;
                hit.name = name;
                hit.type = RegTypeName(type);
                hit.valueType = type;
                hit.preview = preview;
                hit.detail = L"Value  : " + (name.empty() ? std::wstring(L"(Default)") : name) +
                             L"\r\nKey    : " + path + L"\r\nType   : " + RegTypeName(type) +
                             L"\r\n\r\n" + preview;
                hits.push_back(std::move(hit));
                if (hits.size() >= maxHits) { truncated = true; break; }
            }
            ++valueIndex;
        }
        if (needClose) RegCloseKey(hk);
    }
    visitedCount = visited;
}

void RegSearchStart() {
    if (!g_reg.searchEdit) return;
    std::wstring query = Trim(GetText(g_reg.searchEdit));
    if (query.size() < 2) {
        if (g_reg.hint) SetText(g_reg.hint, L"Type at least two characters to search keys and values.");
        return;
    }
    g_reg.searchActive = true;
    g_reg.searchGeneration += 1;
    const uint64_t generation = g_reg.searchGeneration;
    if (g_reg.header) SetText(g_reg.header, Format(L"Searching for \u201C%s\u201D\u2026", query.c_str()));
    if (g_reg.hint) SetText(g_reg.hint, L"Scanning HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE and HKEY_USERS\u2026");
    std::wstring needle = ToLower(query);

    std::thread([generation, needle, query]() {
        auto* payload = new RegSearchPayload();
        payload->generation = generation;
        payload->query = query;
        const auto started = std::chrono::steady_clock::now();
        size_t visited = 0;
        RegSearchWalk(needle, 800, 150000, 16, 8.0, payload->hits, visited, payload->truncated);
        const double seconds =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
        payload->status = Format(L"%s hit(s) \u00B7 %s key(s) \u00B7 %.1fs%s",
                                 CommaNumber(payload->hits.size()).c_str(),
                                 CommaNumber(visited).c_str(), seconds,
                                 payload->truncated ? L" \u00B7 capped" : L"");
        if (!PostMessageW(g_hwnd, WM_APP_REGSEARCH, 0, reinterpret_cast<LPARAM>(payload))) {
            delete payload;
        }
    }).detach();
}

void RegApplySearch(RegSearchPayload* raw) {
    std::unique_ptr<RegSearchPayload> payload(raw);
    if (!payload) return;
    if (payload->generation != g_reg.searchGeneration) return;
    if (!g_reg.list) return;

    RegResetValueLists();
    for (size_t i = 0; i < payload->hits.size(); ++i) {
        const RegHit& hit = payload->hits[i];
        g_reg.valueNames.push_back(hit.name);
        g_reg.valueTypes.push_back(hit.type);
        g_reg.valueData.push_back(hit.preview);
        g_reg.valuePaths.push_back(hit.path);
        g_reg.valueDetails.push_back(hit.detail);
        g_reg.valueKinds.push_back(hit.kind);

        std::wstring label = hit.name.empty() ? L"(Default)" : hit.name;
        LVITEMW entry{};
        entry.mask = LVIF_TEXT | LVIF_IMAGE;
        entry.iItem = ListView_GetItemCount(g_reg.list);
        entry.pszText = const_cast<LPWSTR>(label.c_str());
        entry.iImage = hit.kind == 1 ? g_reg.keyIcon : RegTypeIcon(hit.valueType);
        int row = ListView_InsertItem(g_reg.list, &entry);
        std::wstring preview = RegPreview(hit.preview, 360);
        ListView_SetItemText(g_reg.list, row, 1, const_cast<LPWSTR>(hit.type.c_str()));
        ListView_SetItemText(g_reg.list, row, 2, const_cast<LPWSTR>(preview.c_str()));
    }

    const size_t count = payload->hits.size();
    if (g_reg.header) {
        SetText(g_reg.header, Format(L"%s result(s) for \u201C%s\u201D  \u00B7  HKCU + HKLM + HKU%s",
                                     CommaNumber(count).c_str(), payload->query.c_str(),
                                     payload->truncated ? L"  \u00B7  capped" : L""));
    }
    if (g_reg.hint) SetText(g_reg.hint, payload->status);

    if (count == 0) {
        SetText(g_reg.valueDetail,
                L"No key or value matched \u201C" + payload->query +
                    L"\u201D. Try a shorter term, or clear the search to browse the tree.");
        return;
    }
    ListView_SetItemState(g_reg.list, 0, LVIS_SELECTED | LVIS_FOCUSED,
                          LVIS_SELECTED | LVIS_FOCUSED);
    RegShowValueDetail(0);
}

void RegClearSearch() {
    g_reg.searchActive = false;
    g_reg.searchGeneration += 1;
    g_reg.lastQuery.clear();
    if (g_reg.searchEdit && !GetText(g_reg.searchEdit).empty()) SetText(g_reg.searchEdit, L"");
    if (g_reg.hint) SetText(g_reg.hint, L"Live hives \u00B7 expand a hive to enumerate its subkeys.");
    if (g_reg.tree && TreeView_GetSelection(g_reg.tree)) {
        RegShowValues(g_reg.tree);
    } else {
        RegResetValueLists();
        if (g_reg.header) SetText(g_reg.header, L"Select a key to list its values");
        SetText(g_reg.valueDetail, L"Expand a hive and select a key. Its values appear above with type icons; "
                                   L"select one to read the complete data here.");
    }
}

bool RegGotoPath(const std::wstring& path) {
    if (!g_reg.tree) return false;
    std::vector<std::wstring> parts;
    size_t start = 0;
    while (start <= path.size()) {
        size_t slash = path.find(L'\\', start);
        if (slash == std::wstring::npos) {
            parts.push_back(path.substr(start));
            break;
        }
        parts.push_back(path.substr(start, slash - start));
        start = slash + 1;
    }
    if (parts.empty()) return false;

    HTREEITEM item = TreeView_GetRoot(g_reg.tree);
    bool found = false;
    while (item) {
        wchar_t text[512] = {};
        TVITEMW info{};
        info.hItem = item;
        info.mask = TVIF_TEXT;
        info.pszText = text;
        info.cchTextMax = 512;
        TreeView_GetItem(g_reg.tree, &info);
        if (_wcsicmp(text, parts[0].c_str()) == 0) { found = true; break; }
        item = TreeView_GetNextSibling(g_reg.tree, item);
    }
    if (!found) return false;

    for (size_t i = 1; i < parts.size(); ++i) {
        TVITEMW info{};
        info.hItem = item;
        info.mask = TVIF_PARAM;
        TreeView_GetItem(g_reg.tree, &info);
        auto* ppath = reinterpret_cast<std::wstring*>(info.lParam);
        if (ppath) RegOnExpand(g_reg.tree, item, ppath);

        HTREEITEM child = TreeView_GetChild(g_reg.tree, item);
        HTREEITEM match = nullptr;
        while (child) {
            wchar_t text[512] = {};
            TVITEMW ci{};
            ci.hItem = child;
            ci.mask = TVIF_TEXT;
            ci.pszText = text;
            ci.cchTextMax = 512;
            TreeView_GetItem(g_reg.tree, &ci);
            if (_wcsicmp(text, parts[i].c_str()) == 0) { match = child; break; }
            child = TreeView_GetNextSibling(g_reg.tree, child);
        }
        if (!match) return false;
        TreeView_Expand(g_reg.tree, item, TVE_EXPAND);
        item = match;
    }
    TreeView_SelectItem(g_reg.tree, item);
    TreeView_EnsureVisible(g_reg.tree, item);
    return true;
}

void BuildRegistryPage() {
    Tab& tab = g_tabs[TAB_REGISTRY];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_REGISTRY)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Registry", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"Browse the live registry hives or load an offline hive. The search box walks HKCU, HKLM and HKU for matching key and value names; keys carry shell icons and values are listed by name, type and data.",
        g_fontSmall);
    HWND refreshBtn = MakeButton(tab.page, L"Refresh", IdFor(TAB_REGISTRY, L_REFRESH));
    HWND loadBtn = MakeButton(tab.page, L"Load hive\u2026", IdFor(TAB_REGISTRY, L_HIVE));
    HWND hint = MakeLabel(tab.page, L"Loading hives\u2026", g_fontSmall);

    HWND searchIcon = CreateWindowExW(0, L"STATIC", L"",
                                      WS_CHILD | WS_VISIBLE | SS_ICON | SS_CENTERIMAGE,
                                      0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    if (HICON icon = WindowsSearchIcon()) {
        SendMessageW(searchIcon, STM_SETICON, reinterpret_cast<WPARAM>(icon), 0);
    }
    HWND searchEdit = MakeEdit(tab.page, L"", IdFor(TAB_REGISTRY, L_REGSEARCH));
    SendMessageW(searchEdit, EM_SETCUEBANNER, TRUE,
                 reinterpret_cast<LPARAM>(L"Search keys and values in HKCU, HKLM and HKU"));
    HWND clearBtn = MakeButton(tab.page, L"Clear", IdFor(TAB_REGISTRY, L_REGCLEAR));

    g_reg.icons = ImageList_Create(GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                   ILC_COLOR32, 8, 8);
    auto addStockIcon = [](SHSTOCKICONID id) {
        SHSTOCKICONINFO info{};
        info.cbSize = sizeof(info);
        if (SUCCEEDED(SHGetStockIconInfo(id, SHGSI_ICON | SHGSI_SMALLICON, &info)) && info.hIcon) {
            int index = ImageList_AddIcon(g_reg.icons, info.hIcon);
            DestroyIcon(info.hIcon);
            return index;
        }
        return -1;
    };
    if (g_reg.icons) {
        wchar_t windows[MAX_PATH] = {};
        GetWindowsDirectoryW(windows, MAX_PATH);
        std::wstring regedit = std::wstring(windows) + L"\\regedit.exe";
        SHFILEINFOW fileInfo{};
        if (SHGetFileInfoW(regedit.c_str(), 0, &fileInfo, sizeof(fileInfo),
                           SHGFI_ICON | SHGFI_SMALLICON) && fileInfo.hIcon) {
            g_reg.rootIcon = ImageList_AddIcon(g_reg.icons, fileInfo.hIcon);
            DestroyIcon(fileInfo.hIcon);
        } else {
            g_reg.rootIcon = addStockIcon(SIID_DRIVEFIXED);
        }
        g_reg.keyIcon = addStockIcon(SIID_FOLDER);
        g_reg.textIcon = addStockIcon(SIID_DOCNOASSOC);
        g_reg.numberIcon = addStockIcon(SIID_APPLICATION);
        g_reg.binaryIcon = addStockIcon(SIID_DRIVEUNKNOWN);
        if (g_reg.rootIcon < 0) g_reg.rootIcon = 0;
        if (g_reg.keyIcon < 0) g_reg.keyIcon = 0;
        if (g_reg.textIcon < 0) g_reg.textIcon = 0;
        if (g_reg.numberIcon < 0) g_reg.numberIcon = 0;
        if (g_reg.binaryIcon < 0) g_reg.binaryIcon = 0;
    }

    HWND tree = CreateWindowExW(0, WC_TREEVIEWW, L"",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | TVS_HASLINES | TVS_HASBUTTONS |
                                    TVS_SHOWSELALWAYS | TVS_DISABLEDRAGDROP | TVS_TRACKSELECT,
                                0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tree, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
    SendMessageW(tree, TVM_SETEXTENDEDSTYLE, TVS_EX_DOUBLEBUFFER, TVS_EX_DOUBLEBUFFER);
    SetWindowTheme(tree, L"Explorer", nullptr);
    if (g_reg.icons) TreeView_SetImageList(tree, g_reg.icons, TVSIL_NORMAL);

    HWND header = MakeLabel(tab.page, L"Select a key to list its values", g_fontUI);

    HWND list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL |
                                    LVS_SHOWSELALWAYS | WS_TABSTOP,
                                0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontSmall), TRUE);
    ListView_SetExtendedListViewStyle(list,
                                      LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    SetWindowTheme(list, L"Explorer", nullptr);
    if (g_reg.icons) ListView_SetImageList(list, g_reg.icons, LVSIL_SMALL);

    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    column.fmt = LVCFMT_LEFT;
    auto appendColumn = [&](const wchar_t* name, int width) {
        column.pszText = const_cast<LPWSTR>(name);
        column.cx = S(width);
        int index = Header_GetItemCount(ListView_GetHeader(list));
        ListView_InsertColumn(list, index, &column);
    };
    appendColumn(L"Name", 225);
    appendColumn(L"Type", 130);
    appendColumn(L"Data", 280);

    HWND valueDetail = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_READONLY |
                                           ES_AUTOVSCROLL | WS_VSCROLL | WS_HSCROLL | ES_NOHIDESEL,
                                       0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(valueDetail, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontMono), TRUE);

    tab.tree = tree;
    tab.detailPane = nullptr;
    g_reg.tree = tree;
    g_reg.header = header;
    g_reg.list = list;
    g_reg.valueDetail = valueDetail;
    g_reg.hint = hint;
    g_reg.searchIcon = searchIcon;
    g_reg.searchEdit = searchEdit;
    g_reg.clearBtn = clearBtn;
    Place(refreshBtn, 8, 54, 90, 26);
    Place(loadBtn, 104, 54, 110, 26);
    Place(searchIcon, 226, 57, 20, 20);
    Place(searchEdit, 250, 54, 280, 25);
    Place(clearBtn, 536, 54, 64, 26);
    Place(hint, 610, 58, 320, 20);
    RegRefresh();
}

std::wstring ThumbcacheFolderPath() {
    PWSTR path = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path)) || !path) return L"";
    std::wstring folder = std::wstring(path) + L"\\Microsoft\\Windows\\Explorer";
    CoTaskMemFree(path);
    return folder;
}

HBITMAP DecodeImageToBitmap(const std::vector<unsigned char>& data, int maxSize) {
    if (data.empty()) return nullptr;
    static IWICImagingFactory* factory = nullptr;
    if (!factory) {
        if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                    IID_PPV_ARGS(&factory)))) {
            return nullptr;
        }
    }
    IStream* stream = SHCreateMemStream(data.data(), static_cast<UINT>(data.size()));
    if (!stream) return nullptr;

    HBITMAP bitmap = nullptr;
    IWICBitmapDecoder* decoder = nullptr;
    if (SUCCEEDED(factory->CreateDecoderFromStream(stream, nullptr, WICDecodeMetadataCacheOnDemand,
                                                   &decoder))) {
        IWICBitmapFrameDecode* frame = nullptr;
        if (SUCCEEDED(decoder->GetFrame(0, &frame))) {
            UINT width = 0;
            UINT height = 0;
            if (SUCCEEDED(frame->GetSize(&width, &height)) && width > 0 && height > 0) {
                UINT targetWidth = width;
                UINT targetHeight = height;
                if (maxSize > 0 && (width > static_cast<UINT>(maxSize) ||
                                    height > static_cast<UINT>(maxSize))) {
                    double scale = static_cast<double>(maxSize) / std::max(width, height);
                    targetWidth = std::max<UINT>(1, static_cast<UINT>(width * scale));
                    targetHeight = std::max<UINT>(1, static_cast<UINT>(height * scale));
                }
                IWICBitmapSource* source = frame;
                IWICBitmapScaler* scaler = nullptr;
                if ((targetWidth != width || targetHeight != height) &&
                    SUCCEEDED(factory->CreateBitmapScaler(&scaler)) &&
                    SUCCEEDED(scaler->Initialize(frame, targetWidth, targetHeight,
                                                 WICBitmapInterpolationModeFant))) {
                    source = scaler;
                }
                IWICFormatConverter* converter = nullptr;
                if (SUCCEEDED(factory->CreateFormatConverter(&converter)) &&
                    SUCCEEDED(converter->Initialize(source, GUID_WICPixelFormat32bppPBGRA,
                                                    WICBitmapDitherTypeNone, nullptr, 0.0,
                                                    WICBitmapPaletteTypeCustom))) {
                    BITMAPINFO info{};
                    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
                    info.bmiHeader.biWidth = static_cast<LONG>(targetWidth);
                    info.bmiHeader.biHeight = -static_cast<LONG>(targetHeight);
                    info.bmiHeader.biPlanes = 1;
                    info.bmiHeader.biBitCount = 32;
                    info.bmiHeader.biCompression = BI_RGB;
                    void* bits = nullptr;
                    HDC screen = GetDC(nullptr);
                    HBITMAP created = CreateDIBSection(screen, &info, DIB_RGB_COLORS, &bits,
                                                       nullptr, 0);
                    if (screen) ReleaseDC(nullptr, screen);
                    if (created && bits) {
                        if (SUCCEEDED(converter->CopyPixels(nullptr, targetWidth * 4,
                                                            targetWidth * targetHeight * 4,
                                                            static_cast<BYTE*>(bits)))) {
                            bitmap = created;
                        } else {
                            DeleteObject(created);
                        }
                    } else if (created) {
                        DeleteObject(created);
                    }
                }
                if (converter) converter->Release();
                if (scaler) scaler->Release();
            }
            frame->Release();
        }
        decoder->Release();
    }
    stream->Release();
    return bitmap;
}

void ThumbSetBitmap(HBITMAP bitmap) {
    if (!g_thumb.preview) {
        if (bitmap) DeleteObject(bitmap);
        return;
    }
    HBITMAP previous = reinterpret_cast<HBITMAP>(
        SendMessageW(g_thumb.preview, STM_SETIMAGE, IMAGE_BITMAP, reinterpret_cast<LPARAM>(bitmap)));
    if (previous) DeleteObject(previous);
    g_thumb.bitmap = bitmap;
}

void ThumbSelect(int item) {
    Tab& tab = g_tabs[TAB_THUMBNAIL];
    if (!tab.list || item < 0) return;
    if (static_cast<size_t>(item) >= tab.displayed.size()) return;
    size_t record = tab.displayed[static_cast<size_t>(item)];
    if (record < tab.details.size() && tab.detailPane) {
        SetWindowTextW(tab.detailPane, tab.details[record].c_str());
    }
    if (!g_thumb.preview || record >= tab.records.size()) return;
    const Row& row = tab.records[record];
    unsigned long long offset = 0;
    if (row.size() > 6) offset = wcstoull(row[6].c_str(), nullptr, 16);
    std::vector<unsigned char> data;
    if (offset == 0 || row.empty() || g_thumb.folder.empty() ||
        !ReadThumbcacheImage(g_thumb.folder + L"\\" + row[0], offset, data)) {
        ThumbSetBitmap(nullptr);
        return;
    }
    ThumbSetBitmap(DecodeImageToBitmap(data, 320));
}

void BuildThumbcachePage() {
    Tab& tab = g_tabs[TAB_THUMBNAIL];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_THUMBNAIL)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Thumbcache", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"Every thumbnail Explorer keeps on disk: thumbcache_16/32/48/96/256/1280/exif.db and the other "
        L"cache files under %LocalAppData%\\Microsoft\\Windows\\Explorer. Each CMMM record is decoded with "
        L"its identifier, format, pixel size, entry size and hash, and the stored image is rendered when a row is selected.",
        g_fontSmall);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_THUMBNAIL, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_THUMBNAIL, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 80, 26);
    Place(tab.statusLabel, 205, 90, 780, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, -1, {1}, {0, 2},
                {{L"All fields", FM_ALL}, {L"Identifier", FM_NAME}, {L"Cache or format", FM_ACTION}});
    tab.list = MakeList(tab.page, tab,
                        {L"Cache", L"Identifier", L"Format", L"Pixels", L"Data", L"Entry", L"Offset"},
                        {130, 220, 60, 80, 80, 80, 80});

    g_thumb.folder = ThumbcacheFolderPath();
    g_thumb.preview = CreateWindowExW(WS_EX_CLIENTEDGE, L"STATIC", L"",
                                      WS_CHILD | WS_VISIBLE | SS_BITMAP | SS_CENTERIMAGE,
                                      0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);

    tab.detailPane = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                         ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                                     0, 0, 10, 10, tab.page, nullptr, g_instance, nullptr);
    SendMessageW(tab.detailPane, WM_SETFONT,
                 reinterpret_cast<WPARAM>(g_fontMono ? g_fontMono : g_fontSmall), TRUE);
    SetWindowTextW(tab.detailPane,
                   L"Press Scan to read every thumbcache_*.db file. Selecting a row decodes the stored "
                   L"thumbnail and shows its full record on the right.");
}

std::wstring HiddenAttributeText(DWORD attributes) {
    std::wstring text;
    auto add = [&text](const wchar_t* tag) {
        if (!text.empty()) text += L' ';
        text += tag;
    };
    if (attributes & FILE_ATTRIBUTE_HIDDEN) add(L"H");
    if (attributes & FILE_ATTRIBUTE_SYSTEM) add(L"S");
    if (attributes & FILE_ATTRIBUTE_READONLY) add(L"R");
    if (attributes & FILE_ATTRIBUTE_ARCHIVE) add(L"A");
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) add(L"L");
    return text.empty() ? std::wstring(L"-") : text;
}

bool HiddenMatches(DWORD attributes, int mode) {
    const bool hidden = (attributes & FILE_ATTRIBUTE_HIDDEN) != 0;
    const bool system = (attributes & FILE_ATTRIBUTE_SYSTEM) != 0;
    switch (mode) {
    case 1: return hidden && !system;
    case 2: return hidden && system;
    case 3: return hidden;
    default: return true;
    }
}

void RunHiddenScan(const Sink& sink, std::atomic<bool>& stop, std::wstring root, int mode,
                   bool recursive) {
    while (root.size() > 3 && root.back() == L'\\') root.pop_back();

    const size_t maxRows = 20000;
    const int maxDepth = recursive ? 8 : 0;
    const int maxFolders = 4000;

    std::vector<Row> rows;
    std::vector<std::wstring> details;
    std::vector<std::pair<std::wstring, int>> pending{{root, 0}};
    int visited = 0;
    int found = 0;
    int folders = 0;

    auto flush = [&](bool force) {
        if (rows.empty()) return;
        if (!force && rows.size() < 200) return;
        sink.Detailed(std::move(rows), std::move(details), false,
                      Format(L"%s hidden item(s) \u00B7 scanning %s\u2026",
                             CommaNumber(found).c_str(), root.c_str()));
        rows.clear();
        details.clear();
    };

    while (!pending.empty() && !stop.load()) {
        std::wstring dir = pending.back().first;
        int depth = pending.back().second;
        pending.pop_back();
        ++visited;

        WIN32_FIND_DATAW fd{};
        HANDLE handle = FindFirstFileW((dir + L"\\*").c_str(), &fd);
        if (handle == INVALID_HANDLE_VALUE) continue;
        do {
            std::wstring name = fd.cFileName;
            if (name == L"." || name == L"..") continue;
            const bool isFolder = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            if (isFolder && depth < maxDepth &&
                !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                pending.push_back({dir + L"\\" + name, depth + 1});
            }
            if (!HiddenMatches(fd.dwFileAttributes, mode)) continue;

            std::wstring full = dir + L"\\" + name;
            std::wstring kind = isFolder ? L"Folder" : L"File";
            std::wstring attributes = HiddenAttributeText(fd.dwFileAttributes);
            std::wstring size = isFolder ? std::wstring(L"-")
                                         : SizeText((static_cast<uint64_t>(fd.nFileSizeHigh) << 32) |
                                                    fd.nFileSizeLow);
            std::wstring modified = FileTimeText(fd.ftLastWriteTime);

            rows.push_back({name, kind, attributes, size, modified, full});
            details.push_back(Format(L"Name       : %s\r\nType       : %s\r\nAttributes : %s\r\n"
                                     L"Size       : %s\r\nModified   : %s\r\nCreated    : %s\r\n"
                                     L"Path       : %s",
                                     name.c_str(), kind.c_str(), attributes.c_str(), size.c_str(),
                                     modified.c_str(), FileTimeText(fd.ftCreationTime).c_str(),
                                     full.c_str()));
            ++found;
            if (isFolder) ++folders;
            flush(false);
            if (rows.size() + details.size() > maxRows * 2) break;
        } while (FindNextFileW(handle, &fd) && !stop.load());
        FindClose(handle);
        if (found >= static_cast<int>(maxRows) || visited >= maxFolders) break;
    }
    flush(true);

    Batch batch;
    batch.done = true;
    batch.status = Format(L"%s hidden item(s) \u00B7 %s folder(s) \u00B7 %s folder(s) scanned \u00B7 %s%s",
                          CommaNumber(found).c_str(), CommaNumber(folders).c_str(),
                          CommaNumber(visited).c_str(), root.c_str(),
                          found >= static_cast<int>(maxRows) ? L" (row cap reached)" : L"");
    sink.Post(std::move(batch));
}

void BuildHiddenPage() {
    Tab& tab = g_tabs[TAB_HIDDEN];
    tab.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                               0, 0, 100, 100, g_hwnd,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(TAB_HIDDEN)),
                               g_instance, nullptr);
    tab.title = MakeLabel(tab.page, L"Hidden Files", g_fontTitle);
    tab.desc = MakeLabel(tab.page,
        L"Lists files and folders that carry +h or +s+h, with the full attribute set and path. Recursion optional.",
        g_fontSmall);

    PWSTR profile = nullptr;
    std::wstring home;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Profile, 0, nullptr, &profile)) && profile) {
        home = profile;
        CoTaskMemFree(profile);
    }
    if (home.empty()) home = L"C:\\";

    HWND pathLabel = MakeLabel(tab.page, L"Path", g_fontSmall);
    tab.folderEdit = MakeEdit(tab.page, home, IdFor(TAB_HIDDEN, L_FOLDER));
    HWND browseBtn = MakeButton(tab.page, L"Browse\u2026", IdFor(TAB_HIDDEN, L_BROWSE));
    HWND showLabel = MakeLabel(tab.page, L"Show", g_fontSmall);
    tab.targetCombo = MakeCombo(tab.page, IdFor(TAB_HIDDEN, L_HIDDENMODE));
    ComboAdd(tab.targetCombo, L"Hidden (+h)");
    ComboAdd(tab.targetCombo, L"Hidden + system (+s+h)");
    ComboAdd(tab.targetCombo, L"All hidden (+h and +s+h)");
    ComboAdd(tab.targetCombo, L"Everything");
    SendMessageW(tab.targetCombo, CB_SETCURSEL, 2, 0);
    tab.recurseCheck = MakeCheck(tab.page, L"Include subfolders", IdFor(TAB_HIDDEN, L_ALLDRIVES), true);

    PlaceHeader(tab, pathLabel, 8, 56, 34, 20, 0);
    PlaceHeader(tab, tab.folderEdit, 44, 54, 520, 25, 0);
    PlaceHeader(tab, browseBtn, 570, 54, 86, 26, 0);
    PlaceHeader(tab, showLabel, 668, 56, 38, 20, 0);
    PlaceHeader(tab, tab.targetCombo, 710, 54, 190, 200, 0);
    PlaceHeader(tab, tab.recurseCheck, 912, 56, 160, 20, 0);

    tab.startBtn = MakeButton(tab.page, L"Scan", IdFor(TAB_HIDDEN, L_START));
    tab.stopBtn = MakeButton(tab.page, L"Stop", IdFor(TAB_HIDDEN, L_STOP));
    tab.statusLabel = MakeLabel(tab.page, L"Ready", g_fontSmall);
    Place(tab.startBtn, 8, 86, 90, 26);
    Place(tab.stopBtn, 103, 86, 90, 26);
    Place(tab.statusLabel, 205, 90, 820, 20);
    EnableWindow(tab.stopBtn, FALSE);

    BuildFilter(tab, 4, {0}, {5},
                {{L"All fields", FM_ALL}, {L"Name", FM_NAME}, {L"Action", FM_ACTION}, {L"Date", FM_DATE}});
    tab.list = MakeList(tab.page, tab,
                        {L"Name", L"Type", L"Attributes", L"Size", L"Modified", L"Full path"},
                        {220, 66, 92, 78, 150, 440});
}

void StartHiddenScan() {
    Tab& tab = g_tabs[TAB_HIDDEN];
    if (tab.running) return;
    std::wstring path = Trim(GetText(tab.folderEdit));
    if (path.empty()) {
        MessageBoxW(g_hwnd, L"Enter a folder to scan.", APP_TITLE, MB_ICONWARNING);
        return;
    }
    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        MessageBoxW(g_hwnd, (L"Not a folder:\n" + path).c_str(), APP_TITLE, MB_ICONWARNING);
        return;
    }
    int mode = ComboSelection(tab.targetCombo) + 1;
    bool recursive = IsChecked(tab.recurseCheck);
    StartWork(tab, [path, mode, recursive](const Sink& sink, std::atomic<bool>& stop) {
        RunHiddenScan(sink, stop, path, mode, recursive);
    });
}

void HiddenBrowse() {
    BROWSEINFO bi{};
    bi.hwndOwner = g_hwnd;
    bi.lpszTitle = L"Choose a folder to scan for hidden items";
    bi.ulFlags = BIF_USENEWUI;
    PIDLIST_ABSOLUTE pid = SHBrowseForFolderW(&bi);
    if (!pid) return;
    wchar_t path[MAX_PATH];
    if (SHGetPathFromIDListW(pid, path)) {
        SetText(g_tabs[TAB_HIDDEN].folderEdit, path);
        StartHiddenScan();
    }
    CoTaskMemFree(pid);
}

void BuildPlaceholderTab(int tab, const wchar_t* title, const wchar_t* desc) {
    Tab& t = g_tabs[tab];
    t.page = CreateWindowExW(0, L"WindCheckerPage", L"", WS_CHILD | WS_CLIPCHILDREN,
                             0, 0, 100, 100, g_hwnd,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(tab)),
                             g_instance, nullptr);
    t.title = MakeLabel(t.page, title, g_fontTitle);
    t.desc = MakeLabel(t.page, desc, g_fontSmall);
}

void CreateUi(HWND hwnd) {
    g_hwnd = hwnd;
    for (int i = 0; i < TAB_COUNT; ++i) g_tabs[i].key = i;

    std::vector<SidebarRow> rows(kSidebarRows, kSidebarRows + sizeof(kSidebarRows) / sizeof(kSidebarRows[0]));
    g_sidebar = CreateSidebar(hwnd, g_instance, rows, g_dpi);

    BuildVolumePage();
    BuildSearchPage();
    BuildUsnPage();
    BuildMftPage();
    g_eventChannels = ListEventChannels();
    BuildEventsPage();
    BuildEventViewerPage();
    BuildNfatPage();
    BuildPacketPage();
    BuildPrefetchPage();
    BuildStringsPage();
    BuildPowerShellPage();
    BuildProcessPage();
    BuildServicesPage();
    BuildComputerInfoPage();
    BuildSrumPage();
    BuildAmCachePage();
    BuildUsbPage();
    BuildBamDamPage();
    BuildUserAssistPage();
    BuildRecentDocsPage();
    BuildMruPage();
    BuildWmiPage();
    BuildNetworkArtifactsPage();
    BuildDefenderPage();
    BuildRdpPage();
    BuildActivitiesPage();
    BuildCrashPage();
    BuildWpnPage();
    BuildStartupPage();
    BuildPersistencePage();
    BuildExecutionPage();
    BuildSignaturePage();
    BuildFileHashPage();
    BuildImageMetaPage();

    BuildRegistryPage();
    BuildClipboardPage();
    BuildThumbcachePage();
    BuildHiddenPage();
    BuildCarvePage();

    CreateStatusBar(hwnd);
    ShowPage(0);
    RefreshVolumes();
    SetText(g_status, L"Ready \u00B7 right-click or double-click any row to see its full detail");
}

LRESULT CALLBACK PageProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_COMMAND:
        return SendMessageW(g_hwnd, WM_COMMAND, wParam, lParam);
    case WM_NOTIFY:
        return SendMessageW(g_hwnd, WM_NOTIFY, wParam, lParam);
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        SetBkMode(dc, TRANSPARENT);
        SetBkColor(dc, kCanvas);
        return reinterpret_cast<LRESULT>(g_bgBrush ? g_bgBrush : GetSysColorBrush(COLOR_BTNFACE));
    }
    default:
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
}

LRESULT CALLBACK MainProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        g_hwnd = hwnd;
        CreateUi(hwnd);
        return 0;
    case WM_SIZE:
        LayoutAll();
        return 0;
    case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
        info->ptMinTrackSize.x = S(1180);
        info->ptMinTrackSize.y = S(640);
        return 0;
    }
    case WM_APP_SIDEBAR: {
        int index = static_cast<int>(wParam);
        ShowPage(index);
        if (index == TAB_SERVICES && !g_tabs[TAB_SERVICES].running &&
            g_tabs[TAB_SERVICES].generation == 1) {
            StartServices();
        } else if (index == TAB_COMPUTERINFO && !g_tabs[TAB_COMPUTERINFO].running &&
                   g_tabs[TAB_COMPUTERINFO].generation == 1) {
            StartComputerInfo();
        }
        return 0;
    }
    case WM_NOTIFY: {
        auto* header = reinterpret_cast<LPNMHDR>(lParam);
        if (!header) return 0;

        if (header->code == NM_CUSTOMDRAW) {
            auto* draw = reinterpret_cast<LPNMLVCUSTOMDRAW>(lParam);
            if (header->hwndFrom == g_reg.list || header->hwndFrom == g_memory.list) {
                if (draw->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
                if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                    draw->clrTextBk = (static_cast<int>(draw->nmcd.dwItemSpec) & 1)
                                          ? RGB(0xF2, 0xF6, 0xFC)
                                          : RGB(0xFF, 0xFF, 0xFF);
                    draw->clrText = RGB(0x1B, 0x1B, 0x1F);
                    return CDRF_NEWFONT;
                }
                return CDRF_DODEFAULT;
            }
        }

        if (header->code == LVN_COLUMNCLICK) {
            auto* info = reinterpret_cast<LPNMLISTVIEW>(lParam);
            Tab* tab = TabFromList(header->hwndFrom);
            if (tab && info) {
                bool ascending = !(tab->sortColumn == info->iSubItem && tab->sortAscending);
                SortTab(*tab, info->iSubItem, ascending);
            }
        } else if (header->code == TVN_ITEMEXPANDING) {
            auto* info = reinterpret_cast<LPNMTREEVIEWW>(lParam);
            if (header->hwndFrom == g_reg.tree && info) {
                TVITEMW item{};
                item.hItem = info->itemNew.hItem; item.mask = TVIF_PARAM;
                TreeView_GetItem(g_reg.tree, &item);
                auto* ppath = reinterpret_cast<std::wstring*>(item.lParam);
                if (ppath) RegOnExpand(g_reg.tree, info->itemNew.hItem, ppath);
            }
        } else if (header->code == TVN_SELCHANGEDW) {
            auto* info = reinterpret_cast<LPNMTREEVIEWW>(lParam);
            if (header->hwndFrom == g_ev.tree) {
                EventViewerOnTreeSelect();
            } else if (header->hwndFrom == g_reg.tree) {
                RegShowValues(g_reg.tree);
            } else {
                Tab* tab = TabFromTree(header->hwndFrom);
                if (tab && info) {
                    size_t index = TreeRecordIndex(header->hwndFrom, info->itemNew.hItem);
                    if (index == static_cast<size_t>(-1)) return 0;
                    if (tab->key == TAB_CARVE) CarveShowDetail(*tab, index);
                    else ProcessSelectNode(*tab, index);
                }
            }
        } else if (header->code == LVN_ITEMCHANGED && header->hwndFrom == g_reg.list) {
            auto* info = reinterpret_cast<LPNMLISTVIEW>(lParam);
            if (info && (info->uChanged & LVIF_STATE) && (info->uNewState & LVIS_SELECTED)) {
                RegShowValueDetail(info->iItem);
            }
        } else if (header->code == LVN_ITEMCHANGED && header->hwndFrom == g_tabs[TAB_SERVICES].list) {
            auto* info = reinterpret_cast<LPNMLISTVIEW>(lParam);
            if (info && (info->uChanged & LVIF_STATE) && (info->uNewState & LVIS_SELECTED)) {
                UpdateServiceDetail(info->iItem);
            }
        } else if (header->code == LVN_ITEMCHANGED && header->hwndFrom == g_tabs[TAB_COMPUTERINFO].list) {
            auto* info = reinterpret_cast<LPNMLISTVIEW>(lParam);
            if (info && (info->uChanged & LVIF_STATE) && (info->uNewState & LVIS_SELECTED)) {
                UpdateComputerInfoDetail(info->iItem);
            }
        } else if (header->code == LVN_ITEMCHANGED && header->hwndFrom == g_tabs[TAB_SRUM].list) {
            auto* info = reinterpret_cast<LPNMLISTVIEW>(lParam);
            if (info && (info->uChanged & LVIF_STATE) && (info->uNewState & LVIS_SELECTED)) {
                UpdateStoredDetail(g_tabs[TAB_SRUM], info->iItem);
            }
        } else if (header->code == LVN_ITEMCHANGED && header->hwndFrom == g_tabs[TAB_AMCACHE].list) {
            auto* info = reinterpret_cast<LPNMLISTVIEW>(lParam);
            if (info && (info->uChanged & LVIF_STATE) && (info->uNewState & LVIS_SELECTED)) {
                UpdateStoredDetail(g_tabs[TAB_AMCACHE], info->iItem);
            }
        } else if (header->code == LVN_ITEMCHANGED && TabFromList(header->hwndFrom)) {
            auto* info = reinterpret_cast<LPNMLISTVIEW>(lParam);
            Tab* owner = TabFromList(header->hwndFrom);
            if (info && owner && owner->detailPane && (info->uChanged & LVIF_STATE) &&
                (info->uNewState & LVIS_SELECTED)) {
                if (owner->key == TAB_THUMBNAIL) ThumbSelect(info->iItem);
                else UpdateStoredDetail(*owner, info->iItem);
            }
        } else if (header->code == NM_DBLCLK && header->hwndFrom == g_memory.list) {
            int item = ListView_GetNextItem(g_memory.list, -1, LVNI_SELECTED);
            if (item >= 0) MemoryOpenDump(static_cast<size_t>(item));
        } else if (header->code == NM_DBLCLK && header->hwndFrom == g_carveMedia.list) {
            CarveMediaOpenSelected();
        } else if (header->code == NM_DBLCLK && header->hwndFrom == g_tabs[TAB_STRINGS].list) {
            StringsOpenHex();
        } else if (header->code == NM_DBLCLK && header->hwndFrom == g_reg.list) {
            int item = ListView_GetNextItem(g_reg.list, -1, LVNI_SELECTED);
            if (item >= 0 && static_cast<size_t>(item) < g_reg.valueNames.size()) {
                if (g_reg.valueKinds[item] == 1) {

                    if (!RegGotoPath(g_reg.valuePaths[item])) {
                        ShowTextDialog(L"Key \u2014 " + g_reg.valueNames[item],
                                       L"This key lives in a hive that is not loaded in the tree.",
                                       g_reg.valueDetails[item]);
                    }
                } else {
                    ShowTextDialog(L"Value \u2014 " +
                                       (g_reg.valueNames[item].empty()
                                            ? std::wstring(L"(Default)")
                                            : g_reg.valueNames[item]),
                                   g_reg.valueTypes[item] + L" \u00B7 " + g_reg.valuePaths[item],
                                   g_reg.valueData[item]);
                }
            }
        } else if (header->code == NM_DBLCLK && header->hwndFrom == g_ev.tree) {
            StartEventViewer();
        } else if (header->code == NM_DBLCLK && header->hwndFrom == g_tabs[TAB_CARVE].tree) {
            CarveTreeDoubleClick(g_tabs[TAB_CARVE].tree);
        } else if (header->code == NM_DBLCLK && TabFromTree(header->hwndFrom)) {
            ShowProcessMenu(header->hwndFrom, true);
        } else if (header->code == NM_RCLICK && TabFromTree(header->hwndFrom) &&
                   TabFromTree(header->hwndFrom)->key != TAB_CARVE) {
            ShowProcessMenu(header->hwndFrom, false);
        }
        return 0;
    }
    case WM_TIMER:
        if (wParam >= TIMER_FILTER_BASE && wParam < TIMER_FILTER_BASE + TAB_COUNT) {
            KillTimer(hwnd, wParam);
            int index = static_cast<int>(wParam - TIMER_FILTER_BASE);
            RefreshList(g_tabs[index]);
            return 0;
        }
        if (wParam == TIMER_REGSEARCH) {
            KillTimer(hwnd, TIMER_REGSEARCH);
            std::wstring query = Trim(GetText(g_reg.searchEdit));
            if (query != g_reg.lastQuery) {
                g_reg.lastQuery = query;
                if (query.empty()) RegClearSearch();
                else RegSearchStart();
            }
            return 0;
        }
        return 0;
    case WM_APP_REGSEARCH:
        RegApplySearch(reinterpret_cast<RegSearchPayload*>(lParam));
        return 0;
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        int code = HIWORD(wParam);
        if (id < 1000 || id >= 1000 + TAB_COUNT * 100) return 0;
        int tabIndex = TabOf(id);
        int local = LocalOf(id);
        if (tabIndex < 0 || tabIndex >= TAB_COUNT) return 0;
        Tab& tab = g_tabs[tabIndex];

        if (code == BN_CLICKED) {
            switch (local) {
            case L_EVLOGON:
                if (tabIndex == TAB_EVENTVIEWER) EventViewerPreset(0);
                break;
            case L_EVFAIL:
                if (tabIndex == TAB_EVENTVIEWER) EventViewerPreset(1);
                break;
            case L_EVACCT:
                if (tabIndex == TAB_EVENTVIEWER) EventViewerPreset(2);
                break;
            case L_EVPROC:
                if (tabIndex == TAB_EVENTVIEWER) EventViewerPreset(3);
                break;
            case L_EVALL:
                if (tabIndex == TAB_EVENTVIEWER) EventViewerPreset(4);
                break;
            case L_REFRESH:
                if (tabIndex == TAB_VOLUME) RefreshVolumes();
                else if (tabIndex == TAB_CLIPBOARD) ClipboardRefresh();
                else if (tabIndex == TAB_REGISTRY) RegRefresh();
                break;
            case L_BROWSE:
                if (tabIndex == TAB_HIDDEN) HiddenBrowse();
                else if (tabIndex == TAB_FILEHASH) FileHashBrowse();
                else if (tabIndex == TAB_EXIF) ImageMetaBrowse();
                break;
            case L_MFTRECOVER:
                if (tabIndex == TAB_CARVE) StartMftRecover();
                break;
            case L_VIEWFILES:
                if (tabIndex == TAB_CARVE) CarveMediaSetView(false);
                break;
            case L_VIEWMEDIA:
                if (tabIndex == TAB_CARVE) CarveMediaSetView(true);
                break;
            case L_SAVE:
                if (tabIndex == TAB_CARVE) CarveSaveAll();
                break;
            case L_OPEN:
                if (tabIndex == TAB_CARVE) CarveOpenSelected();
                break;
            case L_HIVE:
                if (tabIndex == TAB_REGISTRY) RegLoadHive();
                break;
            case L_REGCLEAR:
                if (tabIndex == TAB_REGISTRY) RegClearSearch();
                break;
            case L_PROCDETAILS:
                if (tabIndex == TAB_PROCESS) SetProcessMemoryMode(false);
                break;
            case L_SVCSIGN:
                if (tabIndex == TAB_SERVICES) ServiceSignature();
                break;
            case L_SVCDRIVERS:
            case L_SVCRUNNING:
                if (tabIndex == TAB_SERVICES) StartServices();
                break;
            case L_PROCMEMORY:
                if (tabIndex == TAB_PROCESS) SetProcessMemoryMode(true);
                break;
            case L_MEMALL:
                if (tabIndex == TAB_PROCESS) MemoryReloadSelected();
                break;
            case L_MEMMODULES:
                if (tabIndex == TAB_PROCESS) MemoryShowReport(0);
                break;
            case L_MEMTHREADS:
                if (tabIndex == TAB_PROCESS) MemoryShowReport(1);
                break;
            case L_MEMHANDLES:
                if (tabIndex == TAB_PROCESS) MemoryShowReport(2);
                break;
            case L_MEMHEAPS:
                if (tabIndex == TAB_PROCESS) MemoryShowReport(3);
                break;
            case L_MEMMAP:
                if (tabIndex == TAB_PROCESS) MemoryShowReport(4);
                break;
            case L_MEMDUMP:
                if (tabIndex == TAB_PROCESS) MemoryDumpSelected();
                break;
            case L_START:
                if (tabIndex == TAB_SEARCH) StartSearch();
                else if (tabIndex == TAB_USN) StartUsn();
                else if (tabIndex == TAB_MFT) StartMft();
                else if (tabIndex == TAB_EVENTS) StartEvents();
                else if (tabIndex == TAB_EVENTVIEWER) StartEventViewer();
                else if (tabIndex == TAB_NFAT) StartNfat();
                else if (tabIndex == TAB_PACKET) StartPacket();
                else if (tabIndex == TAB_PREFETCH) StartPrefetch();
                else if (tabIndex == TAB_STRINGS) StartStrings();
                else if (tabIndex == TAB_POWERSHELL) StartPowerShell();
                else if (tabIndex == TAB_PROCESS) StartProcess();
                else if (tabIndex == TAB_SERVICES) StartServices();
                else if (tabIndex == TAB_COMPUTERINFO) StartComputerInfo();
                else if (tabIndex == TAB_SRUM) StartSrum();
                else if (tabIndex == TAB_AMCACHE) StartAmCache();
                else if (tabIndex == TAB_STARTUP) StartStartup();
                else if (tabIndex == TAB_PERSISTENCE) StartPersistence();
                else if (tabIndex == TAB_EXECUTION) StartExecution();
                else if (tabIndex == TAB_SIGNATURES) StartSignatures();
                else if (tabIndex == TAB_HIDDEN) StartHiddenScan();
                else if (tabIndex == TAB_CARVE) StartCarve();
                else if (tabIndex >= TAB_USB && tabIndex <= TAB_MRU) StartForensicScan(tabIndex);
                else if (tabIndex == TAB_THUMBNAIL) StartThumbcache();
                else if (tabIndex == TAB_WMI) StartWmiSubscriptions();
                else if (tabIndex == TAB_NETART) StartNetworkArtifacts();
                else if (tabIndex == TAB_DEFENDER) StartDefenderLogs();
                else if (tabIndex == TAB_RDP) StartEventTab(tabIndex);
                else if (tabIndex == TAB_ACTIVITIES) StartActivitiesCache();
                else if (tabIndex == TAB_CRASH) StartCrashDumps();
                else if (tabIndex == TAB_WPN) StartNotificationDatabase();
                else if (tabIndex == TAB_FILEHASH) StartFileHash();
                else if (tabIndex == TAB_EXIF) StartImageMeta();
                break;
            case L_STOP: StopWork(tab); break;
            case L_CLEAR: ClearFilter(tab); break;
            case L_HEXVIEW:
                if (tabIndex == TAB_STRINGS) StringsOpenHex();
                break;
            default: break;
            }
        } else if (code == CBN_SELCHANGE) {
            if (local == L_MODE) {
                SetFilterVisibility(tab);
                RefreshList(tab);
            } else if (local == L_TABLE) {
            }
        } else if (code == EN_CHANGE) {
            if (local == L_SEARCH || local == L_FROM || local == L_TO) ScheduleFilter(tab);
            if (local == L_REGSEARCH && tabIndex == TAB_REGISTRY) {
                SetTimer(g_hwnd, TIMER_REGSEARCH, 320, nullptr);
            }
        }
        return 0;
    }
    case WM_APP_BATCH:
        HandleBatch(reinterpret_cast<Batch*>(lParam));
        return 0;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        SetBkMode(dc, TRANSPARENT);
        SetBkColor(dc, kCanvas);
        return reinterpret_cast<LRESULT>(g_bgBrush ? g_bgBrush : GetSysColorBrush(COLOR_BTNFACE));
    }
    case WM_CLOSE:
        for (Tab& tab : g_tabs) {
            if (tab.stopFlag) tab.stopFlag->store(true);
        }
        HexClose();
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
}


static void LogLine(FILE* file, const std::wstring& s) {
    if (file) {
        fputws(s.c_str(), file);
        fputwc(L'\n', file);
    }
}

int RunMftRecoverCli(const std::wstring& volume, const std::wstring& outFolder) {
    FILE* file = nullptr;
    _wfopen_s(&file, L"windchecker_mft.log", L"w, ccs=UTF-8");

    MftRecoverConfig config;
    config.volume = volume;
    config.deletedOnly = true;

    std::mutex mutex;
    std::vector<Row> rows;
    std::wstring summary;
    std::atomic<bool> stop{false};
    Sink sink;
    sink.onBatch = [&](Batch&& batch) {
        std::lock_guard<std::mutex> lock(mutex);
        if (batch.reset) rows.clear();
        for (Row& row : batch.rows) rows.push_back(std::move(row));
        if (!batch.status.empty()) summary = batch.status;
    };
    RunMftRecover(sink, stop, config);

    LogLine(file, L"SUMMARY " + summary);
    for (const Row& row : rows) {
        std::wstring line = L"FILE";
        for (const std::wstring& cell : row) line += L" | " + cell;
        LogLine(file, line);
    }

    if (!outFolder.empty()) {
        CreateDirectoryW(outFolder.c_str(), nullptr);
        for (const CarvedFile& entry : CarvedSnapshot()) {
            std::wstring saved;
            if (WriteCarvedFile(entry, outFolder, saved)) {
                LogLine(file, L"SAVED " + entry.name + L" -> " + saved);
            }
        }
    }
    if (file) fclose(file);
    return 0;
}

}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    g_instance = instance;
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SetProcessDPIAware();
    HDC screen = GetDC(nullptr);
    g_dpi = GetDeviceCaps(screen, LOGPIXELSX);
    ReleaseDC(nullptr, screen);
    if (g_dpi <= 0) g_dpi = 96;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::wstring mftRecover;
    std::wstring mftOut;
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (_wcsicmp(argv[i], L"--mft-recover") == 0 && i + 1 < argc) {
                mftRecover = argv[++i];
            } else if (_wcsicmp(argv[i], L"--out") == 0 && i + 1 < argc) {
                mftOut = argv[++i];
            }
        }
        LocalFree(argv);
    }
    if (!mftRecover.empty()) {
        int result = RunMftRecoverCli(mftRecover, mftOut);
        WSACleanup();
        return result;
    }

    INITCOMMONCONTROLSEX controls{};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_TREEVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&controls);

    g_fontUI = MakeFont(9, FW_NORMAL);
    g_fontSmall = MakeFont(8, FW_NORMAL);
    g_fontTitle = MakeFont(14, FW_BOLD);
    g_fontMono = CreateFontW(-MulDiv(9, g_dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    g_bgBrush = CreateSolidBrush(kCanvas);

    WNDCLASSEXW pageClass{};
    pageClass.cbSize = sizeof(pageClass);
    pageClass.lpfnWndProc = PageProc;
    pageClass.hInstance = instance;
    pageClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    pageClass.hbrBackground = g_bgBrush;
    pageClass.lpszClassName = L"WindCheckerPage";
    RegisterClassExW(&pageClass);

    WNDCLASSEXW mainClass{};
    mainClass.cbSize = sizeof(mainClass);
    mainClass.lpfnWndProc = MainProc;
    mainClass.hInstance = instance;
    mainClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    SHSTOCKICONINFO windowIcon{};
    windowIcon.cbSize = sizeof(windowIcon);
    HICON largeIcon = nullptr;
    HICON smallIcon = nullptr;
    if (SUCCEEDED(SHGetStockIconInfo(SIID_FIND, SHGSI_ICON | SHGSI_LARGEICON, &windowIcon))) {
        largeIcon = windowIcon.hIcon;
    }
    SHSTOCKICONINFO windowIconSmall{};
    windowIconSmall.cbSize = sizeof(windowIconSmall);
    if (SUCCEEDED(SHGetStockIconInfo(SIID_FIND, SHGSI_ICON | SHGSI_SMALLICON, &windowIconSmall))) {
        smallIcon = windowIconSmall.hIcon;
    }
    mainClass.hIcon = largeIcon;
    if (!mainClass.hIcon) mainClass.hIcon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(101), IMAGE_ICON,
                                                                         0, 0, LR_DEFAULTSIZE | LR_SHARED));
    if (!mainClass.hIcon) mainClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    mainClass.hIconSm = smallIcon;
    if (!mainClass.hIconSm) mainClass.hIconSm = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(101), IMAGE_ICON,
                                                                             GetSystemMetrics(SM_CXSMICON),
                                                                             GetSystemMetrics(SM_CYSMICON), LR_SHARED));
    mainClass.hbrBackground = g_bgBrush;
    mainClass.lpszClassName = L"WindCheckerMain";
    RegisterClassExW(&mainClass);

    HWND hwnd = CreateWindowExW(0, L"WindCheckerMain", APP_TITLE,
                                WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                                CW_USEDEFAULT, CW_USEDEFAULT, S(1380), S(840),
                                nullptr, nullptr, instance, nullptr);
    if (!hwnd) return 1;

    ShowWindow(hwnd, showCommand == SW_SHOWDEFAULT ? SW_SHOWNORMAL : showCommand);
    UpdateWindow(hwnd);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    WSACleanup();
    return static_cast<int>(message.wParam);
}
