#pragma once
#include "common.h"

struct SearchConfig {
    std::vector<std::wstring> roots;
    std::wstring pattern = L"*";
    bool regex = false;
    bool caseSensitive = false;
    unsigned long long minBytes = 0;
    unsigned long long maxBytes = 0;
};

std::vector<std::wstring> LogicalDrives();
std::vector<std::wstring> NtfsDrives();
std::wstring AttributesText(DWORD attributes);
void RunFileSearch(const Sink& sink, std::atomic<bool>& stop, SearchConfig config);
