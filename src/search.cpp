#include "search.h"

#include <algorithm>
#include <regex>

namespace {

bool WildcardMatch(const std::wstring& text, const std::wstring& pattern, bool caseSensitive) {
    std::wstring subject = caseSensitive ? text : ToLower(text);
    std::wstring mask = caseSensitive ? pattern : ToLower(pattern);
    size_t ti = 0, pi = 0, star = std::wstring::npos, retry = 0;
    while (ti < subject.size()) {
        if (pi < mask.size() && (mask[pi] == L'?' || mask[pi] == subject[ti])) {
            ++ti;
            ++pi;
        } else if (pi < mask.size() && mask[pi] == L'*') {
            star = pi++;
            retry = ti;
        } else if (star != std::wstring::npos) {
            pi = star + 1;
            ti = ++retry;
        } else {
            return false;
        }
    }
    while (pi < mask.size() && mask[pi] == L'*') ++pi;
    return pi == mask.size();
}

std::wstring JoinPath(const std::wstring& folder, const std::wstring& name) {
    if (!folder.empty() && (folder.back() == L'\\' || folder.back() == L'/')) return folder + name;
    return folder + L"\\" + name;
}

bool SkipFolder(const std::wstring& name) {
    return _wcsicmp(name.c_str(), L"System Volume Information") == 0 ||
           _wcsicmp(name.c_str(), L"$Recycle.Bin") == 0;
}

std::wstring FileSizeText(unsigned long long size) {
    return SizeText(size);
}

}

std::vector<std::wstring> LogicalDrives() {
    std::vector<std::wstring> roots;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1u << i))) continue;
        roots.push_back(std::wstring(1, static_cast<wchar_t>(L'A' + i)) + L":\\");
    }
    return roots;
}

std::vector<std::wstring> NtfsDrives() {
    std::vector<std::wstring> drives;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1u << i))) continue;
        std::wstring root = std::wstring(1, static_cast<wchar_t>(L'A' + i)) + L":\\";
        wchar_t fs[64] = {};
        if (GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, nullptr, fs, _countof(fs)) &&
            _wcsicmp(fs, L"NTFS") == 0) {
            drives.push_back(root.substr(0, 2));
        }
    }
    return drives;
}

std::wstring AttributesText(DWORD attributes) {
    struct Entry { DWORD mask; const wchar_t* name; };
    static const Entry table[] = {
        {FILE_ATTRIBUTE_READONLY, L"Read-only"},
        {FILE_ATTRIBUTE_HIDDEN, L"Hidden"},
        {FILE_ATTRIBUTE_SYSTEM, L"System"},
        {FILE_ATTRIBUTE_DIRECTORY, L"Directory"},
        {FILE_ATTRIBUTE_ARCHIVE, L"Archive"},
        {FILE_ATTRIBUTE_COMPRESSED, L"Compressed"},
        {FILE_ATTRIBUTE_ENCRYPTED, L"Encrypted"},
        {FILE_ATTRIBUTE_REPARSE_POINT, L"Reparse point"},
        {FILE_ATTRIBUTE_OFFLINE, L"Offline"},
        {FILE_ATTRIBUTE_SPARSE_FILE, L"Sparse"},
    };
    std::wstring text;
    for (const Entry& entry : table) {
        if (!(attributes & entry.mask)) continue;
        if (!text.empty()) text += L", ";
        text += entry.name;
    }
    return text.empty() ? L"Normal" : text;
}

void RunFileSearch(const Sink& sink, std::atomic<bool>& stop, SearchConfig config) {
    std::wregex regex;
    bool useRegex = config.regex;
    if (useRegex) {
        try {
            auto flags = std::regex::ECMAScript | std::regex::optimize;
            if (!config.caseSensitive) flags |= std::regex::icase;
            regex = std::wregex(config.pattern, flags);
        } catch (const std::regex_error&) {
            sink.Error(L"Invalid regular expression: " + config.pattern);
            return;
        }
    }
    if (config.pattern.empty()) config.pattern = L"*";

    unsigned long long checked = 0;
    unsigned long long found = 0;
    std::vector<Row> pending;
    pending.reserve(256);

    auto flush = [&](bool force) {
        if (pending.empty()) return;
        sink.Rows(std::move(pending), false);
        pending.clear();
        pending.reserve(256);
        (void)force;
    };

    auto matches = [&](const std::wstring& name) {
        if (useRegex) return std::regex_search(name, regex);
        return WildcardMatch(name, config.pattern, config.caseSensitive);
    };

    for (const std::wstring& root : config.roots) {
        if (stop.load()) break;
        std::vector<std::wstring> stack;
        stack.push_back(root);

        while (!stack.empty() && !stop.load()) {
            std::wstring folder = std::move(stack.back());
            stack.pop_back();

            WIN32_FIND_DATAW data{};
            HANDLE handle = FindFirstFileExW(JoinPath(folder, L"*").c_str(), FindExInfoBasic, &data,
                                             FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
            if (handle == INVALID_HANDLE_VALUE) {

                handle = FindFirstFileW(JoinPath(folder, L"*").c_str(), &data);
            }
            if (handle == INVALID_HANDLE_VALUE) continue;

            do {
                if (stop.load()) break;
                const std::wstring name = data.cFileName;
                if (name == L"." || name == L"..") continue;

                if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
                    if (SkipFolder(name)) continue;
                    stack.push_back(JoinPath(folder, name));
                    continue;
                }

                ++checked;
                if (!matches(name)) continue;

                unsigned long long size = (static_cast<unsigned long long>(data.nFileSizeHigh) << 32) |
                                          static_cast<unsigned long long>(data.nFileSizeLow);
                if (size < config.minBytes) continue;
                if (config.maxBytes && size > config.maxBytes) continue;

                Row row;
                row.reserve(4);
                row.push_back(JoinPath(folder, name));
                row.push_back(FileSizeText(size));
                row.push_back(FileTimeText(data.ftLastWriteTime));
                row.push_back(AttributesText(data.dwFileAttributes));
                pending.push_back(std::move(row));
                ++found;

                if (pending.size() >= 200) {
                    flush(false);
                    sink.Status(Format(L"Checked %s files \u00B7 %s matches",
                                       CommaNumber(checked).c_str(), CommaNumber(found).c_str()));
                }
                if (checked % 2000 == 0) {
                    sink.Status(Format(L"Checked %s files \u00B7 %s matches",
                                       CommaNumber(checked).c_str(), CommaNumber(found).c_str()));
                }
            } while (FindNextFileW(handle, &data));
            FindClose(handle);

            if (checked % 500 == 0) {
                sink.Status(Format(L"Checked %s files \u00B7 %s matches",
                                   CommaNumber(checked).c_str(), CommaNumber(found).c_str()));
            }
        }
        if (stop.load()) break;
    }

    flush(true);
    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s matching files retained.", CommaNumber(found).c_str()));
    } else {
        sink.Done(Format(L"Completed. Checked %s files; found %s matches.",
                         CommaNumber(checked).c_str(), CommaNumber(found).c_str()));
    }
}
