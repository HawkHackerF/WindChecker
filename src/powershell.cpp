#include "artifacts.h"

#include <algorithm>

namespace {

constexpr size_t MAX_HISTORY_FILE = 32 * 1024 * 1024;

bool ReadTextFile(const std::wstring& path, std::wstring& text) {
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(handle, &size) || size.QuadPart <= 0 ||
        size.QuadPart > static_cast<long long>(MAX_HISTORY_FILE)) {
        CloseHandle(handle);
        return false;
    }
    std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    bool ok = ReadFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) != 0;
    CloseHandle(handle);
    if (!ok) return false;
    bytes.resize(read);

    if (bytes.size() >= 2 && static_cast<BYTE>(bytes[0]) == 0xFF && static_cast<BYTE>(bytes[1]) == 0xFE) {
        text.assign(reinterpret_cast<const wchar_t*>(bytes.data() + 2), (bytes.size() - 2) / sizeof(wchar_t));
        return true;
    }
    size_t start = 0;
    if (bytes.size() >= 3 && static_cast<BYTE>(bytes[0]) == 0xEF &&
        static_cast<BYTE>(bytes[1]) == 0xBB && static_cast<BYTE>(bytes[2]) == 0xBF) {
        start = 3;
    }
    int length = MultiByteToWideChar(CP_UTF8, 0, bytes.data() + start,
                                     static_cast<int>(bytes.size() - start), nullptr, 0);
    if (length <= 0) return false;
    text.assign(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, bytes.data() + start,
                        static_cast<int>(bytes.size() - start), text.data(), length);
    return true;
}

std::wstring LastSegment(const std::wstring& path) {
    size_t at = path.find_last_of(L"\\/");
    return at == std::wstring::npos ? path : path.substr(at + 1);
}

void AddHistoryPath(std::vector<std::pair<std::wstring, std::wstring>>& targets,
                    const std::wstring& profile, const std::wstring& user) {
    static const wchar_t* kSuffixes[] = {
        L"\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        L"\\AppData\\Roaming\\Microsoft\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
    };
    for (const wchar_t* suffix : kSuffixes) {
        std::wstring path = profile + suffix;
        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        bool duplicate = false;
        for (const auto& item : targets) {
            if (_wcsicmp(item.first.c_str(), path.c_str()) == 0) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) targets.emplace_back(path, user);
    }
}

std::wstring HistoryShell(const std::wstring& path) {
    return ToLower(path).find(L"\\windowspowershell\\") != std::wstring::npos
               ? L"Windows PowerShell"
               : L"PowerShell 7";
}

}

void RunPowerShellHistory(const Sink& sink, std::atomic<bool>& stop, PowerShellConfig config) {
    std::vector<std::pair<std::wstring, std::wstring>> targets;

    wchar_t appData[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH)) {
        wchar_t user[256] = {};
        DWORD length = 256;
        GetUserNameW(user, &length);
        AddHistoryPath(targets, appData, user[0] ? user : L"current user");
    }

    if (config.allUsers) {
        wchar_t profiles[MAX_PATH] = {};
        DWORD count = MAX_PATH;
        if (!GetProfilesDirectoryW(profiles, &count)) {
            wcscpy_s(profiles, L"C:\\Users");
        }
        std::wstring pattern = std::wstring(profiles) + L"\\*";
        WIN32_FIND_DATAW data{};
        HANDLE find = FindFirstFileW(pattern.c_str(), &data);
        if (find != INVALID_HANDLE_VALUE) {
            do {
                if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
                std::wstring profile = std::wstring(profiles) + L"\\" + data.cFileName;
                AddHistoryPath(targets, profile, data.cFileName);
            } while (FindNextFileW(find, &data));
            FindClose(find);
        }
    }

    if (config.systemProfile) {
        wchar_t systemRoot[MAX_PATH] = {};
        GetEnvironmentVariableW(L"SystemRoot", systemRoot, MAX_PATH);
        std::wstring profile = std::wstring(systemRoot[0] ? systemRoot : L"C:\\Windows") +
                               L"\\System32\\config\\systemprofile";
        AddHistoryPath(targets, profile, L"SYSTEM");
    }

    if (targets.empty()) {
        sink.Done(L"Completed. No PSReadLine ConsoleHost_history.txt file was found.");
        return;
    }

    std::sort(targets.begin(), targets.end());
    unsigned long long total = 0;
    std::vector<Row> pending;
    std::vector<std::wstring> details;
    pending.reserve(128);
    details.reserve(128);

    auto flush = [&]() {
        if (pending.empty()) return;
        sink.Detailed(std::move(pending), std::move(details), false);
        pending.clear();
        details.clear();
        pending.reserve(128);
        details.reserve(128);
    };

    for (size_t fileIndex = 0; fileIndex < targets.size() && !stop.load(); ++fileIndex) {
        const std::wstring& path = targets[fileIndex].first;
        const std::wstring& user = targets[fileIndex].second;
        sink.Status(Format(L"%s \u00B7 file %d/%d \u00B7 %s commands",
                           path.c_str(), static_cast<int>(fileIndex) + 1,
                           static_cast<int>(targets.size()), CommaNumber(total).c_str()));

        std::wstring text;
        if (!ReadTextFile(path, text)) continue;

        WIN32_FILE_ATTRIBUTE_DATA attributes{};
        std::wstring modified;
        if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes)) {
            modified = FileTimeText(attributes.ftLastWriteTime);
        }

        std::wstring shell = HistoryShell(path);
        size_t start = 0;
        int lineNumber = 0;
        while (start <= text.size() && !stop.load()) {
            size_t end = text.find(L'\n', start);
            if (end == std::wstring::npos) end = text.size();
            std::wstring line = text.substr(start, end - start);
            while (!line.empty() && (line.back() == L'\r' || line.back() == L'\n')) line.pop_back();
            ++lineNumber;
            start = end + 1;
            if (line.empty()) continue;

            Row row;
            row.reserve(5);
            row.push_back(modified);
            row.push_back(user);
            row.push_back(shell);
            row.push_back(Format(L"%d", lineNumber));
            row.push_back(line);
            std::wstring detail = Format(L"History file : %s\r\nUser         : %s\r\nShell        : %s\r\n"
                                         L"Line         : %d\r\nFile modified: %s\r\n\r\nCommand:\r\n%s",
                                         path.c_str(), user.c_str(), shell.c_str(), lineNumber,
                                         modified.c_str(), line.c_str());
            pending.push_back(std::move(row));
            details.push_back(std::move(detail));
            ++total;
            if (pending.size() >= 100) flush();
        }
        flush();
    }

    flush();
    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s PowerShell commands retained.", CommaNumber(total).c_str()));
    } else {
        sink.Done(Format(L"Completed. %s PowerShell commands from %s history file(s).",
                         CommaNumber(total).c_str(), CommaNumber(targets.size()).c_str()));
    }
}
