#include "artifacts.h"

#include <algorithm>

namespace {

struct PersistEntry {
    std::wstring category;
    std::wstring name;
    std::wstring location;
    std::wstring command;
    std::wstring extra;
    DWORD startType = 0;
    std::wstring account;
};

std::wstring ExpandEnv(const std::wstring& text) {
    wchar_t buffer[4096] = {};
    DWORD needed = ExpandEnvironmentStringsW(text.c_str(), buffer, 4096);
    if (needed == 0) return text;
    if (needed <= 4096) return buffer;
    std::wstring wide(needed, L'\0');
    if (ExpandEnvironmentStringsW(text.c_str(), wide.data(), needed) == 0) return text;
    while (!wide.empty() && wide.back() == L'\0') wide.pop_back();
    return wide;
}

std::wstring NormalizeImagePath(const std::wstring& raw) {
    std::wstring path = Trim(raw);
    if (path.size() > 4 && path.compare(0, 4, L"\\??\\") == 0) {
        path = path.substr(4);
    } else if (path.size() > 12 && _wcsnicmp(path.c_str(), L"\\SystemRoot\\", 12) == 0) {
        wchar_t root[MAX_PATH] = {};
        GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
        path = std::wstring(root[0] ? root : L"C:\\Windows") + L"\\" + path.substr(12);
    } else if (_wcsnicmp(path.c_str(), L"System32\\", 9) == 0 ||
               _wcsnicmp(path.c_str(), L"system32\\", 9) == 0) {
        wchar_t root[MAX_PATH] = {};
        GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
        path = std::wstring(root[0] ? root : L"C:\\Windows") + L"\\" + path;
    }
    return path;
}

std::wstring ExecutableFromCommand(const std::wstring& raw) {
    std::wstring text = Trim(ExpandEnv(raw));
    if (text.empty()) return L"";
    if (text[0] == L'"') {
        size_t close = text.find(L'"', 1);
        if (close != std::wstring::npos) return NormalizeImagePath(text.substr(1, close - 1));
        return NormalizeImagePath(text.substr(1));
    }
    std::wstring lower = ToLower(text);
    size_t exe = lower.find(L".exe");
    if (exe == std::wstring::npos) exe = lower.find(L".dll");
    if (exe == std::wstring::npos) exe = lower.find(L".sys");
    if (exe != std::wstring::npos) return NormalizeImagePath(text.substr(0, exe + 4));
    size_t space = text.find(L' ');
    return NormalizeImagePath(space == std::wstring::npos ? text : text.substr(0, space));
}

void AddRegistryValues(std::vector<PersistEntry>& out, HKEY root, REGSAM view,
                       const wchar_t* rootName, const wchar_t* subkey, const wchar_t* category) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | view, &key) != ERROR_SUCCESS) return;

    std::wstring location = std::wstring(rootName) + L"\\" + subkey;
    if (view == KEY_WOW64_32KEY) location += L"  [32-bit view]";

    for (DWORD index = 0;; ++index) {
        wchar_t name[1024] = {};
        DWORD nameLength = 1024;
        BYTE data[8192] = {};
        DWORD dataLength = sizeof(data);
        DWORD type = 0;
        LONG result = RegEnumValueW(key, index, name, &nameLength, nullptr, &type, data, &dataLength);
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) continue;
        if (nameLength == 0) continue;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

        std::wstring command(reinterpret_cast<const wchar_t*>(data), dataLength / sizeof(wchar_t));
        while (!command.empty() && command.back() == L'\0') command.pop_back();
        if (Trim(command).empty()) continue;

        PersistEntry entry;
        entry.category = category;
        entry.name = name;
        entry.location = location;
        entry.command = command;
        out.push_back(std::move(entry));
    }
    RegCloseKey(key);
}

void AddSingleValue(std::vector<PersistEntry>& out, HKEY root, REGSAM view, const wchar_t* rootName,
                    const wchar_t* subkey, const wchar_t* value, const wchar_t* category) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | view, &key) != ERROR_SUCCESS) return;
    wchar_t data[4096] = {};
    DWORD dataLength = sizeof(data);
    DWORD type = 0;
    if (RegQueryValueExW(key, value, nullptr, &type, reinterpret_cast<BYTE*>(data), &dataLength) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        std::wstring command(data, dataLength / sizeof(wchar_t));
        while (!command.empty() && command.back() == L'\0') command.pop_back();
        if (!Trim(command).empty()) {
            PersistEntry entry;
            entry.category = category;
            entry.name = value;
            entry.location = std::wstring(rootName) + L"\\" + subkey;
            entry.command = command;
            out.push_back(std::move(entry));
        }
    }
    RegCloseKey(key);
}

void AddImageFileOptions(std::vector<PersistEntry>& out) {
    static const wchar_t* kRoot = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRoot, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return;

    for (DWORD index = 0;; ++index) {
        wchar_t name[512] = {};
        DWORD nameLength = 512;
        if (RegEnumKeyExW(key, index, name, &nameLength, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        HKEY child = nullptr;
        if (RegOpenKeyExW(key, name, 0, KEY_READ | KEY_WOW64_64KEY, &child) != ERROR_SUCCESS) continue;
        for (const wchar_t* value : {L"Debugger", L"VerifierDlls", L"GlobalFlag"}) {
            wchar_t data[2048] = {};
            DWORD dataLength = sizeof(data);
            DWORD type = 0;
            if (RegQueryValueExW(child, value, nullptr, &type, reinterpret_cast<BYTE*>(data), &dataLength) != ERROR_SUCCESS)
                continue;
            std::wstring text;
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                text.assign(data, dataLength / sizeof(wchar_t));
                while (!text.empty() && text.back() == L'\0') text.pop_back();
            } else if (type == REG_DWORD && dataLength >= 4) {
                text = Format(L"0x%08lX", *reinterpret_cast<DWORD*>(data));
            }
            if (Trim(text).empty()) continue;
            PersistEntry entry;
            entry.category = L"IFEO";
            entry.name = std::wstring(name) + L" \u00B7 " + value;
            entry.location = std::wstring(L"HKLM\\") + kRoot + L"\\" + name;
            entry.command = text;
            out.push_back(std::move(entry));
        }
        RegCloseKey(child);
    }
    RegCloseKey(key);
}

std::wstring ServiceStartText(DWORD start) {
    switch (start) {
    case SERVICE_BOOT_START: return L"boot";
    case SERVICE_SYSTEM_START: return L"system";
    case SERVICE_AUTO_START: return L"auto";
    case SERVICE_DEMAND_START: return L"demand";
    case SERVICE_DISABLED: return L"disabled";
    default: return Format(L"0x%X", start);
    }
}

std::wstring ServiceStateText(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED: return L"stopped";
    case SERVICE_START_PENDING: return L"start pending";
    case SERVICE_STOP_PENDING: return L"stop pending";
    case SERVICE_RUNNING: return L"running";
    case SERVICE_CONTINUE_PENDING: return L"continue pending";
    case SERVICE_PAUSE_PENDING: return L"pause pending";
    case SERVICE_PAUSED: return L"paused";
    default: return Format(L"state %u", state);
    }
}

void AddServices(std::vector<PersistEntry>& out, DWORD serviceType, const wchar_t* category,
                 std::atomic<bool>& stop) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!manager) return;

    DWORD needed = 0;
    DWORD returned = 0;
    DWORD resume = 0;
    std::vector<BYTE> buffer(128 * 1024);
    for (;;) {
        if (stop.load()) break;
        BOOL ok = EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, serviceType,
                                        SERVICE_STATE_ALL, buffer.data(),
                                        static_cast<DWORD>(buffer.size()), &needed, &returned,
                                        &resume, nullptr);
        if (!ok) {
            if (GetLastError() == ERROR_MORE_DATA) {
                buffer.resize(needed + 16384);
                continue;
            }
            break;
        }
        auto* items = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());
        for (DWORD i = 0; i < returned; ++i) {
            const wchar_t* serviceName = items[i].lpServiceName;
            PersistEntry entry;
            entry.category = category;
            entry.name = items[i].lpDisplayName && items[i].lpDisplayName[0]
                             ? std::wstring(items[i].lpDisplayName) + L" (" + serviceName + L")"
                             : std::wstring(serviceName);
            entry.location = std::wstring(L"Service Control Manager \u00B7 ") +
                             ServiceStateText(items[i].ServiceStatusProcess.dwCurrentState);

            SC_HANDLE service = OpenServiceW(manager, serviceName, SERVICE_QUERY_CONFIG);
            if (service) {
                DWORD configSize = 0;
                QueryServiceConfigW(service, nullptr, 0, &configSize);
                std::vector<BYTE> config(configSize ? configSize : 8192);
                auto* info = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data());
                if (QueryServiceConfigW(service, info, static_cast<DWORD>(config.size()), &configSize)) {
                    entry.command = info->lpBinaryPathName ? info->lpBinaryPathName : L"";
                    entry.startType = info->dwStartType;
                    entry.account = info->lpServiceStartName ? info->lpServiceStartName : L"";
                    entry.extra = Format(L"Start type : %s\r\nAccount    : %s\r\n",
                                         ServiceStartText(info->dwStartType).c_str(),
                                         info->lpServiceStartName ? info->lpServiceStartName : L"");
                    if (info->lpDependencies && info->lpDependencies[0]) {
                        entry.extra += L"Depends on : " + std::wstring(info->lpDependencies) + L"\r\n";
                    }
                }
                CloseServiceHandle(service);
            }
            out.push_back(std::move(entry));
        }
        if (needed <= buffer.size()) break;
        buffer.resize(needed + 16384);
    }
    CloseServiceHandle(manager);
}

bool ReadTextFileWide(const std::wstring& path, size_t limit, std::wstring& text) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > static_cast<long long>(limit)) {
        CloseHandle(file);
        return false;
    }
    std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    bool ok = ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) != 0;
    CloseHandle(file);
    if (!ok) return false;
    bytes.resize(read);
    if (bytes.size() >= 2 && static_cast<BYTE>(bytes[0]) == 0xFF && static_cast<BYTE>(bytes[1]) == 0xFE) {
        text.assign(reinterpret_cast<const wchar_t*>(bytes.data() + 2), (bytes.size() - 2) / 2);
        return true;
    }
    size_t start = 0;
    if (bytes.size() >= 3 && static_cast<BYTE>(bytes[0]) == 0xEF && static_cast<BYTE>(bytes[1]) == 0xBB &&
        static_cast<BYTE>(bytes[2]) == 0xBF) {
        start = 3;
    }
    text = Utf8ToWide(bytes.substr(start));
    return true;
}

std::vector<std::wstring> XmlValues(const std::wstring& xml, const wchar_t* tag) {
    std::vector<std::wstring> values;
    std::wstring open = std::wstring(L"<") + tag + L">";
    std::wstring close = std::wstring(L"</") + tag + L">";
    size_t at = 0;
    while ((at = xml.find(open, at)) != std::wstring::npos) {
        at += open.size();
        size_t end = xml.find(close, at);
        if (end == std::wstring::npos) break;
        values.push_back(Trim(xml.substr(at, end - at)));
        at = end + close.size();
    }
    return values;
}

void AddScheduledTasks(std::vector<PersistEntry>& out, const std::wstring& folder,
                       const std::wstring& relative, std::atomic<bool>& stop) {
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW((folder + L"\\*").c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        if (stop.load()) break;
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
        std::wstring full = folder + L"\\" + data.cFileName;
        std::wstring name = relative.empty() ? data.cFileName : relative + L"\\" + data.cFileName;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            AddScheduledTasks(out, full, name, stop);
            continue;
        }
        size_t dot = name.find_last_of(L'.');
        if (dot != std::wstring::npos && _wcsicmp(name.c_str() + dot, L".xml") != 0) continue;

        std::wstring xml;
        if (!ReadTextFileWide(full, 4 * 1024 * 1024, xml)) continue;

        std::vector<std::wstring> commands = XmlValues(xml, L"Command");
        std::vector<std::wstring> arguments = XmlValues(xml, L"Arguments");
        std::vector<std::wstring> authors = XmlValues(xml, L"Author");
        std::vector<std::wstring> users = XmlValues(xml, L"UserId");
        std::vector<std::wstring> enabledValues = XmlValues(xml, L"Enabled");
        std::wstring author = authors.empty() ? L"" : authors.front();
        std::wstring userId = users.empty() ? L"" : users.front();
        std::wstring enabled = enabledValues.empty() ? L"" : enabledValues.front();

        PersistEntry entry;
        entry.category = L"Scheduled task";
        entry.name = name;
        entry.location = full;
        if (!commands.empty()) {
            entry.command = commands.front();
            if (!arguments.empty() && !arguments.front().empty()) entry.command += L" " + arguments.front();
            if (commands.size() > 1) {
                entry.extra = Format(L"Actions    : %d (first shown)\r\n", static_cast<int>(commands.size()));
            }
        }
        if (!author.empty()) entry.extra += L"Author     : " + author + L"\r\n";
        if (!userId.empty()) entry.extra += L"Run as     : " + userId + L"\r\n";
        if (!enabled.empty()) entry.extra += L"Enabled    : " + enabled + L"\r\n";
        out.push_back(std::move(entry));
    } while (FindNextFileW(find, &data));
    FindClose(find);
}

void AddStartupFolder(std::vector<PersistEntry>& out, const std::wstring& folder) {
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW((folder + L"\\*").c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        PersistEntry entry;
        entry.category = L"Startup folder";
        entry.name = data.cFileName;
        entry.location = folder;
        entry.command = folder + L"\\" + data.cFileName;
        out.push_back(std::move(entry));
    } while (FindNextFileW(find, &data));
    FindClose(find);
}

std::wstring BuildDetail(const PersistEntry& entry) {
    std::wstring text;
    text += L"Category   : " + entry.category + L"\r\n";
    text += L"Name       : " + entry.name + L"\r\n";
    text += L"Location   : " + entry.location + L"\r\n";
    text += L"Command    : " + (entry.command.empty() ? L"(empty)" : entry.command) + L"\r\n";
    if (!entry.extra.empty()) text += entry.extra;

    std::wstring exe = ExecutableFromCommand(entry.command);
    if (!exe.empty()) {
        text += L"\r\nExecutable : " + exe + L"\r\n";
        WIN32_FILE_ATTRIBUTE_DATA attributes{};
        if (GetFileAttributesExW(exe.c_str(), GetFileExInfoStandard, &attributes)) {
            unsigned long long bytes = (static_cast<unsigned long long>(attributes.nFileSizeHigh) << 32) |
                                       attributes.nFileSizeLow;
            text += L"File size  : " + SizeText(bytes) + L"\r\n";
            text += L"Modified   : " + FileTimeText(attributes.ftLastWriteTime) + L"\r\n";
            text += L"Signature  : " + FileSignatureText(exe) + L"\r\n";
        } else {
            text += L"File size  : (file not found)\r\n";
        }
    }
    return text;
}

}

void RunPersistenceAudit(const Sink& sink, std::atomic<bool>& stop, PersistenceConfig config) {
    std::vector<PersistEntry> entries;

    if (config.registry) {
        sink.Status(L"Reading autostart registry keys\u2026");
        static const wchar_t* kRunKeys[] = {
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        };
        for (const wchar_t* key : kRunKeys) {
            if (stop.load()) break;
            AddRegistryValues(entries, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, L"HKLM", key, L"Run key");
            AddRegistryValues(entries, HKEY_CURRENT_USER, KEY_WOW64_64KEY, L"HKCU", key, L"Run key");
        }

        static const wchar_t* kWinlogon = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
        for (const wchar_t* value : {L"Shell", L"Userinit", L"Taskman", L"AppSetup", L"GinaDLL", L"VmApplet"}) {
            AddSingleValue(entries, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, L"HKLM", kWinlogon, value, L"Winlogon");
        }
        AddSingleValue(entries, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, L"HKLM",
                       L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", L"AppInit");
        AddSingleValue(entries, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, L"HKLM",
                       L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                       L"AppInit_DLLs", L"AppInit");
        AddImageFileOptions(entries);
    }

    if (config.services && !stop.load()) {
        sink.Status(L"Enumerating services and drivers\u2026");
        AddServices(entries, SERVICE_WIN32, L"Service", stop);
        AddServices(entries, SERVICE_DRIVER, L"Driver", stop);
    }

    if (config.tasks && !stop.load()) {
        sink.Status(L"Parsing scheduled tasks\u2026");
        wchar_t systemRoot[MAX_PATH] = {};
        GetEnvironmentVariableW(L"SystemRoot", systemRoot, MAX_PATH);
        AddScheduledTasks(entries, std::wstring(systemRoot[0] ? systemRoot : L"C:\\Windows") + L"\\System32\\Tasks",
                          L"", stop);
    }

    if (config.folders && !stop.load()) {
        sink.Status(L"Reading startup folders\u2026");
        wchar_t programData[MAX_PATH] = {};
        GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
        if (programData[0]) {
            AddStartupFolder(entries, std::wstring(programData) +
                                          L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        }
        wchar_t profiles[MAX_PATH] = {};
        DWORD count = MAX_PATH;
        if (GetProfilesDirectoryW(profiles, &count)) {
            WIN32_FIND_DATAW data{};
            HANDLE find = FindFirstFileW((std::wstring(profiles) + L"\\*").c_str(), &data);
            if (find != INVALID_HANDLE_VALUE) {
                do {
                    if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                    if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
                    AddStartupFolder(entries,
                                     std::wstring(profiles) + L"\\" + data.cFileName +
                                         L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
                } while (FindNextFileW(find, &data));
                FindClose(find);
            }
        }
    }

    if (stop.load()) {
        sink.Done(L"Stopped. Persistence audit was cancelled.");
        return;
    }

    std::sort(entries.begin(), entries.end(), [](const PersistEntry& a, const PersistEntry& b) {
        if (a.category != b.category) return a.category < b.category;
        return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
    });

    std::vector<Row> pending;
    std::vector<std::wstring> details;
    pending.reserve(32);
    details.reserve(32);
    unsigned long long emitted = 0;
    bool firstBatch = true;

    auto flush = [&]() {
        if (pending.empty()) return;
        sink.Detailed(std::move(pending), std::move(details), firstBatch);
        firstBatch = false;
        pending.clear();
        details.clear();
        pending.reserve(32);
        details.reserve(32);
    };

    for (size_t i = 0; i < entries.size() && !stop.load(); ++i) {
        const PersistEntry& entry = entries[i];
        if ((i % 16) == 0) {
            sink.Status(Format(L"Checking %s/%s \u00B7 %s", CommaNumber(i + 1).c_str(),
                               CommaNumber(entries.size()).c_str(), entry.name.c_str()),
                        static_cast<int>((i + 1) * 100 / entries.size()));
        }
        std::wstring exe = ExecutableFromCommand(entry.command);
        std::wstring signature;
        if (!exe.empty()) signature = FileSignatureText(exe);

        Row row;
        row.reserve(5);
        row.push_back(entry.category);
        row.push_back(entry.name);
        row.push_back(entry.location);
        row.push_back(entry.command);
        row.push_back(signature.empty() ? L"-" : signature);

        pending.push_back(std::move(row));
        details.push_back(BuildDetail(entry));
        ++emitted;
        if (pending.size() >= 32) flush();
    }
    flush();

    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s autostart entries retained.", CommaNumber(emitted).c_str()));
        return;
    }
    sink.Done(Format(L"Completed. %s autostart entries.", CommaNumber(emitted).c_str()));
}

namespace {

std::wstring CurrentUser() {
    wchar_t name[256] = {};
    DWORD size = 256;
    if (!GetUserNameW(name, &size)) return L"current user";
    return name;
}

std::wstring ResolveClsid(const std::wstring& clsid) {
    const std::wstring key = L"CLSID\\" + clsid + L"\\InprocServer32";
    HKEY handle = nullptr;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, key.c_str(), 0, KEY_READ, &handle) != ERROR_SUCCESS) return L"";
    wchar_t data[2048] = {};
    DWORD bytes = sizeof(data);
    DWORD type = 0;
    std::wstring result;
    if (RegQueryValueExW(handle, nullptr, nullptr, &type, reinterpret_cast<BYTE*>(data), &bytes) ==
            ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        result.assign(data, bytes / sizeof(wchar_t));
        while (!result.empty() && result.back() == L'\0') result.pop_back();
    }
    RegCloseKey(handle);
    return result;
}

void AddClsidValues(std::vector<PersistEntry>& out, HKEY root, const wchar_t* rootName,
                    const wchar_t* subkey, const wchar_t* category) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return;
    for (DWORD index = 0;; ++index) {
        wchar_t name[512] = {};
        DWORD nameLength = 512;
        LONG result = RegEnumValueW(key, index, name, &nameLength, nullptr, nullptr, nullptr, nullptr);
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) continue;
        PersistEntry entry;
        entry.category = category;
        entry.name = name;
        entry.location = std::wstring(rootName) + L"\\" + subkey;
        entry.command = ResolveClsid(name);
        if (entry.command.empty()) entry.command = name;
        out.push_back(std::move(entry));
    }
    RegCloseKey(key);
}

void AddActiveSetup(std::vector<PersistEntry>& out, std::atomic<bool>& stop) {
    static const wchar_t* kRoot = L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components";
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRoot, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return;
    for (DWORD index = 0; !stop.load(); ++index) {
        wchar_t name[512] = {};
        DWORD length = 512;
        if (RegEnumKeyExW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        HKEY child = nullptr;
        if (RegOpenKeyExW(key, name, 0, KEY_READ | KEY_WOW64_64KEY, &child) != ERROR_SUCCESS) continue;

        wchar_t label[512] = {};
        DWORD labelBytes = sizeof(label);
        DWORD labelType = 0;
        std::wstring display = name;
        if (RegQueryValueExW(child, nullptr, nullptr, &labelType, reinterpret_cast<BYTE*>(label),
                             &labelBytes) == ERROR_SUCCESS &&
            (labelType == REG_SZ || labelType == REG_EXPAND_SZ)) {
            std::wstring text(label, labelBytes / sizeof(wchar_t));
            while (!text.empty() && text.back() == L'\0') text.pop_back();
            if (!Trim(text).empty()) display = text;
        }
        wchar_t stub[4096] = {};
        DWORD bytes = sizeof(stub);
        DWORD type = 0;
        if (RegQueryValueExW(child, L"StubPath", nullptr, &type, reinterpret_cast<BYTE*>(stub), &bytes) ==
                ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ)) {
            std::wstring command(stub, bytes / sizeof(wchar_t));
            while (!command.empty() && command.back() == L'\0') command.pop_back();
            if (!Trim(command).empty()) {
                PersistEntry entry;
                entry.category = L"Active Setup";
                entry.name = display;
                entry.location = std::wstring(L"HKLM\\") + kRoot + L"\\" + name;
                entry.command = command;
                out.push_back(std::move(entry));
            }
        }
        RegCloseKey(child);
    }
    RegCloseKey(key);
}

void AddWinlogonNotify(std::vector<PersistEntry>& out, std::atomic<bool>& stop) {
    static const wchar_t* kRoot = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify";
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRoot, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return;
    for (DWORD index = 0; !stop.load(); ++index) {
        wchar_t name[512] = {};
        DWORD length = 512;
        if (RegEnumKeyExW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        HKEY child = nullptr;
        if (RegOpenKeyExW(key, name, 0, KEY_READ | KEY_WOW64_64KEY, &child) != ERROR_SUCCESS) continue;
        wchar_t dll[2048] = {};
        DWORD bytes = sizeof(dll);
        DWORD type = 0;
        std::wstring command;
        if (RegQueryValueExW(child, L"DllName", nullptr, &type, reinterpret_cast<BYTE*>(dll), &bytes) ==
                ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ)) {
            command.assign(dll, bytes / sizeof(wchar_t));
            while (!command.empty() && command.back() == L'\0') command.pop_back();
        }
        RegCloseKey(child);
        if (Trim(command).empty()) continue;
        PersistEntry entry;
        entry.category = L"Winlogon Notify";
        entry.name = name;
        entry.location = std::wstring(L"HKLM\\") + kRoot + L"\\" + name;
        entry.command = command;
        out.push_back(std::move(entry));
    }
    RegCloseKey(key);
}

void CollectDisabled(std::set<std::wstring>& disabled, HKEY root, const wchar_t* subkey) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return;
    for (DWORD index = 0;; ++index) {
        wchar_t name[512] = {};
        DWORD nameLength = 512;
        BYTE data[64] = {};
        DWORD bytes = sizeof(data);
        LONG result = RegEnumValueW(key, index, name, &nameLength, nullptr, nullptr, data, &bytes);
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) continue;
        if (bytes > 0 && (data[0] & 0x01)) disabled.insert(ToLower(name));
    }
    RegCloseKey(key);
}

std::wstring RootOf(const std::wstring& location) {
    const size_t slash = location.find(L'\\');
    return slash == std::wstring::npos ? location : location.substr(0, slash);
}

}

void RunStartupInventory(const Sink& sink, std::atomic<bool>& stop) {
    std::vector<PersistEntry> entries;

    sink.Status(L"Reading Run keys\u2026");
    static const wchar_t* kRunKeys[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    };
    for (const wchar_t* key : kRunKeys) {
        if (stop.load()) break;
        AddRegistryValues(entries, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, L"HKLM", key, L"Run key");
        AddRegistryValues(entries, HKEY_CURRENT_USER, KEY_WOW64_64KEY, L"HKCU", key, L"Run key");
    }

    if (!stop.load()) {
        sink.Status(L"Reading Winlogon, Active Setup and shell hooks\u2026");
        static const wchar_t* kWinlogon = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
        for (const wchar_t* value : {L"Shell", L"Userinit", L"Taskman", L"AppSetup", L"VmApplet"}) {
            AddSingleValue(entries, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, L"HKLM", kWinlogon, value,
                           L"Winlogon");
        }
        AddSingleValue(entries, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, L"HKLM",
                       L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs",
                       L"AppInit");
        AddSingleValue(entries, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, L"HKLM",
                       L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                       L"AppInit_DLLs", L"AppInit (32-bit)");
        AddWinlogonNotify(entries, stop);
        AddActiveSetup(entries, stop);
        for (HKEY root : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
            const wchar_t* name = root == HKEY_LOCAL_MACHINE ? L"HKLM" : L"HKCU";
            AddClsidValues(entries, root, name,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
                           L"Shell service object");
            AddClsidValues(entries, root, name,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
                           L"Shell execute hook");
        }
        AddImageFileOptions(entries);
    }

    if (!stop.load()) {
        sink.Status(L"Enumerating auto-start services and drivers\u2026");
        std::vector<PersistEntry> services;
        AddServices(services, SERVICE_WIN32, L"Service", stop);
        AddServices(services, SERVICE_DRIVER, L"Driver", stop);
        for (auto& service : services) {

            if (service.startType == SERVICE_DEMAND_START || service.startType == SERVICE_DISABLED) {
                continue;
            }
            if (service.category == L"Driver") {
                service.category = service.startType == SERVICE_BOOT_START ? L"Driver (boot)"
                                 : service.startType == SERVICE_SYSTEM_START ? L"Driver (system)"
                                                                            : L"Driver (auto)";
            } else {
                service.category = L"Service (auto)";
            }
            entries.push_back(std::move(service));
        }
    }

    if (!stop.load()) {
        sink.Status(L"Parsing scheduled tasks\u2026");
        wchar_t systemRoot[MAX_PATH] = {};
        GetEnvironmentVariableW(L"SystemRoot", systemRoot, MAX_PATH);
        AddScheduledTasks(entries,
                          std::wstring(systemRoot[0] ? systemRoot : L"C:\\Windows") + L"\\System32\\Tasks",
                          L"", stop);
    }

    if (!stop.load()) {
        sink.Status(L"Reading startup folders\u2026");
        wchar_t programData[MAX_PATH] = {};
        GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
        AddStartupFolder(entries, std::wstring(programData[0] ? programData : L"C:\\ProgramData") +
                                      L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");

        wchar_t appData[MAX_PATH] = {};
        GetEnvironmentVariableW(L"AppData", appData, MAX_PATH);
        if (appData[0]) {
            AddStartupFolder(entries,
                             std::wstring(appData) +
                                 L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        }
    }

    if (stop.load()) {
        sink.Done(L"Stopped. Startup inventory was cancelled.");
        return;
    }

    std::set<std::wstring> disabled;
    CollectDisabled(disabled, HKEY_CURRENT_USER,
                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run");
    CollectDisabled(disabled, HKEY_CURRENT_USER,
                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder");
    CollectDisabled(disabled, HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run");
    CollectDisabled(disabled, HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder");

    std::sort(entries.begin(), entries.end(), [](const PersistEntry& a, const PersistEntry& b) {
        if (a.category != b.category) return a.category < b.category;
        return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
    });

    const std::wstring user = CurrentUser();
    std::vector<Row> pending;
    std::vector<std::wstring> details;
    pending.reserve(32);
    details.reserve(32);
    unsigned long long emitted = 0;
    bool firstBatch = true;

    auto flush = [&]() {
        if (pending.empty()) return;
        sink.Detailed(std::move(pending), std::move(details), firstBatch);
        firstBatch = false;
        pending.clear();
        details.clear();
        pending.reserve(32);
        details.reserve(32);
    };

    for (size_t i = 0; i < entries.size() && !stop.load(); ++i) {
        const PersistEntry& entry = entries[i];
        if ((i % 16) == 0) {
            sink.Status(Format(L"Checking %s/%s \u00B7 %s", CommaNumber(i + 1).c_str(),
                               CommaNumber(entries.size()).c_str(), entry.name.c_str()),
                        static_cast<int>((i + 1) * 100 / entries.size()));
        }

        const std::wstring root = RootOf(entry.location);
        std::wstring source = entry.category;
        std::wstring account = entry.account;
        if (entry.category == L"Startup folder") {
            const bool allUsers = ToLower(entry.location).find(L"programdata") != std::wstring::npos;
            source = allUsers ? L"Startup folder (all users)" : L"Startup folder (" + user + L")";
            account = allUsers ? L"All users" : user;
        } else if (entry.category.rfind(L"Service", 0) == 0 || entry.category.rfind(L"Driver", 0) == 0) {
            source = entry.category + L" \u00B7 SCM";
        } else if (entry.category == L"Scheduled task") {
            const size_t at = entry.extra.find(L"Run as     : ");
            if (at != std::wstring::npos) {
                const size_t end = entry.extra.find(L"\r\n", at);
                account = entry.extra.substr(at + 13, end == std::wstring::npos ? std::wstring::npos
                                                                                : end - at - 13);
            }
        } else {
            source = entry.category + L" (" + root + L")";
            if (account.empty()) account = root == L"HKLM" ? L"All users" : user;
        }
        const bool off = disabled.count(ToLower(entry.name)) > 0;

        std::wstring signature;
        const std::wstring exe = ExecutableFromCommand(entry.command);
        if (!exe.empty()) signature = FileSignatureText(exe);

        Row row;
        row.reserve(6);
        row.push_back(source);
        row.push_back(entry.name);
        row.push_back(entry.command);
        row.push_back(account.empty() ? L"-" : account);
        row.push_back(off ? L"no" : L"yes");
        row.push_back(signature.empty() ? L"-" : signature);

        pending.push_back(std::move(row));
        details.push_back(BuildDetail(entry));
        ++emitted;
        if (pending.size() >= 32) flush();
    }
    flush();

    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s startup item(s) retained.", CommaNumber(emitted).c_str()));
        return;
    }
    sink.Done(Format(L"Completed. %s startup item(s).", CommaNumber(emitted).c_str()));
}
