#include "artifacts.h"

#include <psapi.h>

#include <algorithm>

#pragma comment(lib, "psapi.lib")

namespace {

constexpr int MAX_TREE_LINES = 200;
constexpr int MAX_MODULES_SHOWN = 400;
constexpr int MAX_CHILDREN_SHOWN = 60;
constexpr int MAX_RELATED_SHOWN = 40;

struct WcUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct SystemProcessEntry {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    WcUnicodeString ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
};

struct SystemMemoryStats {
    unsigned long long workingSet = 0;
    unsigned long long privateWorkingSet = 0;
    unsigned long long peakWorkingSet = 0;
    unsigned long long virtualSize = 0;
    unsigned long long peakVirtualSize = 0;
    unsigned long long pagefileUsage = 0;
    unsigned long long peakPagefileUsage = 0;
    unsigned long long privateCommit = 0;
    unsigned long long pagedPool = 0;
    unsigned long long nonPagedPool = 0;
    unsigned long pageFaults = 0;
    unsigned long handles = 0;
    unsigned long threads = 0;
    unsigned long session = 0;
};

struct ModuleEntry {
    unsigned long long base = 0;
    unsigned long size = 0;
    std::wstring path;
};

struct FlatService {
    std::wstring name;
    std::wstring display;
    std::wstring state;
    std::wstring start;
    std::wstring account;
    std::wstring binary;
    std::wstring description;
    DWORD pid = 0;
    bool driver = false;
};

struct ProcNode {
    DWORD pid = 0;
    DWORD ppid = 0;
    std::wstring name;
    std::wstring path;
    std::wstring cmd;
    std::wstring user;
    std::wstring started;
    std::wstring arch;
    std::wstring integrity;
    std::wstring priority;
    std::wstring fileSize;
    std::wstring fileModified;
    std::wstring parentName;
    DWORD session = 0;
    DWORD threads = 0;
    DWORD handles = 0;
    bool elevated = false;
    bool accessible = false;
    unsigned long long workingSet = 0;
    unsigned long long privateWorkingSet = 0;
    unsigned long long peakWorkingSet = 0;
    unsigned long long privateBytes = 0;
    unsigned long long virtualBytes = 0;
    unsigned long long peakVirtualBytes = 0;
    unsigned long long commitBytes = 0;
    unsigned long long peakCommitBytes = 0;
    unsigned long long privateCommit = 0;
    unsigned long long pagedPool = 0;
    unsigned long long nonPagedPool = 0;
    unsigned long long pageFaults = 0;
    std::vector<DWORD> children;
    std::vector<ModuleEntry> moduleEntries;
    std::vector<FlatService> serviceEntries;
    std::vector<std::wstring> scripts;
    std::vector<DWORD> related;
    std::wstring treePrefix;
};

void CollectSystemMemory(std::unordered_map<DWORD, SystemMemoryStats>& out) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    using QueryFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    auto query = reinterpret_cast<QueryFn>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!query) return;

    std::vector<unsigned char> buffer(1 << 20);
    LONG status = -1;
    for (int attempt = 0; attempt < 8; ++attempt) {
        ULONG needed = 0;
        status = query(5 , buffer.data(),
                       static_cast<ULONG>(buffer.size()), &needed);
        if (status >= 0) break;
        if (needed > buffer.size()) buffer.resize(needed + 65536);
        else buffer.resize(buffer.size() * 2);
    }
    if (status < 0) return;

    unsigned char* cursor = buffer.data();
    for (;;) {
        auto* entry = reinterpret_cast<SystemProcessEntry*>(cursor);
        DWORD pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(entry->UniqueProcessId));
        SystemMemoryStats stats;
        stats.workingSet = entry->WorkingSetSize;
        stats.privateWorkingSet = entry->WorkingSetPrivateSize.QuadPart > 0
                                      ? static_cast<unsigned long long>(entry->WorkingSetPrivateSize.QuadPart)
                                      : 0;
        stats.peakWorkingSet = entry->PeakWorkingSetSize;
        stats.virtualSize = entry->VirtualSize;
        stats.peakVirtualSize = entry->PeakVirtualSize;
        stats.pagefileUsage = entry->PagefileUsage;
        stats.peakPagefileUsage = entry->PeakPagefileUsage;
        stats.privateCommit = entry->PrivatePageCount;
        stats.pagedPool = entry->QuotaPagedPoolUsage;
        stats.nonPagedPool = entry->QuotaNonPagedPoolUsage;
        stats.pageFaults = entry->PageFaultCount;
        stats.handles = entry->HandleCount;
        stats.threads = entry->NumberOfThreads;
        stats.session = entry->SessionId;
        out[pid] = stats;
        if (entry->NextEntryOffset == 0) break;
        cursor += entry->NextEntryOffset;
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

std::wstring IntegrityText(HANDLE process) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return L"";
    DWORD needed = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &needed);
    std::vector<BYTE> buffer(needed);
    std::wstring result;
    if (needed && GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), needed, &needed)) {
        auto* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());
        DWORD count = *GetSidSubAuthorityCount(label->Label.Sid);
        DWORD rid = *GetSidSubAuthority(label->Label.Sid, count - 1);
        switch (rid) {
        case 0x0000: result = L"Untrusted"; break;
        case 0x1000: result = L"Low"; break;
        case 0x2000: result = L"Medium"; break;
        case 0x2100: result = L"Medium Plus"; break;
        case 0x3000: result = L"High"; break;
        case 0x4000: result = L"System"; break;
        case 0x5000: result = L"Protected"; break;
        default: result = Format(L"0x%04X", rid); break;
        }
    }
    CloseHandle(token);
    return result;
}

bool TokenElevated(HANDLE process, bool& elevated) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION info{};
    DWORD needed = 0;
    bool ok = GetTokenInformation(token, TokenElevation, &info, sizeof(info), &needed) != 0;
    CloseHandle(token);
    if (ok) elevated = info.TokenIsElevated != 0;
    return ok;
}

std::wstring PriorityText(DWORD priority) {
    switch (priority) {
    case IDLE_PRIORITY_CLASS: return L"Idle";
    case BELOW_NORMAL_PRIORITY_CLASS: return L"Below normal";
    case NORMAL_PRIORITY_CLASS: return L"Normal";
    case ABOVE_NORMAL_PRIORITY_CLASS: return L"Above normal";
    case HIGH_PRIORITY_CLASS: return L"High";
    case REALTIME_PRIORITY_CLASS: return L"Realtime";
    default: return Format(L"class 0x%X", priority);
    }
}

std::wstring ArchitectureText(HANDLE process, bool os64) {
    if (!os64) return L"x86";
    BOOL wow64 = FALSE;
    if (IsWow64Process(process, &wow64) && wow64) return L"x86 (WOW64)";
    return L"x64";
}

void CollectModuleEntries(DWORD pid, std::vector<ModuleEntry>& out) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            ModuleEntry module;
            module.base = reinterpret_cast<unsigned long long>(entry.modBaseAddr);
            module.size = entry.modBaseSize;
            module.path = entry.szExePath;
            out.push_back(std::move(module));
            if (static_cast<int>(out.size()) >= MAX_MODULES_SHOWN) break;
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

std::wstring FlatStartText(DWORD start) {
    switch (start) {
    case SERVICE_BOOT_START: return L"boot";
    case SERVICE_SYSTEM_START: return L"system";
    case SERVICE_AUTO_START: return L"auto";
    case SERVICE_DEMAND_START: return L"demand";
    case SERVICE_DISABLED: return L"disabled";
    default: return Format(L"0x%lX", start);
    }
}

std::wstring FlatImagePath(const std::wstring& command) {
    std::wstring text = Trim(command);
    if (text.empty()) return L"";
    if (text.front() == L'"') {
        size_t close = text.find(L'"', 1);
        if (close != std::wstring::npos) return text.substr(1, close - 1);
    }
    std::wstring full = text;
    if (full.rfind(L"\\??\\", 0) == 0) full = full.substr(4);
    if (full.rfind(L"\\SystemRoot\\", 0) == 0) {
        wchar_t windows[MAX_PATH] = {};
        GetWindowsDirectoryW(windows, MAX_PATH);
        full = std::wstring(windows) + full.substr(11);
    }
    if (GetFileAttributesW(full.c_str()) != INVALID_FILE_ATTRIBUTES) return full;
    size_t space = text.find(L' ');
    while (space != std::wstring::npos) {
        std::wstring head = text.substr(0, space);
        if (GetFileAttributesW(head.c_str()) != INVALID_FILE_ATTRIBUTES) return head;
        space = text.find(L' ', space + 1);
    }
    return full;
}

void CollectFlatServices(std::vector<FlatService>& out) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr,
                                       SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    if (!manager) return;

    static const DWORD kTypes[] = {SERVICE_WIN32, SERVICE_DRIVER, 0x00000040};
    std::set<std::wstring> seen;
    std::vector<BYTE> buffer(128 * 1024);
    for (DWORD type : kTypes) {
        DWORD needed = 0;
        DWORD returned = 0;
        DWORD resume = 0;
        for (;;) {
            BOOL ok = EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, type,
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
                const SERVICE_STATUS_PROCESS& status = items[i].ServiceStatusProcess;
                if (status.dwCurrentState != SERVICE_RUNNING) continue;
                FlatService service;
                service.name = items[i].lpServiceName ? items[i].lpServiceName : L"";
                if (service.name.empty()) continue;
                if (!seen.insert(ToLower(service.name)).second) continue;
                service.display = items[i].lpDisplayName ? items[i].lpDisplayName : service.name;
                service.pid = status.dwProcessId;
                service.driver = (status.dwServiceType &
                                  (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER |
                                   SERVICE_ADAPTER | SERVICE_RECOGNIZER_DRIVER)) != 0;
                service.state = ServiceStateText(status.dwCurrentState);

                SC_HANDLE handle = OpenServiceW(manager, service.name.c_str(), SERVICE_QUERY_CONFIG);
                if (handle) {
                    DWORD configSize = 0;
                    QueryServiceConfigW(handle, nullptr, 0, &configSize);
                    std::vector<BYTE> config(configSize ? configSize : 8192);
                    auto* info = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data());
                    if (QueryServiceConfigW(handle, info, static_cast<DWORD>(config.size()),
                                            &configSize)) {
                        service.binary = FlatImagePath(info->lpBinaryPathName
                                                           ? info->lpBinaryPathName
                                                           : L"");
                        service.account = info->lpServiceStartName ? info->lpServiceStartName : L"";
                        service.start = FlatStartText(info->dwStartType);
                    }
                    DWORD descriptionSize = 0;
                    QueryServiceConfig2W(handle, SERVICE_CONFIG_DESCRIPTION, nullptr, 0,
                                         &descriptionSize);
                    if (descriptionSize) {
                        std::vector<BYTE> description(descriptionSize + 64);
                        if (QueryServiceConfig2W(handle, SERVICE_CONFIG_DESCRIPTION,
                                                 description.data(),
                                                 static_cast<DWORD>(description.size()),
                                                 &descriptionSize)) {
                            auto* text = reinterpret_cast<LPWSTR>(description.data());
                            if (text) service.description = text;
                        }
                    }
                    CloseServiceHandle(handle);
                }
                out.push_back(std::move(service));
            }
            if (needed <= buffer.size()) break;
            buffer.resize(needed + 16384);
        }
    }
    CloseServiceHandle(manager);
}

bool ScriptExtension(const std::wstring& extension) {
    static const wchar_t* kExtensions[] = {
        L".ps1", L".psm1", L".psd1", L".bat", L".cmd", L".vbs", L".vbe",
        L".js", L".jse", L".wsf", L".wsh", L".hta", L".py", L".pyw",
        L".sh", L".bash", L".rb", L".pl", L".php", L".lua", L".jar"};
    for (const wchar_t* candidate : kExtensions) {
        if (extension == candidate) return true;
    }
    return false;
}

std::vector<std::wstring> CommandLineTokens(const std::wstring& command) {
    std::vector<std::wstring> tokens;
    std::wstring current;
    bool quoted = false;
    for (wchar_t ch : command) {
        if (ch == L'"') {
            quoted = !quoted;
            continue;
        }
        if (!quoted && (ch == L' ' || ch == L'\t')) {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
            continue;
        }
        current.push_back(ch);
    }
    if (!current.empty()) tokens.push_back(current);
    return tokens;
}

std::wstring ScriptTokenPath(const std::wstring& token, const std::wstring& hostPath) {
    std::wstring text = Trim(token);
    if (text.empty()) return L"";
    if (text.front() == L'-' || text.front() == L'/') return L"";
    if (text.rfind(L"http://", 0) == 0 || text.rfind(L"https://", 0) == 0) return L"";
    size_t dot = text.find_last_of(L'.');
    if (dot == std::wstring::npos || dot + 1 >= text.size()) return L"";
    size_t slash = text.find_last_of(L"\\/");
    if (slash != std::wstring::npos && dot < slash) return L"";
    if (!ScriptExtension(ToLower(text.substr(dot)))) return L"";

    bool absolute = (text.size() > 1 && text[1] == L':') || text.rfind(L"\\\\", 0) == 0;
    if (absolute) return text;
    if (!hostPath.empty()) {
        size_t cut = hostPath.find_last_of(L"\\/");
        if (cut != std::wstring::npos) {
            std::wstring candidate = hostPath.substr(0, cut + 1) + text;
            if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) return candidate;
        }
    }
    wchar_t full[1024] = {};
    if (GetFullPathNameW(text.c_str(), 1024, full, nullptr) &&
        GetFileAttributesW(full) != INVALID_FILE_ATTRIBUTES) {
        return full;
    }
    return text;
}


std::wstring BuildDetail(const ProcNode& node, const std::unordered_map<DWORD, const ProcNode*>& index) {
    std::wstring text;
    text += L"Process      : " + (node.name.empty() ? L"(unknown)" : node.name) + L"\r\n";
    text += Format(L"PID          : %lu (0x%04lX)\r\n", node.pid, node.pid);
    text += Format(L"Parent       : %lu", node.ppid);
    if (!node.parentName.empty()) text += L" (" + node.parentName + L")";
    text += L"\r\n";
    text += L"Executable   : " + (node.path.empty() ? L"(not readable)" : node.path) + L"\r\n";
    if (!node.fileSize.empty()) text += L"File size    : " + node.fileSize + L"\r\n";
    if (!node.fileModified.empty()) text += L"File modified: " + node.fileModified + L"\r\n";
    text += L"Command line : " + (node.cmd.empty() ? L"(not readable)" : node.cmd) + L"\r\n";
    text += L"Owner        : " + (node.user.empty() ? L"(not readable)" : node.user) + L"\r\n";
    text += L"Started      : " + (node.started.empty() ? L"(unknown)" : node.started) + L"\r\n";
    text += Format(L"Session      : %lu\r\n", node.session);
    text += L"Integrity    : " + (node.integrity.empty() ? L"(unknown)" : node.integrity) +
            (node.elevated ? L" \u00B7 elevated" : L"") + L"\r\n";
    text += L"Architecture : " + (node.arch.empty() ? L"(unknown)" : node.arch) + L"\r\n";
    text += L"Priority     : " + (node.priority.empty() ? L"(unknown)" : node.priority) + L"\r\n";

    text += L"\r\n--- memory ---\r\n";
    text += L"Working set  : " + SizeText(node.workingSet) + L"\r\n";
    text += L"  Private    : " + SizeText(node.privateWorkingSet) + L"\r\n";
    text += L"Peak working : " + SizeText(node.peakWorkingSet) + L"\r\n";
    text += L"Commit       : " + SizeText(node.commitBytes) + L"\r\n";
    text += L"  Private    : " + SizeText(node.privateBytes) + L"\r\n";
    text += L"Peak commit  : " + SizeText(node.peakCommitBytes) + L"\r\n";
    text += L"Virtual size : " + SizeText(node.virtualBytes) + L"\r\n";
    text += L"Peak virtual : " + SizeText(node.peakVirtualBytes) + L"\r\n";
    text += L"Page faults  : " + CommaNumber(node.pageFaults) + L"\r\n";
    text += L"Paged pool   : " + SizeText(node.pagedPool) + L"\r\n";
    text += L"Nonpaged pool: " + SizeText(node.nonPagedPool) + L"\r\n";
    text += L"Handles      : " + CommaNumber(node.handles) + L"\r\n";
    text += L"Threads      : " + CommaNumber(node.threads) + L"\r\n";
    if (!node.accessible) {
        text += L"(counters come from the kernel process list; open the process elevated for live handles and memory reads)\r\n";
    }

    text += L"\r\n--- process tree ---\r\n";
    std::vector<std::wstring> chain;
    DWORD walker = node.pid;
    for (int depth = 0; depth < 32 && walker; ++depth) {
        auto found = index.find(walker);
        if (found == index.end()) break;
        chain.push_back(Format(L"%s (%lu)", found->second->name.c_str(), walker));
        if (found->second->ppid == walker || found->second->ppid == 0) break;
        walker = found->second->ppid;
    }
    std::wstring trail;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        if (!trail.empty()) trail += L"  >  ";
        trail += *it;
    }
    text += trail.empty() ? L"(root)" : trail;
    text += L"\r\n";

    text += Format(L"\r\n--- children (%d) ---\r\n", static_cast<int>(node.children.size()));
    if (node.children.empty()) {
        text += L"(none)\r\n";
    } else {
        int shown = 0;
        for (DWORD child : node.children) {
            if (shown++ >= MAX_CHILDREN_SHOWN) {
                text += Format(L"... %d more\r\n", static_cast<int>(node.children.size()) - shown + 1);
                break;
            }
            auto found = index.find(child);
            text += Format(L"%6lu  %s\r\n", child,
                           found == index.end() ? L"(exited)" : found->second->name.c_str());
        }
    }

    text += Format(L"\r\n--- same executable (%d) ---\r\n", static_cast<int>(node.related.size()));
    if (node.related.empty()) {
        text += L"(none)\r\n";
    } else {
        int shown = 0;
        for (DWORD other : node.related) {
            if (shown++ >= MAX_RELATED_SHOWN) {
                text += Format(L"... %d more\r\n", static_cast<int>(node.related.size()) - shown + 1);
                break;
            }
            auto found = index.find(other);
            text += Format(L"%6lu  %s\r\n", other,
                           found == index.end() ? L"(exited)" : found->second->cmd.c_str());
        }
    }

    text += Format(L"\r\n--- scripts (%d) ---\r\n", static_cast<int>(node.scripts.size()));
    if (node.scripts.empty()) {
        text += L"(none)\r\n";
    } else {
        for (const std::wstring& script : node.scripts) text += script + L"\r\n";
    }

    text += Format(L"\r\n--- services hosted in this process (%d) ---\r\n",
                   static_cast<int>(node.serviceEntries.size()));
    if (node.serviceEntries.empty()) {
        text += L"(none)\r\n";
    } else {
        for (const FlatService& service : node.serviceEntries) {
            text += service.name + L"  [" + service.display + L"]  " + service.state + L"\r\n";
        }
    }

    text += Format(L"\r\n--- loaded modules (%d) ---\r\n",
                   static_cast<int>(node.moduleEntries.size()));
    if (node.moduleEntries.empty()) {
        text += L"(not readable; the process may be protected, exited, or 32-bit from a 64-bit build)\r\n";
    } else {
        text += L"base address        size  path\r\n";
        for (const ModuleEntry& module : node.moduleEntries) {
            text += Format(L"0x%016llX  %8s  %s\r\n", module.base,
                           SizeText(module.size).c_str(), module.path.c_str());
        }
    }
    return text;
}

std::wstring BuildScriptDetail(const ProcNode& node, const std::wstring& script) {
    std::wstring name = PathFileName(script);
    std::wstring text;
    text += L"Object       : Script\r\n";
    text += L"Script       : " + (name.empty() ? script : name) + L"\r\n";
    text += L"Interpreter  : " + (node.name.empty() ? L"(unknown)" : node.name) + L"\r\n";
    text += Format(L"Process id   : %lu\r\n", node.pid);
    text += L"Command line : " + (node.cmd.empty() ? L"(not readable)" : node.cmd) + L"\r\n";
    text += L"Owner        : " + (node.user.empty() ? L"(unknown)" : node.user) + L"\r\n";
    text += L"Path         : " + script + L"\r\n";
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (GetFileAttributesExW(script.c_str(), GetFileExInfoStandard, &data)) {
        unsigned long long bytes =
            (static_cast<unsigned long long>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
        text += L"File size    : " + SizeText(bytes) + L"\r\n";
        text += L"File modified: " + FileTimeText(data.ftLastWriteTime) + L"\r\n";
    } else {
        text += L"File         : not found at this path (relative name, or already removed)\r\n";
    }
    return text;
}

std::wstring BuildServiceDetail(const ProcNode& node, const FlatService& service) {
    std::wstring text;
    text += L"Object       : Service\r\n";
    text += L"Service name : " + service.name + L"\r\n";
    text += L"Display name : " + service.display + L"\r\n";
    text += L"State        : " + service.state + L"\r\n";
    text += L"Start type   : " + service.start + L"\r\n";
    text += L"Account      : " + (service.account.empty() ? L"-" : service.account) + L"\r\n";
    text += Format(L"Process id   : %lu\r\n", node.pid);
    text += L"Host process : " + (node.name.empty() ? L"-" : node.name) + L"\r\n";
    text += L"Image path   : " + (service.binary.empty() ? L"(not set)" : service.binary) + L"\r\n";
    if (!service.description.empty()) text += L"Description  : " + service.description + L"\r\n";
    return text;
}

std::wstring BuildModuleDetail(const ProcNode& node, const ModuleEntry& module) {
    std::wstring text;
    text += L"Object       : DLL\r\n";
    text += L"Module       : " + PathFileName(module.path) + L"\r\n";
    text += Format(L"Base address : 0x%016llX\r\n", module.base);
    text += L"Size         : " + SizeText(module.size) + L"\r\n";
    text += L"Path         : " + module.path + L"\r\n";
    text += Format(L"Process      : %s (%lu)\r\n",
                   node.name.empty() ? L"(unknown)" : node.name.c_str(), node.pid);
    text += L"Owner        : " + (node.user.empty() ? L"(unknown)" : node.user) + L"\r\n";
    return text;
}

std::wstring BuildDriverDetail(const KernelModuleInfo& driver, const FlatService* service) {
    std::wstring text;
    text += L"Object       : Driver\r\n";
    text += L"Name         : " + PathFileName(driver.path) + L"\r\n";
    text += Format(L"Base address : 0x%016llX\r\n", driver.base);
    text += L"Size         : " + SizeText(driver.size) + L"\r\n";
    text += L"Path         : " + driver.path + L"\r\n";
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (GetFileAttributesExW(driver.path.c_str(), GetFileExInfoStandard, &data)) {
        text += L"File modified: " + FileTimeText(data.ftLastWriteTime) + L"\r\n";
    }
    if (service) {
        text += L"Service      : " + service->name + L"\r\n";
        text += L"Display name : " + service->display + L"\r\n";
        text += L"State        : " + service->state + L"\r\n";
        text += L"Start type   : " + service->start + L"\r\n";
        text += L"Account      : " + (service->account.empty() ? L"-" : service->account) + L"\r\n";
        if (!service->description.empty()) {
            text += L"Description  : " + service->description + L"\r\n";
        }
    }
    return text;
}

std::wstring BuildDriverServiceDetail(const FlatService& service) {
    std::wstring text;
    text += L"Object       : Driver\r\n";
    text += L"Name         : " +
            (service.binary.empty() ? service.name : PathFileName(service.binary)) + L"\r\n";
    text += L"Service      : " + service.name + L"\r\n";
    text += L"Display name : " + service.display + L"\r\n";
    text += L"State        : " + service.state + L"\r\n";
    text += L"Start type   : " + service.start + L"\r\n";
    text += L"Account      : " + (service.account.empty() ? L"-" : service.account) + L"\r\n";
    text += L"Image path   : " + (service.binary.empty() ? L"(not set)" : service.binary) + L"\r\n";
    if (!service.description.empty()) text += L"Description  : " + service.description + L"\r\n";
    text += L"(running as a driver service; the module was not listed by SystemModuleInformation)\r\n";
    return text;
}

}

void RunProcessExplorer(const Sink& sink, std::atomic<bool>& stop, ProcessConfig config) {
    sink.Status(L"Snapshotting processes\u2026");

    std::vector<ProcNode> nodes;
    std::unordered_map<DWORD, size_t> slot;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        sink.Error(Format(L"CreateToolhelp32Snapshot failed (%lu)", GetLastError()));
        return;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            ProcNode node;
            node.pid = entry.th32ProcessID;
            node.ppid = entry.th32ParentProcessID;
            node.name = entry.szExeFile;
            node.threads = entry.cntThreads;
            slot[node.pid] = nodes.size();
            nodes.push_back(std::move(node));
            if (stop.load()) break;
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    if (stop.load()) {
        sink.Done(L"Stopped before any process could be inspected.");
        return;
    }

    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    bool os64 = systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;

    sink.Status(L"Reading service control manager\u2026");
    std::vector<FlatService> allServices;
    CollectFlatServices(allServices);
    std::vector<FlatService> driverServices;
    for (const FlatService& service : allServices) {
        if (service.driver) {
            driverServices.push_back(service);
            continue;
        }
        if (!config.services) continue;
        auto host = slot.find(service.pid);
        if (host != slot.end()) nodes[host->second].serviceEntries.push_back(service);
    }

    std::unordered_map<DWORD, SystemMemoryStats> systemMemory;
    CollectSystemMemory(systemMemory);

    const size_t total = nodes.size();
    for (size_t i = 0; i < total; ++i) {
        if (stop.load()) break;
        ProcNode& node = nodes[i];
        auto kernel = systemMemory.find(node.pid);
        if (kernel != systemMemory.end()) {
            const SystemMemoryStats& memory = kernel->second;
            node.workingSet = memory.workingSet;
            node.privateWorkingSet = memory.privateWorkingSet;
            node.peakWorkingSet = memory.peakWorkingSet;
            node.virtualBytes = memory.virtualSize;
            node.peakVirtualBytes = memory.peakVirtualSize;
            node.commitBytes = memory.pagefileUsage;
            node.peakCommitBytes = memory.peakPagefileUsage;
            node.privateBytes = memory.privateCommit;
            node.pagedPool = memory.pagedPool;
            node.nonPagedPool = memory.nonPagedPool;
            node.pageFaults = memory.pageFaults;
            if (memory.handles) node.handles = memory.handles;
            if (memory.threads) node.threads = memory.threads;
            node.session = memory.session;
        }
        if ((i % 12) == 0 || i + 1 == total) {
            sink.Status(Format(L"Inspecting process %s/%s \u00B7 %s",
                               CommaNumber(i + 1).c_str(), CommaNumber(total).c_str(),
                               node.name.c_str()),
                        static_cast<int>((i + 1) * 100 / total));
        }

        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, node.pid);
        bool vmRead = process != nullptr;
        if (!process) process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, node.pid);
        if (!process) process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, node.pid);
        if (process) {
            node.accessible = true;
            wchar_t path[1024] = {};
            DWORD size = 1024;
            if (QueryFullProcessImageNameW(process, 0, path, &size)) {
                node.path = path;
                if (node.name.empty()) node.name = PathFileName(node.path);
            }
            node.user = TokenUserText(process);
            FILETIME created{}, exited{}, kernel{}, user{};
            if (GetProcessTimes(process, &created, &exited, &kernel, &user)) {
                node.started = FileTimeText(created);
            }
            node.arch = ArchitectureText(process, os64);
            node.integrity = IntegrityText(process);
            bool elevated = false;
            if (TokenElevated(process, elevated)) node.elevated = elevated;
            DWORD priority = GetPriorityClass(process);
            if (priority) node.priority = PriorityText(priority);
            DWORD handles = 0;
            if (GetProcessHandleCount(process, &handles)) node.handles = handles;
            DWORD session = 0;
            if (ProcessIdToSessionId(node.pid, &session)) node.session = session;
            if (vmRead) {
                node.cmd = ReadCommandLine(process);
                PROCESS_MEMORY_COUNTERS_EX counters{};
                if (K32GetProcessMemoryInfo(process, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
                                            sizeof(counters))) {
                    node.workingSet = counters.WorkingSetSize;
                    node.peakWorkingSet = counters.PeakWorkingSetSize;
                    node.privateBytes = counters.PrivateUsage;
                    node.commitBytes = counters.PagefileUsage;
                    node.peakCommitBytes = counters.PeakPagefileUsage;
                    node.pageFaults = counters.PageFaultCount;
                }
            }
            if (node.path.empty()) {
                wchar_t full[1024] = {};
                DWORD length = GetModuleFileNameExW(process, nullptr, full, 1024);
                if (length) node.path = full;
            }
            CloseHandle(process);
        }

        if (!node.path.empty()) {
            WIN32_FILE_ATTRIBUTE_DATA data{};
            if (GetFileAttributesExW(node.path.c_str(), GetFileExInfoStandard, &data)) {
                unsigned long long bytes = (static_cast<unsigned long long>(data.nFileSizeHigh) << 32) |
                                           data.nFileSizeLow;
                node.fileSize = SizeText(bytes);
                node.fileModified = FileTimeText(data.ftLastWriteTime);
            }
        }
        if (config.modules && node.accessible) {
            CollectModuleEntries(node.pid, node.moduleEntries);
            std::sort(node.moduleEntries.begin(), node.moduleEntries.end(),
                      [](const ModuleEntry& a, const ModuleEntry& b) {
                          int compare = _wcsicmp(PathFileName(a.path).c_str(),
                                                 PathFileName(b.path).c_str());
                          if (compare != 0) return compare < 0;
                          return _wcsicmp(a.path.c_str(), b.path.c_str()) < 0;
                      });
        }
        if (!node.cmd.empty()) {
            std::set<std::wstring> seenScripts;
            for (const std::wstring& token : CommandLineTokens(node.cmd)) {
                std::wstring script = ScriptTokenPath(token, node.path);
                if (script.empty()) continue;
                if (!seenScripts.insert(ToLower(script)).second) continue;
                node.scripts.push_back(script);
            }
            std::sort(node.scripts.begin(), node.scripts.end());
        }
    }

    if (stop.load()) {
        sink.Done(L"Stopped. Process inspection was cancelled.");
        return;
    }

    for (ProcNode& node : nodes) {
        if (node.ppid == node.pid) continue;
        auto parent = slot.find(node.ppid);
        if (parent == slot.end()) continue;
        nodes[parent->second].children.push_back(node.pid);
        node.parentName = nodes[parent->second].name;
    }
    for (ProcNode& node : nodes) {
        std::sort(node.children.begin(), node.children.end());
    }

    std::unordered_map<std::wstring, std::vector<DWORD>> byImage;
    for (const ProcNode& node : nodes) {
        if (node.path.empty()) continue;
        byImage[ToLower(node.path)].push_back(node.pid);
    }
    for (ProcNode& node : nodes) {
        if (node.path.empty()) continue;
        auto found = byImage.find(ToLower(node.path));
        if (found == byImage.end() || found->second.size() < 2) continue;
        for (DWORD pid : found->second) {
            if (pid != node.pid) node.related.push_back(pid);
        }
    }

    std::vector<size_t> order;
    order.reserve(nodes.size());
    std::vector<bool> visited(nodes.size(), false);
    std::vector<size_t> roots;
    for (size_t i = 0; i < nodes.size(); ++i) {
        auto parent = slot.find(nodes[i].ppid);
        if (nodes[i].ppid == nodes[i].pid || parent == slot.end()) roots.push_back(i);
    }
    std::sort(roots.begin(), roots.end(), [&](size_t a, size_t b) {
        return nodes[a].pid < nodes[b].pid;
    });

    struct Frame {
        size_t index;
        std::wstring prefix;
        bool last;
        int depth;
    };
    for (size_t root : roots) {
        std::vector<Frame> stack;
        stack.push_back({root, L"", true, 0});
        while (!stack.empty()) {
            if (stop.load()) break;
            Frame frame = stack.back();
            stack.pop_back();
            if (visited[frame.index]) continue;
            visited[frame.index] = true;
            nodes[frame.index].treePrefix = frame.prefix + (frame.depth == 0 ? L"" : (frame.last ? L"\u2514\u2500 " : L"\u251C\u2500 "));
            order.push_back(frame.index);
            if (frame.depth >= MAX_TREE_LINES) continue;

            const std::vector<DWORD>& children = nodes[frame.index].children;
            std::wstring childPrefix = frame.prefix +
                                       (frame.depth == 0 ? L"" : (frame.last ? L"   " : L"\u2502  "));
            for (size_t c = children.size(); c > 0; --c) {
                auto child = slot.find(children[c - 1]);
                if (child == slot.end() || visited[child->second]) continue;
                stack.push_back({child->second, childPrefix, c == 1, frame.depth + 1});
            }
        }
    }

    for (size_t i = 0; i < nodes.size(); ++i) {
        if (!visited[i]) order.push_back(i);
    }

    std::unordered_map<DWORD, const ProcNode*> index;
    index.reserve(nodes.size() * 2);
    for (const ProcNode& node : nodes) index[node.pid] = &node;

    std::vector<Row> pending;
    std::vector<std::wstring> details;
    pending.reserve(128);
    details.reserve(128);
    bool firstBatch = true;

    auto flush = [&]() {
        if (pending.empty()) return;
        sink.Detailed(std::move(pending), std::move(details), firstBatch);
        firstBatch = false;
        pending.clear();
        details.clear();
        pending.reserve(128);
        details.reserve(128);
    };

    unsigned long long processCount = 0;
    unsigned long long scriptCount = 0;
    unsigned long long serviceCount = 0;
    unsigned long long dllCount = 0;
    unsigned long long driverCount = 0;

    auto emit = [&](Row row, std::wstring detail) {
        pending.push_back(std::move(row));
        details.push_back(std::move(detail));
        if (pending.size() >= 128) flush();
    };

    for (size_t position = 0; position < order.size() && !stop.load(); ++position) {
        const ProcNode& node = nodes[order[position]];

        std::wstring parentText = Format(L"%lu", node.ppid);
        if (!node.parentName.empty()) parentText += L" " + node.parentName;

        Row row;
        row.reserve(8);
        row.push_back(Format(L"%lu", node.pid));
        row.push_back(parentText);
        row.push_back(node.treePrefix + (node.name.empty() ? L"(unknown)" : node.name));
        row.push_back(node.user.empty() ? L"-" : node.user);
        row.push_back(node.started.empty() ? L"-" : node.started);
        row.push_back(node.path.empty() ? L"-" : node.path);
        row.push_back(node.cmd.empty() ? L"-" : node.cmd);
        row.push_back(SizeText(node.workingSet));
        std::wstring privilege = node.integrity.empty() ? L"Unknown" : node.integrity;
        if (node.elevated) privilege += L" \u00B7 elevated";
        row.push_back(privilege);
        emit(std::move(row), BuildDetail(node, index));
        ++processCount;

        for (const std::wstring& script : node.scripts) {
            Row child;
            child.push_back(Format(L"%lu", node.pid));
            child.push_back(L"Script");
            child.push_back(PathFileName(script));
            child.push_back(L"script");
            child.push_back(L"-");
            child.push_back(script);
            emit(std::move(child), BuildScriptDetail(node, script));
            ++scriptCount;
        }
        for (const FlatService& service : node.serviceEntries) {
            Row child;
            child.push_back(Format(L"%lu", node.pid));
            child.push_back(L"Service");
            child.push_back(service.name);
            child.push_back(service.state + L" \u00B7 " + service.start);
            child.push_back(L"-");
            child.push_back(service.binary.empty() ? L"-" : service.binary);
            emit(std::move(child), BuildServiceDetail(node, service));
            ++serviceCount;
        }
        for (const ModuleEntry& module : node.moduleEntries) {
            Row child;
            child.push_back(Format(L"%lu", node.pid));
            child.push_back(L"DLL");
            child.push_back(PathFileName(module.path));
            child.push_back(Format(L"0x%016llX \u00B7 %s", module.base,
                                   SizeText(module.size).c_str()));
            child.push_back(L"-");
            child.push_back(module.path);
            emit(std::move(child), BuildModuleDetail(node, module));
            ++dllCount;
        }
    }

    if (!stop.load()) {
        sink.Status(L"Reading kernel drivers\u2026");
        std::unordered_map<std::wstring, size_t> driverServiceByPath;
        for (size_t i = 0; i < driverServices.size(); ++i) {
            if (driverServices[i].binary.empty()) continue;
            driverServiceByPath[ToLower(driverServices[i].binary)] = i;
        }
        std::vector<bool> driverServiceUsed(driverServices.size(), false);
        const std::vector<KernelModuleInfo> drivers = KernelModules();
        if (!drivers.empty() || !driverServices.empty()) {
            Row group;
            group.push_back(L"-");
            group.push_back(L"Group");
            group.push_back(L"Kernel drivers");
            group.push_back(Format(L"%s loaded", CommaNumber(drivers.size()).c_str()));
            group.push_back(L"-");
            group.push_back(L"-");
            emit(std::move(group),
                 Format(L"Kernel drivers\r\n\r\n%s module(s) loaded into the kernel.\r\n"
                        L"Each child row is one loaded module, matched to its service record when one exists.\r\n",
                        CommaNumber(drivers.size()).c_str()));

            for (const KernelModuleInfo& driver : drivers) {
                const FlatService* service = nullptr;
                auto match = driverServiceByPath.find(ToLower(driver.path));
                if (match != driverServiceByPath.end()) {
                    service = &driverServices[match->second];
                    driverServiceUsed[match->second] = true;
                }
                Row child;
                child.push_back(L"drivers");
                child.push_back(L"Driver");
                child.push_back(PathFileName(driver.path));
                child.push_back(service ? service->name + L" \u00B7 " + service->state
                                        : L"loaded");
                child.push_back(L"-");
                child.push_back(driver.path);
                emit(std::move(child), BuildDriverDetail(driver, service));
                ++driverCount;
            }
            for (size_t i = 0; i < driverServices.size(); ++i) {
                if (driverServiceUsed[i]) continue;
                const FlatService& service = driverServices[i];
                Row child;
                child.push_back(L"drivers");
                child.push_back(L"Driver");
                child.push_back(service.binary.empty() ? service.name
                                                       : PathFileName(service.binary));
                child.push_back(service.state + L" \u00B7 " + service.start);
                child.push_back(L"-");
                child.push_back(service.binary.empty() ? L"-" : service.binary);
                emit(std::move(child), BuildDriverServiceDetail(service));
                ++driverCount;
            }
        }
    }
    flush();

    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s process(es) retained.", CommaNumber(processCount).c_str()));
        return;
    }
    std::wstring summary = Format(
        L"Completed. %s process(es) \u00B7 %s script \u00B7 %s service \u00B7 %s driver \u00B7 %s DLL",
        CommaNumber(processCount).c_str(), CommaNumber(scriptCount).c_str(),
        CommaNumber(serviceCount).c_str(), CommaNumber(driverCount).c_str(),
        CommaNumber(dllCount).c_str());
    sink.Done(summary);
}
