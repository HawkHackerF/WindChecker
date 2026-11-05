#include "common.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cwchar>
#include <vector>

#pragma comment(lib, "ntdll.lib")

namespace {

std::wstring FormatV(const wchar_t* format, va_list args) {
    wchar_t buffer[4096];
    int needed = _vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, args);
    if (needed < 0) return std::wstring(buffer);
    return std::wstring(buffer, static_cast<size_t>(needed));
}

struct RawDnsRec {
    wchar_t name[256];
    wchar_t data[256];
    uint16_t type;
    uint32_t ttl;
};

struct CacheTableEntry {
    CacheTableEntry* pNext;
    PWSTR pszName;
    unsigned short wType;
    unsigned short wDataLength;
    unsigned long dwFlags;
};

void FillDnsRecordData(const DNS_RECORDW* record, RawDnsRec& rec) {
    rec.type = record->wType;
    rec.ttl = record->dwTtl;
    switch (record->wType) {
    case DNS_TYPE_A: {
        IN_ADDR addr{};
        addr.S_un.S_addr = record->Data.A.IpAddress;
        InetNtopW(AF_INET, &addr, rec.data, 256);
        break;
    }
    case DNS_TYPE_AAAA: {
        IN6_ADDR addr{};
        memcpy(&addr, record->Data.AAAA.Ip6Address.IP6Qword, 16);
        InetNtopW(AF_INET6, &addr, rec.data, 256);
        break;
    }
    case DNS_TYPE_CNAME:
        if (record->Data.CNAME.pNameHost) wcsncpy_s(rec.data, record->Data.CNAME.pNameHost, _TRUNCATE);
        break;
    case DNS_TYPE_PTR:
        if (record->Data.PTR.pNameHost) wcsncpy_s(rec.data, record->Data.PTR.pNameHost, _TRUNCATE);
        break;
    case DNS_TYPE_NS:
        if (record->Data.NS.pNameHost) wcsncpy_s(rec.data, record->Data.NS.pNameHost, _TRUNCATE);
        break;
    case DNS_TYPE_MX:
        if (record->Data.MX.pNameExchange) wcsncpy_s(rec.data, record->Data.MX.pNameExchange, _TRUNCATE);
        break;
    case DNS_TYPE_SRV:
        if (record->Data.SRV.pNameTarget) wcsncpy_s(rec.data, record->Data.SRV.pNameTarget, _TRUNCATE);
        break;
    default:
        break;
    }
}

int RawDnsCacheOnce(RawDnsRec* out, int capacity) {
    int count = 0;
    __try {
        HMODULE module = GetModuleHandleW(L"dnsapi.dll");
        if (!module) module = LoadLibraryW(L"dnsapi.dll");
        if (!module) return 0;
        using Fn = int(WINAPI*)(CacheTableEntry*);
        auto fn = reinterpret_cast<Fn>(GetProcAddress(module, "DnsGetCacheDataTable"));
        if (!fn) return 0;
        CacheTableEntry head{};
        fn(&head);
        if (!head.pNext) return 0;
        for (CacheTableEntry* item = head.pNext; item && count < capacity; item = item->pNext) {
            if (!item->pszName || !item->pszName[0]) continue;

            PDNS_RECORD record = nullptr;
            if (DnsQuery_W(item->pszName, item->wType, DNS_QUERY_NO_MULTICAST,
                           nullptr, &record, nullptr) == 0 && record) {
                for (PDNS_RECORD entry = record; entry && count < capacity; entry = entry->pNext) {
                    RawDnsRec& rec = out[count];
                    rec.name[0] = 0;
                    rec.data[0] = 0;
                    rec.type = entry->wType;
                    rec.ttl = 0;
                    wcsncpy_s(rec.name, item->pszName, _TRUNCATE);
                    FillDnsRecordData(entry, rec);
                    ++count;
                }
                DnsRecordListFree(record, DnsFreeRecordList);
            } else {
                RawDnsRec& rec = out[count];
                rec.name[0] = 0;
                rec.data[0] = 0;
                rec.type = item->wType;
                rec.ttl = 0;
                wcsncpy_s(rec.name, item->pszName, _TRUNCATE);
                ++count;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return count;
}

struct LookupState {
    std::mutex mutex;
    std::unordered_map<std::string, std::wstring> reverse;
    std::unordered_set<std::string> reverseQueued;
    std::deque<std::string> reverseQueue;
    int reverseActive = 0;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> reverseAt;

    std::unordered_map<std::string, std::wstring> asn;
    std::unordered_set<std::string> asnQueued;
    std::deque<std::string> asnQueue;
    int asnActive = 0;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> asnAt;
    std::condition_variable asnCv;
    std::chrono::steady_clock::time_point asnNext{};
};

LookupState& Lookups() {
    static LookupState state;
    return state;
}

constexpr int kReverseWorkers = 8;
constexpr int kAsnWorkers = 4;

bool IsUnspecifiedAddress(const std::string& ip) {
    return ip.empty() || ip == "0.0.0.0" || ip == "::" || ip == "*" || ip == "::0";
}

std::string IpApiUrl(const std::string& ip) {
    return "/json/" + ip + "?fields=status,country,city,isp,org,as";
}

std::wstring LookupAsnBlocking(const std::string& ip) {
    std::string body = HttpGet(L"ip-api.com", Utf8ToWide(IpApiUrl(ip)));
    if (body.empty()) return L"";
    if (JsonStringField(body, "status") != L"success") return L"";
    std::wstring as = JsonStringField(body, "as");
    if (as.empty()) as = JsonStringField(body, "isp");
    if (as.empty()) as = JsonStringField(body, "org");
    std::wstring country = JsonStringField(body, "country");
    std::wstring city = JsonStringField(body, "city");
    std::wstring joined;
    for (const std::wstring& part : {as, country, city}) {
        if (part.empty()) continue;
        if (!joined.empty()) joined += L" \u00B7 ";
        joined += part;
    }
    return joined;
}

}

std::wstring ReadCommandLine(HANDLE process) {
    using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto query = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!query) return L"";

    struct ProcessBasicInformation {
        PVOID reserved1;
        PVOID pebBaseAddress;
        PVOID reserved2[2];
        ULONG_PTR uniqueProcessId;
        PVOID reserved3;
    } pbi{};
    if (query(process, 0, &pbi, sizeof(pbi), nullptr) != 0 || !pbi.pebBaseAddress) return L"";

    PVOID parameters = nullptr;
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, static_cast<BYTE*>(pbi.pebBaseAddress) + 0x20, &parameters, sizeof(parameters), &read) || !parameters)
        return L"";

    struct UnicodeStringLocal {
        USHORT length;
        USHORT maximumLength;
        PWSTR buffer;
    } commandLine{};
    if (!ReadProcessMemory(process, static_cast<BYTE*>(parameters) + 0x70, &commandLine, sizeof(commandLine), &read) || !commandLine.length || !commandLine.buffer)
        return L"";

    std::wstring text(commandLine.length / sizeof(wchar_t), L'\0');
    if (!ReadProcessMemory(process, commandLine.buffer, text.data(), commandLine.length, &read)) return L"";
    while (!text.empty() && text.back() == L'\0') text.pop_back();
    return text;
}

std::wstring TokenUserText(HANDLE process) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return L"";
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    std::vector<BYTE> buffer(needed);
    std::wstring result;
    if (needed && GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed)) {
        auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
        wchar_t name[256] = {};
        wchar_t domain[256] = {};
        DWORD nameLength = 256;
        DWORD domainLength = 256;
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, user->User.Sid, name, &nameLength, domain, &domainLength, &use)) {
            result = domain;
            if (!result.empty()) result += L"\\";
            result += name;
        }
    }
    CloseHandle(token);
    return result;
}

std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) return L"";
    int length = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) return L"";
    std::wstring out(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), length);
    return out;
}

std::string WideToUtf8(const std::wstring& text) {
    if (text.empty()) return {};
    int length = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) return {};
    std::string out(static_cast<size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), length, nullptr, nullptr);
    return out;
}

std::wstring Format(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    std::wstring result = FormatV(format, args);
    va_end(args);
    return result;
}

std::wstring SizeText(unsigned long long bytes) {
    const wchar_t* units[] = {L"B", L"KB", L"MB", L"GB", L"TB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    if (unit == 0) return Format(L"%llu B", bytes);
    return Format(L"%.1f %s", value, units[unit]);
}

std::wstring CommaNumber(unsigned long long value) {
    wchar_t raw[32];
    swprintf_s(raw, L"%llu", value);
    std::wstring digits(raw);
    std::wstring out;
    int count = 0;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        if (count && count % 3 == 0) out.push_back(L',');
        out.push_back(*it);
        ++count;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

std::wstring NowStamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    return Format(L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

std::wstring TimeStampFromMs(long long epochMs) {
    FILETIME ft{};
    ULARGE_INTEGER value{};
    value.QuadPart = static_cast<ULONGLONG>(epochMs) * 10000ULL + 116444736000000000ULL;
    ft.dwLowDateTime = value.LowPart;
    ft.dwHighDateTime = value.HighPart;
    return FileTimeText(ft);
}

std::wstring FileTimeText(const FILETIME& fileTime) {
    if (!fileTime.dwLowDateTime && !fileTime.dwHighDateTime) return L"";
    FILETIME local{};
    SYSTEMTIME st{};
    if (!FileTimeToLocalFileTime(&fileTime, &local) || !FileTimeToSystemTime(&local, &st)) return L"";
    return Format(L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

std::wstring ToLower(std::wstring text) {
    if (!text.empty()) CharLowerBuffW(text.data(), static_cast<DWORD>(text.size()));
    return text;
}

bool ContainsInsensitive(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return true;
    return ToLower(haystack).find(ToLower(needle)) != std::wstring::npos;
}

std::wstring Trim(const std::wstring& text) {
    size_t begin = text.find_first_not_of(L" \t\r\n");
    if (begin == std::wstring::npos) return L"";
    size_t end = text.find_last_not_of(L" \t\r\n");
    return text.substr(begin, end - begin + 1);
}

std::wstring TrimTrailingComment(const std::wstring& text) {
    std::wstring result = Trim(text);
    return result;
}

std::wstring IpText(const BYTE* address, int family) {
    wchar_t buffer[INET6_ADDRSTRLEN] = {};
    if (family == AF_INET) {
        InetNtopW(AF_INET, address, buffer, INET6_ADDRSTRLEN);
    } else {
        InetNtopW(AF_INET6, address, buffer, INET6_ADDRSTRLEN);
    }
    return buffer;
}

std::wstring EndpointText(const SOCKADDR_INET& address, USHORT port) {
    if (address.si_family == AF_INET6) {
        return Format(L"[%s]:%u", IpText(address.Ipv6.sin6_addr.u.Byte, AF_INET6).c_str(), port);
    }
    return Format(L"%s:%u", IpText(reinterpret_cast<const BYTE*>(&address.Ipv4.sin_addr), AF_INET).c_str(), port);
}

std::wstring PathFileName(const std::wstring& path) {
    const wchar_t* name = PathFindFileNameW(path.c_str());
    return name ? name : path;
}

std::wstring GuidBraced(const wchar_t* adapterName) {
    if (!adapterName) return L"";
    std::wstring text(adapterName);
    size_t open = text.find(L'{');
    size_t close = text.find(L'}', open);
    if (open == std::wstring::npos || close == std::wstring::npos) return L"";
    return text.substr(open, close - open + 1);
}

std::wstring JsonStringField(const std::string& json, const std::string& key) {
    std::string pattern = "\"" + key + "\":\"";
    size_t start = json.find(pattern);
    if (start == std::string::npos) return L"";
    start += pattern.size();
    std::string value;
    for (size_t i = start; i < json.size(); ++i) {
        char ch = json[i];
        if (ch == '"') break;
        if (ch == '\\' && i + 1 < json.size()) {
            char next = json[++i];
            switch (next) {
            case 'n': value.push_back('\n'); break;
            case 'r': value.push_back('\r'); break;
            case 't': value.push_back('\t'); break;
            case 'u': {
                if (i + 4 < json.size()) {
                    std::string hex = json.substr(i + 1, 4);
                    wchar_t code = static_cast<wchar_t>(std::wcstoul(Utf8ToWide(hex).c_str(), nullptr, 16));
                    std::wstring wide(1, code);
                    value += WideToUtf8(wide);
                    i += 4;
                }
                break;
            }
            default: value.push_back(next); break;
            }
        } else {
            value.push_back(ch);
        }
    }
    return Utf8ToWide(value);
}

std::string HttpGet(const std::wstring& host, const std::wstring& path) {
    HINTERNET session = WinHttpOpen(L"WindChecker/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return {};
    WinHttpSetTimeouts(session, 3000, 3000, 3000, 5000);
    HINTERNET connect = WinHttpConnect(session, host.c_str(), INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return {};
    }
    HINTERNET request = WinHttpOpenRequest(connect, L"GET", path.c_str(), nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    std::string body;
    if (request && WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0) &&
        WinHttpReceiveResponse(request, nullptr)) {
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
            std::string chunk(available, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(request, chunk.data(), available, &read) || !read) break;
            chunk.resize(read);
            body += chunk;
            if (body.size() > 65536) break;
        }
    }
    if (request) WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return body;
}

std::unordered_map<DWORD, std::wstring> SnapshotProcessNames() {
    static std::mutex mutex;
    static std::unordered_map<DWORD, std::wstring> cached;
    static std::chrono::steady_clock::time_point cachedAt{};
    std::lock_guard<std::mutex> lock(mutex);
    auto now = std::chrono::steady_clock::now();
    if (!cached.empty() && now - cachedAt < std::chrono::seconds(5)) return cached;

    std::unordered_map<DWORD, std::wstring> names;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry)) {
            do {
                names[entry.th32ProcessID] = entry.szExeFile;
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    cached = names;
    cachedAt = now;
    return names;
}

ProcInfo GetProcInfo(DWORD pid) {
    static std::mutex mutex;
    static std::unordered_map<DWORD, ProcInfo> cache;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto found = cache.find(pid);
        if (found != cache.end()) return found->second;
    }

    ProcInfo info;
    if (pid == 0) info.name = L"Idle";
    if (pid == 4) info.name = L"System";

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    bool vmRead = process != nullptr;
    if (!process) process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process && pid != 0 && pid != 4) {
        auto names = SnapshotProcessNames();
        auto found = names.find(pid);
        if (found != names.end()) info.name = found->second;
    }
    if (process) {
        wchar_t path[1024] = {};
        DWORD size = 1024;
        if (QueryFullProcessImageNameW(process, 0, path, &size)) {
            info.path = path;
            info.name = PathFileName(info.path);
        }
        info.user = TokenUserText(process);
        FILETIME created{}, exited{}, kernel{}, user{};
        if (GetProcessTimes(process, &created, &exited, &kernel, &user)) info.started = FileTimeText(created);
        if (vmRead) info.cmd = ReadCommandLine(process);
        CloseHandle(process);
    }
    if (info.name.empty()) {
        auto names = SnapshotProcessNames();
        auto found = names.find(pid);
        if (found != names.end()) info.name = found->second;
    }
    {
        std::lock_guard<std::mutex> lock(mutex);
        cache[pid] = info;
    }
    return info;
}

std::wstring ReverseName(const std::string& ip) {
    LookupState& state = Lookups();
    std::lock_guard<std::mutex> lock(state.mutex);
    auto found = state.reverse.find(ip);
    return found == state.reverse.end() ? L"" : found->second;
}

namespace {

std::vector<sockaddr_storage> DnsServerList() {
    static std::mutex mutex;
    static std::vector<sockaddr_storage> servers;
    static bool loaded = false;
    std::lock_guard<std::mutex> lock(mutex);
    if (loaded) return servers;
    loaded = true;

    ULONG size = 16 * 1024;
    std::unique_ptr<BYTE[]> buffer(new BYTE[size]);
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    ULONG result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get()), &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.reset(new BYTE[size]);
        result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                      reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get()), &size);
    }
    if (result != NO_ERROR) return servers;

    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get()); adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) continue;
        for (auto* server = adapter->FirstDnsServerAddress; server; server = server->Next) {
            if (!server->Address.lpSockaddr) continue;
            int length = server->Address.lpSockaddr->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
            sockaddr_storage copy{};
            memcpy(&copy, server->Address.lpSockaddr, length);
            bool duplicate = false;
            for (const sockaddr_storage& existing : servers) {
                if (existing.ss_family != copy.ss_family) continue;
                if (copy.ss_family == AF_INET &&
                    reinterpret_cast<const sockaddr_in*>(&existing)->sin_addr.S_un.S_addr ==
                        reinterpret_cast<const sockaddr_in*>(&copy)->sin_addr.S_un.S_addr) {
                    duplicate = true;
                    break;
                }
                if (copy.ss_family == AF_INET6 &&
                    memcmp(reinterpret_cast<const sockaddr_in6*>(&existing)->sin6_addr.u.Byte,
                           reinterpret_cast<const sockaddr_in6*>(&copy)->sin6_addr.u.Byte, 16) == 0) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) servers.push_back(copy);
        }
    }
    return servers;
}

std::string ReverseLookupName(const std::string& ip) {
    IN_ADDR v4{};
    IN6_ADDR v6{};
    if (InetPtonA(AF_INET, ip.c_str(), &v4) == 1) {
        const BYTE* b = reinterpret_cast<const BYTE*>(&v4);
        return std::to_string(b[3]) + "." + std::to_string(b[2]) + "." +
               std::to_string(b[1]) + "." + std::to_string(b[0]) + ".in-addr.arpa";
    }
    if (InetPtonA(AF_INET6, ip.c_str(), &v6) == 1) {
        static const char hex[] = "0123456789abcdef";
        std::string name;
        for (int i = 15; i >= 0; --i) {
            BYTE value = v6.u.Byte[i];
            name.push_back(hex[value & 0x0F]);
            name.push_back('.');
            name.push_back(hex[(value >> 4) & 0x0F]);
            name.push_back('.');
        }
        name += "ip6.arpa";
        return name;
    }
    return "";
}

bool ParseDnsName(const BYTE* data, size_t length, size_t& offset, std::string& out, int depth = 0) {
    if (depth > 8) return false;
    while (offset < length) {
        BYTE label = data[offset];
        if (label == 0) {
            ++offset;
            return true;
        }
        if ((label & 0xC0) == 0xC0) {
            if (offset + 1 >= length) return false;
            size_t target = (static_cast<size_t>(label & 0x3F) << 8) | data[offset + 1];
            offset += 2;
            if (target >= length) return false;
            std::string tail;
            if (!ParseDnsName(data, length, target, tail, depth + 1)) return false;
            if (!tail.empty()) {
                if (!out.empty()) out += '.';
                out += tail;
            }
            return true;
        }
        if (label > 63 || offset + 1 + label > length) return false;
        ++offset;
        if (!out.empty()) out += '.';
        out.append(reinterpret_cast<const char*>(data + offset), label);
        offset += label;
    }
    return false;
}

std::vector<BYTE> BuildPtrQuery(const std::string& name, uint16_t id) {
    std::vector<BYTE> message;
    message.resize(12, 0);
    message[0] = static_cast<BYTE>(id >> 8);
    message[1] = static_cast<BYTE>(id & 0xFF);
    message[2] = 0x01;
    message[4] = 0x00;
    message[5] = 0x01;
    size_t start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        size_t count = dot - start;
        if (count == 0 || count > 63) break;
        message.push_back(static_cast<BYTE>(count));
        message.insert(message.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                       name.begin() + static_cast<std::ptrdiff_t>(dot));
        start = dot + 1;
        if (dot == name.size()) break;
    }
    message.push_back(0);
    message.push_back(0);
    message.push_back(12);
    message.push_back(0);
    message.push_back(1);
    return message;
}

std::string DnsPtrQuery(const sockaddr_storage& server, const std::string& name, int timeoutMs) {
    uint16_t id = static_cast<uint16_t>(GetTickCount());
    std::vector<BYTE> query = BuildPtrQuery(name, id);
    if (query.empty()) return "";

    SOCKET socketHandle = socket(server.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (socketHandle == INVALID_SOCKET) return "";
    DWORD timeout = static_cast<DWORD>(timeoutMs);
    setsockopt(socketHandle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    std::string result;
    int serverLength = server.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (sendto(socketHandle, reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), 0,
               reinterpret_cast<const sockaddr*>(&server), serverLength) > 0) {
        std::vector<BYTE> response(4096);
        int received = recvfrom(socketHandle, reinterpret_cast<char*>(response.data()),
                                static_cast<int>(response.size()), 0, nullptr, nullptr);
        if (received >= 12) {
            response.resize(static_cast<size_t>(received));
            uint16_t responseId = static_cast<uint16_t>((response[0] << 8) | response[1]);
            uint16_t answers = static_cast<uint16_t>((response[6] << 8) | response[7]);
            if (responseId == id && (response[2] & 0x80) && answers > 0) {
                size_t offset = 12;
                std::string ignored;
                for (int q = 0; q < static_cast<int>((response[4] << 8) | response[5]); ++q) {
                    if (!ParseDnsName(response.data(), response.size(), offset, ignored)) break;
                    offset += 4;
                }
                for (int i = 0; i < answers && offset + 10 <= response.size(); ++i) {
                    if (!ParseDnsName(response.data(), response.size(), offset, ignored)) break;
                    uint16_t type = static_cast<uint16_t>((response[offset] << 8) | response[offset + 1]);
                    uint16_t dataLength = static_cast<uint16_t>((response[offset + 8] << 8) | response[offset + 9]);
                    offset += 10;
                    if (offset + dataLength > response.size()) break;
                    if (type == 12) {
                        size_t dataOffset = offset;
                        std::string host;
                        if (ParseDnsName(response.data(), response.size(), dataOffset, host) && !host.empty()) {
                            result = host;
                            break;
                        }
                    }
                    offset += dataLength;
                }
            }
        }
    }
    closesocket(socketHandle);
    return result;
}

std::wstring ReverseLookupBlocking(const std::string& ip) {
    std::string ptrName = ReverseLookupName(ip);
    if (ptrName.empty()) return L"";

    std::wstring ptrWide = Utf8ToWide(ptrName);
    PDNS_RECORD cached = nullptr;
    DNS_STATUS status = DnsQuery_W(ptrWide.c_str(), DNS_TYPE_PTR,
                                   DNS_QUERY_NO_WIRE_QUERY | DNS_QUERY_NO_MULTICAST,
                                   nullptr, &cached, nullptr);
    if (status == 0 && cached) {
        std::wstring host;
        for (PDNS_RECORD record = cached; record; record = record->pNext) {
            if (record->wType == DNS_TYPE_PTR && record->Data.PTR.pNameHost) {
                host = record->Data.PTR.pNameHost;
                break;
            }
        }
        DnsRecordListFree(cached, DnsFreeRecordList);
        if (!host.empty()) return host;
    }

    int tried = 0;
    for (const sockaddr_storage& server : DnsServerList()) {
        if (tried++ >= 2) break;
        std::string host = DnsPtrQuery(server, ptrName, 2200);
        if (!host.empty()) return Utf8ToWide(host);
    }
    return L"";
}

void ReverseWorkerLoop() {
    LookupState& state = Lookups();
    for (;;) {
        std::string ip;
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            if (state.reverseQueue.empty()) {
                state.reverseActive -= 1;
                return;
            }
            ip = std::move(state.reverseQueue.front());
            state.reverseQueue.pop_front();
        }
        std::wstring name = ReverseLookupBlocking(ip);
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            state.reverse[ip] = name;
            state.reverseAt[ip] = std::chrono::steady_clock::now();
            state.reverseQueued.erase(ip);
        }
    }
}

void AsnWorkerLoop() {
    LookupState& state = Lookups();
    for (;;) {
        std::string ip;
        {
            std::unique_lock<std::mutex> lock(state.mutex);
            if (state.asnQueue.empty()) {
                state.asnActive -= 1;
                return;
            }
            auto now = std::chrono::steady_clock::now();

            auto next = state.asnNext + std::chrono::milliseconds(1500);
            if (now < next) {
                state.asnCv.wait_for(lock, next - now);
                continue;
            }
            ip = std::move(state.asnQueue.front());
            state.asnQueue.pop_front();
            state.asnNext = now;
        }
        std::wstring text = LookupAsnBlocking(ip);
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            state.asn[ip] = text;
            state.asnAt[ip] = std::chrono::steady_clock::now();
            state.asnQueued.erase(ip);
        }
    }
}

}

void RequestReverse(const std::string& ip) {
    if (IsUnspecifiedAddress(ip)) return;

    if (!IsPublicIp(ip)) return;
    LookupState& state = Lookups();
    bool startWorker = false;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        auto cached = state.reverse.find(ip);
        if (cached != state.reverse.end()) {
            if (!cached->second.empty()) return;

            auto at = state.reverseAt.find(ip);
            if (at != state.reverseAt.end() &&
                std::chrono::steady_clock::now() - at->second < std::chrono::minutes(10)) {
                return;
            }
            state.reverse.erase(cached);
        }
        if (state.reverseQueued.count(ip)) {

            auto found = std::find(state.reverseQueue.begin(), state.reverseQueue.end(), ip);
            if (found != state.reverseQueue.end()) {
                state.reverseQueue.erase(found);
                state.reverseQueue.push_front(ip);
            }
            return;
        }
        state.reverseQueued.insert(ip);
        state.reverseQueue.push_front(ip);
        if (state.reverseActive < kReverseWorkers) {
            state.reverseActive += 1;
            startWorker = true;
        }
    }
    if (startWorker) std::thread(ReverseWorkerLoop).detach();
}

std::wstring AsnInfo(const std::string& ip) {
    LookupState& state = Lookups();
    std::lock_guard<std::mutex> lock(state.mutex);
    auto found = state.asn.find(ip);
    return found == state.asn.end() ? L"" : found->second;
}

bool IsPublicIp(const std::string& ip) {
    IN_ADDR v4{};
    if (InetPtonA(AF_INET, ip.c_str(), &v4) == 1) {
        unsigned long value = ntohl(v4.S_un.S_addr);
        unsigned int first = (value >> 24) & 0xFF;
        unsigned int second = (value >> 16) & 0xFF;
        if (first == 0 || first == 10 || first == 127) return false;
        if (first == 169 && second == 254) return false;
        if (first == 172 && second >= 16 && second <= 31) return false;
        if (first == 192 && second == 168) return false;
        if (first == 100 && second >= 64 && second <= 127) return false;
        if (first == 192 && second == 0) return false;
        if (first == 198 && (second == 18 || second == 19)) return false;
        if (first == 198 && second == 51) return false;
        if (first == 203 && second == 0) return false;
        if (first >= 224) return false;
        return true;
    }
    IN6_ADDR v6{};
    if (InetPtonA(AF_INET6, ip.c_str(), &v6) == 1) {
        const BYTE* b = v6.u.Byte;
        if (b[0] == 0xFF) return false;
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return false;
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0xC0) return false;
        if ((b[0] & 0xFE) == 0xFC) return false;
        bool loopback = true;
        for (int i = 0; i < 15; ++i) if (b[i] != 0) loopback = false;
        if (loopback && b[15] == 1) return false;
        return true;
    }
    return false;
}

void RequestAsn(const std::string& ip) {
    if (!IsPublicIp(ip)) return;
    LookupState& state = Lookups();
    bool startWorker = false;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        auto cached = state.asn.find(ip);
        if (cached != state.asn.end()) {
            if (!cached->second.empty()) return;
            auto at = state.asnAt.find(ip);
            if (at != state.asnAt.end() &&
                std::chrono::steady_clock::now() - at->second < std::chrono::minutes(10)) {
                return;
            }
            state.asn.erase(cached);
        }
        if (state.asnQueued.count(ip)) {
            auto found = std::find(state.asnQueue.begin(), state.asnQueue.end(), ip);
            if (found != state.asnQueue.end()) {
                state.asnQueue.erase(found);
                state.asnQueue.push_front(ip);
            }
            return;
        }
        state.asnQueued.insert(ip);
        state.asnQueue.push_front(ip);
        if (state.asnActive < kAsnWorkers) {
            state.asnActive += 1;
            startWorker = true;
        }
        state.asnCv.notify_one();
    }
    if (startWorker) std::thread(AsnWorkerLoop).detach();
}

std::wstring LookupDebugStats() {
    LookupState& state = Lookups();
    std::lock_guard<std::mutex> lock(state.mutex);
    return Format(L"reverse cached=%zu queued=%zu queue=%zu active=%d \u00B7 asn cached=%zu queued=%zu queue=%zu active=%d",
                  state.reverse.size(), state.reverseQueued.size(), state.reverseQueue.size(), state.reverseActive,
                  state.asn.size(), state.asnQueued.size(), state.asnQueue.size(), state.asnActive);
}

std::wstring PortService(USHORT port) {
    struct Entry { USHORT port; const wchar_t* name; };
    static const Entry table[] = {
        {20, L"ftp-data"}, {21, L"ftp"}, {22, L"ssh"}, {23, L"telnet"}, {25, L"smtp"},
        {53, L"dns"}, {67, L"dhcp"}, {68, L"dhcp"}, {69, L"tftp"}, {80, L"http"},
        {110, L"pop3"}, {123, L"ntp"}, {135, L"msrpc"}, {137, L"netbios-ns"}, {138, L"netbios-dgm"},
        {139, L"netbios-ssn"}, {143, L"imap"}, {161, L"snmp"}, {389, L"ldap"}, {443, L"https"},
        {445, L"smb"}, {465, L"smtps"}, {514, L"syslog"}, {587, L"submission"}, {636, L"ldaps"},
        {993, L"imaps"}, {995, L"pop3s"}, {1433, L"mssql"}, {1521, L"oracle"}, {3306, L"mysql"},
        {3389, L"rdp"}, {5432, L"postgresql"}, {5900, L"vnc"}, {5985, L"winrm-http"},
        {5986, L"winrm-https"}, {8080, L"http-alt"}, {8443, L"https-alt"}
    };
    for (const Entry& entry : table) if (entry.port == port) return entry.name;
    return L"";
}

std::vector<DnsEntry> GetDnsCache() {
    static std::mutex cacheMutex;
    static std::vector<DnsEntry> cached;
    static std::chrono::steady_clock::time_point cachedAt{};
    static bool loaded = false;

    std::lock_guard<std::mutex> lock(cacheMutex);
    auto now = std::chrono::steady_clock::now();
    if (loaded && cachedAt.time_since_epoch().count() &&
        std::chrono::duration_cast<std::chrono::seconds>(now - cachedAt).count() < 8) {
        return cached;
    }

    std::vector<DnsEntry> entries;
    constexpr int capacity = 4096;
    std::unique_ptr<RawDnsRec[]> raw(new RawDnsRec[capacity]);
    int count = RawDnsCacheOnce(raw.get(), capacity);
    entries.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; ++i) {
        DnsEntry entry;
        entry.name = raw[i].name;
        entry.data = raw[i].data;
        entry.type = raw[i].type;
        entry.ttl = raw[i].ttl;
        entries.push_back(std::move(entry));
    }
    cached = entries;
    cachedAt = now;
    loaded = true;
    return entries;
}

std::vector<Row> CollectVolumes() {
    std::vector<Row> rows;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1u << i))) continue;
        wchar_t drive[3] = {static_cast<wchar_t>(L'A' + i), L':', 0};
        std::wstring root = std::wstring(drive) + L"\\";
        UINT type = GetDriveTypeW(root.c_str());

        wchar_t label[261] = {};
        wchar_t fs[261] = {};
        DWORD serial = 0, maximum = 0, flags = 0;
        BOOL infoOk = GetVolumeInformationW(root.c_str(), label, 261, &serial, &maximum, &flags, fs, 261);

        ULARGE_INTEGER freeBytes{}, totalBytes{}, totalFree{};
        BOOL spaceOk = GetDiskFreeSpaceExW(root.c_str(), &freeBytes, &totalBytes, &totalFree);

        std::wstring status = type == DRIVE_FIXED ? L"Mounted" : (type == DRIVE_REMOVABLE ? L"Removable" :
                               (type == DRIVE_REMOTE ? L"Network" : (type == DRIVE_CDROM ? L"Optical" : L"Unavailable")));
        if (!infoOk) status = L"Unavailable";

        rows.push_back({
            drive,
            infoOk ? label : L"",
            infoOk ? fs : L"Unknown",
            spaceOk ? SizeText(totalBytes.QuadPart) : L"",
            spaceOk ? SizeText(totalFree.QuadPart) : L"",
            status
        });
    }
    return rows;
}

std::vector<std::wstring> LocalAddresses() {
    std::vector<std::wstring> addresses;
    ULONG size = 16 * 1024;
    std::unique_ptr<BYTE[]> buffer(new BYTE[size]);
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get()), &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.reset(new BYTE[size]);
        result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                      reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get()), &size);
    }
    if (result == NO_ERROR) {
        for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get()); adapter; adapter = adapter->Next) {
            for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
                wchar_t text[INET6_ADDRSTRLEN] = {};
                if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                    auto* v4 = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
                    InetNtopW(AF_INET, &v4->sin_addr, text, INET6_ADDRSTRLEN);
                } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
                    auto* v6 = reinterpret_cast<sockaddr_in6*>(unicast->Address.lpSockaddr);
                    InetNtopW(AF_INET6, &v6->sin6_addr, text, INET6_ADDRSTRLEN);
                }
                if (text[0]) addresses.emplace_back(text);
            }
        }
    }
    return addresses;
}
