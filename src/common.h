#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <windns.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <shellapi.h>
#include <shlwapi.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shlwapi.lib")

#define WM_APP_BATCH (WM_APP + 1)

constexpr size_t DISPLAY_LIMIT = 20000;
constexpr size_t COLLECT_LIMIT = 250000;

using Row = std::vector<std::wstring>;

struct Batch {
    int tab = 0;
    uint64_t generation = 0;
    bool reset = false;
    bool done = false;
    bool error = false;
    std::wstring status;
    int progress = -1;
    std::vector<Row> rows;
    std::vector<std::wstring> details;
};

struct Sink {
    HWND hwnd = nullptr;
    int tab = 0;
    uint64_t generation = 0;
    std::function<void(Batch&&)> onBatch;

    void Post(Batch&& batch) const {
        batch.tab = tab;
        batch.generation = generation;
        if (onBatch) {
            onBatch(std::move(batch));
            return;
        }
        auto* payload = new Batch(std::move(batch));
        if (!PostMessageW(hwnd, WM_APP_BATCH, 0, reinterpret_cast<LPARAM>(payload))) {
            delete payload;
        }
    }
    void Status(const std::wstring& text, int progress = -1) const {
        Batch batch;
        batch.status = text;
        batch.progress = progress;
        Post(std::move(batch));
    }
    void Rows(std::vector<Row> rows, bool reset = false, const std::wstring& text = L"", int progress = -1) const {
        Batch batch;
        batch.rows = std::move(rows);
        batch.reset = reset;
        batch.status = text;
        batch.progress = progress;
        Post(std::move(batch));
    }
    void Detailed(std::vector<Row> rows, std::vector<std::wstring> details, bool reset = false,
                  const std::wstring& text = L"", int progress = -1) const {
        Batch batch;
        batch.rows = std::move(rows);
        batch.details = std::move(details);
        batch.reset = reset;
        batch.status = text;
        batch.progress = progress;
        Post(std::move(batch));
    }
    void Done(const std::wstring& text) const {
        Batch batch;
        batch.done = true;
        batch.status = text;
        Post(std::move(batch));
    }
    void Error(const std::wstring& text) const {
        Batch batch;
        batch.error = true;
        batch.status = text;
        Post(std::move(batch));
    }
};

struct ProcInfo {
    std::wstring name;
    std::wstring path;
    std::wstring user;
    std::wstring cmd;
    std::wstring started;
};

struct DnsEntry {
    std::wstring name;
    std::wstring data;
    uint16_t type = 0;
    uint32_t ttl = 0;
};

struct ArpEntry {
    std::wstring ip;
    std::wstring mac;
    std::wstring state;
};

std::wstring Utf8ToWide(const std::string& text);
std::string WideToUtf8(const std::wstring& text);
std::wstring Format(const wchar_t* format, ...);
std::wstring SizeText(unsigned long long bytes);
std::wstring CommaNumber(unsigned long long value);
std::wstring NowStamp();
std::wstring TimeStampFromMs(long long epochMs);
std::wstring FileTimeText(const FILETIME& fileTime);
std::wstring ToLower(std::wstring text);
bool ContainsInsensitive(const std::wstring& haystack, const std::wstring& needle);
std::wstring Trim(const std::wstring& text);
std::wstring TrimTrailingComment(const std::wstring& text);
std::wstring IpText(const BYTE* address, int family);
std::wstring EndpointText(const SOCKADDR_INET& address, USHORT port);
std::wstring PathFileName(const std::wstring& path);
std::wstring GuidBraced(const wchar_t* adapterName);
std::wstring JsonStringField(const std::string& json, const std::string& key);
std::string HttpGet(const std::wstring& host, const std::wstring& path);

struct SignatureInfo {
    std::wstring status;
    std::wstring signer;
    std::wstring issuer;
    std::wstring thumbprint;
    std::wstring serial;
    std::wstring notBefore;
    std::wstring notAfter;
    std::wstring certificateLocation;
    std::wstring catalogPath;
    bool selfSigned = false;
    bool valid = false;
    std::vector<std::wstring> chain;
};

SignatureInfo GetSignatureInfo(const std::wstring& path);
std::wstring SignatureReportText(const SignatureInfo& info, const std::wstring& path);
std::wstring CertificateReport(const std::wstring& path);
std::wstring FileSignatureText(const std::wstring& path);
std::wstring HashFileReport(const std::wstring& path);
std::wstring AlternateStreamsReport(const std::wstring& path);
bool HashFileDigest(const std::wstring& path, const wchar_t* algorithm,
                    std::vector<unsigned char>& digest);
std::wstring HexLower(const std::vector<unsigned char>& digest);

ProcInfo GetProcInfo(DWORD pid);
std::wstring ReadCommandLine(HANDLE process);
std::wstring TokenUserText(HANDLE process);
std::unordered_map<DWORD, std::wstring> SnapshotProcessNames();
std::wstring ReverseName(const std::string& ip);
void RequestReverse(const std::string& ip);
std::wstring AsnInfo(const std::string& ip);
void RequestAsn(const std::string& ip);
std::wstring LookupDebugStats();
bool IsPublicIp(const std::string& ip);
std::wstring PortService(USHORT port);
std::vector<DnsEntry> GetDnsCache();

std::vector<Row> CollectVolumes();
std::vector<std::wstring> LocalAddresses();
