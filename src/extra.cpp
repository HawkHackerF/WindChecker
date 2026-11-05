#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include "artifacts.h"
#include "evtx.h"
#include "forensics.h"

#include <oleauto.h>
#include <shlobj.h>
#include <wbemidl.h>
#include <winevt.h>

#include <algorithm>
#include <cstring>
#include <functional>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

struct sqlite3;
struct sqlite3_stmt;

namespace {

std::wstring EnvText(const wchar_t* name) {
    wchar_t buffer[32768] = {};
    DWORD length = GetEnvironmentVariableW(name, buffer, 32768);
    if (length == 0 || length >= 32768) return L"";
    return std::wstring(buffer, length);
}

bool IsDirectory(const std::wstring& path) {
    DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

std::vector<std::wstring> ListEntries(const std::wstring& pattern, bool directories) {
    std::vector<std::wstring> result;
    WIN32_FIND_DATAW fd{};
    HANDLE find = FindFirstFileW(pattern.c_str(), &fd);
    if (find == INVALID_HANDLE_VALUE) return result;
    do {
        if (fd.cFileName[0] == L'.' && (fd.cFileName[1] == 0 ||
                                        (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0))) {
            continue;
        }
        bool isDirectory = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (isDirectory != directories) continue;
        result.push_back(fd.cFileName);
    } while (FindNextFileW(find, &fd));
    FindClose(find);
    std::sort(result.begin(), result.end());
    return result;
}

std::wstring LastWriteText(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return L"";
    return FileTimeText(data.ftLastWriteTime);
}

std::wstring FileSizeOf(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return L"";
    ULARGE_INTEGER size{};
    size.HighPart = data.nFileSizeHigh;
    size.LowPart = data.nFileSizeLow;
    return SizeText(size.QuadPart);
}

bool ReadBytes(const std::wstring& path, std::vector<unsigned char>& out, size_t limit) {
    out.clear();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0) {
        CloseHandle(file);
        return false;
    }
    if (static_cast<unsigned long long>(size.QuadPart) > limit) {
        CloseHandle(file);
        return false;
    }
    out.resize(static_cast<size_t>(size.QuadPart));
    size_t done = 0;
    while (done < out.size()) {
        DWORD chunk = 0;
        DWORD want = static_cast<DWORD>(std::min<size_t>(out.size() - done, 1u << 20));
        if (!ReadFile(file, out.data() + done, want, &chunk, nullptr) || chunk == 0) break;
        done += chunk;
    }
    CloseHandle(file);
    out.resize(done);
    return !out.empty();
}

bool ReadHead(const std::wstring& path, std::vector<unsigned char>& out, size_t count) {
    out.clear();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    out.resize(count);
    DWORD read = 0;
    BOOL ok = ReadFile(file, out.data(), static_cast<DWORD>(count), &read, nullptr);
    CloseHandle(file);
    if (!ok) {
        out.clear();
        return false;
    }
    out.resize(read);
    return !out.empty();
}

std::wstring DecodeBytes(const unsigned char* data, size_t size) {
    if (size >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) {
        data += 3;
        size -= 3;
    }
    if (size >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
        return std::wstring(reinterpret_cast<const wchar_t*>(data + 2), (size - 2) / 2);
    }
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     reinterpret_cast<const char*>(data), static_cast<int>(size),
                                     nullptr, 0);
    UINT codePage = CP_UTF8;
    if (needed <= 0) {
        codePage = CP_ACP;
        needed = MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(data),
                                     static_cast<int>(size), nullptr, 0);
    }
    if (needed <= 0) return L"";
    std::wstring text(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(codePage, 0, reinterpret_cast<const char*>(data), static_cast<int>(size),
                        text.data(), needed);
    return text;
}

std::wstring ReadText(const std::wstring& path, size_t limit) {
    std::vector<unsigned char> data;
    if (!ReadBytes(path, data, limit)) return L"";
    return DecodeBytes(data.data(), data.size());
}

std::vector<std::wstring> SplitLines(const std::wstring& text) {
    std::vector<std::wstring> lines;
    std::wstring current;
    for (wchar_t ch : text) {
        if (ch == L'\r') continue;
        if (ch == L'\n') {
            lines.push_back(current);
            current.clear();
            continue;
        }
        current.push_back(ch);
    }
    if (!current.empty()) lines.push_back(current);
    return lines;
}

std::wstring TagText(const std::wstring& xml, const std::wstring& tag, size_t from) {
    std::wstring open = L"<" + tag;
    size_t at = xml.find(open, from);
    if (at == std::wstring::npos) return L"";
    size_t tagEnd = xml.find(L'>', at);
    if (tagEnd == std::wstring::npos) return L"";
    if (tagEnd > at && xml[tagEnd - 1] == L'/') return L"";
    size_t close = xml.find(L"</" + tag + L">", tagEnd);
    if (close == std::wstring::npos) return L"";
    std::wstring value = xml.substr(tagEnd + 1, close - tagEnd - 1);
    value = Trim(value);
    return value;
}

std::wstring SystemTimeBlobText(const std::vector<unsigned char>& data) {
    if (data.size() < sizeof(SYSTEMTIME)) return L"";
    SYSTEMTIME st{};
    std::memcpy(&st, data.data(), sizeof(st));
    if (st.wYear < 1601 || st.wYear > 9999) return L"";
    FILETIME ft{};
    if (!SystemTimeToFileTime(&st, &ft)) return L"";
    return FileTimeText(ft);
}

std::wstring UnixText(long long value) {
    if (value <= 0) return L"-";
    if (value > 116444736000000000LL) {
        FILETIME ft{};
        ft.dwLowDateTime = static_cast<DWORD>(value & 0xFFFFFFFFLL);
        ft.dwHighDateTime = static_cast<DWORD>((value >> 32) & 0xFFFFFFFFLL);
        return FileTimeText(ft);
    }
    if (value > 100000000000LL) return TimeStampFromMs(value);
    if (value > 1000000000LL) return TimeStampFromMs(value * 1000);
    return L"-";
}

std::wstring JsonText(const std::wstring& json, const std::wstring& key) {
    std::wstring needle = L"\"" + key + L"\":";
    size_t at = json.find(needle);
    if (at == std::wstring::npos) return L"";
    at += needle.size();
    while (at < json.size() && (json[at] == L' ' || json[at] == L'\t')) ++at;
    if (at >= json.size() || json[at] != L'"') return L"";
    ++at;
    std::wstring out;
    for (size_t i = at; i < json.size(); ++i) {
        wchar_t ch = json[i];
        if (ch == L'\\' && i + 1 < json.size()) {
            wchar_t next = json[++i];
            switch (next) {
            case L'n': out += L' '; break;
            case L'r': out += L' '; break;
            case L't': out += L' '; break;
            case L'u': {
                if (i + 4 < json.size()) {
                    wchar_t hex[5] = {json[i + 1], json[i + 2], json[i + 3], json[i + 4], 0};
                    out.push_back(static_cast<wchar_t>(wcstoul(hex, nullptr, 16)));
                    i += 4;
                }
                break;
            }
            default: out += next; break;
            }
            continue;
        }
        if (ch == L'"') break;
        out += ch;
    }
    return out;
}

std::wstring CleanText(const std::wstring& text) {
    std::wstring out;
    out.reserve(text.size());
    for (wchar_t ch : text) {
        if (ch >= 0x2066 && ch <= 0x2069) continue;
        if (ch == 0x200E || ch == 0x200F || (ch >= 0x202A && ch <= 0x202E)) continue;
        out.push_back(ch);
    }
    return out;
}

std::wstring SockaddrText(const SOCKADDR* address) {
    wchar_t buffer[96] = {};
    if (address->sa_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(address);
        InetNtopW(AF_INET, &v4->sin_addr, buffer, 96);
    } else if (address->sa_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
        InetNtopW(AF_INET6, &v6->sin6_addr, buffer, 96);
    }
    return buffer;
}

std::wstring MacText(const UCHAR* address, ULONG length) {
    if (!address || length == 0 || length > 8) return L"-";
    std::wstring text;
    wchar_t buffer[8] = {};
    for (ULONG i = 0; i < length; ++i) {
        swprintf_s(buffer, L"%02X", address[i]);
        if (i) text += L'-';
        text += buffer;
    }
    return text;
}

std::wstring NeighborStateText(NL_NEIGHBOR_STATE state) {
    switch (state) {
    case NlnsUnreachable: return L"Unreachable";
    case NlnsIncomplete: return L"Incomplete";
    case NlnsProbe: return L"Probe";
    case NlnsDelay: return L"Delay";
    case NlnsStale: return L"Stale";
    case NlnsReachable: return L"Reachable";
    case NlnsPermanent: return L"Permanent";
    default: return L"Unknown";
    }
}

std::wstring DnsTypeText(uint16_t type) {
    switch (type) {
    case 1: return L"A";
    case 2: return L"NS";
    case 5: return L"CNAME";
    case 6: return L"SOA";
    case 12: return L"PTR";
    case 15: return L"MX";
    case 16: return L"TXT";
    case 28: return L"AAAA";
    case 33: return L"SRV";
    default: return Format(L"type %u", type);
    }
}

std::wstring LocalAppData() {
    PWSTR path = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path)) || !path) return L"";
    std::wstring result = path;
    CoTaskMemFree(path);
    return result;
}

std::wstring ProgramData() {
    std::wstring value = EnvText(L"ProgramData");
    if (!value.empty()) return value;
    return L"C:\\ProgramData";
}

std::wstring WindowsFolder() {
    std::wstring value = EnvText(L"SystemRoot");
    if (!value.empty()) return value;
    return L"C:\\Windows";
}

void Flush(const Sink& sink, std::vector<Row>& rows, std::vector<std::wstring>& details) {
    if (rows.empty()) return;
    sink.Detailed(std::move(rows), std::move(details), false);
    rows.clear();
    details.clear();
    rows.reserve(256);
    details.reserve(256);
}

struct SqliteApi {
    HMODULE module = nullptr;
    int (*open_v2)(const char*, sqlite3**, int, const char*) = nullptr;
    int (*close)(sqlite3*) = nullptr;
    int (*prepare_v2)(sqlite3*, const char*, int, sqlite3_stmt**, const char**) = nullptr;
    int (*step)(sqlite3_stmt*) = nullptr;
    int (*finalize)(sqlite3_stmt*) = nullptr;
    int (*column_count)(sqlite3_stmt*) = nullptr;
    const unsigned char* (*column_text)(sqlite3_stmt*, int) = nullptr;
    int (*column_bytes)(sqlite3_stmt*, int) = nullptr;
    long long (*column_int64)(sqlite3_stmt*, int) = nullptr;
    int (*column_type)(sqlite3_stmt*, int) = nullptr;
    const char* (*column_name)(sqlite3_stmt*, int) = nullptr;
    const char* (*errmsg)(sqlite3*) = nullptr;

    bool Load() {
        if (module) return true;
        module = LoadLibraryW(L"winsqlite3.dll");
        if (!module) return false;
        open_v2 = reinterpret_cast<decltype(open_v2)>(GetProcAddress(module, "sqlite3_open_v2"));
        close = reinterpret_cast<decltype(close)>(GetProcAddress(module, "sqlite3_close"));
        prepare_v2 = reinterpret_cast<decltype(prepare_v2)>(GetProcAddress(module, "sqlite3_prepare_v2"));
        step = reinterpret_cast<decltype(step)>(GetProcAddress(module, "sqlite3_step"));
        finalize = reinterpret_cast<decltype(finalize)>(GetProcAddress(module, "sqlite3_finalize"));
        column_count = reinterpret_cast<decltype(column_count)>(GetProcAddress(module, "sqlite3_column_count"));
        column_text = reinterpret_cast<decltype(column_text)>(GetProcAddress(module, "sqlite3_column_text"));
        column_bytes = reinterpret_cast<decltype(column_bytes)>(GetProcAddress(module, "sqlite3_column_bytes"));
        column_int64 = reinterpret_cast<decltype(column_int64)>(GetProcAddress(module, "sqlite3_column_int64"));
        column_type = reinterpret_cast<decltype(column_type)>(GetProcAddress(module, "sqlite3_column_type"));
        column_name = reinterpret_cast<decltype(column_name)>(GetProcAddress(module, "sqlite3_column_name"));
        errmsg = reinterpret_cast<decltype(errmsg)>(GetProcAddress(module, "sqlite3_errmsg"));
        return open_v2 && close && prepare_v2 && step && finalize && column_count && column_text &&
               column_int64 && column_type && column_name;
    }
};

SqliteApi& Sqlite() {
    static SqliteApi api;
    api.Load();
    return api;
}

std::wstring CopyDatabase(const std::wstring& source) {
    wchar_t temp[32768] = {};
    DWORD length = GetTempPathW(32768, temp);
    if (length == 0) return L"";
    std::wstring folder = std::wstring(temp, length) + L"windchecker-db";
    CreateDirectoryW(folder.c_str(), nullptr);
    std::wstring target = folder + L"\\" + PathFileName(source);
    if (!CopyFileW(source.c_str(), target.c_str(), FALSE)) return L"";
    for (const wchar_t* suffix : {L"-wal", L"-shm"}) {
        std::wstring from = source + suffix;
        if (GetFileAttributesW(from.c_str()) != INVALID_FILE_ATTRIBUTES) {
            CopyFileW(from.c_str(), (target + suffix).c_str(), FALSE);
        }
    }
    return target;
}

void RemoveCopy(const std::wstring& target) {
    if (target.empty()) return;
    DeleteFileW((target + L"-wal").c_str());
    DeleteFileW((target + L"-shm").c_str());
    DeleteFileW(target.c_str());
}

bool SqliteQuery(const std::wstring& path, const std::string& sql,
                 const std::function<bool(sqlite3_stmt*)>& onRow, std::wstring& error) {
    SqliteApi& api = Sqlite();
    if (!api.open_v2) {
        error = L"winsqlite3.dll is not available on this system.";
        return false;
    }
    sqlite3* db = nullptr;
    std::string utf8 = WideToUtf8(path);
    if (api.open_v2(utf8.c_str(), &db, 0x00000001, nullptr) != 0 || !db) {
        error = L"The SQLite database could not be opened.";
        if (db) api.close(db);
        return false;
    }
    sqlite3_stmt* statement = nullptr;
    if (api.prepare_v2(db, sql.c_str(), -1, &statement, nullptr) != 0 || !statement) {
        error = api.errmsg ? Utf8ToWide(api.errmsg(db)) : L"The SQLite query could not be prepared.";
        api.close(db);
        return false;
    }
    while (api.step(statement) == 100) {
        if (!onRow(statement)) break;
    }
    api.finalize(statement);
    api.close(db);
    return true;
}

std::wstring ColumnText(sqlite3_stmt* statement, int column) {
    const unsigned char* value = Sqlite().column_text(statement, column);
    if (!value) return L"";
    return Utf8ToWide(reinterpret_cast<const char*>(value));
}

int ColumnIndex(sqlite3_stmt* statement, const char* name) {
    int count = Sqlite().column_count(statement);
    for (int i = 0; i < count; ++i) {
        const char* label = Sqlite().column_name(statement, i);
        if (label && _stricmp(label, name) == 0) return i;
    }
    return -1;
}

std::wstring ColumnByName(sqlite3_stmt* statement, const char* name) {
    int index = ColumnIndex(statement, name);
    return index >= 0 ? ColumnText(statement, index) : L"";
}

std::wstring ColumnValueText(sqlite3_stmt* statement, int column) {
    SqliteApi& api = Sqlite();
    int type = api.column_type(statement, column);
    if (type == 5) return L"";
    if (type == 4) {
        const unsigned char* data = api.column_text(statement, column);
        int size = api.column_bytes ? api.column_bytes(statement, column) : 0;
        if (!data || size <= 0) return L"";
        std::wstring hex;
        wchar_t buffer[8] = {};
        int shown = size < 64 ? size : 64;
        for (int i = 0; i < shown; ++i) {
            swprintf_s(buffer, L"%02X", data[i]);
            hex += buffer;
        }
        if (size > shown) hex += L" \u2026";
        return Format(L"0x%s (%d bytes)", hex.c_str(), size);
    }
    if (type == 1) return Format(L"%lld", api.column_int64(statement, column));
    return ColumnText(statement, column);
}

void AppendLine(std::wstring& text, const std::wstring& name, const std::wstring& value,
                size_t width) {
    if (value.empty()) return;
    text += name;
    if (name.size() < width) text.append(width - name.size(), L' ');
    text += L" : " + value + L"\r\n";
}

std::wstring DumpColumns(sqlite3_stmt* statement) {
    std::wstring text;
    int count = Sqlite().column_count(statement);
    std::vector<std::pair<std::wstring, std::wstring>> values;
    values.reserve(static_cast<size_t>(count));
    size_t width = 0;
    for (int i = 0; i < count; ++i) {
        const char* label = Sqlite().column_name(statement, i);
        std::wstring name = label ? Utf8ToWide(label) : Format(L"column%d", i);
        std::wstring value = ColumnValueText(statement, i);
        width = (std::max)(width, name.size());
        values.emplace_back(std::move(name), std::move(value));
    }
    if (width > 32) width = 32;
    for (const auto& entry : values) AppendLine(text, entry.first, entry.second, width);
    return text;
}

std::wstring HexPreview(const std::vector<BYTE>& data, size_t limit) {
    if (data.empty()) return L"";
    std::wstring hex;
    wchar_t buffer[8] = {};
    size_t shown = data.size() < limit ? data.size() : limit;
    for (size_t i = 0; i < shown; ++i) {
        swprintf_s(buffer, L"%02X", data[i]);
        hex += buffer;
    }
    if (data.size() > shown) hex += L" \u2026";
    return Format(L"0x%s (%llu bytes)", hex.c_str(),
                  static_cast<unsigned long long>(data.size()));
}

std::wstring DumpRegValues(const fc::RegView& view, const std::wstring& key) {
    std::wstring text;
    for (const std::wstring& name : view.ValueNames(key)) {
        std::wstring value = view.QueryString(key, name);
        if (!value.empty()) {
            AppendLine(text, name.empty() ? L"(default)" : name, value, 24);
            continue;
        }
        std::vector<BYTE> binary;
        if (view.QueryBinary(key, name, binary) && !binary.empty()) {
            AppendLine(text, name.empty() ? L"(default)" : name, HexPreview(binary, 64), 24);
        }
    }
    return text;
}

void QueryEvents(const std::wstring& channel, int limit, std::atomic<bool>& stop,
                 const std::function<void(const std::wstring& xml)>& onEvent) {
    EVT_HANDLE query = EvtQuery(nullptr, channel.c_str(), L"*",
                                EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!query) return;
    int count = 0;
    EVT_HANDLE events[16] = {};
    DWORD returned = 0;
    while (!stop.load() && count < limit) {
        if (!EvtNext(query, 16, events, 1000, 0, &returned)) break;
        for (DWORD i = 0; i < returned && count < limit; ++i) {
            std::wstring xml;
            if (EvtxRender(events[i], xml)) {
                ++count;
                onEvent(xml);
            }
            EvtClose(events[i]);
            events[i] = nullptr;
        }
        if (returned < 16) break;
    }
    for (EVT_HANDLE event : events) {
        if (event) EvtClose(event);
    }
    EvtClose(query);
}

std::wstring EventDataField(const std::wstring& xml, const wchar_t* name) {
    std::wstring needle = std::wstring(L"<Data Name=\"") + name + L"\"";
    size_t at = xml.find(needle);
    if (at == std::wstring::npos) return L"";
    size_t tagEnd = xml.find(L'>', at);
    if (tagEnd == std::wstring::npos) return L"";
    if (tagEnd > at && xml[tagEnd - 1] == L'/') return L"";
    size_t close = xml.find(L"</Data>", tagEnd);
    if (close == std::wstring::npos) return L"";
    return EvtxDecode(xml.substr(tagEnd + 1, close - tagEnd - 1));
}

std::wstring ArrayText(const VARIANT& value) {
    if (!(value.vt & VT_ARRAY) || !value.parray) return L"(array)";
    VARTYPE base = static_cast<VARTYPE>(value.vt & ~VT_ARRAY);
    LONG lower = 0;
    LONG upper = -1;
    if (FAILED(SafeArrayGetLBound(value.parray, 1, &lower)) ||
        FAILED(SafeArrayGetUBound(value.parray, 1, &upper))) {
        return L"(array)";
    }
    std::wstring text;
    for (LONG index = lower; index <= upper; ++index) {
        VARIANT item;
        VariantInit(&item);
        item.vt = base == VT_VARIANT ? VT_VARIANT : base;
        HRESULT hr = SafeArrayGetElement(value.parray, &index, &item);
        if (FAILED(hr)) {
            VariantClear(&item);
            continue;
        }
        std::wstring element;
        if (item.vt == VT_BSTR && item.bstrVal) {
            element = item.bstrVal;
        } else if (item.vt != VT_NULL && item.vt != VT_EMPTY) {
            VARIANT converted;
            VariantInit(&converted);
            if (SUCCEEDED(VariantChangeType(&converted, &item, 0, VT_BSTR)) &&
                converted.vt == VT_BSTR && converted.bstrVal) {
                element = converted.bstrVal;
            }
            VariantClear(&converted);
        }
        VariantClear(&item);
        if (element.empty()) continue;
        if (!text.empty()) text += L", ";
        text += element;
    }
    return text.empty() ? L"(empty array)" : text;
}

std::wstring VariantText(IWbemClassObject* object, const wchar_t* name) {
    VARIANT value;
    VariantInit(&value);
    std::wstring text;
    if (SUCCEEDED(object->Get(name, 0, &value, nullptr, nullptr)) && value.vt != VT_NULL &&
        value.vt != VT_EMPTY) {
        if (value.vt & VT_ARRAY) {
            text = ArrayText(value);
        } else {
            VARIANT converted;
            VariantInit(&converted);
            if (SUCCEEDED(VariantChangeType(&converted, &value, 0, VT_BSTR)) &&
                converted.vt == VT_BSTR && converted.bstrVal) {
                text = converted.bstrVal;
            }
            VariantClear(&converted);
        }
    }
    VariantClear(&value);
    return Trim(text);
}

std::wstring DumpWmiObject(IWbemClassObject* object) {
    std::vector<std::pair<std::wstring, std::wstring>> properties;
    if (SUCCEEDED(object->BeginEnumeration(0))) {
        BSTR name = nullptr;
        VARIANT value;
        VariantInit(&value);
        while (object->Next(0, &name, &value, nullptr, nullptr) == S_OK) {
            std::wstring key = name ? std::wstring(name) : std::wstring();
            if (name) SysFreeString(name);
            name = nullptr;
            std::wstring text;
            if (value.vt == VT_BSTR && value.bstrVal) {
                text = value.bstrVal;
            } else if (value.vt != VT_NULL && value.vt != VT_EMPTY) {
                if (value.vt & VT_ARRAY) {
                    text = ArrayText(value);
                } else {
                    VARIANT converted;
                    VariantInit(&converted);
                    if (SUCCEEDED(VariantChangeType(&converted, &value, 0, VT_BSTR)) &&
                        converted.vt == VT_BSTR && converted.bstrVal) {
                        text = converted.bstrVal;
                    }
                    VariantClear(&converted);
                }
            }
            VariantClear(&value);
            VariantInit(&value);
            if (!key.empty()) properties.emplace_back(std::move(key), Trim(text));
        }
        object->EndEnumeration();
    }
    std::sort(properties.begin(), properties.end(),
              [](const std::pair<std::wstring, std::wstring>& left,
                 const std::pair<std::wstring, std::wstring>& right) {
                  return _wcsicmp(left.first.c_str(), right.first.c_str()) < 0;
              });
    size_t width = 0;
    for (const auto& entry : properties) width = (std::max)(width, entry.first.size());
    if (width > 32) width = 32;
    std::wstring text = L"--- all object properties ---\r\n";
    for (const auto& entry : properties) AppendLine(text, entry.first, entry.second, width);
    return text;
}

void QueryWmi(IWbemServices* services, const wchar_t* wql,
              const std::function<void(IWbemClassObject*)>& onObject, std::atomic<bool>& stop) {
    BSTR language = SysAllocString(L"WQL");
    BSTR query = SysAllocString(wql);
    IEnumWbemClassObject* enumerator = nullptr;
    HRESULT hr = services->ExecQuery(language, query,
                                     WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                     nullptr, &enumerator);
    SysFreeString(language);
    SysFreeString(query);
    if (FAILED(hr) || !enumerator) return;
    while (!stop.load()) {
        IWbemClassObject* object = nullptr;
        ULONG returned = 0;
        HRESULT next = enumerator->Next(500, 1, &object, &returned);
        if (FAILED(next) || returned == 0 || !object) break;
        onObject(object);
        object->Release();
    }
    enumerator->Release();
}

std::wstring ConsumerDetail(IWbemClassObject* object, const std::wstring& className) {
    if (className == L"CommandLineEventConsumer") {
        std::wstring command = VariantText(object, L"CommandLineTemplate");
        if (command.empty()) command = VariantText(object, L"ExecutablePath");
        return command;
    }
    if (className == L"ActiveScriptEventConsumer") {
        std::wstring engine = VariantText(object, L"ScriptingEngine");
        std::wstring script = VariantText(object, L"ScriptText");
        if (!engine.empty()) script = L"[" + engine + L"] " + script;
        return script;
    }
    if (className == L"LogFileEventConsumer") {
        std::wstring file = VariantText(object, L"Filename");
        std::wstring text = VariantText(object, L"Text");
        if (!file.empty()) return file + L" \u00B7 " + text;
        return text;
    }
    if (className == L"NTEventLogEventConsumer") {
        return VariantText(object, L"SourceName") + L" \u00B7 " + VariantText(object, L"MessageText");
    }
    if (className == L"SMTPEventConsumer") {
        return VariantText(object, L"Subject") + L" \u00B7 " + VariantText(object, L"To");
    }
    return VariantText(object, L"Name");
}

std::wstring DumpStreamName(unsigned int type) {
    switch (type) {
        case 0: return L"UnusedStream";
        case 1: return L"ReservedStream0";
        case 2: return L"ReservedStream1";
        case 3: return L"ThreadListStream";
        case 4: return L"ModuleListStream";
        case 5: return L"MemoryListStream";
        case 6: return L"ExceptionStream";
        case 7: return L"SystemInfoStream";
        case 8: return L"ThreadExListStream";
        case 9: return L"Memory64ListStream";
        case 10: return L"CommentStreamA";
        case 11: return L"CommentStreamW";
        case 12: return L"HandleDataStream";
        case 13: return L"FunctionTableStream";
        case 14: return L"UnloadedModuleListStream";
        case 15: return L"MiscInfoStream";
        case 16: return L"MemoryInfoListStream";
        case 17: return L"ThreadInfoListStream";
        case 18: return L"HandleOperationListStream";
        case 19: return L"TokenStream";
        case 20: return L"JavaScriptDataStream";
        case 21: return L"SystemMemoryInfoStream";
        case 22: return L"ProcessVmCountersStream";
        case 23: return L"IptTraceStream";
        case 24: return L"ThreadNamesStream";
        default: return Format(L"Stream%u", type);
    }
}

std::wstring DumpFlags(unsigned long long flags) {
    struct FlagName { unsigned long long bit; const wchar_t* name; };
    static const FlagName names[] = {
        {0x00000001ULL, L"MiniDumpWithDataSegs"},
        {0x00000002ULL, L"MiniDumpWithFullMemory"},
        {0x00000004ULL, L"MiniDumpWithHandleData"},
        {0x00000008ULL, L"MiniDumpFilterMemory"},
        {0x00000010ULL, L"MiniDumpScanMemory"},
        {0x00000020ULL, L"MiniDumpWithUnloadedModules"},
        {0x00000040ULL, L"MiniDumpWithIndirectlyReferencedMemory"},
        {0x00000080ULL, L"MiniDumpFilterModulePaths"},
        {0x00000100ULL, L"MiniDumpWithProcessThreadData"},
        {0x00000200ULL, L"MiniDumpWithPrivateReadWriteMemory"},
        {0x00000400ULL, L"MiniDumpWithoutOptionalData"},
        {0x00000800ULL, L"MiniDumpWithFullMemoryInfo"},
        {0x00001000ULL, L"MiniDumpWithThreadInfo"},
        {0x00002000ULL, L"MiniDumpWithCodeSegs"},
        {0x00004000ULL, L"MiniDumpWithoutAuxiliaryState"},
        {0x00008000ULL, L"MiniDumpWithFullAuxiliaryState"},
        {0x00010000ULL, L"MiniDumpWithPrivateWriteCopyMemory"},
        {0x00020000ULL, L"MiniDumpIgnoreInaccessibleMemory"},
        {0x00040000ULL, L"MiniDumpWithTokenInformation"},
        {0x00080000ULL, L"MiniDumpWithModuleHeaders"},
        {0x00100000ULL, L"MiniDumpFilterTriage"},
        {0x00200000ULL, L"MiniDumpWithAvxXStateContext"},
        {0x00400000ULL, L"MiniDumpWithIptTrace"},
    };
    if (flags == 0) return L"MiniDumpNormal (0x0)";
    std::wstring text;
    unsigned long long remaining = flags;
    for (const FlagName& entry : names) {
        if ((flags & entry.bit) == 0) continue;
        remaining &= ~entry.bit;
        if (!text.empty()) text += L" | ";
        text += entry.name;
    }
    if (remaining != 0) {
        if (!text.empty()) text += L" | ";
        text += Format(L"0x%llX", remaining);
    }
    return Format(L"%s (0x%llX)", text.c_str(), flags);
}

std::wstring FieldOf(const std::vector<EvtxField>& fields, const wchar_t* name) {
    for (const EvtxField& field : fields) {
        if (_wcsicmp(field.name.c_str(), name) == 0) return field.value;
    }
    return L"";
}

std::wstring FieldOfAny(const std::vector<EvtxField>& fields,
                        std::initializer_list<const wchar_t*> names) {
    for (const wchar_t* name : names) {
        std::wstring value = FieldOf(fields, name);
        if (!value.empty()) return value;
    }
    return L"";
}

std::wstring DefenderMeaning(const std::wstring& id) {
    int value = _wtoi(id.c_str());
    switch (value) {
        case 1000: return L"Scan started";
        case 1001: return L"Scan completed";
        case 1002: return L"Scan stopped by the user";
        case 1003: return L"Scan paused";
        case 1004: return L"Scan resumed";
        case 1005: return L"Scan failed";
        case 1006: return L"Malware was removed or quarantined";
        case 1007: return L"Malware action completed";
        case 1008: return L"Malware action failed";
        case 1009: return L"Malware was restored from quarantine";
        case 1010: return L"Failed to restore quarantined item";
        case 1011: return L"Quarantined item was deleted";
        case 1012: return L"Failed to delete quarantined item";
        case 1013: return L"Item was deleted from quarantine";
        case 1015: return L"Suspicious behaviour detected";
        case 1116: return L"Malware detected: Defender found a threat";
        case 1117: return L"Malware action taken: Defender acted on a detected threat";
        case 1118: return L"Remediation started";
        case 1119: return L"Remediation completed";
        case 1120: return L"Remediation failed";
        case 1150: return L"Defender health report";
        case 1151: return L"Defender health report (expired)";
        case 5001: return L"Real-time protection was disabled";
        case 5004: return L"Real-time protection configuration changed";
        case 5007: return L"Defender configuration changed";
        case 5010: return L"Scanning was disabled";
        case 5011: return L"Scanning was enabled";
        case 5012: return L"Antivirus was disabled";
        case 5013: return L"Antivirus was enabled";
        case 5014: return L"Defender platform configuration changed";
        default: return L"";
    }
}

std::wstring RdpMeaning(const std::wstring& id) {
    int value = _wtoi(id.c_str());
    switch (value) {
        case 21: return L"Session logon succeeded";
        case 22: return L"Shell start notification received";
        case 23: return L"Session logoff succeeded";
        case 24: return L"Session disconnected";
        case 25: return L"Session reconnection succeeded";
        case 39: return L"Session disconnected by another session";
        case 40: return L"Session disconnected with a reason code";
        case 41: return L"Session begin";
        case 42: return L"Session end";
        case 1149: return L"Remote Desktop user authentication succeeded";
        case 1148: return L"Remote Desktop authentication attempt";
        case 131: return L"Remote Desktop licensing mode changed";
        default: return L"";
    }
}

}

void RunWmiSubscriptions(const Sink& sink, std::atomic<bool>& stop) {
    HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool uninit = SUCCEEDED(initialized);

    CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);

    IWbemLocator* locator = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&locator));
    if (FAILED(hr) || !locator) {
        if (uninit) CoUninitialize();
        sink.Error(L"The WMI locator could not be created.");
        return;
    }

    BSTR path = SysAllocString(L"ROOT\\SUBSCRIPTION");
    IWbemServices* services = nullptr;
    hr = locator->ConnectServer(path, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
    SysFreeString(path);
    locator->Release();
    if (FAILED(hr) || !services) {
        if (uninit) CoUninitialize();
        sink.Error(L"The ROOT\\SUBSCRIPTION namespace could not be opened. "
                   L"Run WindChecker elevated to read permanent WMI subscriptions.");
        return;
    }

    CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    std::vector<Row> rows;
    std::vector<std::wstring> details;
    rows.reserve(64);
    details.reserve(64);
    unsigned long long total = 0;

    auto add = [&](const std::wstring& kind, const std::wstring& name, const std::wstring& scope,
                   const std::wstring& detail, const std::wstring& source,
                   const std::wstring& extra) {
        Row row;
        row.push_back(kind);
        row.push_back(name.empty() ? L"(unnamed)" : name);
        row.push_back(detail.empty() ? L"-" : detail);
        row.push_back(scope.empty() ? L"-" : scope);
        row.push_back(source);
        rows.push_back(std::move(row));
        std::wstring text;
        text += L"Kind     : " + kind + L"\r\n";
        text += L"Name     : " + (name.empty() ? L"(unnamed)" : name) + L"\r\n";
        text += L"Scope    : " + (scope.empty() ? L"-" : scope) + L"\r\n";
        text += L"Detail   : " + (detail.empty() ? L"-" : detail) + L"\r\n";
        text += L"Source   : " + source;
        if (!extra.empty()) text += L"\r\n\r\n" + extra;
        details.push_back(std::move(text));
        ++total;
        if (rows.size() >= 64) Flush(sink, rows, details);
    };

    sink.Status(L"Reading permanent WMI event filters\u2026", 20);
    QueryWmi(services, L"SELECT * FROM __EventFilter", [&](IWbemClassObject* object) {
        add(L"Event filter", VariantText(object, L"Name"), VariantText(object, L"EventNamespace"),
            VariantText(object, L"Query"), L"ROOT\\SUBSCRIPTION::__EventFilter",
            DumpWmiObject(object));
    }, stop);

    if (!stop.load()) {
        sink.Status(L"Reading permanent WMI consumers\u2026", 55);
        QueryWmi(services, L"SELECT * FROM __EventConsumer", [&](IWbemClassObject* object) {
            std::wstring className = VariantText(object, L"__CLASS");
            add(L"Consumer \u00B7 " + className, VariantText(object, L"Name"),
                VariantText(object, L"__RELPATH"), ConsumerDetail(object, className),
                L"ROOT\\SUBSCRIPTION::__EventConsumer", DumpWmiObject(object));
        }, stop);
    }

    if (!stop.load()) {
        sink.Status(L"Reading filter-to-consumer bindings\u2026", 85);
        QueryWmi(services, L"SELECT * FROM __FilterToConsumerBinding", [&](IWbemClassObject* object) {
            add(L"Binding", VariantText(object, L"Filter"), VariantText(object, L"Consumer"),
                VariantText(object, L"__RELPATH"),
                L"ROOT\\SUBSCRIPTION::__FilterToConsumerBinding", DumpWmiObject(object));
        }, stop);
    }

    Flush(sink, rows, details);
    services->Release();
    if (uninit) CoUninitialize();

    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s WMI subscription record(s) retained.", CommaNumber(total).c_str()));
    } else {
        sink.Done(Format(L"Completed. %s permanent WMI subscription record(s).", CommaNumber(total).c_str()));
    }
}

void RunNetworkArtifacts(const Sink& sink, std::atomic<bool>& stop) {
    std::vector<Row> rows;
    std::vector<std::wstring> details;
    rows.reserve(256);
    details.reserve(256);
    unsigned long long total = 0;

    auto add = [&](const std::wstring& type, const std::wstring& name, const std::wstring& detail,
                   const std::wstring& value, const std::wstring& stamp,
                   const std::wstring& extra) {
        Row row;
        row.push_back(type);
        row.push_back(name.empty() ? L"-" : name);
        row.push_back(detail.empty() ? L"-" : detail);
        row.push_back(value.empty() ? L"-" : value);
        row.push_back(stamp.empty() ? L"-" : stamp);
        rows.push_back(std::move(row));
        std::wstring text;
        text += L"Type    : " + type + L"\r\n";
        text += L"Name    : " + (name.empty() ? L"-" : name) + L"\r\n";
        text += L"Detail  : " + (detail.empty() ? L"-" : detail) + L"\r\n";
        text += L"Value   : " + (value.empty() ? L"-" : value) + L"\r\n";
        text += L"Seen    : " + (stamp.empty() ? L"-" : stamp);
        if (!extra.empty()) text += L"\r\n\r\n" + extra;
        details.push_back(std::move(text));
        ++total;
        if (rows.size() >= 200) Flush(sink, rows, details);
    };

    sink.Status(L"Reading DNS cache\u2026", 10);
    for (const DnsEntry& entry : GetDnsCache()) {
        if (stop.load()) break;
        std::wstring extra;
        extra += L"Source    : GetDnsCache (DNS client resolver cache)\r\n";
        extra += L"Record    : " + entry.name + L"\r\n";
        extra += L"Type code : " + Format(L"%u", static_cast<unsigned int>(entry.type)) +
                 L" (" + DnsTypeText(entry.type) + L")\r\n";
        extra += L"TTL       : " + Format(L"%u second(s)", entry.ttl) + L"\r\n";
        extra += L"Data      : " + entry.data;
        add(L"DNS cache", entry.name, DnsTypeText(entry.type), entry.data,
            Format(L"TTL %u s", entry.ttl), extra);
    }

    if (!stop.load()) {
        sink.Status(L"Reading ARP / neighbour cache\u2026", 35);
        PMIB_IPNET_TABLE2 table = nullptr;
        if (GetIpNetTable2(AF_UNSPEC, &table) == NO_ERROR && table) {
            for (ULONG i = 0; i < table->NumEntries && !stop.load(); ++i) {
                const MIB_IPNET_ROW2& entry = table->Table[i];
                std::wstring extra;
                extra += L"Source          : GetIpNetTable2 (AF_UNSPEC)\r\n";
                extra += L"Row             : " + Format(L"%lu of %lu", i, table->NumEntries) + L"\r\n";
                extra += L"Interface index : " + Format(L"%lu", entry.InterfaceIndex) + L"\r\n";
                extra += Format(L"Interface LUID  : 0x%llX\r\n",
                                static_cast<unsigned long long>(entry.InterfaceLuid.Value));
                extra += L"Address family  : " +
                         std::wstring(entry.Address.si_family == AF_INET ? L"IPv4" : L"IPv6") + L"\r\n";
                extra += L"State (raw)     : " + Format(L"%d", static_cast<int>(entry.State)) + L"\r\n";
                extra += L"Flags           : " + Format(L"0x%X", entry.Flags) + L"\r\n";
                extra += L"Physical length : " +
                         Format(L"%u byte(s)", static_cast<unsigned int>(entry.PhysicalAddressLength)) +
                         L"\r\n";
                extra += Format(L"Reachability    : %lld (%s)\r\n",
                                static_cast<long long>(entry.ReachabilityTime.LastReachable),
                                entry.ReachabilityTime.LastReachable == 0 ? L"unknown" : L"100ns ticks");
                add(L"ARP / neighbour",
                    SockaddrText(reinterpret_cast<const SOCKADDR*>(&entry.Address)),
                    NeighborStateText(entry.State),
                    MacText(entry.PhysicalAddress, entry.PhysicalAddressLength),
                    entry.InterfaceIndex ? Format(L"Interface %lu", entry.InterfaceIndex) : L"",
                    extra);
            }
            FreeMibTable(table);
        }
    }

    if (!stop.load()) {
        sink.Status(L"Reading WLAN profiles\u2026", 60);
        std::wstring interfaces = ProgramData() + L"\\Microsoft\\Wlansvc\\Profiles\\Interfaces";
        for (const std::wstring& adapter : ListEntries(interfaces + L"\\*", true)) {
            if (stop.load()) break;
            std::wstring folder = interfaces + L"\\" + adapter;
            for (const std::wstring& file : ListEntries(folder + L"\\*.xml", false)) {
                std::wstring path = folder + L"\\" + file;
                std::wstring xml = ReadText(path, 4u * 1024u * 1024u);
                if (xml.empty()) continue;
                size_t ssidAt = xml.find(L"<SSID>");
                std::wstring ssid = ssidAt == std::wstring::npos
                                        ? L"" : TagText(xml, L"name", ssidAt);
                std::wstring profile = TagText(xml, L"name", 0);
                std::wstring auth = TagText(xml, L"authentication", 0);
                std::wstring encryption = TagText(xml, L"encryption", 0);
                bool hasKey = xml.find(L"<keyMaterial>") != std::wstring::npos;
                std::wstring detail = auth;
                if (!encryption.empty()) detail += L" / " + encryption;
                if (hasKey) detail += L" \u00B7 stored key";
                std::wstring extra;
                extra += L"Profile file  : " + path + L"\r\n";
                extra += L"Adapter folder: " + adapter + L"\r\n";
                extra += L"Profile name  : " + (profile.empty() ? L"-" : profile) + L"\r\n";
                extra += L"SSID          : " + (ssid.empty() ? L"-" : ssid) + L"\r\n";
                extra += L"Authentication: " + (auth.empty() ? L"-" : auth) + L"\r\n";
                extra += L"Encryption    : " + (encryption.empty() ? L"-" : encryption) + L"\r\n";
                extra += L"Key material  : " + std::wstring(hasKey ? L"present" : L"absent") + L"\r\n";
                extra += L"File size     : " + FileSizeOf(path) + L"\r\n";
                extra += L"Written       : " + LastWriteText(path) + L"\r\n";
                extra += L"\r\n--- profile XML (" + CommaNumber(xml.size()) + L" char(s)) ---\r\n" + xml;
                add(L"WLAN profile", ssid.empty() ? profile : ssid, detail, adapter,
                    LastWriteText(path), extra);
            }
        }
    }

    if (!stop.load()) {
        sink.Status(L"Reading network connection history\u2026", 85);
        fc::RegView view = fc::LiveHklm();
        std::wstring base = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles";
        for (const std::wstring& guid : view.Subkeys(base)) {
            if (stop.load()) break;
            std::wstring key = base + L"\\" + guid;
            std::wstring name = view.QueryString(key, L"ProfileName");
            std::wstring description = view.QueryString(key, L"Description");
            std::wstring category = view.QueryString(key, L"Category");
            std::vector<BYTE> created;
            std::vector<BYTE> connected;
            view.QueryBinary(key, L"DateCreated", created);
            view.QueryBinary(key, L"DateLastConnected", connected);
            std::wstring stamp = SystemTimeBlobText(connected);
            if (stamp.empty()) stamp = SystemTimeBlobText(created);
            std::wstring detail = description;
            if (!category.empty()) {
                if (!detail.empty()) detail += L" \u00B7 ";
                detail += L"category " + category;
            }
            std::wstring extra;
            extra += L"Registry key  : HKLM\\" + key + L"\r\n";
            extra += L"GUID          : " + guid + L"\r\n";
            extra += L"Created       : " + SystemTimeBlobText(created) + L"\r\n";
            extra += L"Last connected: " + SystemTimeBlobText(connected) + L"\r\n";
            extra += L"Key written   : " + view.LastWrite(key) + L"\r\n";
            extra += L"\r\n--- registry values ---\r\n";
            extra += DumpRegValues(view, key);
            add(L"Network history", name, detail, guid, stamp, extra);
        }
    }

    Flush(sink, rows, details);
    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s network artifact record(s) retained.", CommaNumber(total).c_str()));
    } else {
        sink.Done(Format(L"Completed. %s network artifact record(s).", CommaNumber(total).c_str()));
    }
}


std::wstring ExtractBinaryStrings(const std::vector<unsigned char>& data) {
    std::wstring out;
    size_t i = 0;
    while (i + 1 < data.size()) {
        if (data[i + 1] == 0 && data[i] >= 0x20 && data[i] < 0x7F) {
            std::wstring run;
            size_t j = i;
            while (j + 1 < data.size() && data[j + 1] == 0 && data[j] >= 0x20 && data[j] < 0x7F) {
                run += static_cast<wchar_t>(data[j]);
                j += 2;
            }
            if (run.size() >= 4) { out += run + L"\r\n"; i = j; continue; }
        }
        if (data[i] >= 0x20 && data[i] < 0x7F) {
            std::wstring run;
            size_t j = i;
            while (j < data.size() && data[j] >= 0x20 && data[j] < 0x7F) {
                run += static_cast<wchar_t>(data[j]);
                j++;
            }
            if (run.size() >= 4) { out += run + L"\r\n"; i = j; continue; }
        }
        i++;
    }
    return out;
}

void RunDefenderLogs(const Sink& sink, std::atomic<bool>& stop) {
    std::vector<Row> rows;
    std::vector<std::wstring> details;
    rows.reserve(256);
    details.reserve(256);
    unsigned long long total = 0;

    auto add = [&](const std::wstring& stamp, const std::wstring& source,
                   const std::wstring& kind, const std::wstring& title,
                   const std::wstring& detail, const std::wstring& summary = L"") {
        Row row;
        row.push_back(stamp.empty() ? L"-" : stamp);
        row.push_back(source);
        row.push_back(kind);
        row.push_back(title.empty() ? L"-" : (title.size() > 200 ? title.substr(0, 200) : title));
        std::wstring cell = summary.empty() ? detail : summary;
        row.push_back(cell.empty() ? L"-" : (cell.size() > 300 ? cell.substr(0, 300) : cell));
        rows.push_back(std::move(row));
        details.push_back(L"Time    : " + (stamp.empty() ? L"-" : stamp) + L"\r\n" +
                          L"Source  : " + source + L"\r\n" + L"Kind    : " + kind + L"\r\n" +
                          L"Title   : " + (title.empty() ? L"-" : title) + L"\r\n\r\n" + detail);
        ++total;
        if (rows.size() >= 128) Flush(sink, rows, details);
    };

    sink.Status(L"Reading Defender operational log\u2026", 15);
    const std::wstring channel = L"Microsoft-Windows-Windows Defender/Operational";
    QueryEvents(channel, 3000, stop, [&](const std::wstring& xml) {
        std::wstring id = EvtxElement(xml, L"EventID");
        std::vector<EvtxField> fields = EvtxDataFields(xml);

        std::wstring threat = FieldOfAny(fields, {L"Threat Name", L"ThreatName"});
        std::wstring severity = FieldOfAny(fields, {L"Severity Name", L"Severity"});
        std::wstring category = FieldOfAny(fields, {L"Category Name", L"Category"});
        std::wstring action = FieldOfAny(fields, {L"Action Name", L"Action"});
        std::wstring actionOk = FieldOfAny(fields, {L"Action Success", L"ActionSuccess"});
        std::wstring target = FieldOfAny(fields, {L"Path", L"Resource", L"Target Name", L"Target"});
        std::wstring process = FieldOfAny(fields, {L"Process Name", L"Process"});
        std::wstring user = FieldOfAny(fields, {L"Detection User", L"User Name", L"User"});
        std::wstring origin = FieldOfAny(fields, {L"Detection Origin", L"Origin"});
        std::wstring detectionType = FieldOfAny(fields, {L"Detection Type", L"Type"});
        std::wstring threatId = FieldOfAny(fields, {L"Threat ID", L"ThreatID"});
        std::wstring status = FieldOfAny(fields, {L"Execution Status", L"Status"});
        std::wstring errorCode = FieldOfAny(fields, {L"Execution Error Code", L"Error Code"});
        std::wstring product = FieldOfAny(fields, {L"Product Name"});
        std::wstring productVersion = FieldOfAny(fields, {L"Product Version"});
        std::wstring engine = FieldOfAny(fields, {L"Engine Version"});
        std::wstring signatures = FieldOfAny(fields, {L"Security intelligence Version", L"AV Signature Version"});
        std::wstring oldValue = FieldOfAny(fields, {L"Old Value"});
        std::wstring newValue = FieldOfAny(fields, {L"New Value"});
        std::wstring meaning = DefenderMeaning(id);

        std::wstring title = threat;
        if (title.empty()) title = target;
        if (title.empty()) title = product;
        if (title.empty()) title = meaning;
        if (title.empty()) title = EvtxDataText(xml);

        std::wstring detail;
        detail += L"--- what happened ---\r\n";
        detail += L"Event          : " + (id.empty() ? L"?" : id) + L"\r\n";
        detail += L"Meaning        : " + (meaning.empty() ? L"Defender event" : meaning) + L"\r\n";
        if (!threat.empty()) detail += L"Threat name    : " + threat + L"\r\n";
        if (!severity.empty()) detail += L"Severity       : " + severity + L"\r\n";
        if (!category.empty()) detail += L"Category       : " + category + L"\r\n";
        if (!detectionType.empty()) detail += L"Detection type : " + detectionType + L"\r\n";
        if (!origin.empty()) detail += L"Detection from : " + origin + L"\r\n";
        if (!action.empty()) detail += L"Action taken   : " + action + L"\r\n";
        if (!actionOk.empty()) detail += L"Action success : " + actionOk + L"\r\n";
        if (!status.empty()) detail += L"Execution state: " + status + L"\r\n";
        if (!errorCode.empty()) detail += L"Error code     : " + errorCode + L"\r\n";
        if (!target.empty()) detail += L"Target (path)  : " + target + L"\r\n";
        if (!process.empty()) detail += L"Process        : " + process + L"\r\n";
        if (!user.empty()) detail += L"User           : " + user + L"\r\n";
        if (!threatId.empty()) detail += L"Threat ID      : " + threatId + L"\r\n";
        if (!oldValue.empty()) detail += L"Old value      : " + oldValue + L"\r\n";
        if (!newValue.empty()) detail += L"New value      : " + newValue + L"\r\n";
        if (!product.empty()) {
            detail += L"Product        : " + product;
            if (!productVersion.empty()) detail += L" " + productVersion;
            detail += L"\r\n";
        }
        if (!engine.empty()) detail += L"Engine version : " + engine + L"\r\n";
        if (!signatures.empty()) detail += L"Signatures     : " + signatures + L"\r\n";
        detail += L"\r\n" + EvtxFullDetail(xml);
        std::wstring summary;
        if (!action.empty()) summary = L"Action: " + action;
        if (!target.empty()) {
            if (!summary.empty()) summary += L" \u00B7 ";
            summary += L"Target: " + target;
        }
        if (summary.empty()) summary = meaning;
        add(EvtxStamp(xml), L"Defender event", L"Event " + (id.empty() ? L"?" : id), title, detail,
            summary);
    });

    if (!stop.load()) {
        sink.Status(L"Reading Defender support folder\u2026", 65);
        std::wstring folder = ProgramData() + L"\\Microsoft\\Windows Defender\\Support";
        for (const std::wstring& file : ListEntries(folder + L"\\*", false)) {
            if (stop.load()) break;
            std::wstring path = folder + L"\\" + file;
            std::wstring stamp = LastWriteText(path);
            if (file.rfind(L"MPDetection", 0) == 0 || file.rfind(L"MPLog", 0) == 0 ||
                file.rfind(L"MPScanSkip", 0) == 0) {
                std::wstring text = ReadText(path, 64u * 1024u * 1024u);
                int lines = 0;
                for (const std::wstring& line : SplitLines(text)) {
                    if (stop.load()) break;
                    std::wstring trimmed = Trim(line);
                    if (trimmed.empty()) continue;
                    std::wstring when;
                    std::wstring message = trimmed;
                    if (trimmed.size() > 24 && trimmed[4] == L'-' && trimmed[10] == L'T') {
                        when = trimmed.substr(0, 23);
                        std::replace(when.begin(), when.end(), L'T', L' ');
                        message = Trim(trimmed.substr(23));
                    }
                    add(when, file, L"Support log", message.size() > 160 ? message.substr(0, 160) : message,
                        L"File    : " + path + L"\r\n" +
                        L"Size    : " + FileSizeOf(path) + L"\r\n" +
                        L"Written : " + stamp + L"\r\n" +
                        L"Line    : " + Format(L"%d", lines + 1) + L"\r\n\r\n" + message);
                    if (++lines >= 400) break;
                }
            } else {
                std::wstring detail;
                detail += L"File    : " + path + L"\r\n";
                detail += L"Size    : " + FileSizeOf(path) + L"\r\n";
                detail += L"Written : " + stamp + L"\r\n";
                std::vector<unsigned char> head;
                if (ReadHead(path, head, 8192)) {
                    std::wstring text = DecodeBytes(head.data(), head.size());
                    if (!text.empty()) {
                        detail += L"\r\n--- head (" + CommaNumber(head.size()) +
                                  L" byte(s)) ---\r\n" + text;
                    } else {
                        detail += L"\r\n--- head (hex) ---\r\n" + HexPreview(head, 512);
                    }
                }
                add(stamp, file, L"Support file", FileSizeOf(path), detail);
            }
        }
    }


    if (!stop.load()) {
        sink.Status(L"Reading Defender threat protection history...", 85);
        std::wstring history =
            ProgramData() + L"\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory";
        for (const std::wstring& threatId : ListEntries(history + L"\\*", true)) {
            if (stop.load()) break;
            std::wstring tdir = history + L"\\" + threatId;
            std::vector<std::wstring> files = ListEntries(tdir + L"\\*", false);
            if (files.empty()) continue;
            std::wstring logPath;
            for (const std::wstring& f : files) {
                if (f == L"ThreatLog.txt" || f == L"CrashLog.txt" ||
                    (f.size() >= 4 && (f.substr(f.size() - 4) == L".txt" || f.substr(f.size() - 4) == L".log"))) {
                    logPath = tdir + L"\\" + f;
                    break;
                }
            }
            std::wstring text;
            std::wstring source = L"Threat protection";
            if (!logPath.empty()) {
                text = ReadText(logPath, 4u * 1024u * 1024u);
            } else {
                logPath = tdir + L"\\" + files.front();
                std::vector<unsigned char> bin;
                if (ReadHead(logPath, bin, 1024u * 1024u) && !bin.empty()) {
                    text = ExtractBinaryStrings(bin);
                    source = L"Threat resource";
                }
            }
            if (text.empty()) text = L"(no readable log content)";
            std::wstring firstLine, tname, target, sha256, sha1, md5, tid, tsize, cmdline;
            std::vector<std::wstring> lines = SplitLines(text);
            auto grab = [&](const std::wstring& key, std::wstring& out) {
                for (size_t i = 0; i < lines.size(); ++i) {
                    std::wstring t = Trim(lines[i]);
                    if (t.empty()) continue;
                    if (t == key && i + 1 < lines.size()) { out = Trim(lines[i + 1]); return; }
                    if (t.size() > key.size() && t.compare(0, key.size(), key) == 0) {
                        out = Trim(t.substr(key.size())); return;
                    }
                }
            };
            grab(L"ThreatTrackingThreatName", tname);
            grab(L"ThreatTrackingSha256", sha256);
            grab(L"ThreatTrackingSha1", sha1);
            grab(L"ThreatTrackingMD5", md5);
            grab(L"ThreatTrackingId", tid);
            grab(L"ThreatTrackingSize", tsize);
            grab(L"file", target);
            grab(L"CmdLine", cmdline);
            grab(L"internalCmdLine", cmdline);
            // Fall back to a malware-classification line if no explicit name key.
            if (tname.empty()) {
                for (const std::wstring& line : lines) {
                    std::wstring t = Trim(line);
                    if (t.find(L":Win32/") != std::wstring::npos ||
                        t.find(L"Win32/") != std::wstring::npos ||
                        t.find(L"Trojan:") != std::wstring::npos ||
                        t.find(L"Misleading:") != std::wstring::npos ||
                        t.find(L"Virus:") != std::wstring::npos ||
                        t.find(L"Worm:") != std::wstring::npos ||
                        t.find(L"Backdoor:") != std::wstring::npos ||
                        t.find(L"Exploit:") != std::wstring::npos ||
                        t.find(L"Ransom:") != std::wstring::npos ||
                        t.find(L"HackTool:") != std::wstring::npos ||
                        t.find(L"Adware:") != std::wstring::npos) {
                        tname = t; break;
                    }
                }
            }
            for (const std::wstring& line : lines) {
                std::wstring t = Trim(line);
                if (firstLine.empty() && !t.empty()) firstLine = t;
            }
            std::wstring title = !tname.empty() ? tname : firstLine;
            std::wstring what;
            auto kv = [&](const std::wstring& k, const std::wstring& v) {
                if (!v.empty()) what += k + L" : " + v + L"\r\n";
            };
            kv(L"Threat name", tname);
            kv(L"Target file", target);
            kv(L"SHA256", sha256);
            kv(L"SHA1", sha1);
            kv(L"MD5", md5);
            kv(L"Size", tsize);
            kv(L"Tracking ID", tid);
            kv(L"Command line", cmdline);
            std::wstring extra;
            for (const std::wstring& f : files) {
                extra += L"\r\n" + f + L"  (" + FileSizeOf(tdir + L"\\" + f) + L")  written " + LastWriteText(tdir + L"\\" + f);
            }
            std::wstring detail = L"Threat ID      : " + threatId + L"\r\n" +
                                  L"History folder : " + tdir + L"\r\n" +
                                  L"Log file       : " + logPath + L"\r\n" +
                                  L"Size           : " + FileSizeOf(logPath) + L"\r\n" +
                                  L"Last written   : " + LastWriteText(logPath) + L"\r\n";
            if (!what.empty()) detail += L"\r\n--- what happened ---\r\n" + what;
            if (!extra.empty()) detail += L"\r\n--- related files ---" + extra + L"\r\n";
            detail += L"\r\n--- raw threat log ---\r\n" + text;
            std::wstring summ = L"Threat " + threatId;
            if (!title.empty()) summ += L" - " + title;
            add(LastWriteText(logPath), source, L"Threat " + threatId, title, detail, summ);
        }
    }

    Flush(sink, rows, details);
    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s Defender record(s) retained.", CommaNumber(total).c_str()));
    } else {
        sink.Done(Format(L"Completed. %s Defender record(s).", CommaNumber(total).c_str()));
    }
}

void RunActivitiesCache(const Sink& sink, std::atomic<bool>& stop) {
    std::wstring root = LocalAppData() + L"\\ConnectedDevicesPlatform";
    std::vector<std::wstring> databases;
    for (const std::wstring& folder : ListEntries(root + L"\\*", true)) {
        std::wstring candidate = root + L"\\" + folder + L"\\ActivitiesCache.db";
        if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
            databases.push_back(candidate);
        }
    }
    std::wstring direct = root + L"\\ActivitiesCache.db";
    if (GetFileAttributesW(direct.c_str()) != INVALID_FILE_ATTRIBUTES) databases.push_back(direct);

    if (databases.empty()) {
        sink.Done(L"No ActivitiesCache.db was found under " + root + L".");
        return;
    }

    std::vector<Row> rows;
    std::vector<std::wstring> details;
    rows.reserve(256);
    details.reserve(256);
    unsigned long long total = 0;
    std::wstring lastError;

    for (const std::wstring& database : databases) {
        if (stop.load()) break;
        sink.Status(L"Reading " + database + L"\u2026", 40);
        std::wstring copy = CopyDatabase(database);
        if (copy.empty()) {
            lastError = L"ActivitiesCache.db could not be copied for reading.";
            continue;
        }
        SqliteQuery(copy, "SELECT * FROM Activity ORDER BY StartTime DESC",
                    [&](sqlite3_stmt* statement) {
            if (stop.load()) return false;
            std::wstring appId = ColumnByName(statement, "AppId");
            long long start = 0;
            long long end = 0;
            long long modified = 0;
            int startIndex = ColumnIndex(statement, "StartTime");
            int endIndex = ColumnIndex(statement, "EndTime");
            int modifiedIndex = ColumnIndex(statement, "LastModifiedTime");
            int typeIndex = ColumnIndex(statement, "ActivityType");
            if (startIndex >= 0) start = Sqlite().column_int64(statement, startIndex);
            if (endIndex >= 0) end = Sqlite().column_int64(statement, endIndex);
            if (modifiedIndex >= 0) modified = Sqlite().column_int64(statement, modifiedIndex);
            std::wstring type = typeIndex >= 0
                                    ? Format(L"%lld", Sqlite().column_int64(statement, typeIndex))
                                    : L"";
            std::wstring payload = ColumnByName(statement, "Payload");
            std::wstring clipboard = ColumnByName(statement, "ClipboardPayload");

            std::wstring app = JsonText(appId, L"application");
            std::wstring title = JsonText(payload, L"displayText");
            std::wstring description = JsonText(payload, L"description");
            std::wstring appName = JsonText(payload, L"appDisplayName");
            std::wstring payloadType = JsonText(payload, L"type");
            long long activeSeconds = 0;
            size_t durationAt = payload.find(L"\"activeDurationSeconds\"");
            if (durationAt != std::wstring::npos) {
                size_t colon = payload.find(L':', durationAt);
                if (colon != std::wstring::npos) {
                    activeSeconds = wcstoll(payload.c_str() + colon + 1, nullptr, 10);
                }
            }
            std::wstring detailText = title.empty() ? description : title;
            if (!appName.empty()) detailText = appName + L" \u00B7 " + detailText;
            if (detailText.empty() && !payloadType.empty()) {
                detailText = payloadType;
                if (activeSeconds > 0) detailText += Format(L" \u00B7 %lld s", activeSeconds);
            }
            if (detailText.empty()) detailText = clipboard.empty() ? payload : clipboard;

            Row row;
            row.push_back(UnixText(start));
            row.push_back(app.empty() ? L"-" : app);
            row.push_back(detailText.size() > 400 ? detailText.substr(0, 400) : detailText);
            row.push_back(UnixText(end));
            row.push_back(type);
            row.push_back(PathFileName(database));
            rows.push_back(std::move(row));

            std::wstring detail;
            detail += L"Database : " + database + L"\r\n";
            detail += L"Start    : " + UnixText(start) + L"\r\n";
            detail += L"End      : " + UnixText(end) + L"\r\n";
            detail += L"Modified : " + UnixText(modified) + L"\r\n\r\n";
            detail += DumpColumns(statement);
            if (!payload.empty() || !clipboard.empty()) {
                detail += L"\r\n--- decoded payload ---\r\n";
                if (!payloadType.empty()) detail += L"type         : " + payloadType + L"\r\n";
                if (!appName.empty()) detail += L"appDisplayName: " + appName + L"\r\n";
                if (!title.empty()) detail += L"displayText  : " + title + L"\r\n";
                if (!description.empty()) detail += L"description  : " + description + L"\r\n";
                if (activeSeconds > 0) detail += Format(L"activeSeconds: %lld\r\n", activeSeconds);
            }
            details.push_back(std::move(detail));
            ++total;
            if (rows.size() >= 200) Flush(sink, rows, details);
            return true;
        }, lastError);
        RemoveCopy(copy);
    }

    Flush(sink, rows, details);
    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s activity record(s) retained.", CommaNumber(total).c_str()));
    } else if (total == 0 && !lastError.empty()) {
        sink.Error(lastError);
    } else {
        sink.Done(Format(L"Completed. %s activity record(s) from %s database(s).",
                         CommaNumber(total).c_str(), CommaNumber(databases.size()).c_str()));
    }
}

void RunCrashDumps(const Sink& sink, std::atomic<bool>& stop) {
    std::vector<std::wstring> patterns;
    patterns.push_back(WindowsFolder() + L"\\Minidump\\*.dmp");
    patterns.push_back(LocalAppData() + L"\\CrashDumps\\*.dmp");
    patterns.push_back(WindowsFolder() + L"\\LiveKernelReports\\*.dmp");
    patterns.push_back(WindowsFolder() + L"\\LiveKernelReports\\*\\*.dmp");

    std::vector<std::wstring> files;
    for (const std::wstring& pattern : patterns) {
        WIN32_FIND_DATAW fd{};
        HANDLE find = FindFirstFileW(pattern.c_str(), &fd);
        if (find == INVALID_HANDLE_VALUE) continue;
        std::wstring folder = pattern.substr(0, pattern.find_last_of(L'\\'));
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            files.push_back(folder + L"\\" + fd.cFileName);
        } while (FindNextFileW(find, &fd));
        FindClose(find);
    }
    std::wstring memoryDump = WindowsFolder() + L"\\MEMORY.DMP";
    if (GetFileAttributesW(memoryDump.c_str()) != INVALID_FILE_ATTRIBUTES) files.push_back(memoryDump);

    std::vector<Row> rows;
    std::vector<std::wstring> details;
    rows.reserve(64);
    details.reserve(64);
    unsigned long long total = 0;

    for (const std::wstring& path : files) {
        if (stop.load()) break;
        sink.Status(L"Reading " + PathFileName(path) + L"\u2026", 50);

        std::vector<unsigned char> data;
        std::wstring kind = L"Unknown";
        std::wstring crashTime;
        std::wstring module;
        std::wstring headerText;
        std::wstring streamText;

        if (ReadHead(path, data, 4096)) {
            if (data.size() >= 4 && data[0] == 'M' && data[1] == 'D' && data[2] == 'M' &&
                data[3] == 'P') {
                kind = L"User minidump";
                if (data.size() >= 0x20) {
                    auto read32 = [&](size_t at) {
                        return static_cast<unsigned int>(data[at]) |
                               (static_cast<unsigned int>(data[at + 1]) << 8) |
                               (static_cast<unsigned int>(data[at + 2]) << 16) |
                               (static_cast<unsigned int>(data[at + 3]) << 24);
                    };
                    unsigned int streams = read32(8);
                    unsigned int directory = read32(12);
                    unsigned int stamp = read32(0x14);
                    unsigned long long flags = static_cast<unsigned long long>(read32(0x18)) |
                                               (static_cast<unsigned long long>(read32(0x1C)) << 32);
                    crashTime = UnixText(static_cast<long long>(stamp));
                    headerText = Format(L"--- minidump header ---\r\n"
                                        L"Signature      : MDMP\r\n"
                                        L"Version        : 0x%08X\r\n"
                                        L"Streams        : %u\r\n"
                                        L"Directory RVA  : 0x%X\r\n"
                                        L"CheckSum       : 0x%08X\r\n"
                                        L"TimeDateStamp  : 0x%08X (%s)\r\n"
                                        L"Flags          : %s\r\n",
                                        read32(4), streams, directory, read32(0x10), stamp,
                                        crashTime.c_str(), DumpFlags(flags).c_str());
                }
            } else if (data.size() >= 8 && data[0] == 'P' && data[1] == 'A' && data[2] == 'G' &&
                       data[3] == 'E') {
                kind = L"Kernel dump";
                unsigned int pageSize = 0;
                unsigned int minor = 0;
                unsigned int major = 0;
                if (data.size() >= 0x20) {
                    auto read32 = [&](size_t at) {
                        return static_cast<unsigned int>(data[at]) |
                               (static_cast<unsigned int>(data[at + 1]) << 8) |
                               (static_cast<unsigned int>(data[at + 2]) << 16) |
                               (static_cast<unsigned int>(data[at + 3]) << 24);
                    };
                    major = read32(0x04);
                    minor = read32(0x08);
                    pageSize = read32(0x14);
                    headerText = Format(L"--- kernel dump header ---\r\n"
                                        L"Signature      : PAGE\r\n"
                                        L"Major version  : %u\r\n"
                                        L"Minor version  : %u\r\n"
                                        L"Page size      : %u\r\n",
                                        major, minor, pageSize);
                }
            }
        }

        if (kind == L"User minidump") {
            std::vector<unsigned char> full;
            if (ReadHead(path, full, 64ULL * 1024ULL * 1024ULL) && full.size() >= 0x20) {
                auto read32 = [&](size_t at) {
                    return static_cast<unsigned int>(full[at]) |
                           (static_cast<unsigned int>(full[at + 1]) << 8) |
                           (static_cast<unsigned int>(full[at + 2]) << 16) |
                           (static_cast<unsigned int>(full[at + 3]) << 24);
                };
                unsigned int streams = read32(8);
                unsigned int directory = read32(12);
                streamText = L"\r\n--- stream directory ---\r\n";
                for (unsigned int i = 0; i < streams && !stop.load(); ++i) {
                    size_t at = static_cast<size_t>(directory) + static_cast<size_t>(i) * 12;
                    if (at + 12 > full.size()) break;
                    unsigned int type = read32(at);
                    unsigned int size = read32(at + 4);
                    unsigned int rva = read32(at + 8);
                    streamText += Format(L"[%u] %-28s type %u  size %u  rva 0x%X\r\n", i,
                                         DumpStreamName(type).c_str(), type, size, rva);
                    if (type != 4 || rva + 8 > full.size()) continue;
                    unsigned int count = read32(static_cast<size_t>(rva));
                    if (count == 0) continue;
                    size_t moduleAt = static_cast<size_t>(rva) + 4;
                    if (moduleAt + 108 > full.size()) continue;
                    unsigned int nameRva = read32(moduleAt + 20);
                    if (nameRva + 4 > full.size()) continue;
                    unsigned int length = read32(static_cast<size_t>(nameRva));
                    size_t available = full.size() - static_cast<size_t>(nameRva) - 4;
                    if (length > available) length = static_cast<unsigned int>(available);
                    std::wstring name(reinterpret_cast<const wchar_t*>(full.data() + nameRva + 4),
                                      length / sizeof(wchar_t));
                    module = PathFileName(name);
                    break;
                }
            }
        }

        Row row;
        row.push_back(PathFileName(path));
        row.push_back(FileSizeOf(path));
        row.push_back(LastWriteText(path));
        row.push_back(kind);
        row.push_back(crashTime.empty() ? L"-" : crashTime);
        row.push_back(module.empty() ? L"-" : module);
        rows.push_back(std::move(row));

        std::wstring detail;
        detail += L"File        : " + path + L"\r\n";
        detail += L"Size        : " + FileSizeOf(path) + L"\r\n";
        detail += L"Written     : " + LastWriteText(path) + L"\r\n";
        detail += L"Kind        : " + kind + L"\r\n";
        detail += L"Crash time  : " + (crashTime.empty() ? L"-" : crashTime) + L"\r\n";
        detail += L"Module      : " + (module.empty() ? L"-" : module) + L"\r\n";
        if (!headerText.empty()) detail += L"\r\n" + headerText;
        if (!streamText.empty()) detail += streamText;
        details.push_back(std::move(detail));
        ++total;
        if (rows.size() >= 64) Flush(sink, rows, details);
    }

    Flush(sink, rows, details);
    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s crash dump(s) retained.", CommaNumber(total).c_str()));
    } else {
        sink.Done(Format(L"Completed. %s crash dump record(s).", CommaNumber(total).c_str()));
    }
}

std::wstring NotificationAppFallback(const std::wstring& handler) {
    if (handler.empty()) return L"";
    std::wstring value = handler;
    size_t bang = value.find(L'!');
    if (bang != std::wstring::npos) value = value.substr(0, bang);
    size_t underscore = value.find(L'_');
    if (underscore != std::wstring::npos) value = value.substr(0, underscore);
    if (value.empty()) value = handler;
    struct Known { const wchar_t* id; const wchar_t* name; };
    static const Known known[] = {
        {L"Microsoft.WindowsStore", L"Microsoft Store"},
        {L"Microsoft.Windows.ShellExperienceHost", L"Windows Shell"},
        {L"Microsoft.Windows.Cortana", L"Cortana"},
        {L"Microsoft.Windows.Search", L"Windows Search"},
        {L"Microsoft.Windows.Explorer", L"Windows Explorer"},
        {L"Microsoft.Windows.ContentDeliveryManager", L"Windows Spotlight"},
        {L"Microsoft.WindowsTerminal", L"Windows Terminal"},
        {L"Microsoft.XboxGamingOverlay", L"Xbox Game Bar"},
        {L"Microsoft.YourPhone", L"Phone Link"},
        {L"Microsoft.OutlookForWindows", L"Outlook"},
        {L"Microsoft.People", L"People"},
        {L"Microsoft.MicrosoftEdge", L"Microsoft Edge"},
        {L"MicrosoftTeams", L"Microsoft Teams"},
        {L"Microsoft.WindowsCalculator", L"Calculator"},
        {L"Microsoft.WindowsAlarms", L"Alarms & Clock"},
        {L"Microsoft.WindowsCamera", L"Camera"},
        {L"Microsoft.ZuneMusic", L"Media Player"},
        {L"Microsoft.ZuneVideo", L"Movies & TV"},
        {L"Microsoft.Windows.Photos", L"Photos"},
        {L"Microsoft.WindowsNotepad", L"Notepad"},
        {L"Microsoft.Paint", L"Paint"},
        {L"Microsoft.ScreenSketch", L"Snipping Tool"},
        {L"Microsoft.GetHelp", L"Get Help"},
        {L"Microsoft.WindowsFeedbackHub", L"Feedback Hub"},
        {L"Microsoft.Windows.SecHealthUI", L"Windows Security"},
        {L"Microsoft.Windows.Defender", L"Windows Security"},
        {L"Windows.SystemToast.SecurityAndMaintenance", L"Security and Maintenance"},
        {L"Windows.SystemToast.WindowsUpdate", L"Windows Update"},
        {L"Windows.SystemToast.Backup", L"Backup"},
        {L"Windows.SystemToast.Suggested", L"Windows Tips"},
        {L"Windows.SystemToast.DeviceSetup", L"Device Setup"},
        {L"Windows.SystemToast.CapabilityAccessManager", L"Privacy settings"},
        {L"Windows.SystemToast.LowDisk", L"Low disk space"},
        {L"Windows.SystemToast.StorageSense", L"Storage Sense"},
    };
    for (const Known& entry : known) {
        if (_wcsicmp(value.c_str(), entry.id) == 0) return entry.name;
    }
    return value;
}

std::wstring NotificationAppDisplay(const std::wstring& handler) {
    std::wstring fallback = NotificationAppFallback(handler);
    if (handler.empty()) return fallback;
    wchar_t buffer[512] = {};
    DWORD size = sizeof(buffer);
    std::wstring key = L"Software\\Classes\\AppUserModelId\\" + handler;
    if (RegGetValueW(HKEY_CURRENT_USER, key.c_str(), L"DisplayName", RRF_RT_REG_SZ, nullptr, buffer,
                     &size) == ERROR_SUCCESS) {
        std::wstring value = buffer;
        if (!value.empty() && value[0] != L'@') return value;
    }
    return fallback;
}

std::wstring TagAttribute(const std::wstring& xml, const std::wstring& tag,
                          const std::wstring& attribute, size_t from) {
    std::wstring open = L"<" + tag;
    size_t at = xml.find(open, from);
    if (at == std::wstring::npos) return L"";
    size_t tagEnd = xml.find(L'>', at);
    if (tagEnd == std::wstring::npos) return L"";
    std::wstring head = xml.substr(at, tagEnd - at);
    std::wstring needle = L" " + attribute + L"=\"";
    size_t pos = head.find(needle);
    if (pos == std::wstring::npos) return L"";
    pos += needle.size();
    size_t close = head.find(L'"', pos);
    if (close == std::wstring::npos) return L"";
    return head.substr(pos, close - pos);
}

long long UnixSeconds(long long value) {
    if (value > 116444736000000000LL) return (value - 116444736000000000LL) / 10000000LL;
    if (value > 100000000000LL) return value / 1000;
    if (value > 1000000000LL) return value;
    return 0;
}

long long NowUnixSeconds() {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER value{};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return static_cast<long long>(value.QuadPart / 10000000ULL) - 11644473600LL;
}

void RunNotificationDatabase(const Sink& sink, std::atomic<bool>& stop) {
    std::vector<Row> rows;
    std::vector<std::wstring> details;
    rows.reserve(256);
    details.reserve(256);
    unsigned long long total = 0;
    unsigned long long activeCount = 0;
    unsigned long long handlerCount = 0;
    std::wstring error;

    auto add = [&](const std::wstring& stamp, const std::wstring& app,
                   const std::wstring& title, const std::wstring& body,
                   const std::wstring& kind, const std::wstring& status,
                   const std::wstring& detail) {
        Row row;
        row.push_back(stamp.empty() ? L"-" : stamp);
        row.push_back(app.empty() ? L"-" : app);
        row.push_back(title.empty() ? L"-" : title);
        std::wstring preview = body;
        if (preview.size() > 300) preview = preview.substr(0, 300) + L"\u2026";
        row.push_back(preview.empty() ? L"-" : preview);
        row.push_back(kind.empty() ? L"-" : kind);
        row.push_back(status.empty() ? L"-" : status);
        rows.push_back(std::move(row));
        details.push_back(detail);
        ++total;
        if (rows.size() >= 200) Flush(sink, rows, details);
    };

    std::wstring database = LocalAppData() + L"\\Microsoft\\Windows\\Notifications\\wpndatabase.db";
    if (GetFileAttributesW(database.c_str()) == INVALID_FILE_ATTRIBUTES) {
        sink.Done(L"No wpndatabase.db was found at " + database + L".");
        return;
    }

    sink.Status(L"Reading notification database\u2026", 40);
    std::wstring copy = CopyDatabase(database);
    if (copy.empty()) {
        sink.Error(L"wpndatabase.db could not be copied for reading.");
        return;
    }

    SqliteQuery(copy,
                "SELECT n.*, h.PrimaryId AS HandlerPrimaryId, h.HandlerType AS HandlerKind "
                "FROM Notification n LEFT JOIN NotificationHandler h ON n.HandlerId = h.RecordId "
                "ORDER BY n.ArrivalTime DESC",
                [&](sqlite3_stmt* statement) {
        if (stop.load()) return false;
        long long arrival = 0;
        int arrivalIndex = ColumnIndex(statement, "ArrivalTime");
        if (arrivalIndex >= 0) arrival = Sqlite().column_int64(statement, arrivalIndex);
        long long expiry = 0;
        int expiryIndex = ColumnIndex(statement, "ExpiryTime");
        if (expiryIndex >= 0) expiry = Sqlite().column_int64(statement, expiryIndex);
        std::wstring type = ColumnByName(statement, "Type");
        std::wstring payload = ColumnByName(statement, "Payload");
        std::wstring handler = ColumnByName(statement, "HandlerPrimaryId");
        std::wstring handlerKind = ColumnByName(statement, "HandlerKind");
        std::wstring group = ColumnByName(statement, "Group");
        std::wstring tag = ColumnByName(statement, "Tag");

        // Every <text> element is a line of the toast body: the first is the title.
        std::vector<std::wstring> texts;
        size_t scan = 0;
        while (true) {
            size_t pos = payload.find(L"<text", scan);
            if (pos == std::wstring::npos) break;
            std::wstring value = CleanText(TagText(payload, L"text", pos));
            if (!value.empty()) texts.push_back(value);
            scan = pos + 5;
        }
        std::wstring title = texts.empty() ? L"" : texts.front();
        std::wstring body;
        for (size_t i = 1; i < texts.size(); ++i) {
            if (!body.empty()) body += L" ";
            body += texts[i];
        }
        if (title.empty() && !body.empty()) {
            title = body;
            body.clear();
        }

        std::wstring image = TagAttribute(payload, L"image", L"src", 0);
        std::wstring audio = TagAttribute(payload, L"audio", L"src", 0);
        std::wstring scenario = TagAttribute(payload, L"toast", L"scenario", 0);
        std::wstring launch = TagAttribute(payload, L"toast", L"launch", 0);

        std::wstring app = NotificationAppDisplay(handler);
        if (app.empty()) app = handler.empty() ? L"(unknown app)" : handler;

        std::wstring status;
        if (expiry > 0) {
            status = UnixSeconds(expiry) > NowUnixSeconds() ? L"Active" : L"Expired";
        } else {
            status = L"Active";
        }
        if (status == L"Active") ++activeCount;

        std::wstring detail;
        detail += L"Application : " + app + L"\r\n";
        if (!handler.empty()) detail += L"App id      : " + handler + L"\r\n";
        detail += L"Arrived     : " + UnixText(arrival) + L"\r\n";
        detail += L"Expires     : " + UnixText(expiry) + L"\r\n";
        detail += L"Status      : " + status + L"\r\n";
        if (!type.empty()) detail += L"Type        : " + type + L"\r\n";
        if (!handlerKind.empty()) detail += L"Handler     : " + handlerKind + L"\r\n";
        if (!group.empty()) detail += L"Group       : " + group + L"\r\n";
        if (!tag.empty()) detail += L"Tag         : " + tag + L"\r\n";
        if (!scenario.empty()) detail += L"Scenario    : " + scenario + L"\r\n";
        if (!launch.empty()) detail += L"Launch arg  : " + launch + L"\r\n";
        if (!image.empty()) detail += L"Image       : " + image + L"\r\n";
        if (!audio.empty()) detail += L"Audio       : " + audio + L"\r\n";
        if (!texts.empty()) {
            detail += L"\r\n--- text lines ---\r\n";
            for (size_t i = 0; i < texts.size(); ++i) {
                detail += Format(L"[%zu] %s\r\n", i + 1, texts[i].c_str());
            }
        }
        std::wstring actions;
        size_t actionAt = 0;
        while (true) {
            size_t pos = payload.find(L"<action", actionAt);
            if (pos == std::wstring::npos) break;
            std::wstring content = TagAttribute(payload, L"action", L"content", pos);
            std::wstring arguments = TagAttribute(payload, L"action", L"arguments", pos);
            if (!content.empty()) {
                actions += L"  \u2022 " + content;
                if (!arguments.empty()) actions += L"  (" + arguments + L")";
                actions += L"\r\n";
            }
            actionAt = pos + 7;
        }
        if (!actions.empty()) detail += L"\r\n--- actions ---\r\n" + actions;
        detail += L"\r\n--- notification record (all columns) ---\r\n";
        detail += DumpColumns(statement);
        if (!payload.empty()) {
            detail += L"\r\n--- payload (" + CommaNumber(payload.size()) + L" char(s)) ---\r\n";
            detail += payload;
        }
        add(UnixText(arrival), app, title, body, type.empty() ? L"Notification" : type, status, detail);
        return true;
    }, error);
    RemoveCopy(copy);

    if (!stop.load()) {
        sink.Status(L"Reading registered notification apps\u2026", 70);
        std::wstring handlerCopy = CopyDatabase(database);
        if (!handlerCopy.empty()) {
            SqliteQuery(handlerCopy,
                        "SELECT * FROM NotificationHandler ORDER BY ModifiedTime DESC",
                        [&](sqlite3_stmt* statement) {
                if (stop.load()) return false;
                std::wstring primary = ColumnByName(statement, "PrimaryId");
                std::wstring type = ColumnByName(statement, "HandlerType");
                long long modified = 0;
                int modifiedIndex = ColumnIndex(statement, "ModifiedTime");
                if (modifiedIndex >= 0) modified = Sqlite().column_int64(statement, modifiedIndex);

                std::wstring app = NotificationAppDisplay(primary);
                if (app.empty()) app = primary.empty() ? L"(unknown app)" : primary;
                std::wstring detail;
                detail += L"Application : " + app + L"\r\n";
                if (!primary.empty()) detail += L"App id      : " + primary + L"\r\n";
                if (!type.empty()) detail += L"Handler     : " + type + L"\r\n";
                detail += L"Modified    : " + UnixText(modified) + L"\r\n";
                detail += L"Database    : " + database + L"\r\n\r\n";
                detail += L"--- handler record (all columns) ---\r\n";
                detail += DumpColumns(statement);
                add(UnixText(modified), app, L"Registered notification app",
                    type.empty() ? L"Notification handler" : type, L"Registered app", L"-", detail);
                ++handlerCount;
                return true;
            }, error);
            RemoveCopy(handlerCopy);
        }
    }

    Flush(sink, rows, details);
    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s notification record(s) retained.", CommaNumber(total).c_str()));
    } else if (total == 0 && !error.empty()) {
        sink.Error(error);
    } else {
        sink.Done(Format(L"Completed. %s notification(s), %s still active, %s registered app(s).",
                         CommaNumber(total - handlerCount).c_str(),
                         CommaNumber(activeCount).c_str(),
                         CommaNumber(handlerCount).c_str()));
    }
}
