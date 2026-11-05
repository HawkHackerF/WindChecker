#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include "artifacts.h"

#include <shlobj.h>

#include <algorithm>
#include <cstring>

namespace {

unsigned int ReadU32(const unsigned char* data) {
    return static_cast<unsigned int>(data[0]) |
           (static_cast<unsigned int>(data[1]) << 8) |
           (static_cast<unsigned int>(data[2]) << 16) |
           (static_cast<unsigned int>(data[3]) << 24);
}

unsigned long long ReadU64(const unsigned char* data) {
    return static_cast<unsigned long long>(ReadU32(data)) |
           (static_cast<unsigned long long>(ReadU32(data + 4)) << 32);
}

unsigned int ReadU32BE(const unsigned char* data) {
    return (static_cast<unsigned int>(data[0]) << 24) |
           (static_cast<unsigned int>(data[1]) << 16) |
           (static_cast<unsigned int>(data[2]) << 8) |
           static_cast<unsigned int>(data[3]);
}

std::wstring ThumbcacheFolder() {
    PWSTR path = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path)) || !path) return L"";
    std::wstring folder = std::wstring(path) + L"\\Microsoft\\Windows\\Explorer";
    CoTaskMemFree(path);
    return folder;
}

bool ReadFileBytes(const std::wstring& path, std::vector<unsigned char>& out, size_t limit) {
    out.clear();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        static_cast<unsigned long long>(size.QuadPart) > limit) {
        CloseHandle(file);
        return false;
    }
    out.resize(static_cast<size_t>(size.QuadPart));
    size_t read = 0;
    while (read < out.size()) {
        DWORD chunk = 0;
        DWORD want = static_cast<DWORD>(std::min<size_t>(out.size() - read, 1u << 20));
        if (!ReadFile(file, out.data() + read, want, &chunk, nullptr) || chunk == 0) break;
        read += chunk;
    }
    CloseHandle(file);
    out.resize(read);
    return !out.empty();
}

std::wstring IdentifierText(const unsigned char* data, unsigned int size) {
    if (size == 0) return L"(empty)";
    if ((size % 2) == 0 && size >= 4) {
        std::wstring text;
        text.reserve(size / 2);
        size_t printable = 0;
        for (unsigned int i = 0; i + 1 < size; i += 2) {
            wchar_t ch = static_cast<wchar_t>(data[i] | (data[i + 1] << 8));
            text.push_back(ch);
            if (ch >= 0x20 && ch != 0x7F) ++printable;
        }
        while (!text.empty() && text.back() == L'\0') text.pop_back();
        if (!text.empty() && printable * 10 >= text.size() * 8) return text;
    }
    std::wstring hex;
    unsigned int shown = std::min<unsigned int>(size, 32);
    wchar_t buffer[8] = {};
    for (unsigned int i = 0; i < shown; ++i) {
        swprintf_s(buffer, L"%02X", data[i]);
        hex += buffer;
        if (i + 1 < shown) hex += L' ';
    }
    if (size > shown) hex += L" \u2026";
    return hex;
}

std::wstring FormatText(const unsigned char* data, size_t size) {
    if (size >= 2 && data[0] == 'B' && data[1] == 'M') return L"BMP";
    if (size >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) return L"JPEG";
    if (size >= 8 && data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G')
        return L"PNG";
    if (size >= 3 && data[0] == 'G' && data[1] == 'I' && data[2] == 'F') return L"GIF";
    if (size >= 4 && ((data[0] == 'I' && data[1] == 'I') || (data[0] == 'M' && data[1] == 'M')) &&
        (data[2] == 0x2A || data[2] == 0x2B)) {
        return L"TIFF";
    }
    if (size >= 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01 && data[3] == 0x00)
        return L"ICO";
    if (size >= 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x02 && data[3] == 0x00)
        return L"CUR";
    if (size >= 12 && data[0] == 'R' && data[1] == 'I' && data[2] == 'F' && data[3] == 'F')
        return L"WEBP";
    return L"binary";
}

std::wstring DimensionsText(const unsigned char* data, size_t size, const std::wstring& format) {
    long long width = 0;
    long long height = 0;
    if (format == L"BMP" && size >= 26) {
        width = static_cast<int>(ReadU32(data + 18));
        height = static_cast<int>(ReadU32(data + 22));
        if (height < 0) height = -height;
    } else if (format == L"PNG" && size >= 24) {
        width = ReadU32BE(data + 16);
        height = ReadU32BE(data + 20);
    } else if (format == L"GIF" && size >= 10) {
        width = data[6] | (data[7] << 8);
        height = data[8] | (data[9] << 8);
    } else if (format == L"JPEG") {
        size_t at = 2;
        while (at + 9 < size) {
            if (data[at] != 0xFF) { ++at; continue; }
            unsigned char marker = data[at + 1];
            if (marker == 0xD8 || marker == 0xD9 || (marker >= 0xD0 && marker <= 0xD7)) {
                at += 2;
                continue;
            }
            size_t length = (data[at + 2] << 8) | data[at + 3];
            if (length < 2) break;
            if ((marker >= 0xC0 && marker <= 0xC3) || (marker >= 0xC5 && marker <= 0xC7) ||
                (marker >= 0xC9 && marker <= 0xCB) || (marker >= 0xCD && marker <= 0xCF)) {
                if (at + 9 < size) {
                    height = (data[at + 5] << 8) | data[at + 6];
                    width = (data[at + 7] << 8) | data[at + 8];
                }
                break;
            }
            at += 2 + length;
        }
    } else if (format == L"ICO" || format == L"CUR") {
        if (size >= 8) {
            width = data[6] == 0 ? 256 : data[6];
            height = data[7] == 0 ? 256 : data[7];
        }
    }
    if (width <= 0 || height <= 0) return L"-";
    return Format(L"%lld \u00D7 %lld", width, height);
}

std::wstring HexPreview(const unsigned char* data, size_t size, size_t limit) {
    std::wstring text;
    size_t shown = std::min(size, limit);
    wchar_t buffer[8] = {};
    for (size_t i = 0; i < shown; ++i) {
        if (i && (i % 16) == 0) text += L"\r\n";
        else if (i) text += L' ';
        swprintf_s(buffer, L"%02X", data[i]);
        text += buffer;
    }
    return text;
}

bool DecodeEntry(const std::wstring& cacheName, const std::wstring& cachePath,
                 const unsigned char* entry, unsigned long long offset, Row& row,
                 std::wstring& detail) {
    unsigned int entrySize = ReadU32(entry + 4);
    unsigned int identifierSize = ReadU32(entry + 0x10);
    unsigned int dataSize = ReadU32(entry + 0x18);
    unsigned int headerWidth = ReadU32(entry + 0x1C);
    unsigned int headerHeight = ReadU32(entry + 0x20);
    unsigned long long hash = ReadU64(entry + 8);
    if (entrySize < 0x38 || identifierSize > entrySize || dataSize > entrySize) return false;

    const unsigned char* identifier = entry + 0x38;
    const unsigned char* image = identifier + identifierSize;
    std::wstring label = IdentifierText(identifier, identifierSize);
    std::wstring format = dataSize > 0 ? FormatText(image, dataSize) : L"(none)";
    std::wstring dimensions = dataSize > 0 ? DimensionsText(image, dataSize, format) : L"-";

    row.clear();
    row.push_back(cacheName);
    row.push_back(label);
    row.push_back(format);
    row.push_back(dimensions);
    row.push_back(SizeText(dataSize));
    row.push_back(SizeText(entrySize));
    row.push_back(Format(L"0x%llX", offset));

    detail = L"Cache file   : " + cachePath + L"\r\n";
    detail += L"Entry offset : " + Format(L"0x%llX", offset) + L"\r\n";
    detail += L"Identifier   : " + label + L"\r\n";
    detail += Format(L"Entry size   : %s bytes\r\n", CommaNumber(entrySize).c_str());
    detail += Format(L"Data size    : %s bytes\r\n", CommaNumber(dataSize).c_str());
    detail += L"Format       : " + format + L"\r\n";
    detail += L"Dimensions   : " + dimensions;
    if (headerWidth > 0 && headerHeight > 0) {
        detail += Format(L" (header %u \u00D7 %u)", headerWidth, headerHeight);
    }
    detail += L"\r\n";
    detail += Format(L"Entry hash   : 0x%016llX\r\n", hash);
    if (dataSize > 0) {
        detail += L"\r\n--- first bytes ---\r\n";
        detail += HexPreview(image, dataSize, 128);
    }
    return true;
}

void FlushRows(const Sink& sink, std::vector<Row>& rows, std::vector<std::wstring>& details) {
    if (rows.empty()) return;
    sink.Detailed(std::move(rows), std::move(details), false);
    rows.clear();
    details.clear();
    rows.reserve(256);
    details.reserve(256);
}

}

void RunThumbcacheScan(const Sink& sink, std::atomic<bool>& stop) {
    std::wstring folder = ThumbcacheFolder();
    if (folder.empty()) {
        sink.Error(L"The Local AppData thumbnail cache folder could not be resolved.");
        return;
    }

    std::vector<std::wstring> files;
    WIN32_FIND_DATAW fd{};
    HANDLE find = FindFirstFileW((folder + L"\\thumbcache_*.db").c_str(), &fd);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) files.push_back(fd.cFileName);
        } while (FindNextFileW(find, &fd));
        FindClose(find);
    }
    std::sort(files.begin(), files.end());

    if (files.empty()) {
        sink.Done(L"No thumbcache_*.db file was found in " + folder + L".");
        return;
    }

    std::vector<Row> rows;
    std::vector<std::wstring> details;
    rows.reserve(256);
    details.reserve(256);

    unsigned long long total = 0;
    int fileIndex = 0;
    for (const std::wstring& name : files) {
        if (stop.load()) break;
        ++fileIndex;
        sink.Status(Format(L"%s \u00B7 cache %d/%d \u00B7 %s entries",
                           name.c_str(), fileIndex, static_cast<int>(files.size()),
                           CommaNumber(total).c_str()),
                    fileIndex * 100 / static_cast<int>(files.size()));

        std::wstring path = folder + L"\\" + name;
        std::vector<unsigned char> data;
        if (!ReadFileBytes(path, data, 512ULL * 1024ULL * 1024ULL)) continue;

        unsigned long long offset = 0x18;
        unsigned long long fileEntries = 0;
        while (offset + 0x38 <= data.size() && !stop.load()) {
            const unsigned char* entry = data.data() + offset;
            if (std::memcmp(entry, "CMMM", 4) != 0) {
                unsigned long long scan = offset + 8;
                bool resynced = false;
                while (scan + 0x38 <= data.size()) {
                    if (std::memcmp(data.data() + scan, "CMMM", 4) == 0) {
                        offset = scan;
                        resynced = true;
                        break;
                    }
                    scan += 8;
                }
                if (!resynced) break;
                continue;
            }
            Row row;
            std::wstring detail;
            if (!DecodeEntry(name, path, entry, offset, row, detail)) break;
            rows.push_back(std::move(row));
            details.push_back(std::move(detail));
            ++total;
            ++fileEntries;
            unsigned int entrySize = ReadU32(entry + 4);
            offset = (offset + entrySize + 7) & ~7ULL;
            if (rows.size() >= 200) FlushRows(sink, rows, details);
        }
        if (fileEntries == 0) {
            Row row;
            row.push_back(name);
            row.push_back(L"(no thumbnail entries)");
            row.push_back(L"-");
            row.push_back(L"-");
            row.push_back(SizeText(data.size()));
            row.push_back(L"-");
            row.push_back(L"-");
            rows.push_back(std::move(row));
            details.push_back(L"Cache file : " + path + L"\r\nEntries    : 0\r\nFile size  : " +
                              SizeText(data.size()));
        }
    }
    FlushRows(sink, rows, details);

    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s thumbnail records retained from %s cache file(s).",
                         CommaNumber(total).c_str(), CommaNumber(files.size()).c_str()));
    } else {
        sink.Done(Format(L"Completed. %s thumbnail records read from %s cache file(s) in %s.",
                         CommaNumber(total).c_str(), CommaNumber(files.size()).c_str(),
                         folder.c_str()));
    }
}

bool ReadThumbcacheImage(const std::wstring& cachePath, unsigned long long entryOffset,
                         std::vector<unsigned char>& data) {
    data.clear();
    HANDLE file = CreateFileW(cachePath.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    unsigned char header[0x38] = {};
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(entryOffset);
    if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) {
        CloseHandle(file);
        return false;
    }
    DWORD read = 0;
    if (!ReadFile(file, header, sizeof(header), &read, nullptr) || read != sizeof(header) ||
        std::memcmp(header, "CMMM", 4) != 0) {
        CloseHandle(file);
        return false;
    }

    unsigned int identifierSize = ReadU32(header + 0x10);
    unsigned int dataSize = ReadU32(header + 0x18);
    if (dataSize == 0 || dataSize > 64u * 1024u * 1024u) {
        CloseHandle(file);
        return false;
    }

    position.QuadPart = static_cast<LONGLONG>(entryOffset + 0x38 + identifierSize);
    if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) {
        CloseHandle(file);
        return false;
    }
    data.resize(dataSize);
    size_t done = 0;
    while (done < data.size()) {
        DWORD chunk = 0;
        DWORD want = static_cast<DWORD>(std::min<size_t>(data.size() - done, 1u << 20));
        if (!ReadFile(file, data.data() + done, want, &chunk, nullptr) || chunk == 0) break;
        done += chunk;
    }
    CloseHandle(file);
    data.resize(done);
    return !data.empty();
}
