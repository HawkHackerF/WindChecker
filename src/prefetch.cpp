#include "artifacts.h"

#include <algorithm>
#include <cstring>

typedef LONG NTSTATUS;

extern "C" {
NTSTATUS NTAPI RtlGetCompressionWorkSpaceSize(USHORT format, PULONG workspace, PULONG fragment);
NTSTATUS NTAPI RtlDecompressBufferEx(USHORT format, PUCHAR target, ULONG targetSize,
                                    PUCHAR source, ULONG sourceSize, PULONG finalSize,
                                    PVOID workspace);
}

namespace {

constexpr USHORT kXpressHuff = 0x0004;

struct PrefetchFile {
    std::wstring path;
    std::wstring name;
    FILETIME modified{};
};

uint32_t U32(const std::vector<BYTE>& data, size_t offset) {
    if (offset + 4 > data.size()) return 0;
    uint32_t value = 0;
    std::memcpy(&value, data.data() + offset, sizeof(value));
    return value;
}

uint64_t U64(const std::vector<BYTE>& data, size_t offset) {
    if (offset + 8 > data.size()) return 0;
    uint64_t value = 0;
    std::memcpy(&value, data.data() + offset, sizeof(value));
    return value;
}

std::wstring Utf16(const BYTE* data, size_t bytes) {
    if (!data || bytes < 2) return L"";
    std::wstring text(reinterpret_cast<const wchar_t*>(data), bytes / sizeof(wchar_t));
    size_t null = text.find(L'\0');
    if (null != std::wstring::npos) text.resize(null);
    return text;
}

std::wstring FileTimeFromU64(uint64_t value) {
    if (!value) return L"";
    FILETIME ft{};
    ft.dwLowDateTime = static_cast<DWORD>(value & 0xFFFFFFFFULL);
    ft.dwHighDateTime = static_cast<DWORD>(value >> 32);
    return FileTimeText(ft);
}

uint64_t FileTimeKey(const FILETIME& value) {
    ULARGE_INTEGER large{};
    large.LowPart = value.dwLowDateTime;
    large.HighPart = value.dwHighDateTime;
    return large.QuadPart;
}

bool ReadFileBytes(const std::wstring& path, std::vector<BYTE>& data, size_t maximum) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        static_cast<unsigned long long>(size.QuadPart) > maximum) {
        CloseHandle(file);
        return false;
    }
    data.resize(static_cast<size_t>(size.QuadPart));
    size_t done = 0;
    while (done < data.size()) {
        DWORD read = 0;
        DWORD want = static_cast<DWORD>(std::min<size_t>(data.size() - done, 1u << 20));
        if (!ReadFile(file, data.data() + done, want, &read, nullptr) || read == 0) break;
        done += read;
    }
    CloseHandle(file);
    data.resize(done);
    return done > 0;
}

bool DecompressPrefetch(const std::vector<BYTE>& raw, std::vector<BYTE>& image,
                        bool& compressed, std::wstring& error) {
    compressed = false;
    if (raw.size() >= 8 && std::memcmp(raw.data(), "MAM\x04", 4) == 0) {
        uint32_t expected = 0;
        std::memcpy(&expected, raw.data() + 4, sizeof(expected));
        if (expected == 0 || expected > 256u * 1024u * 1024u) {
            error = L"Invalid MAM uncompressed size";
            return false;
        }
        ULONG workspaceSize = 0;
        ULONG fragmentSize = 0;
        NTSTATUS status = RtlGetCompressionWorkSpaceSize(kXpressHuff,
                                                         &workspaceSize, &fragmentSize);
        if (status < 0) {
            error = Format(L"Work-space query failed (NTSTATUS 0x%08X)",
                           static_cast<unsigned int>(status));
            return false;
        }
        image.resize(expected);
        std::vector<BYTE> workspace(workspaceSize > 0 ? workspaceSize : 1);
        ULONG finalSize = 0;
        status = RtlDecompressBufferEx(kXpressHuff,
                                       image.data(), static_cast<ULONG>(image.size()),
                                       const_cast<PUCHAR>(raw.data() + 8),
                                       static_cast<ULONG>(raw.size() - 8),
                                       &finalSize, workspace.data());
        if (status < 0) {
            error = Format(L"XPRESS-Huffman decompression failed (NTSTATUS 0x%08X)",
                           static_cast<unsigned int>(status));
            return false;
        }
        image.resize(finalSize);
        compressed = true;
        return true;
    }
    if (raw.size() >= 8 && std::memcmp(raw.data() + 4, "SCCA", 4) == 0) {
        image = raw;
        return true;
    }
    error = L"Not a Windows prefetch file";
    return false;
}

std::wstring PrefetchVersionName(uint32_t version) {
    switch (version) {
    case 17: return L"Windows XP / Vista / 7";
    case 23: return L"Windows 8 / 8.1";
    case 26: return L"Windows 10 (early)";
    case 30: return L"Windows 10 / 11";
    default: return L"unknown build";
    }
}

bool ParsePrefetchImage(std::vector<BYTE> data, bool compressed,
                        std::vector<Row>& details, std::wstring& error) {
    if (data.size() < 0xA4 || std::memcmp(data.data() + 4, "SCCA", 4) != 0) {
        error = L"Missing SCCA signature";
        return false;
    }
    uint32_t version = U32(data, 0);
    std::wstring executable = Utf16(data.data() + 0x10, 60);
    uint32_t fileSize = U32(data, 0x0C);
    uint32_t digest = U32(data, 0x4C);

    DWORD metricsOffset = 0, traceOffset = 0, stringsOffset = 0, volumesOffset = 0;
    DWORD runsOffset = 0, runCountOffset = 0, metricSize = 0;
    if (version >= 23) {
        metricsOffset = 0x54;
        traceOffset = 0x5C;
        stringsOffset = 0x64;
        volumesOffset = 0x6C;
        runsOffset = 0x80;
        runCountOffset = 0xD0;
        metricSize = 32;
    } else {
        metricsOffset = 0x80;
        traceOffset = 0x88;
        stringsOffset = 0x90;
        volumesOffset = 0x98;
        runsOffset = 0x60;
        runCountOffset = 0x6C;
        metricSize = 20;
    }

    auto add = [&](const std::wstring& category, const std::wstring& field,
                   const std::wstring& value) {
        details.push_back(Row{category, field, value});
    };

    add(L"Header", L"Version", Format(L"%u (%s)", version,
                                      PrefetchVersionName(version).c_str()));
    add(L"Header", L"Signature", L"SCCA");
    add(L"Header", L"Compression",
        compressed ? L"MAM / XPRESS-Huffman" : L"None (stored)");
    add(L"Header", L"File size", Format(L"%u bytes", fileSize));
    add(L"Header", L"Executable", executable.empty() ? L"(not recorded)" : executable);
    add(L"Header", L"Prefetch hash", Format(L"0x%08X", digest));
    uint32_t runCount = U32(data, runCountOffset);
    add(L"Header", L"Run count",
        (runCount > 0 && runCount < 1000000) ? CommaNumber(runCount) : L"not recorded");

    for (int index = 0; index < 8; ++index) {
        uint64_t stamp = U64(data, runsOffset + static_cast<size_t>(index) * 8);
        if (!stamp) continue;
        std::wstring text = FileTimeFromU64(stamp);
        add(Format(L"Run %d", index + 1), L"Last execution",
            text.empty() ? Format(L"0x%016llX", static_cast<unsigned long long>(stamp)) : text);
    }

    uint32_t volumeOffset = U32(data, volumesOffset);
    uint32_t volumeCount = U32(data, volumesOffset + 4);
    for (uint32_t index = 0; index < volumeCount && index < 64; ++index) {
        size_t base = static_cast<size_t>(volumeOffset) + static_cast<size_t>(index) * 96;
        if (base + 96 > data.size()) break;
        uint32_t chars = U32(data, base + 4);
        std::wstring device;
        const size_t candidates[] = {base + 0x5C, base + 0x68, base + 0x60};
        for (size_t candidate : candidates) {
            if (candidate + static_cast<size_t>(chars) * 2 > data.size()) continue;
            std::wstring text = Utf16(data.data() + candidate, static_cast<size_t>(chars) * 2);
            if (!text.empty() && text[0] == L'\\') {
                device = std::move(text);
                break;
            }
        }
        uint32_t serial = U32(data, base + 0x10);
        uint64_t created = U64(data, base + 8);
        std::wstring createdText = FileTimeFromU64(created);
        add(Format(L"Volume %u", index + 1), L"Device path",
            device.empty() ? L"(unresolved)" : device);
        add(Format(L"Volume %u", index + 1), L"Serial number", Format(L"0x%08X", serial));
        add(Format(L"Volume %u", index + 1), L"Creation time",
            createdText.empty() ? Format(L"0x%016llX", static_cast<unsigned long long>(created))
                                : createdText);
    }

    uint32_t stringsSize = U32(data, stringsOffset + 4);
    size_t poolStart = static_cast<size_t>(stringsOffset);
    if (poolStart > data.size()) poolStart = data.size();
    size_t poolLength = std::min<size_t>(stringsSize, data.size() - poolStart);
    const BYTE* pool = data.data() + poolStart;

    uint32_t metricsCount = U32(data, metricsOffset + 4);
    for (uint32_t index = 0; index < metricsCount && index < 50000; ++index) {
        size_t base = static_cast<size_t>(metricsOffset) + static_cast<size_t>(index) * metricSize;
        if (base + metricSize > data.size()) break;
        uint32_t duration = U32(data, base + 4);
        uint32_t average = U32(data, base + 8);
        uint32_t nameOffset = U32(data, base + 12);
        uint32_t nameLength = U32(data, base + 16);
        uint64_t target = static_cast<uint64_t>(nameOffset) + static_cast<uint64_t>(nameLength) * 2;

        std::wstring label;
        if (nameLength > 0 && nameLength < 4096 && target <= poolLength) {
            label = Utf16(pool + nameOffset, static_cast<size_t>(nameLength) * 2);
        }
        std::wstring detail = Format(L"duration %s \u00B7 average %s",
                                     CommaNumber(duration).c_str(),
                                     CommaNumber(average).c_str());
        if (label.empty()) detail += Format(L" \u00B7 name offset 0x%X", nameOffset);
        add(Format(L"File metric %u", index + 1),
            label.empty() ? L"Unresolved reference" : label, detail);
    }

    if (poolLength && metricsCount == 0) {
        std::wstring text = Utf16(pool, poolLength);
        size_t start = 0;
        while (start <= text.size()) {
            size_t end = text.find(L'\0', start);
            if (end == std::wstring::npos) end = text.size();
            std::wstring piece = Trim(text.substr(start, end - start));
            if (!piece.empty()) add(L"File reference", piece, L"from filename strings pool");
            if (end == text.size()) break;
            start = end + 1;
        }
    }

    uint32_t traceOffsetValue = U32(data, traceOffset);
    uint32_t traceCount = U32(data, traceOffset + 4);
    add(L"Header", L"Trace chains",
        Format(L"%s record(s) at 0x%X", CommaNumber(traceCount).c_str(), traceOffsetValue));
    return true;
}

bool IsShortcutPrintable(BYTE value) {
    return value >= 0x20 && value <= 0x7E;
}

std::wstring BestShortcutPath(const std::vector<BYTE>& data) {
    std::wstring best;
    size_t index = 0;
    while (index + 1 < data.size()) {
        if (!IsShortcutPrintable(data[index]) || data[index + 1] != 0) {
            ++index;
            continue;
        }
        size_t cursor = index;
        std::wstring text;
        while (cursor + 1 < data.size() && IsShortcutPrintable(data[cursor]) &&
               data[cursor + 1] == 0) {
            text.push_back(static_cast<wchar_t>(data[cursor]));
            cursor += 2;
        }
        if (text.size() >= 4 &&
            (text.find(L":\\") != std::wstring::npos || text.rfind(L"\\\\", 0) == 0) &&
            text.size() > best.size()) {
            best = std::move(text);
        }
        index = cursor > index ? cursor : index + 1;
    }
    if (best.size() > 800) best.resize(800);
    return best;
}

std::wstring JoinPath(const std::wstring& folder, const std::wstring& name) {
    if (!folder.empty() && (folder.back() == L'\\' || folder.back() == L'/')) return folder + name;
    return folder + L"\\" + name;
}

void FlushRows(const Sink& sink, std::vector<Row>& pending) {
    if (pending.empty()) return;
    sink.Rows(std::move(pending), false);
    pending.clear();
    pending.reserve(256);
}

void WalkRecent(const Sink& sink, std::atomic<bool>& stop, const std::wstring& root,
                std::vector<Row>& pending, unsigned long long& shown,
                unsigned long long& recentRows) {
    std::vector<std::wstring> stack;
    stack.push_back(root);
    while (!stack.empty() && !stop.load()) {
        std::wstring folder = std::move(stack.back());
        stack.pop_back();

        WIN32_FIND_DATAW data{};
        HANDLE find = FindFirstFileExW(JoinPath(folder, L"*").c_str(), FindExInfoBasic, &data,
                                       FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (find == INVALID_HANDLE_VALUE) {
            find = FindFirstFileW(JoinPath(folder, L"*").c_str(), &data);
        }
        if (find == INVALID_HANDLE_VALUE) continue;

        do {
            if (stop.load()) break;
            std::wstring name = data.cFileName;
            if (name == L"." || name == L"..") continue;
            std::wstring path = JoinPath(folder, name);
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
                stack.push_back(std::move(path));
                continue;
            }

            const wchar_t* extension = PathFindExtensionW(name.c_str());
            bool shortcut = extension && _wcsicmp(extension, L".lnk") == 0;
            bool jumpList = extension && (_wcsicmp(extension, L".automaticdestinations-ms") == 0 ||
                                          _wcsicmp(extension, L".customdestinations-ms") == 0);
            if (!shortcut && !jumpList) continue;

            std::wstring detail = L"Jump List container";
            if (shortcut) {
                std::vector<BYTE> prefix;
                if (ReadFileBytes(path, prefix, 262144)) {
                    std::wstring target = BestShortcutPath(prefix);
                    detail = target.empty() ? L"Shortcut target not recovered" : target;
                } else {
                    detail = L"Shortcut target not recovered";
                }
            }

            Row row;
            row.reserve(6);
            row.push_back(FileTimeText(data.ftLastWriteTime));
            row.push_back(L"Recent");
            row.push_back(name);
            row.push_back(shortcut ? L"Shortcut" : L"Jump List");
            row.push_back(std::move(detail));
            row.push_back(std::move(path));
            pending.push_back(std::move(row));
            ++shown;
            ++recentRows;
            if (pending.size() >= 200) FlushRows(sink, pending);
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }
}

}

void RunPrefetchRecent(const Sink& sink, std::atomic<bool>& stop, PrefetchConfig config) {
    if (!config.details && !config.recent) {
        sink.Error(L"Select Prefetch details, Recent shortcuts and Jump Lists, or both.");
        return;
    }

    std::wstring folder = config.folder;
    if (folder.empty()) {
        wchar_t systemRoot[MAX_PATH] = {};
        GetEnvironmentVariableW(L"SystemRoot", systemRoot, MAX_PATH);
        folder = JoinPath(systemRoot[0] ? systemRoot : L"C:\\Windows", L"Prefetch");
    }

    std::vector<PrefetchFile> files;
    if (config.details) {
        WIN32_FIND_DATAW data{};
        HANDLE find = FindFirstFileExW(JoinPath(folder, L"*.pf").c_str(), FindExInfoBasic, &data,
                                       FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (find == INVALID_HANDLE_VALUE) {
            find = FindFirstFileW(JoinPath(folder, L"*.pf").c_str(), &data);
        }
        if (find == INVALID_HANDLE_VALUE) {
            sink.Error(L"Folder not found or no prefetch files: " + folder);
            return;
        }
        do {
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            PrefetchFile entry;
            entry.path = JoinPath(folder, data.cFileName);
            entry.name = data.cFileName;
            entry.modified = data.ftLastWriteTime;
            files.push_back(std::move(entry));
        } while (FindNextFileW(find, &data));
        FindClose(find);

        std::sort(files.begin(), files.end(), [](const PrefetchFile& left, const PrefetchFile& right) {
            return FileTimeKey(left.modified) > FileTimeKey(right.modified);
        });
        if (config.maxFiles > 0 && files.size() > static_cast<size_t>(config.maxFiles)) {
            files.resize(static_cast<size_t>(config.maxFiles));
        }
    }

    unsigned long long steps = files.size() + (config.recent ? 1 : 0);
    unsigned long long parsed = 0;
    unsigned long long shown = 0;
    unsigned long long recentRows = 0;
    std::wstring firstFailure;
    int failures = 0;
    std::vector<Row> pending;
    pending.reserve(256);

    for (size_t index = 0; index < files.size(); ++index) {
        if (stop.load()) break;
        const PrefetchFile& file = files[index];
        int progress = steps ? static_cast<int>((index + 1) * 100 / steps) : -1;
        sink.Status(Format(L"%s/%s prefetch files \u00B7 %s rows",
                           CommaNumber(index + 1).c_str(), CommaNumber(files.size()).c_str(),
                           CommaNumber(shown).c_str()), progress);

        std::vector<BYTE> raw;
        std::vector<BYTE> image;
        std::wstring error;
        if (!ReadFileBytes(file.path, raw, 512u * 1024u * 1024u)) {
            ++failures;
            if (firstFailure.empty()) firstFailure = file.name + L": cannot read the file";
            continue;
        }
        bool compressed = false;
        if (!DecompressPrefetch(raw, image, compressed, error)) {
            ++failures;
            if (firstFailure.empty()) firstFailure = file.name + L": " + error;
            continue;
        }
        std::vector<Row> details;
        if (!ParsePrefetchImage(std::move(image), compressed, details, error)) {
            ++failures;
            if (firstFailure.empty()) firstFailure = file.name + L": " + error;
            continue;
        }
        ++parsed;
        std::wstring stamp = FileTimeText(file.modified);
        for (Row& detail : details) {
            Row row;
            row.reserve(6);
            row.push_back(stamp);
            row.push_back(L"Prefetch");
            row.push_back(file.name);
            for (std::wstring& cell : detail) row.push_back(std::move(cell));
            pending.push_back(std::move(row));
            ++shown;
        }
        if (pending.size() >= 200) FlushRows(sink, pending);
    }
    FlushRows(sink, pending);

    if (config.recent && !stop.load()) {
        if (steps) {
            int progress = static_cast<int>((files.size() + 1) * 100 / steps);
            sink.Status(L"Recent shortcuts and Jump Lists\u2026", progress);
        } else {
            sink.Status(L"Recent shortcuts and Jump Lists\u2026");
        }

        wchar_t systemDrive[16] = {};
        GetEnvironmentVariableW(L"SystemDrive", systemDrive, 16);
        std::wstring users = JoinPath(systemDrive[0] ? systemDrive : L"C:", L"Users");

        WIN32_FIND_DATAW data{};
        HANDLE find = FindFirstFileW(JoinPath(users, L"*").c_str(), &data);
        if (find != INVALID_HANDLE_VALUE) {
            do {
                if (stop.load()) break;
                std::wstring name = data.cFileName;
                if (name == L"." || name == L"..") continue;
                if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                std::wstring recent = JoinPath(JoinPath(JoinPath(JoinPath(users, name),
                                                                 L"AppData"), L"Roaming"),
                                               L"Microsoft");
                recent = JoinPath(JoinPath(recent, L"Windows"), L"Recent");
                DWORD attributes = GetFileAttributesW(recent.c_str());
                if (attributes == INVALID_FILE_ATTRIBUTES ||
                    !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    continue;
                }
                WalkRecent(sink, stop, recent, pending, shown, recentRows);
                FlushRows(sink, pending);
            } while (FindNextFileW(find, &data));
            FindClose(find);
        }
    }
    FlushRows(sink, pending);

    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s rows kept (%s prefetch files parsed).",
                         CommaNumber(shown).c_str(), CommaNumber(parsed).c_str()));
        return;
    }

    std::wstring parts;
    if (config.details) parts = CommaNumber(parsed) + L" prefetch file(s)";
    if (config.recent) {
        if (!parts.empty()) parts += L" and ";
        parts += CommaNumber(recentRows) + L" recent shortcut/Jump List artifacts";
    }
    std::wstring note = failures ? Format(L" \u00B7 %d unreadable", failures) : L"";
    sink.Done(Format(L"Completed. Parsed %s; %s rows%s.",
                     parts.c_str(), CommaNumber(shown).c_str(), note.c_str()));
}
