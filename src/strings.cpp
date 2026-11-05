#include "artifacts.h"

#include <algorithm>

namespace {

constexpr size_t BLOCK_SIZE = 256 * 1024;
constexpr size_t CARRY_SIZE = 16 * 1024;
constexpr size_t MAX_STRING = 8192;
constexpr unsigned long long EMIT_LIMIT = 200000;

bool IsTextByte(BYTE value) {
    return value == 0x09 || value == 0x0A || value == 0x0D ||
           (value >= 0x20 && value <= 0x7E);
}

std::wstring CleanText(const std::wstring& raw, int minimum) {
    std::wstring text;
    text.reserve(raw.size());
    for (wchar_t ch : raw) {
        if (ch == L'\r' || ch == L'\n') text.push_back(L' ');
        else text.push_back(ch);
    }
    text = Trim(text);
    if (static_cast<int>(text.size()) < minimum) return L"";
    if (text.size() > MAX_STRING) text.resize(MAX_STRING);
    return text;
}

void FlushRows(const Sink& sink, std::vector<Row>& pending) {
    if (pending.empty()) return;
    sink.Rows(std::move(pending), false);
    pending.clear();
    pending.reserve(128);
}

unsigned long long VolumeSize(const std::wstring& volume) {
    std::wstring root = volume;
    if (root.empty() || root.back() != L'\\') root += L"\\";
    ULARGE_INTEGER freeBytes{};
    ULARGE_INTEGER totalBytes{};
    if (!GetDiskFreeSpaceExW(root.c_str(), &freeBytes, &totalBytes, nullptr)) return 0;
    return totalBytes.QuadPart;
}

std::wstring ContextText(const BYTE* data, size_t size, size_t start, size_t end, size_t radius) {
    const size_t from = start > radius ? start - radius : 0;
    const size_t to = std::min(size, end + radius);
    std::wstring text;
    text.reserve(to - from);
    for (size_t i = from; i < to; ++i) {
        const BYTE value = data[i];
        text.push_back(value >= 0x20 && value < 0x7F ? static_cast<wchar_t>(value) : L'.');
    }
    return text;
}

void ScanBuffer(const std::wstring& volume, const BYTE* data, size_t size, size_t base,
                size_t emitFrom, int minimum, bool utf16, bool ascii,
                std::vector<Row>& pending, unsigned long long& found) {
    if (utf16) {
        size_t index = 0;
        while (index + 1 < size) {
            if (!IsTextByte(data[index]) || data[index + 1] != 0) {
                ++index;
                continue;
            }
            size_t cursor = index;
            while (cursor + 1 < size && IsTextByte(data[cursor]) && data[cursor + 1] == 0) {
                cursor += 2;
            }
            const size_t characters = (cursor - index) / 2;
            const size_t absolute = base + index;
            if (static_cast<int>(characters) >= minimum && absolute >= emitFrom) {
                ++found;
                if (found <= EMIT_LIMIT) {
                    std::wstring raw;
                    raw.reserve(characters);
                    for (size_t i = index; i < cursor; i += 2) {
                        raw.push_back(static_cast<wchar_t>(data[i]));
                    }
                    std::wstring value = CleanText(raw, minimum);
                    if (!value.empty()) {
                        Row row;
                        row.reserve(6);
                        row.push_back(volume);
                        row.push_back(Format(L"0x%012llX", static_cast<unsigned long long>(absolute)));
                        row.push_back(L"UTF-16LE");
                        row.push_back(Format(L"%zu", characters));
                        row.push_back(value);
                        row.push_back(ContextText(data, size, index, cursor, 24));
                        pending.push_back(std::move(row));
                    }
                }
            }
            index = cursor > index ? cursor : index + 1;
        }
    }

    if (ascii) {
        size_t index = 0;
        while (index < size) {
            if (!IsTextByte(data[index])) {
                ++index;
                continue;
            }
            size_t cursor = index;
            while (cursor < size && IsTextByte(data[cursor])) ++cursor;
            const size_t length = cursor - index;
            const size_t absolute = base + index;
            if (static_cast<int>(length) >= minimum && absolute >= emitFrom) {
                ++found;
                if (found <= EMIT_LIMIT) {
                    std::wstring raw;
                    raw.reserve(length);
                    for (size_t i = index; i < cursor; ++i) {
                        raw.push_back(static_cast<wchar_t>(data[i]));
                    }
                    std::wstring value = CleanText(raw, minimum);
                    if (!value.empty()) {
                        Row row;
                        row.reserve(6);
                        row.push_back(volume);
                        row.push_back(Format(L"0x%012llX", static_cast<unsigned long long>(absolute)));
                        row.push_back(L"ASCII");
                        row.push_back(Format(L"%zu", length));
                        row.push_back(value);
                        row.push_back(ContextText(data, size, index, cursor, 24));
                        pending.push_back(std::move(row));
                    }
                }
            }
            index = cursor > index ? cursor : index + 1;
        }
    }
}

}

void RunDiskStrings(const Sink& sink, std::atomic<bool>& stop, StringsConfig config) {
    if (!config.utf16 && !config.ascii) {
        sink.Error(L"Select UTF-16, ASCII, or both.");
        return;
    }
    int minimum = config.minLength < 3 ? 3 : config.minLength;

    unsigned long long total = 0;
    for (const std::wstring& volume : config.volumes) total += VolumeSize(volume);
    if (config.limitBytes) total = total ? std::min(total, config.limitBytes) : config.limitBytes;

    unsigned long long scanned = 0;
    unsigned long long found = 0;
    unsigned long long nextReport = 8ULL * 1024ULL * 1024ULL;
    std::vector<Row> pending;
    pending.reserve(128);

    for (const std::wstring& volume : config.volumes) {
        if (stop.load()) break;
        if (config.limitBytes && scanned >= config.limitBytes) break;

        std::wstring path = L"\\\\.\\" + volume;
        HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            sink.Status(Format(L"%s \u00B7 cannot open the raw volume (error %lu)",
                               volume.c_str(), GetLastError()));
            continue;
        }

        std::vector<BYTE> buffer(BLOCK_SIZE);
        std::vector<BYTE> carry;
        carry.reserve(CARRY_SIZE);
        unsigned long long volumeScanned = 0;
        size_t emitFrom = 0;

        while (!stop.load()) {
            if (config.limitBytes && scanned >= config.limitBytes) break;
            DWORD read = 0;
            if (!ReadFile(handle, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) ||
                read == 0) {
                break;
            }
            size_t blockSize = read;
            size_t base = carry.empty() ? 0 : static_cast<size_t>(volumeScanned) - carry.size();
            volumeScanned += blockSize;
            scanned += blockSize;

            std::vector<BYTE> data;
            data.reserve(carry.size() + blockSize);
            data.insert(data.end(), carry.begin(), carry.end());
            data.insert(data.end(), buffer.begin(), buffer.begin() + blockSize);

            ScanBuffer(volume, data.data(), data.size(), base, emitFrom, minimum,
                       config.utf16, config.ascii, pending, found);
            emitFrom = static_cast<size_t>(volumeScanned);

            size_t keep = std::min<size_t>(CARRY_SIZE, data.size());
            carry.assign(data.end() - static_cast<ptrdiff_t>(keep), data.end());

            if (pending.size() >= 100) {
                FlushRows(sink, pending);
                sink.Status(Format(L"%s \u00B7 read %s \u00B7 %s strings",
                                   volume.c_str(), SizeText(scanned).c_str(),
                                   CommaNumber(found).c_str()));
            }
            if (scanned >= nextReport) {
                nextReport = (scanned / (8ULL * 1024ULL * 1024ULL) + 1) * 8ULL * 1024ULL * 1024ULL;
                int progress = total ? static_cast<int>(std::min<unsigned long long>(100, scanned * 100 / total)) : -1;
                sink.Status(Format(L"%s \u00B7 read %s \u00B7 %s strings",
                                   volume.c_str(), SizeText(scanned).c_str(),
                                   CommaNumber(found).c_str()), progress);
            }
        }

        FlushRows(sink, pending);
        CloseHandle(handle);
        if (stop.load()) break;
    }

    FlushRows(sink, pending);
    const std::wstring listed = CommaNumber(std::min<unsigned long long>(found, EMIT_LIMIT));
    if (stop.load()) {
        sink.Done(Format(L"Stopped. Read %s \u00B7 %s string(s) found \u00B7 %s listed.",
                         SizeText(scanned).c_str(), CommaNumber(found).c_str(), listed.c_str()));
    } else {
        sink.Done(Format(L"Completed. Read %s \u00B7 %s string(s) found \u00B7 %s listed.",
                         SizeText(scanned).c_str(), CommaNumber(found).c_str(), listed.c_str()));
    }
}
