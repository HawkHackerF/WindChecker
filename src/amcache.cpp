#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include "common.h"
#include "artifacts.h"

#include <algorithm>
#include <cstring>
#include <cwctype>

#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>

#pragma comment(lib, "vssapi.lib")
#pragma comment(lib, "ole32.lib")

namespace {

struct HiveValue {
    std::wstring name;
    std::wstring text;
    DWORD type = 0;
};

std::wstring MultiSzText(const std::vector<BYTE>& buffer) {
    std::wstring joined;
    const wchar_t* cursor = reinterpret_cast<const wchar_t*>(buffer.data());
    size_t remaining = buffer.size() / sizeof(wchar_t);
    while (remaining && *cursor) {
        size_t length = wcsnlen(cursor, remaining);
        if (!joined.empty()) joined += L"; ";
        joined.append(cursor, length);
        cursor += length + 1;
        remaining -= length + 1;
    }
    return joined;
}

std::wstring ValueText(DWORD type, const std::vector<BYTE>& buffer) {
    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ:
        return Trim(std::wstring(reinterpret_cast<const wchar_t*>(buffer.data())));
    case REG_MULTI_SZ:
        return MultiSzText(buffer);
    case REG_DWORD: {
        DWORD value = 0;
        if (buffer.size() >= 4) std::memcpy(&value, buffer.data(), 4);
        return Format(L"%lu (0x%08lX)", value, value);
    }
    case REG_QWORD: {
        unsigned long long value = 0;
        if (buffer.size() >= 8) std::memcpy(&value, buffer.data(), 8);
        FILETIME fileTime{};
        fileTime.dwLowDateTime = static_cast<DWORD>(value & 0xFFFFFFFF);
        fileTime.dwHighDateTime = static_cast<DWORD>(value >> 32);
        std::wstring stamp = FileTimeText(fileTime);
        if (!stamp.empty() && value > 116444736000000000ULL) {
            return Format(L"%llu \u00B7 %s", value, stamp.c_str());
        }
        return Format(L"%llu (0x%llX)", value, value);
    }
    default: {
        if (buffer.empty()) return L"";
        std::wstring hex;
        size_t limit = buffer.size() < 64 ? buffer.size() : 64;
        for (size_t i = 0; i < limit; ++i) {
            if (i) hex += L" ";
            hex += Format(L"%02X", buffer[i]);
        }
        if (buffer.size() > limit) hex += L" \u2026";
        return hex;
    }
    }
}

std::vector<HiveValue> ReadValues(HKEY key) {
    std::vector<HiveValue> values;
    wchar_t name[512] = {};
    BYTE data[8192] = {};
    for (DWORD index = 0;; ++index) {
        DWORD nameLength = 512;
        DWORD type = 0;
        DWORD size = sizeof(data);
        LONG status = RegEnumValueW(key, index, name, &nameLength, nullptr, &type, data, &size);
        if (status != ERROR_SUCCESS) break;
        HiveValue value;
        value.name.assign(name, nameLength);
        value.type = type;
        std::vector<BYTE> buffer(data, data + size);
        if (size == sizeof(data)) {
            DWORD needed = 0;
            if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &needed) == ERROR_SUCCESS && needed) {
                std::vector<BYTE> large(needed + 2);
                DWORD read = needed;
                if (RegQueryValueExW(key, name, nullptr, &type, large.data(), &read) == ERROR_SUCCESS) {
                    buffer.assign(large.begin(), large.begin() + read);
                }
            }
        }
        value.text = ValueText(type, buffer);
        values.push_back(std::move(value));
    }
    return values;
}

std::wstring FindValue(const std::vector<HiveValue>& values, const wchar_t* name) {
    for (const HiveValue& value : values) {
        if (_wcsicmp(value.name.c_str(), name) == 0) return value.text;
    }
    return L"";
}

std::wstring ValueStem(const std::vector<HiveValue>& values, std::initializer_list<const wchar_t*> names) {
    for (const wchar_t* name : names) {
        std::wstring text = FindValue(values, name);
        if (!text.empty()) return text;
    }
    return L"";
}

bool CopyLockedFile(const std::wstring& source, const std::wstring& target) {
    HANDLE in = CreateFileW(source.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (in == INVALID_HANDLE_VALUE) return false;
    HANDLE out = CreateFileW(target.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (out == INVALID_HANDLE_VALUE) {
        CloseHandle(in);
        return false;
    }
    std::vector<BYTE> buffer(1 << 20);
    bool ok = true;
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(in, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            ok = false;
            break;
        }
        if (!read) break;
        DWORD written = 0;
        if (!WriteFile(out, buffer.data(), read, &written, nullptr) || written != read) {
            ok = false;
            break;
        }
    }
    CloseHandle(out);
    CloseHandle(in);
    return ok;
}

class VolumeSnapshot {
public:
    ~VolumeSnapshot() { Release(); }

    bool Create(wchar_t drive, std::wstring& device, std::wstring& error) {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(hr)) comInitialized_ = true;
        else if (hr != RPC_E_CHANGED_MODE) {
            error = Format(L"COM could not be initialised (0x%08lX).", static_cast<unsigned long>(hr));
            return false;
        }

        hr = CreateVssBackupComponents(&backup_);
        if (FAILED(hr) || !backup_) {
            error = Format(L"VSS is not available (0x%08lX).", static_cast<unsigned long>(hr));
            return false;
        }
        hr = backup_->InitializeForBackup();
        if (FAILED(hr)) {
            error = Format(L"VSS initialisation failed (0x%08lX).", static_cast<unsigned long>(hr));
            return false;
        }
        backup_->SetContext(VSS_CTX_BACKUP);
        backup_->SetBackupState(false, false, VSS_BT_COPY, false);

        hr = backup_->StartSnapshotSet(&setId_);
        if (FAILED(hr)) {
            error = Format(L"VSS could not start a snapshot set (0x%08lX).", static_cast<unsigned long>(hr));
            return false;
        }

        wchar_t volume[8] = {};
        swprintf_s(volume, L"%c:\\", drive);
        VSS_ID snapshotId{};
        hr = backup_->AddToSnapshotSet(volume, GUID_NULL, &snapshotId);
        if (FAILED(hr)) {
            error = Format(L"VSS could not add %s to the snapshot set (0x%08lX).", volume,
                           static_cast<unsigned long>(hr));
            return false;
        }

        IVssAsync* async = nullptr;
        hr = backup_->PrepareForBackup(&async);
        if (FAILED(hr) || !WaitAsync(async, error)) return false;
        hr = backup_->DoSnapshotSet(&async);
        if (FAILED(hr) || !WaitAsync(async, error)) return false;

        VSS_SNAPSHOT_PROP properties{};
        hr = backup_->GetSnapshotProperties(snapshotId, &properties);
        if (FAILED(hr) || !properties.m_pwszSnapshotDeviceObject) {
            error = Format(L"VSS snapshot properties are unavailable (0x%08lX).",
                           static_cast<unsigned long>(hr));
            return false;
        }
        device = properties.m_pwszSnapshotDeviceObject;
        VssFreeSnapshotProperties(&properties);
        created_ = true;
        return true;
    }

    void Release() {
        if (backup_ && created_) {
            LONG deleted = 0;
            VSS_ID nonDeleted = GUID_NULL;
            backup_->DeleteSnapshots(setId_, VSS_OBJECT_SNAPSHOT_SET, TRUE, &deleted, &nonDeleted);
            created_ = false;
        }
        if (backup_) {
            backup_->Release();
            backup_ = nullptr;
        }
        if (comInitialized_) {
            CoUninitialize();
            comInitialized_ = false;
        }
    }

private:
    static bool WaitAsync(IVssAsync* async, std::wstring& error) {
        if (!async) {
            error = L"VSS returned no asynchronous handle.";
            return false;
        }
        HRESULT status = S_OK;
        HRESULT hr = async->Wait();
        if (SUCCEEDED(hr)) hr = async->QueryStatus(&status, nullptr);
        async->Release();
        if (FAILED(hr) || status != VSS_S_ASYNC_FINISHED) {
            error = Format(L"VSS operation did not finish (0x%08lX).",
                           static_cast<unsigned long>(FAILED(hr) ? hr : status));
            return false;
        }
        return true;
    }

    IVssBackupComponents* backup_ = nullptr;
    bool comInitialized_ = false;
    bool created_ = false;
    VSS_ID setId_{};
};

std::wstring KeyLastWrite(HKEY key) {
    FILETIME written{};
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         nullptr, nullptr, &written) != ERROR_SUCCESS) {
        return L"";
    }
    return FileTimeText(written);
}

std::wstring CategoryLabel(const std::wstring& name) {
    if (name == L"InventoryApplicationFile") return L"Application file";
    if (name == L"InventoryApplication") return L"Application";
    if (name == L"InventoryDriverBinary") return L"Driver binary";
    if (name == L"InventoryDeviceContainer") return L"Device container";
    if (name == L"InventoryDevicePnp") return L"Device (PnP)";
    if (name == L"InventoryApplicationShortcut") return L"Shortcut";
    if (name == L"InventoryApplicationThumbnail") return L"Thumbnail";
    if (name == L"File") return L"File (first run)";
    if (name == L"Programs") return L"Program";
    return name;
}

std::wstring LooksLikeHash(const std::wstring& text) {
    if (text.size() != 40 && text.size() != 64) return L"";
    for (wchar_t ch : text) {
        if (!iswxdigit(ch)) return L"";
    }
    return text;
}

std::wstring FileNameOf(const std::wstring& path) {
    size_t split = path.find_last_of(L"\\/");
    return split == std::wstring::npos ? path : path.substr(split + 1);
}

void AddRecentFileCache(const std::wstring& path, std::vector<Row>& rows,
                        std::vector<std::wstring>& details, std::atomic<bool>& stop) {
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER size{};
    GetFileSizeEx(handle, &size);
    if (size.QuadPart <= 0 || size.QuadPart > 16 * 1024 * 1024) {
        CloseHandle(handle);
        return;
    }
    std::vector<BYTE> data(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(handle, data.data(), static_cast<DWORD>(data.size()), &read, nullptr);
    CloseHandle(handle);
    if (!ok) return;

    size_t offset = 0;
    while (offset + 4 <= read) {
        if (stop.load()) break;
        if (offset < 32) {
            offset = 32;
            continue;
        }
        size_t start = offset;
        while (offset + 1 < read && (data[offset] || data[offset + 1])) offset += 2;
        if (offset <= start) {
            offset += 2;
            continue;
        }
        std::wstring text(reinterpret_cast<const wchar_t*>(data.data() + start),
                          (offset - start) / 2);
        offset += 2;
        if (text.size() < 4) continue;
        rows.push_back(Row{L"RecentFileCache", FileNameOf(text), L"", L"", text, L"", L""});
        details.push_back(L"Source: RecentFileCache.bcf\r\nPath: " + text + L"\r\n");
    }
}

}

void RunAmCacheViewer(const Sink& sink, std::atomic<bool>& stop) {
    std::vector<Row> rows;
    std::vector<std::wstring> details;

    wchar_t windowsDir[MAX_PATH] = {};
    GetWindowsDirectoryW(windowsDir, MAX_PATH);
    std::wstring hivePath = std::wstring(windowsDir) + L"\\AppCompat\\Programs\\Amcache.hve";
    std::wstring recentPath = std::wstring(windowsDir) + L"\\AppCompat\\Programs\\RecentFileCache.bcf";

    WIN32_FILE_ATTRIBUTE_DATA info{};
    if (GetFileAttributesExW(hivePath.c_str(), GetFileExInfoStandard, &info)) {
        ULARGE_INTEGER size{};
        size.LowPart = info.nFileSizeLow;
        size.HighPart = info.nFileSizeHigh;
        rows.push_back(Row{L"Amcache", L"Amcache.hve", L"", L"", hivePath, FileTimeText(info.ftLastWriteTime),
                           SizeText(size.QuadPart)});
        details.push_back(L"Path: " + hivePath + L"\r\nSize: " + SizeText(size.QuadPart) +
                          L"\r\nLast write: " + FileTimeText(info.ftLastWriteTime));
    }

    wchar_t tempRoot[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempRoot);
    std::wstring workDir = std::wstring(tempRoot) + Format(L"WindCheckerAmcache_%lu", GetCurrentProcessId());
    CreateDirectoryW(workDir.c_str(), nullptr);
    std::wstring copyPath = workDir + L"\\Amcache.hve";

    std::wstring hiveSource = hivePath;
    std::wstring snapshotDevice;
    std::wstring snapshotError;
    bool copied = false;
    {
        VolumeSnapshot snapshot;
        if (snapshot.Create(windowsDir[0], snapshotDevice, snapshotError)) {
            std::wstring snapHive = snapshotDevice + L"\\Windows\\AppCompat\\Programs\\Amcache.hve";
            copied = CopyLockedFile(snapHive, copyPath);
            if (copied) {
                hiveSource = snapHive;
                CopyLockedFile(snapHive + L".LOG1", copyPath + L".LOG1");
                CopyLockedFile(snapHive + L".LOG2", copyPath + L".LOG2");
            }
        }
    }
    if (!copied) copied = CopyLockedFile(hivePath, copyPath);

    HKEY root = nullptr;
    LONG loadStatus = ERROR_FILE_NOT_FOUND;
    if (copied) {
        CopyLockedFile(hivePath + L".LOG1", copyPath + L".LOG1");
        CopyLockedFile(hivePath + L".LOG2", copyPath + L".LOG2");
        loadStatus = RegLoadAppKeyW(copyPath.c_str(), &root, KEY_READ, 0, 0);
    }

    unsigned long long entries = 0;
    if (loadStatus == ERROR_SUCCESS && root) {
        HKEY rootKey = nullptr;
        if (RegOpenKeyExW(root, L"Root", 0, KEY_READ, &rootKey) == ERROR_SUCCESS) {
            std::vector<std::wstring> categories;
            wchar_t categoryName[256] = {};
            for (DWORD index = 0;; ++index) {
                DWORD length = 256;
                if (RegEnumKeyExW(rootKey, index, categoryName, &length, nullptr, nullptr, nullptr,
                                  nullptr) != ERROR_SUCCESS) {
                    break;
                }
                categories.emplace_back(categoryName, length);
            }
            auto rank = [](const std::wstring& name) -> int {
                if (name == L"InventoryApplicationFile") return 0;
                if (name == L"InventoryApplication") return 1;
                if (name == L"InventoryDriverBinary") return 2;
                if (name == L"InventoryDevicePnp") return 3;
                if (name == L"InventoryDeviceContainer") return 4;
                if (name == L"InventoryApplicationShortcut") return 5;
                if (name == L"InventoryApplicationFramework") return 6;
                if (name == L"InventoryApplicationDriver") return 7;
                if (name == L"InventoryApplicationAppV") return 8;
                if (name == L"InventoryApplicationThumbnail") return 9;
                if (name == L"File") return 10;
                if (name == L"Programs") return 11;
                if (name == L"DeviceCensus") return 99;
                return 50;
            };
            std::stable_sort(categories.begin(), categories.end(),
                             [&](const std::wstring& left, const std::wstring& right) {
                                 const int a = rank(left);
                                 const int b = rank(right);
                                 if (a != b) return a < b;
                                 return left < right;
                             });

            for (const std::wstring& category : categories) {
                if (stop.load()) break;
                std::wstring label = CategoryLabel(category);
                std::wstring categoryPath = std::wstring(L"Root\\") + category;
                HKEY categoryKey = nullptr;
                if (RegOpenKeyExW(rootKey, category.c_str(), 0, KEY_READ, &categoryKey) != ERROR_SUCCESS) continue;

                wchar_t entryName[512] = {};
                for (DWORD entryIndex = 0;; ++entryIndex) {
                    DWORD entryLength = 512;
                    if (RegEnumKeyExW(categoryKey, entryIndex, entryName, &entryLength, nullptr, nullptr,
                                      nullptr, nullptr) != ERROR_SUCCESS) {
                        break;
                    }
                    if (stop.load()) break;
                    std::wstring keyName(entryName, entryLength);
                    HKEY entryKey = nullptr;
                    if (RegOpenKeyExW(categoryKey, entryName, 0, KEY_READ, &entryKey) != ERROR_SUCCESS) continue;

                    std::vector<HiveValue> values = ReadValues(entryKey);
                    std::wstring lastWrite = KeyLastWrite(entryKey);
                    RegCloseKey(entryKey);

                    std::wstring name = ValueStem(values, {L"Name", L"DriverName", L"ModelName",
                                                           L"FriendlyName", L"LowerCaseLongPath"});
                    std::wstring path = ValueStem(values, {L"LowerCaseLongPath", L"ImagePath",
                                                           L"RootDirPath", L"ShortcutPath", L"Path",
                                                           L"InstallLocation", L"ManifestPath"});
                    if (name.empty()) name = FileNameOf(path);
                    if (name.empty()) name = keyName;
                    std::wstring version = ValueStem(values, {L"Version", L"DriverVersion", L"ProductVersion"});
                    std::wstring publisher = ValueStem(values, {L"Publisher", L"Manufacturer"});
                    std::wstring timestamp = ValueStem(values, {L"InstallDate", L"LinkDate",
                                                                L"DriverDate", L"LastConnected", L"LastSeen"});
                    std::wstring sha1 = LooksLikeHash(FindValue(values, L"FileId"));
                    if (sha1.empty()) sha1 = LooksLikeHash(keyName);
                    if (sha1.empty()) {
                        std::wstring fileId = FindValue(values, L"FileId");
                        if (fileId.size() >= 16 && fileId.size() <= 64) {
                            bool hex = true;
                            for (wchar_t ch : fileId) {
                                if (!iswxdigit(ch)) {
                                    hex = false;
                                    break;
                                }
                            }
                            if (hex) sha1 = fileId;
                        }
                    }
                    if (timestamp.empty()) {
                        for (const HiveValue& value : values) {
                            if (!value.name.empty() && iswdigit(value.name[0]) && value.text.size() > 20) {
                                timestamp = value.text;
                                break;
                            }
                        }
                    }

                    Row row;
                    row.push_back(label);
                    row.push_back(name);
                    row.push_back(version);
                    row.push_back(publisher);
                    row.push_back(path);
                    row.push_back(timestamp);
                    row.push_back(sha1);
                    rows.push_back(std::move(row));

                    std::wstring detail;
                    detail += L"Category   : " + label + L" (" + category + L")\r\n";
                    detail += L"Key        : " + categoryPath + L"\\" + keyName + L"\r\n";
                    if (!lastWrite.empty()) detail += L"Last write : " + lastWrite + L"\r\n";
                    detail += L"\r\n";
                    for (const HiveValue& value : values) {
                        std::wstring label = value.name.empty() ? L"(Default)" : value.name;
                        detail += label;
                        if (label.size() < 24) detail.append(24 - label.size(), L' ');
                        detail += L": " + (value.text.empty() ? std::wstring(L"-") : value.text) + L"\r\n";
                    }
                    details.push_back(std::move(detail));
                    ++entries;

                    if (entries % 2000 == 0) {
                        sink.Status(Format(L"Reading Amcache \u00B7 %s entries", CommaNumber(entries).c_str()));
                    }
                }
                RegCloseKey(categoryKey);
            }
            RegCloseKey(rootKey);
        }
        RegCloseKey(root);
    } else {
        std::wstring reason = loadStatus == ERROR_SUCCESS ? L"unknown" : Format(L"error %ld", loadStatus);
        rows.push_back(Row{L"Amcache", L"Amcache.hve", L"", L"", L"Could not load the hive", reason, L""});
        std::wstring detail = L"The Amcache hive could not be loaded from a temporary copy. " + reason + L"\r\n";
        if (!snapshotError.empty()) detail += L"Volume snapshot: " + snapshotError + L"\r\n";
        detail += L"WindChecker must run as Administrator and the Volume Shadow Copy service must be running.";
        details.push_back(detail);
    }

    if (copied) {
        DeleteFileW(copyPath.c_str());
        DeleteFileW((copyPath + L".LOG1").c_str());
        DeleteFileW((copyPath + L".LOG2").c_str());
        RemoveDirectoryW(workDir.c_str());
    }

    AddRecentFileCache(recentPath, rows, details, stop);

    const std::wstring summary =
        Format(L"%s Amcache entr%s loaded from %s%s%s",
               CommaNumber(entries).c_str(), entries == 1 ? L"y" : L"ies", hivePath.c_str(),
               hiveSource == hivePath ? L"" : L" via a VSS snapshot",
               rows.size() > entries + 1 ? L" \u00B7 plus RecentFileCache" : L"");
    sink.Detailed(std::move(rows), std::move(details), true, summary, 100);
    sink.Done(summary);
}
