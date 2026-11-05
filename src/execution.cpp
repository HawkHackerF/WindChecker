#include "artifacts.h"

#include <sddl.h>

#include <algorithm>

namespace {

struct ExecEntry {
    std::wstring category;
    std::wstring time;
    std::wstring path;
    std::wstring detail;
    std::wstring source;
    std::wstring raw;
};

bool ReadRegistryBinary(HKEY root, const wchar_t* subkey, const wchar_t* value, std::vector<BYTE>& data) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return false;
    DWORD type = 0;
    DWORD size = 0;
    LONG result = RegQueryValueExW(key, value, nullptr, &type, nullptr, &size);
    if (result != ERROR_SUCCESS || size == 0) {
        RegCloseKey(key);
        return false;
    }
    data.resize(size);
    result = RegQueryValueExW(key, value, nullptr, &type, data.data(), &size);
    RegCloseKey(key);
    if (result != ERROR_SUCCESS) return false;
    data.resize(size);
    return true;
}

std::wstring RegistryString(HKEY root, const wchar_t* subkey, const wchar_t* value) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return L"";
    wchar_t buffer[2048] = {};
    DWORD size = sizeof(buffer);
    DWORD type = 0;
    std::wstring text;
    if (RegQueryValueExW(key, value, nullptr, &type, reinterpret_cast<BYTE*>(buffer), &size) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        text.assign(buffer, size / sizeof(wchar_t));
        while (!text.empty() && text.back() == L'\0') text.pop_back();
    }
    RegCloseKey(key);
    return text;
}

std::wstring KeyLastWrite(HKEY root, const wchar_t* subkey) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return L"";
    FILETIME written{};
    std::wstring text;
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         nullptr, nullptr, &written) == ERROR_SUCCESS) {
        text = FileTimeText(written);
    }
    RegCloseKey(key);
    return text;
}

std::wstring FileTimeFromBlob(const std::vector<BYTE>& data) {
    if (data.size() < 8) return L"";
    FILETIME stamp{};
    if (data.size() >= 12 && *reinterpret_cast<const DWORD*>(data.data()) == 0x00000010) {
        memcpy(&stamp, data.data() + 4, 8);
    } else {
        memcpy(&stamp, data.data(), 8);
    }
    return FileTimeText(stamp);
}

std::vector<std::wstring> SplitTabs(const std::wstring& text) {
    std::vector<std::wstring> fields;
    size_t start = 0;
    for (;;) {
        size_t at = text.find(L'\t', start);
        if (at == std::wstring::npos) {
            fields.push_back(text.substr(start));
            break;
        }
        fields.push_back(text.substr(start, at - start));
        start = at + 1;
    }
    return fields;
}

std::wstring MachineFromHex(const std::wstring& hex) {
    std::wstring value = ToLower(hex);
    while (value.size() > 1 && value[0] == L'0') value.erase(0, 1);
    if (value == L"8664") return L"x64";
    if (value == L"14c") return L"x86";
    if (value == L"aa64") return L"ARM64";
    if (value == L"1c4") return L"ARM";
    return L"";
}

void CollectShimCache(std::vector<ExecEntry>& out, std::wstring& note, std::atomic<bool>& stop) {
    std::vector<BYTE> blob;
    if (!ReadRegistryBinary(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
                            L"AppCompatCache", blob)) {
        note = L"AppCompatCache could not be read";
        return;
    }
    if (blob.size() < 0x40) {
        note = L"AppCompatCache is empty";
        return;
    }

    size_t start = std::wstring::npos;
    size_t searchLimit = std::min<size_t>(blob.size(), 0x100);
    for (size_t i = 0; i + 4 <= searchLimit; ++i) {
        if (blob[i] == '1' && blob[i + 1] == '0' && blob[i + 2] == 't' && blob[i + 3] == 's') {
            start = i;
            break;
        }
    }
    if (start == std::wstring::npos) {
        note = L"AppCompatCache format not recognised";
        return;
    }

    size_t position = start;
    int parsed = 0;
    while (position + 14 <= blob.size() && !stop.load()) {
        if (!(blob[position] == '1' && blob[position + 1] == '0' && blob[position + 2] == 't' &&
              blob[position + 3] == 's')) {
            break;
        }
        DWORD length = *reinterpret_cast<const DWORD*>(blob.data() + position + 8);
        if (length < 12 || length > 65536 || position + 12 + length > blob.size()) break;

        size_t body = position + 12;
        size_t bodyEnd = body + length;
        WORD pathLength = *reinterpret_cast<const WORD*>(blob.data() + body);
        if (pathLength == 0 || pathLength % 2 != 0 || body + 2 + pathLength > bodyEnd) break;

        std::wstring path(reinterpret_cast<const wchar_t*>(blob.data() + body + 2), pathLength / sizeof(wchar_t));
        while (!path.empty() && path.back() == L'\0') path.pop_back();

        std::wstring time;
        size_t timeAt = body + 2 + pathLength;
        if (timeAt + 8 <= bodyEnd) {
            FILETIME stamp{};
            memcpy(&stamp, blob.data() + timeAt, 8);
            time = FileTimeText(stamp);
        }

        if (!path.empty()) {
            ExecEntry entry;
            entry.category = L"ShimCache";
            entry.time = time;
            entry.source = L"AppCompatCache";

            if (path.find(L'\t') != std::wstring::npos) {
                std::vector<std::wstring> fields = SplitTabs(path);
                std::wstring package = fields.size() > 4 ? fields[4] : L"";
                std::wstring publisher = fields.size() > 5 ? fields[5] : L"";
                std::wstring machine = fields.size() > 3 ? MachineFromHex(fields[3]) : L"";
                entry.path = package.empty() ? path : package + (publisher.empty() ? L"" : L"_" + publisher);
                entry.detail = L"AppX package execution";
                if (!machine.empty()) entry.detail += L" \u00B7 " + machine;
                entry.raw = L"Registry : HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache\r\n"
                            L"Value    : AppCompatCache (binary)\r\n";
                entry.raw += Format(L"Entry at : 0x%llX, %lu bytes\r\n",
                                    static_cast<unsigned long long>(position), length);
                entry.raw += L"Kind     : AppX package entry\r\nPackage  : " + package + L"\r\n";
                if (!publisher.empty()) entry.raw += L"Publisher: " + publisher + L"\r\n";
                if (!machine.empty()) entry.raw += L"Machine  : " + machine + L"\r\n";
                entry.raw += L"Raw record:\r\n";
                for (size_t f = 0; f < fields.size(); ++f) {
                    entry.raw += Format(L"  [%d] %s\r\n", static_cast<int>(f), fields[f].c_str());
                }
            } else {
                entry.path = path;
                entry.detail = L"cached application compatibility entry";
                entry.raw = Format(
                    L"Registry : HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache\r\n"
                    L"Value    : AppCompatCache (binary)\r\nEntry at : 0x%llX, %lu bytes\r\n"
                    L"Path     : %s\r\nLast write: %s",
                    static_cast<unsigned long long>(position), length, path.c_str(),
                    time.empty() ? L"(not present)" : time.c_str());
            }
            out.push_back(std::move(entry));
            ++parsed;
        }
        position = bodyEnd;
    }
    if (parsed == 0) note = L"AppCompatCache contained no readable entries";
}

void CollectUsbStorage(std::vector<ExecEntry>& out, std::wstring& note, std::atomic<bool>& stop) {
    static const wchar_t* kRoot = L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR";
    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRoot, 0, KEY_READ | KEY_WOW64_64KEY, &root) != ERROR_SUCCESS) {
        note = L"USBSTOR could not be read (administrator rights required)";
        return;
    }
    for (DWORD deviceIndex = 0;; ++deviceIndex) {
        wchar_t device[512] = {};
        DWORD deviceLength = 512;
        if (RegEnumKeyExW(root, deviceIndex, device, &deviceLength, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        std::wstring devicePath = std::wstring(kRoot) + L"\\" + device;
        std::wstring friendly = RegistryString(HKEY_LOCAL_MACHINE, devicePath.c_str(), L"FriendlyName");
        std::wstring description = RegistryString(HKEY_LOCAL_MACHINE, devicePath.c_str(), L"DeviceDesc");
        std::wstring manufacturer = RegistryString(HKEY_LOCAL_MACHINE, devicePath.c_str(), L"Mfg");
        std::wstring service = RegistryString(HKEY_LOCAL_MACHINE, devicePath.c_str(), L"Service");

        HKEY deviceKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, devicePath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &deviceKey) !=
            ERROR_SUCCESS) {
            continue;
        }
        for (DWORD instanceIndex = 0;; ++instanceIndex) {
            if (stop.load()) break;
            wchar_t instance[512] = {};
            DWORD instanceLength = 512;
            if (RegEnumKeyExW(deviceKey, instanceIndex, instance, &instanceLength, nullptr, nullptr, nullptr,
                              nullptr) != ERROR_SUCCESS) {
                break;
            }
            std::wstring instancePath = devicePath + L"\\" + instance;
            static const wchar_t* kProps = L"\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\";
            std::vector<BYTE> blob;
            std::wstring installed, connected, removed;
            if (ReadRegistryBinary(HKEY_LOCAL_MACHINE, (instancePath + kProps + L"0064").c_str(), L"", blob)) {
                installed = FileTimeFromBlob(blob);
            }
            blob.clear();
            if (ReadRegistryBinary(HKEY_LOCAL_MACHINE, (instancePath + kProps + L"0066").c_str(), L"", blob)) {
                connected = FileTimeFromBlob(blob);
            }
            blob.clear();
            if (ReadRegistryBinary(HKEY_LOCAL_MACHINE, (instancePath + kProps + L"0067").c_str(), L"", blob)) {
                removed = FileTimeFromBlob(blob);
            }
            if (installed.empty() && connected.empty() && removed.empty()) {
                installed = KeyLastWrite(HKEY_LOCAL_MACHINE, instancePath.c_str());
            }

            ExecEntry entry;
            entry.category = L"USB device";
            entry.time = !connected.empty() ? connected : (!removed.empty() ? removed : installed);
            entry.path = !friendly.empty() ? friendly : (!description.empty() ? description : device);
            std::wstring detail;
            if (!manufacturer.empty()) detail += manufacturer + L" \u00B7 ";
            if (!service.empty()) detail += service + L" \u00B7 ";
            detail += L"instance " + std::wstring(instance);
            entry.detail = detail;
            entry.source = L"USBSTOR";
            entry.raw = Format(L"Registry     : HKLM\\%s\r\n"
                               L"Device       : %s\r\nInstance     : %s\r\nManufacturer : %s\r\n"
                               L"Service      : %s\r\nFirst install: %s\r\nLast connect : %s\r\n"
                               L"Last removal : %s",
                               instancePath.c_str(), device, instance,
                               manufacturer.empty() ? L"-" : manufacturer.c_str(),
                               service.empty() ? L"-" : service.c_str(),
                               installed.empty() ? L"-" : installed.c_str(),
                               connected.empty() ? L"-" : connected.c_str(),
                               removed.empty() ? L"-" : removed.c_str());
            out.push_back(std::move(entry));
        }
        RegCloseKey(deviceKey);
    }
    RegCloseKey(root);
}

std::wstring SidAccount(const std::wstring& sid) {
    PSID parsed = nullptr;
    if (!ConvertStringSidToSidW(sid.c_str(), &parsed)) return L"";
    wchar_t name[256] = {};
    wchar_t domain[256] = {};
    DWORD nameLength = 256;
    DWORD domainLength = 256;
    SID_NAME_USE use;
    std::wstring text;
    if (LookupAccountSidW(nullptr, parsed, name, &nameLength, domain, &domainLength, &use)) {
        if (domain[0]) text = std::wstring(domain) + L"\\";
        text += name;
    }
    LocalFree(parsed);
    return text;
}

void CollectRecycleBin(std::vector<ExecEntry>& out, std::wstring& note, std::atomic<bool>& stop) {
    DWORD drives = GetLogicalDrives();
    int found = 0;
    for (int letter = 0; letter < 26 && !stop.load(); ++letter) {
        if (!(drives & (1u << letter))) continue;
        wchar_t drive[4] = {static_cast<wchar_t>(L'A' + letter), L':', L'\\', 0};
        UINT type = GetDriveTypeW(drive);
        if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) continue;

        std::wstring bin = std::wstring(drive) + L"$Recycle.Bin";
        WIN32_FIND_DATAW data{};
        HANDLE find = FindFirstFileW((bin + L"\\*").c_str(), &data);
        if (find == INVALID_HANDLE_VALUE) continue;
        do {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
            std::wstring folder = bin + L"\\" + data.cFileName;
            std::wstring account = SidAccount(data.cFileName);

            WIN32_FIND_DATAW item{};
            HANDLE items = FindFirstFileW((folder + L"\\$I*").c_str(), &item);
            if (items == INVALID_HANDLE_VALUE) continue;
            do {
                if (stop.load()) break;
                if (item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                std::wstring indexFile = folder + L"\\" + item.cFileName;

                HANDLE file = CreateFileW(indexFile.c_str(), GENERIC_READ,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                          FILE_ATTRIBUTE_NORMAL, nullptr);
                if (file == INVALID_HANDLE_VALUE) continue;
                BYTE buffer[1200] = {};
                DWORD read = 0;
                ReadFile(file, buffer, sizeof(buffer), &read, nullptr);
                CloseHandle(file);
                if (read < 24) continue;

                unsigned long long version = 0;
                unsigned long long size = 0;
                unsigned long long stampRaw = 0;
                memcpy(&version, buffer, 8);
                memcpy(&size, buffer + 8, 8);
                memcpy(&stampRaw, buffer + 16, 8);

                std::wstring name;
                if (version == 2) {
                    DWORD chars = 0;
                    memcpy(&chars, buffer + 24, 4);
                    size_t offset = 28;
                    if (chars == 0 && read >= 32) {
                        memcpy(&chars, buffer + 28, 4);
                        offset = 32;
                    }
                    if (chars > 0 && offset + static_cast<size_t>(chars) * 2 <= read) {
                        name.assign(reinterpret_cast<const wchar_t*>(buffer + offset), chars);
                    }
                } else if (version == 1 && read >= 24 + 520) {
                    name.assign(reinterpret_cast<const wchar_t*>(buffer + 24), 260);
                }
                while (!name.empty() && name.back() == L'\0') name.pop_back();
                if (name.empty()) continue;

                FILETIME stamp{};
                stamp.dwLowDateTime = static_cast<DWORD>(stampRaw & 0xFFFFFFFF);
                stamp.dwHighDateTime = static_cast<DWORD>(stampRaw >> 32);

                std::wstring recovered = L"$R" + std::wstring(item.cFileName).substr(2);
                std::wstring recoveredPath = folder + L"\\" + recovered;
                WIN32_FILE_ATTRIBUTE_DATA recoveredInfo{};
                bool present = GetFileAttributesExW(recoveredPath.c_str(), GetFileExInfoStandard,
                                                    &recoveredInfo) != 0;

                ExecEntry entry;
                entry.category = L"Recycle Bin";
                entry.time = FileTimeText(stamp);
                entry.path = name;
                entry.detail = Format(L"%s \u00B7 deleted by %s", SizeText(size).c_str(),
                                      account.empty() ? data.cFileName : account.c_str());
                entry.source = L"$Recycle.Bin";
                entry.raw = Format(L"Index file   : %s\r\nOriginal path: %s\r\nDeleted size : %s\r\n"
                                   L"Deleted at   : %s\r\nOwner        : %s\r\n"
                                   L"Recovered    : %s",
                                   indexFile.c_str(), name.c_str(), SizeText(size).c_str(),
                                   FileTimeText(stamp).c_str(),
                                   account.empty() ? data.cFileName : account.c_str(),
                                   present ? (recoveredPath + L" (present)").c_str()
                                           : L"(content file is gone)");
                out.push_back(std::move(entry));
                ++found;
            } while (FindNextFileW(items, &item));
            FindClose(items);
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }
    if (found == 0) note = L"no readable $Recycle.Bin entries";
}

}

void RunExecutionDevices(const Sink& sink, std::atomic<bool>& stop, ExecConfig config) {
    std::vector<ExecEntry> entries;
    std::vector<std::wstring> notes;

    if (config.shimcache && !stop.load()) {
        sink.Status(L"Parsing AppCompatCache (ShimCache)\u2026");
        std::wstring note;
        CollectShimCache(entries, note, stop);
        if (!note.empty()) notes.push_back(note);
    }
    if (config.usb && !stop.load()) {
        sink.Status(L"Reading USB storage history\u2026");
        std::wstring note;
        CollectUsbStorage(entries, note, stop);
        if (!note.empty()) notes.push_back(note);
    }
    if (config.recycle && !stop.load()) {
        sink.Status(L"Parsing Recycle Bin index files\u2026");
        std::wstring note;
        CollectRecycleBin(entries, note, stop);
        if (!note.empty()) notes.push_back(note);
    }

    if (stop.load()) {
        sink.Done(L"Stopped. Execution and device history was cancelled.");
        return;
    }

    std::stable_sort(entries.begin(), entries.end(), [](const ExecEntry& a, const ExecEntry& b) {
        if (a.category != b.category) return a.category < b.category;
        return a.time > b.time;
    });

    std::vector<Row> pending;
    std::vector<std::wstring> details;
    pending.reserve(64);
    details.reserve(64);
    unsigned long long emitted = 0;
    bool firstBatch = true;

    auto flush = [&]() {
        if (pending.empty()) return;
        sink.Detailed(std::move(pending), std::move(details), firstBatch);
        firstBatch = false;
        pending.clear();
        details.clear();
        pending.reserve(64);
        details.reserve(64);
    };

    for (size_t i = 0; i < entries.size() && !stop.load(); ++i) {
        const ExecEntry& entry = entries[i];
        Row row;
        row.reserve(5);
        row.push_back(entry.category);
        row.push_back(entry.time.empty() ? L"-" : entry.time);
        row.push_back(entry.path);
        row.push_back(entry.detail);
        row.push_back(entry.source);
        pending.push_back(std::move(row));
        details.push_back(entry.raw);
        ++emitted;
        if (pending.size() >= 64) flush();
    }
    flush();

    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s entries retained.", CommaNumber(emitted).c_str()));
        return;
    }

    std::wstring summary = Format(L"Completed. %s execution and device entries",
                                  CommaNumber(emitted).c_str());
    for (const std::wstring& note : notes) summary += L" \u00B7 " + note;
    sink.Done(summary);
}
