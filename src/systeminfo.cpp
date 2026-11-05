#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include "common.h"
#include "artifacts.h"

#include <winioctl.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <lm.h>
#include <lmjoin.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cwchar>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "netapi32.lib")

namespace {

const GUID kDisplayClass = {0x4d36e968, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};
const GUID kDiskClass = {0x4d36e967, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};
const GUID kSecurityClass = {0xd94ee5d8, 0xd189, 0x4994, {0x83, 0xd2, 0xf6, 0x8d, 0x7d, 0x41, 0xb0, 0xe6}};


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

std::wstring RegText(HKEY root, const wchar_t* subkey, const wchar_t* name, bool expand = false) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return L"";
    std::wstring result;
    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) == ERROR_SUCCESS && size > 0 &&
        (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ)) {
        std::vector<BYTE> buffer(static_cast<size_t>(size) + sizeof(wchar_t) * 2, 0);
        DWORD read = size;
        if (RegQueryValueExW(key, name, nullptr, &type, buffer.data(), &read) == ERROR_SUCCESS) {
            if (type == REG_MULTI_SZ) {
                result = MultiSzText(buffer);
            } else {
                result.assign(reinterpret_cast<const wchar_t*>(buffer.data()));
                if (expand && type == REG_EXPAND_SZ) {
                    wchar_t expanded[2048] = {};
                    DWORD needed = ExpandEnvironmentStringsW(result.c_str(), expanded, 2048);
                    if (needed && needed <= 2048) result = expanded;
                }
            }
        }
    }
    RegCloseKey(key);
    return Trim(result);
}

bool RegNumber(HKEY root, const wchar_t* subkey, const wchar_t* name, DWORD& value) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return false;
    DWORD type = 0;
    DWORD size = sizeof(value);
    bool ok = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(&value), &size) == ERROR_SUCCESS &&
              type == REG_DWORD && size == sizeof(value);
    RegCloseKey(key);
    return ok;
}

bool RegNumber64(HKEY root, const wchar_t* subkey, const wchar_t* name, unsigned long long& value) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return false;
    DWORD type = 0;
    DWORD size = sizeof(value);
    bool ok = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(&value), &size) == ERROR_SUCCESS &&
              type == REG_QWORD && size == sizeof(value);
    RegCloseKey(key);
    return ok;
}

bool RegBinaryDword(HKEY root, const wchar_t* subkey, const wchar_t* name, DWORD& value) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return false;
    DWORD type = 0;
    BYTE buffer[16] = {};
    DWORD size = sizeof(buffer);
    bool ok = RegQueryValueExW(key, name, nullptr, &type, buffer, &size) == ERROR_SUCCESS &&
              type == REG_BINARY && size >= sizeof(DWORD);
    if (ok) memcpy(&value, buffer, sizeof(DWORD));
    RegCloseKey(key);
    return ok;
}

std::vector<std::wstring> RegSubkeys(HKEY root, const wchar_t* subkey) {
    std::vector<std::wstring> names;
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return names;
    wchar_t name[512] = {};
    for (DWORD index = 0;; ++index) {
        DWORD length = 512;
        if (RegEnumKeyExW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        names.emplace_back(name, length);
    }
    RegCloseKey(key);
    return names;
}


std::wstring JoinText(const std::vector<std::wstring>& items, const wchar_t* separator) {
    std::wstring text;
    for (const std::wstring& item : items) {
        if (item.empty()) continue;
        if (!text.empty()) text += separator;
        text += item;
    }
    return text;
}

std::wstring DetailLines(const std::vector<std::pair<std::wstring, std::wstring>>& fields) {
    std::wstring text;
    for (const auto& field : fields) {
        if (field.second.empty()) continue;
        text += field.first;
        text += L": ";
        text += field.second;
        text += L"\r\n";
    }
    return text;
}

std::wstring MacText(const BYTE* address, ULONG length) {
    if (!address || !length) return L"";
    std::wstring text;
    for (ULONG i = 0; i < length; ++i) {
        if (i) text += L"-";
        text += Format(L"%02X", address[i]);
    }
    return text;
}

std::wstring SockText(const SOCKADDR* address) {
    wchar_t host[INET6_ADDRSTRLEN] = {};
    if (!address) return L"";
    if (address->sa_family == AF_INET) {
        auto* v4 = reinterpret_cast<const SOCKADDR_IN*>(address);
        InetNtopW(AF_INET, &v4->sin_addr, host, INET6_ADDRSTRLEN);
    } else if (address->sa_family == AF_INET6) {
        auto* v6 = reinterpret_cast<const SOCKADDR_IN6*>(address);
        InetNtopW(AF_INET6, &v6->sin6_addr, host, INET6_ADDRSTRLEN);
    }
    return host;
}

std::wstring EpochText(DWORD seconds) {
    if (!seconds) return L"";
    ULARGE_INTEGER value{};
    value.QuadPart = (static_cast<unsigned long long>(seconds) + 11644473600ULL) * 10000000ULL;
    FILETIME fileTime{value.LowPart, value.HighPart};
    return FileTimeText(fileTime);
}

std::wstring DurationText(unsigned long long milliseconds) {
    unsigned long long total = milliseconds / 1000;
    unsigned long long days = total / 86400;
    unsigned long long hours = (total % 86400) / 3600;
    unsigned long long minutes = (total % 3600) / 60;
    unsigned long long seconds = total % 60;
    std::wstring text;
    if (days) text += Format(L"%llu day(s) ", days);
    text += Format(L"%02llu:%02llu:%02llu", hours, minutes, seconds);
    return text;
}

std::wstring ArchitectureText() {
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    switch (info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: return L"x64";
    case PROCESSOR_ARCHITECTURE_ARM64: return L"ARM64";
    case PROCESSOR_ARCHITECTURE_ARM: return L"ARM";
    case PROCESSOR_ARCHITECTURE_IA64: return L"Itanium";
    case PROCESSOR_ARCHITECTURE_INTEL: return L"x86";
    default: return Format(L"unknown (%u)", info.wProcessorArchitecture);
    }
}

bool ElevatedProcess() {
    HANDLE token = nullptr;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    bool elevated = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(token);
    }
    return elevated;
}

std::wstring SidText(PSID sid) {
    if (!sid) return L"";
    LPWSTR text = nullptr;
    std::wstring result;
    if (ConvertSidToStringSidW(sid, &text)) {
        result = text;
        LocalFree(text);
    }
    return result;
}

std::wstring MachineSid() {
    LSA_OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    LSA_HANDLE policy = nullptr;
    if (LsaOpenPolicy(nullptr, &attributes, POLICY_VIEW_LOCAL_INFORMATION, &policy) != 0) return L"";
    PPOLICY_ACCOUNT_DOMAIN_INFO info = nullptr;
    std::wstring result;
    if (LsaQueryInformationPolicy(policy, PolicyAccountDomainInformation,
                                  reinterpret_cast<PVOID*>(&info)) == 0 &&
        info && info->DomainSid) {
        result = SidText(info->DomainSid);
    }
    if (info) LsaFreeMemory(info);
    LsaClose(policy);
    return result;
}

std::wstring CurrentUserSid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return L"";
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    std::wstring result;
    if (size && GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
        result = SidText(user->User.Sid);
    }
    CloseHandle(token);
    return result;
}


struct SmbiosStruct {
    BYTE type = 0;
    std::vector<BYTE> data;
    std::vector<std::string> strings;
};

std::vector<SmbiosStruct> ReadSmbios() {
    std::vector<SmbiosStruct> out;
    DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (size < 8) return out;
    std::vector<BYTE> buffer(size);
    DWORD read = GetSystemFirmwareTable('RSMB', 0, buffer.data(), size);
    if (read < 8) return out;

    const BYTE* data = buffer.data() + 8;
    size_t remaining = read - 8;
    while (remaining >= 4) {
        BYTE type = data[0];
        BYTE length = data[1];
        if (length < 4 || length > remaining) break;

        SmbiosStruct entry;
        entry.type = type;
        entry.data.assign(data, data + length);

        size_t offset = length;
        int guard = 0;
        while (offset < remaining && guard++ < 512) {
            if (data[offset] == 0) {
                ++offset;
                if (offset < remaining && data[offset] == 0) ++offset;
                break;
            }
            size_t start = offset;
            while (offset < remaining && data[offset] != 0) ++offset;
            entry.strings.push_back(std::string(reinterpret_cast<const char*>(data + start), offset - start));
            if (offset < remaining) ++offset;
            if (offset < remaining && data[offset] == 0) {
                ++offset;
                break;
            }
        }
        if (offset > remaining) break;

        bool end = type == 127;
        data += offset;
        remaining -= offset;
        out.push_back(std::move(entry));
        if (end) break;
    }
    return out;
}

std::wstring SmbiosString(const SmbiosStruct& entry, int index) {
    if (index <= 0 || static_cast<size_t>(index) > entry.strings.size()) return L"";
    return Trim(Utf8ToWide(entry.strings[static_cast<size_t>(index) - 1]));
}

BYTE ByteAt(const SmbiosStruct& entry, size_t offset) {
    return offset < entry.data.size() ? entry.data[offset] : 0;
}

WORD WordAt(const SmbiosStruct& entry, size_t offset) {
    return static_cast<WORD>(ByteAt(entry, offset) | (ByteAt(entry, offset + 1) << 8));
}

DWORD DwordAt(const SmbiosStruct& entry, size_t offset) {
    return static_cast<DWORD>(ByteAt(entry, offset)) |
           (static_cast<DWORD>(ByteAt(entry, offset + 1)) << 8) |
           (static_cast<DWORD>(ByteAt(entry, offset + 2)) << 16) |
           (static_cast<DWORD>(ByteAt(entry, offset + 3)) << 24);
}

const SmbiosStruct* FindSmbios(const std::vector<SmbiosStruct>& table, BYTE type) {
    for (const SmbiosStruct& entry : table) {
        if (entry.type == type) return &entry;
    }
    return nullptr;
}

std::wstring SmbiosUuid(const SmbiosStruct& entry) {
    if (entry.data.size() < 0x18) return L"";
    const BYTE* raw = entry.data.data() + 0x08;
    bool allZero = true;
    bool allOnes = true;
    for (int i = 0; i < 16; ++i) {
        if (raw[i] != 0) allZero = false;
        if (raw[i] != 0xFF) allOnes = false;
    }
    if (allZero || allOnes) return L"";
    return Format(L"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                  raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6],
                  raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
}

std::wstring MemoryTypeText(BYTE type) {
    switch (type) {
    case 0x03: return L"DRAM";
    case 0x0F: return L"SDRAM";
    case 0x11: return L"RDRAM";
    case 0x12: return L"DDR";
    case 0x13: return L"DDR2";
    case 0x14: return L"DDR2 FB-DIMM";
    case 0x18: return L"DDR3";
    case 0x1A: return L"DDR4";
    case 0x1B: return L"LPDDR";
    case 0x1C: return L"LPDDR2";
    case 0x1D: return L"LPDDR3";
    case 0x1E: return L"LPDDR4";
    case 0x22: return L"DDR5";
    case 0x23: return L"LPDDR5";
    default: return Format(L"type 0x%02X", type);
    }
}

std::wstring MemoryFormText(BYTE form) {
    switch (form) {
    case 0x09: return L"DIMM";
    case 0x0A: return L"TSOP";
    case 0x0B: return L"PGA";
    case 0x0C: return L"RIMM";
    case 0x0D: return L"SODIMM";
    case 0x0E: return L"SRIMM";
    case 0x0F: return L"FB-DIMM";
    case 0x10: return L"Die";
    default: return Format(L"form 0x%02X", form);
    }
}

std::wstring ChassisText(BYTE type) {
    switch (type & 0x7F) {
    case 0x03: return L"Desktop";
    case 0x04: return L"Low profile desktop";
    case 0x05: return L"Pizza box";
    case 0x06: return L"Mini tower";
    case 0x07: return L"Tower";
    case 0x08: return L"Portable";
    case 0x09: return L"Laptop";
    case 0x0A: return L"Notebook";
    case 0x0B: return L"Hand held";
    case 0x0C: return L"Docking station";
    case 0x0D: return L"All in one";
    case 0x0E: return L"Sub notebook";
    case 0x0F: return L"Space-saving";
    case 0x10: return L"Lunch box";
    case 0x11: return L"Main server chassis";
    case 0x1E: return L"Tablet";
    case 0x1F: return L"Convertible";
    case 0x20: return L"Detachable";
    default: return Format(L"chassis 0x%02X", type & 0x7F);
    }
}

unsigned long long MemoryModuleMb(const SmbiosStruct& entry) {
    WORD size = WordAt(entry, 0x0C);
    if (size == 0xFFFF) {
        DWORD extended = DwordAt(entry, 0x1C) & 0x7FFFFFFF;
        return extended;
    }
    if (size == 0) return 0;
    if (size & 0x8000) return (size & 0x7FFF) / 1024;
    return size;
}

std::wstring BusTypeText(int type) {
    switch (type) {
    case 1: return L"SCSI";
    case 2: return L"ATAPI";
    case 3: return L"ATA";
    case 4: return L"IEEE 1394";
    case 5: return L"SSA";
    case 6: return L"Fibre channel";
    case 7: return L"USB";
    case 8: return L"RAID";
    case 9: return L"iSCSI";
    case 10: return L"SAS";
    case 11: return L"SATA";
    case 12: return L"SD";
    case 13: return L"MMC";
    case 14: return L"Virtual";
    case 15: return L"File-backed virtual";
    case 16: return L"Storage spaces";
    case 17: return L"NVMe";
    case 18: return L"SCM";
    case 19: return L"UFS";
    default: return Format(L"bus %d", type);
    }
}

std::wstring AdapterTypeText(ULONG type) {
    switch (type) {
    case IF_TYPE_ETHERNET_CSMACD: return L"Ethernet";
    case IF_TYPE_IEEE80211: return L"Wi-Fi";
    case IF_TYPE_PPP: return L"PPP";
    case IF_TYPE_SOFTWARE_LOOPBACK: return L"Loopback";
    case IF_TYPE_TUNNEL: return L"Tunnel";
    case IF_TYPE_ATM: return L"ATM";
    case IF_TYPE_IEEE1394: return L"IEEE 1394";
    case IF_TYPE_OTHER: return L"Other";
    default: return Format(L"type %lu", type);
    }
}


struct DeviceEntry {
    std::wstring description;
    std::wstring manufacturer;
    std::wstring service;
    std::wstring location;
    std::wstring hardwareIds;
    std::wstring driverKey;
    std::wstring driverVersion;
    std::wstring driverDate;
    std::wstring provider;
    std::wstring status;
    std::wstring instanceId;
};

std::wstring DeviceProperty(HDEVINFO set, SP_DEVINFO_DATA& device, DWORD property) {
    DWORD type = 0;
    DWORD size = 0;
    SetupDiGetDeviceRegistryPropertyW(set, &device, property, &type, nullptr, 0, &size);
    if (!size) return L"";
    std::vector<BYTE> buffer(static_cast<size_t>(size) + sizeof(wchar_t) * 2, 0);
    if (!SetupDiGetDeviceRegistryPropertyW(set, &device, property, &type, buffer.data(), size, &size)) return L"";
    if (type == REG_MULTI_SZ) return MultiSzText(buffer);
    return Trim(std::wstring(reinterpret_cast<const wchar_t*>(buffer.data())));
}

std::vector<DeviceEntry> EnumerateDeviceClass(const GUID& guid) {
    std::vector<DeviceEntry> entries;
    HDEVINFO set = SetupDiGetClassDevsW(&guid, nullptr, nullptr, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) return entries;

    SP_DEVINFO_DATA device{};
    device.cbSize = sizeof(device);
    for (DWORD index = 0; SetupDiEnumDeviceInfo(set, index, &device); ++index) {
        DeviceEntry entry;
        entry.description = DeviceProperty(set, device, SPDRP_DEVICEDESC);
        entry.manufacturer = DeviceProperty(set, device, SPDRP_MFG);
        entry.service = DeviceProperty(set, device, SPDRP_SERVICE);
        entry.location = DeviceProperty(set, device, SPDRP_LOCATION_INFORMATION);
        entry.hardwareIds = DeviceProperty(set, device, SPDRP_HARDWAREID);
        wchar_t instanceId[512] = {};
        if (SetupDiGetDeviceInstanceIdW(set, &device, instanceId, 512, nullptr)) {
            entry.instanceId = instanceId;
        }

        std::wstring driverKey = DeviceProperty(set, device, SPDRP_DRIVER);
        entry.driverKey = driverKey;
        if (!driverKey.empty()) {
            wchar_t guidText[64] = {};
            StringFromGUID2(guid, guidText, 64);
            std::wstring path = L"SYSTEM\\CurrentControlSet\\Control\\Class\\";
            if (driverKey[0] == L'{') path += driverKey;
            else path += std::wstring(guidText) + L"\\" + driverKey;
            entry.driverVersion = RegText(HKEY_LOCAL_MACHINE, path.c_str(), L"DriverVersion");
            entry.driverDate = RegText(HKEY_LOCAL_MACHINE, path.c_str(), L"DriverDate");
            entry.provider = RegText(HKEY_LOCAL_MACHINE, path.c_str(), L"ProviderName");
        }

        ULONG status = 0;
        ULONG problem = 0;
        if (CM_Get_DevNode_Status(&status, &problem, device.DevInst, 0) == CR_SUCCESS) {
            entry.status = (status & DN_STARTED) ? L"Started" : L"Stopped";
            if (problem) entry.status += Format(L" (problem %lu)", problem);
        }
        if (entry.description.empty()) entry.description = entry.instanceId;
        if (entry.description.empty()) continue;
        entries.push_back(std::move(entry));
    }
    SetupDiDestroyDeviceInfoList(set);
    return entries;
}

std::wstring DeviceDetail(const DeviceEntry& entry) {
    return DetailLines({{L"Manufacturer", entry.manufacturer},
                        {L"Status", entry.status},
                        {L"Service", entry.service},
                        {L"Driver version", entry.driverVersion},
                        {L"Driver date", entry.driverDate},
                        {L"Driver provider", entry.provider},
                        {L"Location", entry.location},
                        {L"Instance ID", entry.instanceId},
                        {L"Hardware IDs", entry.hardwareIds}});
}


class Collector {
public:
    Collector(const Sink& sink, std::atomic<bool>& stop) : sink_(sink), stop_(stop) {}

    void Reset() { sink_.Detailed({}, {}, true); }

    void Section(const wchar_t* name) {
        Flush();
        section_ = name;
        ++sections_;
        if (!stop_.load()) sink_.Status(Format(L"Collecting %s\u2026", name));
    }

    void Add(const std::wstring& property, const std::wstring& value, const std::wstring& detail = L"") {
        if (stop_.load() || value.empty()) return;
        rows_.push_back(Row{section_, property, value});
        std::wstring text = detail;
        if (text.empty()) {
            text = L"Section  : " + section_ + L"\r\nProperty : " + property +
                   L"\r\nValue    : " + value;
        }
        details_.push_back(std::move(text));
        ++items_;
        if (rows_.size() >= 200) Flush();
    }

    void AddFlag(const std::wstring& property, bool enabled) {
        Add(property, enabled ? L"Enabled" : L"Disabled");
    }

    void Flush() {
        if (rows_.empty()) return;
        sink_.Detailed(std::move(rows_), std::move(details_), false);
        rows_.clear();
        details_.clear();
    }

    int items() const { return items_; }
    int sections() const { return sections_; }
    bool stopped() const { return stop_.load(); }

private:
    const Sink& sink_;
    std::atomic<bool>& stop_;
    std::wstring section_;
    std::vector<Row> rows_;
    std::vector<std::wstring> details_;
    int items_ = 0;
    int sections_ = 0;
};


void AddIdentity(Collector& c) {
    c.Section(L"Machine identity");

    auto computerName = [](COMPUTER_NAME_FORMAT format) {
        wchar_t buffer[256] = {};
        DWORD size = 256;
        return GetComputerNameExW(format, buffer, &size) ? std::wstring(buffer) : std::wstring();
    };
    c.Add(L"Computer name (NetBIOS)", computerName(ComputerNameNetBIOS));
    c.Add(L"DNS host name", computerName(ComputerNameDnsHostname));
    c.Add(L"Fully qualified name", computerName(ComputerNameDnsFullyQualified));
    c.Add(L"DNS domain", computerName(ComputerNameDnsDomain));

    LPWSTR joinName = nullptr;
    NETSETUP_JOIN_STATUS joinStatus = NetSetupUnknownStatus;
    if (NetGetJoinInformation(nullptr, &joinName, &joinStatus) == NERR_Success) {
        std::wstring text = joinName ? joinName : L"";
        c.Add(joinStatus == NetSetupDomainName ? L"Active Directory domain" : L"Workgroup", text);
        if (joinName) NetApiBufferFree(joinName);
    }

    std::wstring machineGuid = RegText(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    c.Add(L"Machine GUID (HWID)", machineGuid,
          machineGuid.empty() ? L""
                              : L"The MachineGuid value written by Windows setup. Many applications use it as the "
                                L"machine fingerprint (HWID).\r\nRegistry: HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid\r\n");

    c.Add(L"Machine SID", MachineSid(),
          L"Derived from the local account domain SID; every local account SID starts with this prefix.");

    std::wstring productId = RegText(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductId");
    c.Add(L"Windows Product ID", productId);
    std::wstring sqmId = RegText(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId");
    c.Add(L"SQM machine ID", sqmId);

    wchar_t user[256] = {};
    DWORD userSize = 256;
    GetUserNameW(user, &userSize);
    std::wstring domain = RegText(HKEY_CURRENT_USER, L"Volatile Environment", L"USERDOMAIN");
    std::wstring userProfile = RegText(HKEY_CURRENT_USER, L"Volatile Environment", L"USERPROFILE");
    c.Add(L"Current user", domain.empty() ? std::wstring(user) : domain + L"\\" + user);
    c.Add(L"Current user SID", CurrentUserSid());
    c.Add(L"User profile", userProfile);
    c.Add(L"Process elevation", ElevatedProcess() ? L"Administrator" : L"Standard user",
          L"Elevation of the WindChecker process itself. Deep hardware queries can be limited without elevation.");
    c.Add(L"Process architecture", ArchitectureText());

    DWORD sessionId = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
        c.Add(L"Session ID", Format(L"%lu", sessionId));
    }
}

void AddOperatingSystem(Collector& c) {
    c.Section(L"Operating system");
    const wchar_t* versionKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

    c.Add(L"Product name", RegText(HKEY_LOCAL_MACHINE, versionKey, L"ProductName"));
    c.Add(L"Edition", RegText(HKEY_LOCAL_MACHINE, versionKey, L"EditionID"));
    c.Add(L"Display version", RegText(HKEY_LOCAL_MACHINE, versionKey, L"DisplayVersion"));
    c.Add(L"Release ID", RegText(HKEY_LOCAL_MACHINE, versionKey, L"ReleaseId"));

    std::wstring build = RegText(HKEY_LOCAL_MACHINE, versionKey, L"CurrentBuildNumber");
    DWORD ubr = 0;
    if (RegNumber(HKEY_LOCAL_MACHINE, versionKey, L"UBR", ubr)) {
        if (!build.empty()) build += Format(L".%lu", ubr);
    }
    c.Add(L"Build", build);
    c.Add(L"Build lab", RegText(HKEY_LOCAL_MACHINE, versionKey, L"BuildLabEx"));
    c.Add(L"Installation type", RegText(HKEY_LOCAL_MACHINE, versionKey, L"InstallationType"));

    DWORD installDate = 0;
    if (RegNumber(HKEY_LOCAL_MACHINE, versionKey, L"InstallDate", installDate)) {
        c.Add(L"Install date", EpochText(installDate));
    }
    c.Add(L"Registered owner", RegText(HKEY_LOCAL_MACHINE, versionKey, L"RegisteredOwner"));
    c.Add(L"Registered organization", RegText(HKEY_LOCAL_MACHINE, versionKey, L"RegisteredOrganization"));

    std::wstring productType = RegText(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions", L"ProductType");
    if (productType == L"WinNT") productType = L"Workstation (WinNT)";
    else if (productType == L"ServerNT") productType = L"Server (ServerNT)";
    else if (productType == L"LanmanNT") productType = L"Domain controller (LanmanNT)";
    c.Add(L"Product type", productType);

    wchar_t systemRoot[MAX_PATH] = {};
    GetWindowsDirectoryW(systemRoot, MAX_PATH);
    c.Add(L"Windows directory", systemRoot);
    wchar_t systemDrive[64] = {};
    GetEnvironmentVariableW(L"SystemDrive", systemDrive, 64);
    c.Add(L"System drive", systemDrive);
    c.Add(L"Program files", RegText(HKEY_LOCAL_MACHINE, versionKey, L"ProgramFilesDir", true));

    ULONGLONG uptime = GetTickCount64();
    c.Add(L"Uptime", DurationText(uptime));
    FILETIME nowFileTime{};
    GetSystemTimeAsFileTime(&nowFileTime);
    ULARGE_INTEGER nowValue{};
    nowValue.LowPart = nowFileTime.dwLowDateTime;
    nowValue.HighPart = nowFileTime.dwHighDateTime;
    unsigned long long bootValue = nowValue.QuadPart - uptime * 10000ULL;
    FILETIME bootTime{static_cast<DWORD>(bootValue & 0xFFFFFFFF), static_cast<DWORD>(bootValue >> 32)};
    c.Add(L"Last boot", FileTimeText(bootTime));

    TIME_ZONE_INFORMATION zone{};
    DWORD zoneId = GetTimeZoneInformation(&zone);
    std::wstring zoneName = zoneId == TIME_ZONE_ID_DAYLIGHT ? zone.DaylightName : zone.StandardName;
    c.Add(L"Time zone", Format(L"%s (UTC%+d)", zoneName.c_str(), -(static_cast<int>(zone.Bias) / 60)));
    c.Add(L"Current time", NowStamp());

    wchar_t localeName[LOCALE_NAME_MAX_LENGTH] = {};
    if (GetSystemDefaultLocaleName(localeName, LOCALE_NAME_MAX_LENGTH)) {
        c.Add(L"System locale", localeName);
    }
    if (GetUserDefaultLocaleName(localeName, LOCALE_NAME_MAX_LENGTH)) {
        c.Add(L"User locale", localeName);
    }
    c.Add(L"ANSI code page", Format(L"%u", GetACP()));
    c.Add(L"OEM code page", Format(L"%u", GetOEMCP()));

    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    c.Add(L"Processor architecture", ArchitectureText());
    c.Add(L"Page size", SizeText(info.dwPageSize));
    c.Add(L"Allocation granularity", SizeText(info.dwAllocationGranularity));
}

void AddFirmware(Collector& c) {
    c.Section(L"Firmware and SMBIOS");

    std::vector<SmbiosStruct> table = ReadSmbios();
    {

        DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
        if (size >= 8) {
            std::vector<BYTE> header(size);
            if (GetSystemFirmwareTable('RSMB', 0, header.data(), size) >= 8) {
                if (header[3]) {
                    c.Add(L"SMBIOS version", Format(L"%u.%u (DMI %u)", header[1], header[2], header[3]));
                } else {
                    c.Add(L"SMBIOS version", Format(L"%u.%u", header[1], header[2]));
                }
            }
        }
    }

    FIRMWARE_TYPE firmwareType{};
    if (GetFirmwareType(&firmwareType)) {
        const wchar_t* text = L"Unknown";
        if (firmwareType == FirmwareTypeBios) text = L"Legacy BIOS";
        else if (firmwareType == FirmwareTypeUefi) text = L"UEFI";
        c.Add(L"Firmware type", text);
    }

    DWORD secureBoot = 0;
    if (RegNumber(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                  L"UEFISecureBootEnabled", secureBoot)) {
        c.AddFlag(L"Secure Boot", secureBoot != 0);
    } else if (firmwareType == FirmwareTypeBios) {
        c.Add(L"Secure Boot", L"Not available (legacy BIOS)");
    }

    if (const SmbiosStruct* bios = FindSmbios(table, 0)) {
        c.Add(L"BIOS vendor", SmbiosString(*bios, ByteAt(*bios, 0x04)));
        c.Add(L"BIOS version", SmbiosString(*bios, ByteAt(*bios, 0x05)));
        c.Add(L"BIOS release date", SmbiosString(*bios, ByteAt(*bios, 0x08)));
        c.Add(L"BIOS ROM size", Format(L"%u KB", (ByteAt(*bios, 0x09) + 1) * 64));
    }

    if (const SmbiosStruct* system = FindSmbios(table, 1)) {
        c.Add(L"System manufacturer", SmbiosString(*system, ByteAt(*system, 0x04)));
        c.Add(L"System product", SmbiosString(*system, ByteAt(*system, 0x05)));
        c.Add(L"System version", SmbiosString(*system, ByteAt(*system, 0x06)));
        std::wstring serial = SmbiosString(*system, ByteAt(*system, 0x07));
        c.Add(L"System serial number", serial,
              L"SMBIOS Type 1 serial number; often used as the hardware ID by licensing systems.");
        std::wstring uuid = SmbiosUuid(*system);
        c.Add(L"System UUID", uuid,
              L"SMBIOS Type 1 UUID. This is the firmware-level machine identifier (HWID).");
        c.Add(L"System SKU", SmbiosString(*system, ByteAt(*system, 0x19)));
        c.Add(L"System family", SmbiosString(*system, ByteAt(*system, 0x1A)));
    }

    if (const SmbiosStruct* board = FindSmbios(table, 2)) {
        c.Add(L"Baseboard manufacturer", SmbiosString(*board, ByteAt(*board, 0x04)));
        c.Add(L"Baseboard product", SmbiosString(*board, ByteAt(*board, 0x05)));
        c.Add(L"Baseboard version", SmbiosString(*board, ByteAt(*board, 0x06)));
        c.Add(L"Baseboard serial", SmbiosString(*board, ByteAt(*board, 0x07)));
        c.Add(L"Baseboard asset tag", SmbiosString(*board, ByteAt(*board, 0x08)));
    }

    if (const SmbiosStruct* chassis = FindSmbios(table, 3)) {
        c.Add(L"Chassis type", ChassisText(ByteAt(*chassis, 0x05)));
        c.Add(L"Chassis manufacturer", SmbiosString(*chassis, ByteAt(*chassis, 0x04)));
        c.Add(L"Chassis serial", SmbiosString(*chassis, ByteAt(*chassis, 0x07)));
        c.Add(L"Chassis asset tag", SmbiosString(*chassis, ByteAt(*chassis, 0x08)));
    }

    if (table.empty()) {
        c.Add(L"BIOS vendor", RegText(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor"));
        c.Add(L"BIOS version", RegText(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVersion"));
        c.Add(L"System manufacturer", RegText(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer"));
        c.Add(L"System product", RegText(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName"));
        c.Add(L"Baseboard product", RegText(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardProduct"));
    }
}

void AddProcessor(Collector& c) {
    c.Section(L"Processor");
    const wchar_t* cpuKey = L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
    c.Add(L"Name", RegText(HKEY_LOCAL_MACHINE, cpuKey, L"ProcessorNameString"));
    c.Add(L"Vendor", RegText(HKEY_LOCAL_MACHINE, cpuKey, L"VendorIdentifier"));
    c.Add(L"Identifier", RegText(HKEY_LOCAL_MACHINE, cpuKey, L"Identifier"));
    c.Add(L"Architecture", ArchitectureText());

    DWORD mhz = 0;
    if (RegNumber(HKEY_LOCAL_MACHINE, cpuKey, L"~MHz", mhz)) {
        c.Add(L"Reported clock", Format(L"%lu MHz", mhz));
    }

    DWORD length = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &length);
    if (length) {
        std::vector<BYTE> buffer(length);
        if (GetLogicalProcessorInformationEx(RelationProcessorCore,
                                             reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data()),
                                             &length)) {
            size_t offset = 0;
            DWORD cores = 0;
            while (offset + 8 <= length) {
                auto* info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data() + offset);
                if (!info->Size) break;
                if (info->Relationship == RelationProcessorCore) ++cores;
                offset += info->Size;
            }
            c.Add(L"Physical cores", Format(L"%lu", cores));
        }
    }
    c.Add(L"Logical processors", Format(L"%lu", GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)));

    length = 0;
    GetLogicalProcessorInformationEx(RelationCache, nullptr, &length);
    if (length) {
        std::vector<BYTE> buffer(length);
        if (GetLogicalProcessorInformationEx(RelationCache,
                                             reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data()),
                                             &length)) {
            std::map<DWORD, DWORD> best;
            size_t offset = 0;
            while (offset + 8 <= length) {
                auto* info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data() + offset);
                if (!info->Size) break;
                if (info->Relationship == RelationCache) {
                    DWORD level = info->Cache.Level;
                    DWORD size = info->Cache.CacheSize;
                    auto found = best.find(level);
                    if (found == best.end() || found->second < size) best[level] = size;
                }
                offset += info->Size;
            }
            for (const auto& entry : best) {
                c.Add(Format(L"L%lu cache", entry.first), SizeText(entry.second));
            }
        }
    }

    std::vector<SmbiosStruct> table = ReadSmbios();
    if (const SmbiosStruct* cpu = FindSmbios(table, 4)) {
        c.Add(L"Socket", SmbiosString(*cpu, ByteAt(*cpu, 0x04)));
        c.Add(L"SMBIOS manufacturer", SmbiosString(*cpu, ByteAt(*cpu, 0x07)));
        c.Add(L"SMBIOS version", SmbiosString(*cpu, ByteAt(*cpu, 0x10)));
        DWORD maxSpeed = WordAt(*cpu, 0x14);
        DWORD currentSpeed = WordAt(*cpu, 0x16);
        if (maxSpeed) c.Add(L"Max speed", Format(L"%lu MHz", maxSpeed));
        if (currentSpeed) c.Add(L"Current speed", Format(L"%lu MHz", currentSpeed));
        if (cpu->data.size() >= 0x10) {
            DWORD low = DwordAt(*cpu, 0x08);
            DWORD high = DwordAt(*cpu, 0x0C);
            if (low || high) c.Add(L"Processor ID", Format(L"%08X%08X", high, low));
        }
    }
}

void AddMemory(Collector& c) {
    c.Section(L"Memory");
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    if (GlobalMemoryStatusEx(&memory)) {
        c.Add(L"Installed physical memory", SizeText(memory.ullTotalPhys));
        c.Add(L"Available physical memory", SizeText(memory.ullAvailPhys));
        c.Add(L"Memory load", Format(L"%lu%%", memory.dwMemoryLoad));
        c.Add(L"Page file total", SizeText(memory.ullTotalPageFile));
        c.Add(L"Page file available", SizeText(memory.ullAvailPageFile));
        c.Add(L"Virtual address space", SizeText(memory.ullTotalVirtual));
        c.Add(L"Virtual address space free", SizeText(memory.ullAvailVirtual));
    }

    std::vector<SmbiosStruct> table = ReadSmbios();
    int modules = 0;
    for (const SmbiosStruct& entry : table) {
        if (entry.type != 17) continue;
        unsigned long long megabytes = MemoryModuleMb(entry);
        if (!megabytes) continue;
        ++modules;
        std::wstring locator = SmbiosString(entry, ByteAt(entry, 0x10));
        std::wstring bank = SmbiosString(entry, ByteAt(entry, 0x11));
        if (locator.empty()) locator = Format(L"Module %d", modules);
        std::wstring manufacturer = SmbiosString(entry, ByteAt(entry, 0x17));
        std::wstring partNumber = SmbiosString(entry, ByteAt(entry, 0x1A));
        std::wstring serial = SmbiosString(entry, ByteAt(entry, 0x18));
        std::wstring type = MemoryTypeText(ByteAt(entry, 0x12));
        std::wstring form = MemoryFormText(ByteAt(entry, 0x0E));
        DWORD speed = WordAt(entry, 0x15);
        DWORD configured = entry.data.size() >= 0x22 ? WordAt(entry, 0x20) : 0;

        std::wstring value = SizeText(megabytes * 1024ULL * 1024ULL);
        if (!type.empty()) value += L" \u00B7 " + type;
        if (speed) value += Format(L"-%lu", speed);
        if (!manufacturer.empty()) value += L" \u00B7 " + manufacturer;
        if (!partNumber.empty()) value += L" " + partNumber;

        c.Add(locator, value,
              DetailLines({{L"Slot", locator},
                           {L"Bank", bank},
                           {L"Size", SizeText(megabytes * 1024ULL * 1024ULL)},
                           {L"Type", type},
                           {L"Form factor", form},
                           {L"Speed", speed ? Format(L"%lu MT/s", speed) : L""},
                           {L"Configured speed", configured ? Format(L"%lu MT/s", configured) : L""},
                           {L"Manufacturer", manufacturer},
                           {L"Part number", partNumber},
                           {L"Serial number", serial}}));
    }
    if (modules) c.Add(L"Populated slots", Format(L"%d", modules));
}

void AddStorage(Collector& c) {
    c.Section(L"Storage");

    unsigned long long diskTotal = 0;
    int disks = 0;
    for (int index = 0; index < 32; ++index) {
        std::wstring path = Format(L"\\\\.\\PhysicalDrive%d", index);
        HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                    OPEN_EXISTING, 0, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            handle = CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
        }
        if (handle == INVALID_HANDLE_VALUE) continue;

        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;
        std::vector<BYTE> buffer(4096);
        DWORD returned = 0;
        std::wstring vendor, product, serial, revision;
        int busType = 0;
        if (DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                            buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr)) {
            auto* descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
            auto field = [&](DWORD offset) -> std::wstring {
                if (!offset || offset >= returned) return L"";
                const char* text = reinterpret_cast<const char*>(buffer.data() + offset);
                size_t maxLength = returned - offset;
                size_t length = strnlen(text, maxLength);
                return Trim(Utf8ToWide(std::string(text, length)));
            };
            vendor = field(descriptor->VendorIdOffset);
            product = field(descriptor->ProductIdOffset);
            serial = field(descriptor->SerialNumberOffset);
            revision = field(descriptor->ProductRevisionOffset);
            busType = static_cast<int>(descriptor->BusType);
        }

        GET_LENGTH_INFORMATION lengthInfo{};
        DWORD got = 0;
        unsigned long long bytes = 0;
        if (DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0, &lengthInfo,
                            sizeof(lengthInfo), &got, nullptr)) {
            bytes = static_cast<unsigned long long>(lengthInfo.Length.QuadPart);
        }
        if (!bytes) {
            std::vector<BYTE> geometryBuffer(sizeof(DISK_GEOMETRY_EX) + 512, 0);
            if (DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0,
                                geometryBuffer.data(), static_cast<DWORD>(geometryBuffer.size()),
                                &got, nullptr)) {
                auto* geometry = reinterpret_cast<DISK_GEOMETRY_EX*>(geometryBuffer.data());
                bytes = static_cast<unsigned long long>(geometry->DiskSize.QuadPart);
            }
        }
        CloseHandle(handle);

        ++disks;
        diskTotal += bytes;
        std::wstring label = product.empty() ? Format(L"Disk %d", index) : product;
        if (!vendor.empty() && product.find(vendor) == std::wstring::npos) label = vendor + L" " + label;
        std::wstring value = label;
        if (bytes) value += L" \u00B7 " + SizeText(bytes);

        c.Add(Format(L"Disk %d", index), value,
              DetailLines({{L"Path", path},
                           {L"Vendor", vendor},
                           {L"Model", product},
                           {L"Serial number", serial},
                           {L"Revision", revision},
                           {L"Bus type", BusTypeText(busType)},
                           {L"Capacity", bytes ? SizeText(bytes) : L""}}));
    }
    if (disks) c.Add(L"Physical disk total", SizeText(diskTotal));

    wchar_t drives[1024] = {};
    DWORD length = GetLogicalDriveStringsW(1024, drives);
    if (length) {
        for (const wchar_t* drive = drives; *drive; drive += wcslen(drive) + 1) {
            UINT type = GetDriveTypeW(drive);
            if (type == DRIVE_NO_ROOT_DIR) continue;

            wchar_t label[256] = {};
            wchar_t fileSystem[64] = {};
            DWORD serial = 0;
            DWORD maxComponent = 0;
            DWORD flags = 0;
            bool infoOk = GetVolumeInformationW(drive, label, 256, &serial, &maxComponent, &flags,
                                                fileSystem, 64) != FALSE;

            ULARGE_INTEGER freeBytes{}, totalBytes{}, totalFree{};
            bool spaceOk = GetDiskFreeSpaceExW(drive, &freeBytes, &totalBytes, &totalFree) != FALSE;

            std::wstring typeText;
            switch (type) {
            case DRIVE_FIXED: typeText = L"Fixed"; break;
            case DRIVE_REMOVABLE: typeText = L"Removable"; break;
            case DRIVE_REMOTE: typeText = L"Network"; break;
            case DRIVE_CDROM: typeText = L"Optical"; break;
            case DRIVE_RAMDISK: typeText = L"RAM disk"; break;
            default: typeText = L"Unknown"; break;
            }

            std::wstring value = typeText;
            if (fileSystem[0]) value += std::wstring(L" \u00B7 ") + fileSystem;
            if (label[0]) value += std::wstring(L" \u00B7 ") + label;
            if (spaceOk) {
                value += Format(L" \u00B7 %s free of %s", SizeText(freeBytes.QuadPart).c_str(),
                                SizeText(totalBytes.QuadPart).c_str());
            }

            c.Add(drive, value,
                  DetailLines({{L"Drive type", typeText},
                               {L"Label", label},
                               {L"File system", fileSystem},
                               {L"Volume serial", Format(L"%04X-%04X", serial >> 16, serial & 0xFFFF)},
                               {L"Capacity", spaceOk ? SizeText(totalBytes.QuadPart) : L""},
                               {L"Free", spaceOk ? SizeText(freeBytes.QuadPart) : L""},
                               {L"Maximum component", infoOk ? Format(L"%lu", maxComponent) : L""}}));
        }
    }
}

void AddGraphics(Collector& c) {
    c.Section(L"Graphics");

    std::vector<DeviceEntry> adapters = EnumerateDeviceClass(kDisplayClass);
    for (const DeviceEntry& adapter : adapters) {
        std::wstring detail = DeviceDetail(adapter);
        DISPLAY_DEVICEW device{};
        device.cb = sizeof(device);
        for (DWORD index = 0; EnumDisplayDevicesW(nullptr, index, &device, 0); ++index) {
            if (!(device.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP)) continue;
            if (adapter.description.find(device.DeviceString) == std::wstring::npos &&
                device.DeviceString[0] &&
                std::wstring(device.DeviceString).find(adapter.description) == std::wstring::npos) {
                continue;
            }
            detail += L"Active display: " + std::wstring(device.DeviceName) + L"\r\n";
            break;
        }

        unsigned long long vram = 0;
        const wchar_t* classRoot = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}";
        for (const std::wstring& subkey : RegSubkeys(HKEY_LOCAL_MACHINE, classRoot)) {
            std::wstring path = std::wstring(classRoot) + L"\\" + subkey;
            std::wstring desc = RegText(HKEY_LOCAL_MACHINE, path.c_str(), L"DriverDesc");
            if (desc.empty() || ToLower(desc) != ToLower(adapter.description)) continue;
            unsigned long long bytes = 0;
            if (RegNumber64(HKEY_LOCAL_MACHINE, path.c_str(), L"HardwareInformation.qwMemorySize", bytes)) {
                vram = bytes / (1024ULL * 1024ULL);
            } else {
                DWORD legacy = 0;
                if (RegBinaryDword(HKEY_LOCAL_MACHINE, path.c_str(), L"HardwareInformation.MemorySize", legacy)) {
                    vram = legacy / (1024ULL * 1024ULL);
                }
            }
            if (vram) detail += Format(L"VRAM: %llu MB\r\n", vram);
            break;
        }

        std::wstring value = adapter.driverVersion.empty() ? adapter.status
                                                           : L"Driver " + adapter.driverVersion;
        if (vram) value += Format(L" \u00B7 %llu MB", vram);
        c.Add(adapter.description, value, detail);
    }
    if (adapters.empty()) c.Add(L"Graphics adapter", L"None reported");

    int monitorIndex = 0;
    DISPLAY_DEVICEW device{};
    device.cb = sizeof(device);
    for (DWORD index = 0; EnumDisplayDevicesW(nullptr, index, &device, 0); ++index) {
        if (!(device.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP)) continue;
        DISPLAY_DEVICEW monitor{};
        monitor.cb = sizeof(monitor);
        for (DWORD sub = 0; EnumDisplayDevicesW(device.DeviceName, sub, &monitor, 0); ++sub) {
            DEVMODEW mode{};
            mode.dmSize = sizeof(mode);
            EnumDisplaySettingsW(device.DeviceName, ENUM_CURRENT_SETTINGS, &mode);
            ++monitorIndex;
            std::wstring value = Format(L"%ld \u00D7 %ld", mode.dmPelsWidth, mode.dmPelsHeight);
            if (mode.dmDisplayFrequency) value += Format(L" @ %lu Hz", mode.dmDisplayFrequency);
            if (device.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) value += L" \u00B7 primary";
            c.Add(Format(L"Display %d", monitorIndex), value,
                  DetailLines({{L"Adapter", device.DeviceString},
                               {L"Monitor", monitor.DeviceString},
                               {L"Monitor ID", monitor.DeviceID},
                               {L"Device", device.DeviceName},
                               {L"Resolution", Format(L"%ld \u00D7 %ld", mode.dmPelsWidth, mode.dmPelsHeight)},
                               {L"Refresh rate", mode.dmDisplayFrequency ? Format(L"%lu Hz", mode.dmDisplayFrequency) : L""},
                               {L"Colour depth", Format(L"%lu bpp", mode.dmBitsPerPel)}}));
        }
    }
    if (!monitorIndex) {
        c.Add(L"Display", L"Not enumerated");
    }
}

void AddNetwork(Collector& c) {
    c.Section(L"Network");

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
    if (result != NO_ERROR) {
        c.Add(L"Adapters", Format(L"Enumeration failed (error %lu)", result));
        return;
    }

    int count = 0;
    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get()); adapter; adapter = adapter->Next) {
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        std::vector<std::wstring> v4, v6, gateway, dns;
        for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            std::wstring address = SockText(unicast->Address.lpSockaddr);
            if (address.empty()) continue;
            if (unicast->Address.lpSockaddr->sa_family == AF_INET) v4.push_back(address);
            else v6.push_back(address);
        }
        for (auto* entry = adapter->FirstGatewayAddress; entry; entry = entry->Next) {
            std::wstring address = SockText(entry->Address.lpSockaddr);
            if (!address.empty()) gateway.push_back(address);
        }
        for (auto* entry = adapter->FirstDnsServerAddress; entry; entry = entry->Next) {
            std::wstring address = SockText(entry->Address.lpSockaddr);
            if (!address.empty()) dns.push_back(address);
        }

        std::wstring mac = MacText(adapter->PhysicalAddress, adapter->PhysicalAddressLength);
        bool up = adapter->OperStatus == IfOperStatusUp;
        std::wstring value = up ? L"Up" : L"Disconnected";
        if (!v4.empty()) value += L" \u00B7 " + JoinText(v4, L", ");
        if (!mac.empty()) value += L" \u00B7 " + mac;

        ++count;
        c.Add(adapter->FriendlyName[0] ? adapter->FriendlyName : adapter->Description, value,
              DetailLines({{L"Description", adapter->Description},
                           {L"Friendly name", adapter->FriendlyName},
                           {L"Type", AdapterTypeText(adapter->IfType)},
                           {L"Status", up ? L"Up" : L"Disconnected"},
                           {L"MAC address", mac},
                           {L"IPv4", JoinText(v4, L", ")},
                           {L"IPv6", JoinText(v6, L", ")},
                           {L"Gateway", JoinText(gateway, L", ")},
                           {L"DNS servers", JoinText(dns, L", ")},
                           {L"DNS suffix", adapter->DnsSuffix},
                           {L"MTU", Format(L"%lu", adapter->Mtu)},
                           {L"Link speed", adapter->TransmitLinkSpeed ? Format(L"%s", SizeText(adapter->TransmitLinkSpeed / 8).c_str()) + L"/s" : L""},
                           {L"Adapter GUID", Utf8ToWide(adapter->AdapterName ? adapter->AdapterName : "")},
                           {L"Interface index", Format(L"%lu", adapter->IfIndex)}}));
    }
    c.Add(L"Adapter count", Format(L"%d", count));
}

void AddSecurity(Collector& c) {
    c.Section(L"Security posture");

    DWORD value = 0;
    if (RegNumber(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                  L"EnableLUA", value)) {
        c.AddFlag(L"User Account Control", value != 0);
    }
    if (RegNumber(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                  L"ConsentPromptBehaviorAdmin", value)) {
        std::wstring prompt;
        switch (value) {
        case 0: prompt = L"Elevate without prompting"; break;
        case 1: prompt = L"Prompt for credentials on secure desktop"; break;
        case 2: prompt = L"Prompt for consent on secure desktop"; break;
        case 5: prompt = L"Prompt for consent for non-Windows binaries"; break;
        default: prompt = Format(L"Mode %lu", value); break;
        }
        c.Add(L"UAC admin prompt", prompt);
    }

    if (RegNumber(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                  L"DisableAntiSpyware", value)) {
        c.AddFlag(L"Defender anti-spyware", value == 0);
    }
    if (RegNumber(HKEY_LOCAL_MACHINE,
                  L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
                  L"DisableRealtimeMonitoring", value)) {
        c.AddFlag(L"Defender real-time protection", value == 0);
    }

    const wchar_t* firewallRoot = L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy";
    struct Profile {
        const wchar_t* key;
        const wchar_t* label;
    };
    const Profile profiles[] = {{L"DomainProfile", L"Domain"},
                                {L"StandardProfile", L"Private"},
                                {L"PublicProfile", L"Public"}};
    for (const Profile& profile : profiles) {
        std::wstring path = std::wstring(firewallRoot) + L"\\" + profile.key;
        if (RegNumber(HKEY_LOCAL_MACHINE, path.c_str(), L"EnableFirewall", value)) {
            c.AddFlag(Format(L"Firewall (%s profile)", profile.label), value != 0);
        }
    }

    if (RegNumber(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL", value)) {
        c.AddFlag(L"LSA protection (RunAsPPL)", value != 0);
    }
    if (RegNumber(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                  L"EnableVirtualizationBasedSecurity", value)) {
        c.AddFlag(L"Virtualization-based security", value != 0);
    }
    if (RegNumber(HKEY_LOCAL_MACHINE,
                  L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                  L"Enabled", value)) {
        c.AddFlag(L"Memory integrity (HVCI)", value != 0);
    }

    std::vector<DeviceEntry> tpm = EnumerateDeviceClass(kSecurityClass);
    if (tpm.empty()) {
        c.Add(L"TPM", L"Not reported by the device tree");
    } else {
        for (const DeviceEntry& device : tpm) {
            c.Add(L"TPM", device.description, DeviceDetail(device));
        }
    }
}

void AddAccounts(Collector& c) {
    c.Section(L"Accounts and sessions");

    LPUSER_INFO_3 users = nullptr;
    DWORD read = 0;
    DWORD total = 0;
    DWORD resume = 0;
    NET_API_STATUS status = NetUserEnum(nullptr, 3, FILTER_NORMAL_ACCOUNT,
                                        reinterpret_cast<LPBYTE*>(&users), MAX_PREFERRED_LENGTH,
                                        &read, &total, &resume);
    if (status == NERR_Success && users) {
        for (DWORD index = 0; index < read; ++index) {
            const USER_INFO_3& user = users[index];
            std::wstring name = user.usri3_name ? user.usri3_name : L"";
            if (name.empty()) continue;
            std::wstring fullName = user.usri3_full_name ? user.usri3_full_name : L"";
            std::wstring comment = user.usri3_comment ? user.usri3_comment : L"";
            bool disabled = (user.usri3_flags & UF_ACCOUNTDISABLE) != 0;
            bool locked = (user.usri3_flags & UF_LOCKOUT) != 0;
            bool admin = user.usri3_priv == USER_PRIV_ADMIN;

            std::wstring value = admin ? L"Administrator" : L"Standard user";
            if (disabled) value += L" \u00B7 disabled";
            if (locked) value += L" \u00B7 locked out";

            c.Add(name, value,
                  DetailLines({{L"Full name", fullName},
                               {L"Comment", comment},
                               {L"Privilege", admin ? L"Administrator" : L"User"},
                               {L"Disabled", disabled ? L"Yes" : L"No"},
                               {L"Locked out", locked ? L"Yes" : L"No"},
                               {L"Password required", (user.usri3_flags & UF_PASSWD_NOTREQD) ? L"No" : L"Yes"},
                               {L"Password never expires", (user.usri3_flags & UF_DONT_EXPIRE_PASSWD) ? L"Yes" : L"No"},
                               {L"Last logon", EpochText(user.usri3_last_logon)},
                               {L"Logon count", Format(L"%lu", user.usri3_num_logons)}}));
        }
    }
    if (users) NetApiBufferFree(users);

    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD count = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        for (DWORD index = 0; index < count; ++index) {
            const WTS_SESSION_INFOW& session = sessions[index];
            LPWSTR user = nullptr;
            LPWSTR domain = nullptr;
            LPWSTR client = nullptr;
            DWORD bytes = 0;
            if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session.SessionId, WTSUserName,
                                            &user, &bytes) && user && user[0]) {
                WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session.SessionId, WTSDomainName,
                                            &domain, &bytes);
                WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session.SessionId, WTSClientName,
                                            &client, &bytes);
                std::wstring account = std::wstring(domain && domain[0] ? domain : L"") + L"\\" + user;
                std::wstring state = session.State == WTSActive ? L"Active" : L"Disconnected";
                c.Add(Format(L"Session %lu", session.SessionId), account + L" \u00B7 " + state,
                      DetailLines({{L"User", account},
                                   {L"State", state},
                                   {L"Client", client ? client : L""},
                                   {L"Station", session.pWinStationName}}));
            }
            if (user) WTSFreeMemory(user);
            if (domain) WTSFreeMemory(domain);
            if (client) WTSFreeMemory(client);
        }
        WTSFreeMemory(sessions);
    }
}

void AddEnvironment(Collector& c) {
    c.Section(L"Environment");
    LPWCH block = GetEnvironmentStringsW();
    if (!block) return;
    std::vector<std::wstring> entries;
    for (const wchar_t* cursor = block; *cursor; cursor += wcslen(cursor) + 1) {
        entries.emplace_back(cursor);
    }
    FreeEnvironmentStringsW(block);
    std::sort(entries.begin(), entries.end());
    for (const std::wstring& entry : entries) {
        if (entry.empty() || entry[0] == L'=') continue;
        size_t split = entry.find(L'=');
        if (split == std::wstring::npos) continue;
        c.Add(entry.substr(0, split), entry.substr(split + 1));
    }
}

void AddInstalledSoftware(Collector& c) {
    c.Section(L"Installed software");

    struct Entry {
        std::wstring name;
        std::wstring version;
        std::wstring publisher;
        std::wstring date;
        std::wstring location;
        std::wstring key;
        unsigned long long sizeKb = 0;
    };
    std::vector<Entry> entries;
    std::set<std::wstring> seen;

    const wchar_t* roots[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    };
    for (const wchar_t* root : roots) {
        for (const std::wstring& subkey : RegSubkeys(HKEY_LOCAL_MACHINE, root)) {
            std::wstring path = std::wstring(root) + L"\\" + subkey;
            std::wstring name = RegText(HKEY_LOCAL_MACHINE, path.c_str(), L"DisplayName");
            if (name.empty()) continue;
            std::wstring key = ToLower(name + L"|" + subkey);
            if (!seen.insert(key).second) continue;

            Entry entry;
            entry.name = name;
            entry.version = RegText(HKEY_LOCAL_MACHINE, path.c_str(), L"DisplayVersion");
            entry.publisher = RegText(HKEY_LOCAL_MACHINE, path.c_str(), L"Publisher");
            entry.date = RegText(HKEY_LOCAL_MACHINE, path.c_str(), L"InstallDate");
            entry.location = RegText(HKEY_LOCAL_MACHINE, path.c_str(), L"InstallLocation");
            entry.key = path;
            DWORD sizeKb = 0;
            if (RegNumber(HKEY_LOCAL_MACHINE, path.c_str(), L"EstimatedSize", sizeKb)) entry.sizeKb = sizeKb;
            entries.push_back(std::move(entry));
        }
    }
    for (const std::wstring& subkey :
         RegSubkeys(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")) {
        std::wstring path = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\") + subkey;
        std::wstring name = RegText(HKEY_CURRENT_USER, path.c_str(), L"DisplayName");
        if (name.empty()) continue;
        std::wstring key = ToLower(name + L"|" + subkey);
        if (!seen.insert(key).second) continue;

        Entry entry;
        entry.name = name;
        entry.version = RegText(HKEY_CURRENT_USER, path.c_str(), L"DisplayVersion");
        entry.publisher = RegText(HKEY_CURRENT_USER, path.c_str(), L"Publisher");
        entry.date = RegText(HKEY_CURRENT_USER, path.c_str(), L"InstallDate");
        entry.location = RegText(HKEY_CURRENT_USER, path.c_str(), L"InstallLocation");
        entry.key = L"HKCU\\" + path;
        DWORD sizeKb = 0;
        if (RegNumber(HKEY_CURRENT_USER, path.c_str(), L"EstimatedSize", sizeKb)) entry.sizeKb = sizeKb;
        entries.push_back(std::move(entry));
    }

    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
        return ToLower(a.name) < ToLower(b.name);
    });

    int shown = 0;
    for (const Entry& entry : entries) {
        if (shown >= 800) break;
        ++shown;
        std::wstring value = entry.version.empty() ? entry.publisher : entry.version;
        if (!entry.publisher.empty() && !entry.version.empty()) value += L" \u00B7 " + entry.publisher;
        if (value.empty()) value = L"Installed";
        c.Add(entry.name, value,
              DetailLines({{L"Version", entry.version},
                           {L"Publisher", entry.publisher},
                           {L"Install date", entry.date},
                           {L"Install location", entry.location},
                           {L"Estimated size", entry.sizeKb ? SizeText(entry.sizeKb * 1024ULL) : L""},
                           {L"Registry key", entry.key}}));
    }
    c.Add(L"Installed packages", Format(L"%zu", entries.size()));
}

void AddUpdates(Collector& c) {
    c.Section(L"Updates");
    std::vector<std::wstring> packages =
        RegSubkeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages");
    std::set<std::wstring> seen;
    std::vector<std::pair<std::wstring, std::wstring>> updates;
    for (const std::wstring& package : packages) {
        size_t at = package.find(L"KB");
        if (at == std::wstring::npos || at + 2 >= package.size()) continue;
        std::wstring number;
        for (size_t i = at + 2; i < package.size() && iswdigit(package[i]); ++i) number.push_back(package[i]);
        if (number.size() < 5) continue;
        std::wstring kb = L"KB" + number;
        if (!seen.insert(kb).second) continue;
        updates.emplace_back(kb, package);
    }
    std::sort(updates.begin(), updates.end(), [](const auto& a, const auto& b) {
        return a.first > b.first;
    });
    for (size_t i = 0; i < updates.size() && i < 500; ++i) {
        c.Add(updates[i].first, L"Installed", L"Package: " + updates[i].second + L"\r\n");
    }
    c.Add(L"Detected updates", Format(L"%zu", updates.size()));
}

}

void RunComputerInfo(const Sink& sink, std::atomic<bool>& stop) {
    Collector collector(sink, stop);
    collector.Reset();

    AddIdentity(collector);
    if (collector.stopped()) return;
    AddOperatingSystem(collector);
    if (collector.stopped()) return;
    AddFirmware(collector);
    if (collector.stopped()) return;
    AddProcessor(collector);
    if (collector.stopped()) return;
    AddMemory(collector);
    if (collector.stopped()) return;
    AddStorage(collector);
    if (collector.stopped()) return;
    AddGraphics(collector);
    if (collector.stopped()) return;
    AddNetwork(collector);
    if (collector.stopped()) return;
    AddSecurity(collector);
    if (collector.stopped()) return;
    AddAccounts(collector);
    if (collector.stopped()) return;
    AddEnvironment(collector);
    if (collector.stopped()) return;
    AddInstalledSoftware(collector);
    if (collector.stopped()) return;
    AddUpdates(collector);
    collector.Flush();

    if (collector.stopped()) {
        sink.Done(Format(L"Stopped. %s item(s) collected.", CommaNumber(collector.items()).c_str()));
        return;
    }
    sink.Done(Format(L"Completed. %s item(s) across %d section(s).",
                     CommaNumber(collector.items()).c_str(), collector.sections()));
}
