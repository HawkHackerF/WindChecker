#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include "forensics.h"
#include "ese.h"

#include <shlobj.h>

#include <algorithm>
#include <cstring>
#include <map>

namespace fc {


bool RegView::OpenKey(const std::wstring& subkey, HKEY& out) const {
    std::wstring full;
    if (prefix.empty()) {
        full = subkey;
    } else if (subkey.empty()) {
        full = prefix;
    } else {
        full = prefix + L"\\" + subkey;
    }
    return RegOpenKeyExW(root, full.empty() ? nullptr : full.c_str(), 0,
                        KEY_READ | KEY_WOW64_64KEY, &out) == ERROR_SUCCESS;
}

std::wstring RegView::QueryString(const std::wstring& subkey, const std::wstring& value) const {
    HKEY key = nullptr;
    if (!OpenKey(subkey, key)) return L"";
    std::wstring result;
    DWORD type = 0, size = 0;
    LPCWSTR name = value.empty() ? nullptr : value.c_str();
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) == ERROR_SUCCESS && size > 0 &&
        (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ)) {
        std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 2, 0);
        DWORD read = size;
        if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()),
                             &read) == ERROR_SUCCESS) {
            result.assign(buffer.data());
        }
    }
    RegCloseKey(key);
    return Trim(result);
}

bool RegView::QueryBinary(const std::wstring& subkey, const std::wstring& value,
                          std::vector<BYTE>& out) const {
    HKEY key = nullptr;
    if (!OpenKey(subkey, key)) return false;
    DWORD type = 0, size = 0;
    LPCWSTR name = value.empty() ? nullptr : value.c_str();
    out.clear();
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS ||
        type != REG_BINARY || size == 0) {
        RegCloseKey(key);
        return false;
    }
    out.resize(size);
    DWORD read = size;
    const bool ok = RegQueryValueExW(key, name, nullptr, &type, out.data(), &read) == ERROR_SUCCESS;
    RegCloseKey(key);
    if (!ok) out.clear();
    return ok;
}

std::wstring RegView::LastWrite(const std::wstring& subkey) const {
    HKEY key = nullptr;
    if (!OpenKey(subkey, key)) return L"";
    FILETIME ft{};
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         nullptr, nullptr, &ft) != ERROR_SUCCESS) {
        RegCloseKey(key);
        return L"";
    }
    std::wstring text = FileTimeText(ft);
    RegCloseKey(key);
    return text;
}

std::vector<std::wstring> RegView::Subkeys(const std::wstring& subkey) const {
    HKEY key = nullptr;
    if (!OpenKey(subkey, key)) return {};
    std::vector<std::wstring> names;
    wchar_t name[512] = {};
    for (DWORD i = 0;; ++i) {
        DWORD length = 512;
        if (RegEnumKeyExW(key, i, name, &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        names.emplace_back(name, length);
    }
    RegCloseKey(key);
    return names;
}

std::vector<std::wstring> RegView::ValueNames(const std::wstring& subkey) const {
    HKEY key = nullptr;
    if (!OpenKey(subkey, key)) return {};
    std::vector<std::wstring> names;
    wchar_t name[16384] = {};
    for (DWORD i = 0;; ++i) {
        DWORD length = 16383;
        if (RegEnumValueW(key, i, name, &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        names.emplace_back(name, length);
    }
    RegCloseKey(key);
    return names;
}


RegView LiveHklm() {
    RegView view;
    view.root = HKEY_LOCAL_MACHINE;
    view.rootLabel = L"HKLM (live)";
    return view;
}

RegView LiveHkcu() {
    RegView view;
    view.root = HKEY_CURRENT_USER;
    view.rootLabel = L"HKCU (live)";
    return view;
}


std::wstring Rot13(const std::wstring& text) {
    std::wstring out = text;
    for (wchar_t& c : out) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>((c - L'A' + 13) % 26 + L'A');
        else if (c >= L'a' && c <= L'z') c = static_cast<wchar_t>((c - L'a' + 13) % 26 + L'a');
    }
    return out;
}

std::vector<int> DecodeMruListEx(const std::vector<BYTE>& data) {
    std::vector<int> order;
    const size_t n = data.size();
    for (size_t i = 0; i + 4 <= n; i += 4) {
        DWORD value = 0;
        std::memcpy(&value, data.data() + i, 4);
        if (value == 0xFFFFFFFF) break;
        order.push_back(static_cast<int>(value));
    }
    return order;
}

static bool SafeGetPathFromPidl(const BYTE* data, size_t size, wchar_t* out, size_t outChars) {
    if (size < 2 || !out || outChars == 0) return false;
    size_t offset = 0;
    bool terminated = false;
    while (offset + 2 <= size) {
        unsigned short cb = 0;
        std::memcpy(&cb, data + offset, 2);
        if (cb == 0) {
            terminated = true;
            break;
        }
        if (offset + cb > size) return false;
        offset += cb;
    }
    if (!terminated) return false;

    wchar_t path[MAX_PATH * 4] = {};
    bool ok = false;
    __try {
        ok = SHGetPathFromIDListW(reinterpret_cast<LPITEMIDLIST>(const_cast<BYTE*>(data)), path) != 0 &&
             path[0] != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    if (ok) {
        for (size_t i = 0; i < outChars - 1 && i < _countof(path); ++i) {
            out[i] = path[i];
            if (path[i] == 0) break;
        }
        out[outChars - 1] = 0;
        return true;
    }
    return false;
}

static std::wstring PidlFallbackName(const BYTE* data, size_t size) {
    if (size < 4) return L"";
    const wchar_t* chars = reinterpret_cast<const wchar_t*>(data);
    const size_t n = size / 2;
    size_t bestStart = 0, bestLen = 0, curStart = 0, curLen = 0;
    for (size_t i = 0; i < n; ++i) {
        wchar_t c = chars[i];
        bool printable = (c >= 0x20 && c < 0x7F) || (c >= 0x00A0);
        if (printable) {
            if (curLen == 0) curStart = i;
            ++curLen;
            if (curLen > bestLen) {
                bestLen = curLen;
                bestStart = curStart;
            }
        } else {
            curLen = 0;
        }
    }
    if (bestLen >= 2) return std::wstring(chars + bestStart, bestLen);
    return L"";
}

std::wstring DecodePidlPath(const std::vector<BYTE>& pidl) {
    if (pidl.size() < 2) return L"";
    std::vector<BYTE> buf = pidl;
    if (!(buf[buf.size() - 1] == 0 && buf[buf.size() - 2] == 0)) {
        buf.push_back(0);
        buf.push_back(0);
    }
    wchar_t path[MAX_PATH * 4] = {};
    if (SafeGetPathFromPidl(buf.data(), buf.size(), path, _countof(path)))
        return path;
    std::wstring name = PidlFallbackName(buf.data(), buf.size());
    if (!name.empty()) return name;
    return L"(PIDL) " + wc::HexPreview(buf.data(), static_cast<unsigned long>(std::min(buf.size(), size_t(64))));
}

std::wstring SidToAccount(const std::wstring& sid) {
    PSID parsed = nullptr;
    if (!ConvertStringSidToSidW(sid.c_str(), &parsed)) return sid;
    wchar_t name[256] = {};
    wchar_t domain[256] = {};
    DWORD nameLength = 256, domainLength = 256;
    SID_NAME_USE use = SidTypeUnknown;
    std::wstring text = sid;
    if (LookupAccountSidW(nullptr, parsed, name, &nameLength, domain, &domainLength, &use)) {
        text = (domain[0] ? std::wstring(domain) + L"\\" : L"") + name;
    }
    LocalFree(parsed);
    return text;
}

std::wstring LeFileTimeText(const BYTE* data, size_t size) {
    if (size < 8 || !data) return L"";
    unsigned long long value = 0;
    std::memcpy(&value, data, 8);
    FILETIME ft{};
    ft.dwLowDateTime = static_cast<DWORD>(value & 0xFFFFFFFF);
    ft.dwHighDateTime = static_cast<DWORD>(value >> 32);
    return FileTimeText(ft);
}

std::wstring LeFileTimeText(const std::vector<BYTE>& data) {
    return LeFileTimeText(data.data(), data.size());
}


static std::wstring DumpRegKey(const RegView& view, const std::wstring& key) {
    std::wstring text;
    for (const std::wstring& name : view.ValueNames(key)) {
        std::wstring value = view.QueryString(key, name);
        if (!value.empty()) {
            text += (name.empty() ? L"(default)" : name) + L" : " + value + L"\r\n";
            continue;
        }
        std::vector<BYTE> data;
        if (view.QueryBinary(key, name, data) && !data.empty()) {
            text += (name.empty() ? L"(default)" : name) + L" : " +
                    wc::HexPreview(data.data(), static_cast<unsigned long>(data.size()), 64) +
                    Format(L" (%llu bytes)\r\n", static_cast<unsigned long long>(data.size()));
        }
    }
    return text;
}

namespace {

// USB-IF assigned vendor IDs (subset) used to show a friendly vendor name next to the raw VID,
// the way USBDeview does.
const wchar_t* UsbVendorName(const std::wstring& vid) {
    struct Entry { const wchar_t* id; const wchar_t* name; };
    static const Entry kKnown[] = {
        {L"03F0", L"HP"}, {L"0408", L"Quanta"}, {L"0451", L"Texas Instruments"},
        {L"0457", L"Silicon Integrated Systems"}, {L"0458", L"Genius"}, {L"0461", L"Primax"},
        {L"046D", L"Logitech"}, {L"0471", L"Philips"}, {L"047F", L"Plantronics"},
        {L"0480", L"Toshiba"}, {L"04A9", L"Canon"}, {L"04B0", L"Nikon"}, {L"04B3", L"IBM"},
        {L"04B8", L"Epson"}, {L"04CA", L"Lite-On"}, {L"04CB", L"Fujitsu"}, {L"04DA", L"Panasonic"},
        {L"04DD", L"Sharp"}, {L"04E6", L"SCM Microsystems"}, {L"04E8", L"Samsung"},
        {L"04F2", L"Chicony"}, {L"04F3", L"Elan"}, {L"04F9", L"Brother"}, {L"050D", L"Belkin"},
        {L"051D", L"APC"}, {L"0531", L"VIA"}, {L"053D", L"STMicroelectronics"},
        {L"0557", L"ATEN"}, {L"056A", L"Wacom"}, {L"058F", L"Alcor Micro"}, {L"059B", L"Iomega"},
        {L"05AC", L"Apple"}, {L"05A9", L"OmniVision"}, {L"05C6", L"Qualcomm"}, {L"05E3", L"Genesys Logic"},
        {L"0644", L"TEAC"}, {L"066F", L"SigmaTel"}, {L"067B", L"Prolific"},
        {L"0718", L"Imation"}, {L"0738", L"Mad Catz"}, {L"0763", L"M-Audio"},
        {L"0781", L"SanDisk"}, {L"090C", L"Feiya"}, {L"0951", L"Kingston"}, {L"0979", L"Kensington"},
        {L"0984", L"Kodak"}, {L"0A5C", L"Broadcom"}, {L"0B95", L"ASIX"}, {L"0BB4", L"HTC"},
        {L"0C45", L"Microdia"}, {L"0D3D", L"Printronics"}, {L"0DB0", L"MSI"},
        {L"0E0F", L"VMware"}, {L"0EA0", L"Ours Technology"}, {L"0FCE", L"Sony Ericsson"},
        {L"1004", L"LG"}, {L"10C4", L"Silicon Labs"}, {L"1132", L"Chrontel"}, {L"1234", L"Generic"},
        {L"125F", L"ADATA"}, {L"12D1", L"Huawei"}, {L"13FE", L"Kingston"}, {L"14CD", L"Super Top"},
        {L"152D", L"JMicron"}, {L"1532", L"Razer"}, {L"174C", L"ASMedia"}, {L"18D1", L"Google"},
        {L"1908", L"GEMBIRD"}, {L"1A40", L"Terminus"}, {L"1BBB", L"T&A Mobile"}, {L"1C9E", L"Option"},
        {L"2001", L"D-Link"}, {L"203A", L"Maxell"}, {L"2109", L"VIA Labs"}, {L"22B8", L"Motorola"},
        {L"2341", L"Arduino"}, {L"25A7", L"A4Tech"}, {L"2717", L"Xiaomi"}, {L"2915", L"Microsoft"},
        {L"2A70", L"OnePlus"}, {L"320F", L"JMTek"}, {L"346D", L"HB"}, {L"3538", L"Power Quotient"},
        {L"413C", L"Dell"}, {L"4242", L"Texas Instruments"}, {L"4348", L"WinChipHead"},
        {L"048D", L"Integrated Technology Express"}, {L"04B4", L"Cypress Semiconductor"},
        {L"0930", L"Toshiba"}, {L"0BDA", L"Realtek"}, {L"1050", L"Yubico"}, {L"1366", L"SEGGER"},
        {L"148F", L"Ralink"}, {L"17EF", L"Lenovo"}, {L"17E9", L"DisplayLink"}, {L"18EC", L"Arkmicro"},
        {L"1A86", L"QinHeng"}, {L"1C4F", L"SiGma Micro"}, {L"1E7D", L"Roccat"}, {L"1EBC", L"Toptronic"},
        {L"2040", L"Hauppauge"}, {L"2304", L"Pinnacle"}, {L"26BD", L"Samsung"}, {L"8087", L"Intel"},
        {L"8564", L"Transcend"}, {L"8565", L"Exsys"}, {L"9986", L"Seagate"}, {L"9710", L"MosChip"},
        {L"BCM", L"Broadcom"}, {L"DELL", L"Dell"},
    };
    for (const auto& e : kKnown) {
        if (_wcsicmp(e.id, vid.c_str()) == 0) return e.name;
    }
    return L"";
}

// Parse Ven_/Prod_/Rev_ tokens out of a USB device key name (e.g. "Disk&Ven_Generic&Prod_X&Rev_1.00").
void ParseDeviceTokens(const std::wstring& name, std::wstring& ven, std::wstring& prod,
                       std::wstring& rev) {
    size_t start = 0;
    while (start < name.size()) {
        size_t end = name.find(L'&', start);
        std::wstring tok = (end == std::wstring::npos) ? name.substr(start) : name.substr(start, end - start);
        if (tok.size() >= 5 && _wcsnicmp(tok.c_str(), L"Ven_", 4) == 0) ven = tok.substr(4);
        else if (tok.size() >= 6 && _wcsnicmp(tok.c_str(), L"Prod_", 5) == 0) prod = tok.substr(5);
        else if (tok.size() >= 5 && _wcsnicmp(tok.c_str(), L"Rev_", 4) == 0) rev = tok.substr(4);
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
}

// MountedDevices values are UTF-16LE device paths, possibly truncated at an embedded NUL.
std::wstring DecodeDevicePath(const std::vector<BYTE>& data) {
    std::wstring s;
    for (size_t i = 0; i + 1 < data.size(); i += 2) {
        wchar_t ch = static_cast<wchar_t>(data[i] | (data[i + 1] << 8));
        if (ch == 0) break;
        s += ch;
    }
    return s;
}

// Lower-case and turn '#' separators into '\' so a USBSTOR registry path and a MountedDevices
// blob can be compared with a simple substring test.
std::wstring NormalizePath(const std::wstring& p) {
    std::wstring out;
    out.reserve(p.size());
    for (wchar_t c : p) {
        if (c == L'#') out += L'\\';
        else if (c >= L'A' && c <= L'Z') out += static_cast<wchar_t>(c - L'A' + L'a');
        else out += c;
    }
    return out;
}

}  // namespace

void RunUsbHistory(const Sink& sink, std::atomic<bool>& stop, const RegView& view) {
    // 1) VID/PID map from the USB branch: instance id -> {vid, pid}. The USBSTOR instance id is
    //    identical to the instance id under USB\VID_xxxx&PID_xxxx, so it links storage devices to
    //    their vendor/product identifiers.
    std::map<std::wstring, std::pair<std::wstring, std::wstring>> usbVidPid;
    for (const std::wstring& dev : view.Subkeys(L"CurrentControlSet\\Enum\\USB")) {
        std::wstring vid, pid;
        size_t v = dev.find(L"VID_");
        size_t p = dev.find(L"PID_");
        if (v != std::wstring::npos) vid = dev.substr(v + 4, 4);
        if (p != std::wstring::npos) pid = dev.substr(p + 4, 4);
        if (vid.empty() && pid.empty()) continue;
        const std::wstring base = L"CurrentControlSet\\Enum\\USB\\" + dev;
        for (const std::wstring& inst : view.Subkeys(base)) {
            usbVidPid[inst] = {vid, pid};
        }
    }

    // 2) MountedDevices. A \DosDevices\X: entry stores the volume GUID; the matching
    //    \??\Volume{GUID} entry stores the underlying device path. We keep both so we can join a
    //    drive letter to a USBSTOR device instance the way USBDeview does.
    std::vector<std::pair<std::wstring, std::wstring>> mounted;  // "F:" -> normalized data
    std::map<std::wstring, std::wstring> volumeToDevice;          // "\??\volume{...}" -> device path
    for (const std::wstring& name : view.ValueNames(L"MountedDevices")) {
        std::vector<BYTE> data;
        if (!view.QueryBinary(L"MountedDevices", name, data)) continue;
        std::wstring decoded = NormalizePath(DecodeDevicePath(data));
        if (name.find(L"DosDevices") != std::wstring::npos) {
            std::wstring drive = name;
            size_t sep = drive.rfind(L'\\');
            if (sep != std::wstring::npos) drive = drive.substr(sep + 1);
            mounted.emplace_back(drive, decoded);
        } else if (name.find(L"Volume{") != std::wstring::npos) {
            volumeToDevice[NormalizePath(name)] = decoded;
        }
    }

    std::vector<Row> rows;
    std::vector<std::wstring> details;
    const wchar_t* roots[] = {L"CurrentControlSet\\Enum\\USBSTOR",
                              L"CurrentControlSet\\Enum\\USB"};
    size_t total = 0;
    for (const wchar_t* base : roots) {
        for (const std::wstring& device : view.Subkeys(base)) {
            if (stop.load()) break;
            const std::wstring devicePath = std::wstring(base) + L"\\" + device;
            const std::wstring friendly = view.QueryString(devicePath, L"FriendlyName");
            const std::wstring desc = view.QueryString(devicePath, L"DeviceDesc");
            const std::wstring mfg = view.QueryString(devicePath, L"Mfg");
            const std::wstring svc = view.QueryString(devicePath, L"Service");
            const std::wstring parent = view.QueryString(devicePath, L"ParentIdPrefix");

            std::wstring dVen, dProd, dRev;
            ParseDeviceTokens(device, dVen, dProd, dRev);

            for (const std::wstring& instance : view.Subkeys(devicePath)) {
                const std::wstring ip = devicePath + L"\\" + instance;
                std::vector<BYTE> b;
                std::wstring installed, connected, removed;
                if (view.QueryBinary(ip + L"\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064",
                                     L"", b))
                    installed = LeFileTimeText(b);
                b.clear();
                if (view.QueryBinary(ip + L"\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066",
                                     L"", b))
                    connected = LeFileTimeText(b);
                b.clear();
                if (view.QueryBinary(ip + L"\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067",
                                     L"", b))
                    removed = LeFileTimeText(b);
                if (installed.empty() && connected.empty() && removed.empty())
                    installed = view.LastWrite(ip);

                // Resolve VID/PID: exact instance-id match first, then serial-prefix fallback.
                std::wstring vid, pid;
                auto it = usbVidPid.find(instance);
                if (it != usbVidPid.end()) {
                    vid = it->second.first;
                    pid = it->second.second;
                } else {
                    size_t amp = instance.find(L'&');
                    std::wstring serial = (amp == std::wstring::npos) ? instance : instance.substr(0, amp);
                    for (const auto& kv : usbVidPid) {
                        if (kv.first.size() >= serial.size() &&
                            _wcsnicmp(kv.first.c_str(), serial.c_str(), serial.size()) == 0) {
                            vid = kv.second.first;
                            pid = kv.second.second;
                            break;
                        }
                    }
                }

                // Drive letter(s): match the instance path directly, or resolve a drive letter's
                // volume GUID through volumeToDevice to the underlying device path.
                std::wstring driveLetters;
                std::wstring volumeGuid;
                std::wstring needle = NormalizePath(ip);
                size_t epos = needle.find(L"enum\\");
                if (epos != std::wstring::npos) needle = needle.substr(epos + 5);
                for (const auto& m : mounted) {
                    bool match = m.second.find(needle) != std::wstring::npos;
                    if (!match) {
                        auto vit = volumeToDevice.find(m.second);
                        if (vit != volumeToDevice.end() && vit->second.find(needle) != std::wstring::npos)
                            match = true;
                    }
                    if (match) {
                        if (!driveLetters.empty()) driveLetters += L", ";
                        driveLetters += m.first;
                    }
                }
                if (driveLetters.empty()) {
                    for (const auto& kv : volumeToDevice) {
                        if (kv.second.find(needle) != std::wstring::npos) {
                            volumeGuid = kv.first;
                            size_t s = volumeGuid.find(L"Volume{");
                            if (s != std::wstring::npos) volumeGuid = volumeGuid.substr(s);
                            break;
                        }
                    }
                }
                std::wstring driveDisplay =
                    driveLetters.empty() ? (volumeGuid.empty() ? L"(none)" : volumeGuid) : driveLetters;

                const std::wstring vendorName = UsbVendorName(vid);
                std::wstring vendor = mfg.empty() ? dVen : mfg;
                if (!vendorName.empty() && _wcsicmp(vendorName.c_str(), vendor.c_str()) != 0) {
                    vendor += L" (" + vendorName + L")";
                } else if (vendor.empty() && !vid.empty()) {
                    vendor = vid;
                }
                std::wstring product = dProd.empty() ? desc : dProd;

                const std::wstring name = !friendly.empty() ? friendly : (!desc.empty() ? desc : device);

                bool hasDrive = !driveLetters.empty();
                bool recentlyConnected =
                    !connected.empty() && (removed.empty() || connected >= removed);
                std::wstring connectedNow = (hasDrive || recentlyConnected) ? L"Yes" : L"No";

                std::wstring vidSuffix = vendorName.empty() ? L"" : (L" (" + vendorName + L")");
                std::wstring detail = Format(
                    L"Registry    : %s\\%s\r\nDevice      : %s\r\nInstance    : %s\r\n"
                    L"Vendor      : %s\r\nProduct     : %s\r\nRevision    : %s\r\n"
                    L"Vendor ID   : %s%s\r\nProduct ID  : %s\r\n"
                    L"Serial      : %s\r\nService     : %s\r\nParentIdPrefix: %s\r\n"
                    L"Drive / volume: %s\r\nConnected   : %s\r\n"
                    L"First install: %s\r\nLast connect : %s\r\nLast removal : %s\r\n"
                    L"Device key  : %s\r\nInstance key: %s\r\nKey written  : %s\r\n",
                    base, device.c_str(), device.c_str(), instance.c_str(),
                    vendor.c_str(), product.c_str(), dRev.c_str(),
                    vid.c_str(), vidSuffix.c_str(), pid.c_str(),
                    instance.c_str(), svc.c_str(), parent.c_str(),
                    driveDisplay.c_str(), connectedNow.c_str(),
                    installed.c_str(), connected.c_str(), removed.c_str(),
                    devicePath.c_str(), ip.c_str(), view.LastWrite(ip).c_str());
                std::wstring values = DumpRegKey(view, devicePath);
                if (!values.empty()) detail += L"\r\n--- device values ---\r\n" + values;
                values = DumpRegKey(view, ip);
                if (!values.empty()) detail += L"\r\n--- instance values ---\r\n" + values;

                rows.push_back(Row{name, vendor, product, vid, pid, instance, dRev,
                                   driveDisplay,
                                   installed, connected, removed, connectedNow});
                details.push_back(detail);
                ++total;
            }
        }
    }
    if (total == 0) {
        rows.push_back(Row{L"(none found)", L"", L"", L"", L"", L"", L"", L"", L"", L"", L"", L""});
        details.push_back(L"No USB device history under HKLM\\SYSTEM\\CurrentControlSet\\Enum. "
                          L"Administrator rights are required to read this key.");
    }
    const std::wstring summary = Format(L"%zu USB device entr(y/ies) from %s", total, view.rootLabel.c_str());
    sink.Detailed(std::move(rows), std::move(details), true, summary);
    sink.Done(summary);
}


void RunBamDam(const Sink& sink, std::atomic<bool>& stop, const RegView& view) {
    std::vector<Row> rows;
    std::vector<std::wstring> details;
    const wchar_t* bases[] = {
        L"CurrentControlSet\\Services\\bam\\State\\UserSettings",
        L"CurrentControlSet\\Services\\dam\\State\\UserSettings"};
    size_t total = 0;
    for (const wchar_t* base : bases) {
        const std::wstring source = (std::wstring(base).find(L"\\bam\\") != std::wstring::npos)
                                        ? L"BAM"
                                        : L"DAM";
        for (const std::wstring& sid : view.Subkeys(base)) {
            if (stop.load()) break;
            const std::wstring account = SidToAccount(sid);
            const std::wstring userKey = std::wstring(base) + L"\\" + sid;
            for (const std::wstring& valueName : view.ValueNames(userKey)) {
                if (valueName.empty()) continue;
                std::vector<BYTE> data;
                if (!view.QueryBinary(userKey, valueName, data)) continue;
                const std::wstring executed = LeFileTimeText(data);
                std::wstring detail = Format(
                    L"Source     : %s\r\nUser       : %s (%s)\r\nExecutable : %s\r\n"
                    L"Last run   : %s\r\nRegistry   : %s\\%s\r\nValue name : %s\r\n"
                    L"Value size : %llu byte(s)\r\nRaw data   : %s",
                    source.c_str(), account.c_str(), sid.c_str(), valueName.c_str(), executed.c_str(),
                    base, sid.c_str(), valueName.c_str(),
                    static_cast<unsigned long long>(data.size()),
                    wc::HexPreview(data.data(), static_cast<unsigned long>(data.size()), 64).c_str());
                rows.push_back(Row{valueName, account, executed, source, L""});
                details.push_back(detail);
                ++total;
            }
        }
    }
    if (total == 0) {
        rows.push_back(Row{L"(none found)", L"", L"", L"", L""});
        details.push_back(L"No BAM/DAM entries under HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
                          L"{bam,dam}\\State\\UserSettings. Administrator rights may be required.");
    }
    const std::wstring summary = Format(L"%zu BAM/DAM entr(y/ies) from %s", total, view.rootLabel.c_str());
    sink.Detailed(std::move(rows), std::move(details), true, summary);
    sink.Done(summary);
}


void RunUserAssist(const Sink& sink, std::atomic<bool>& stop, const RegView& view) {
    std::vector<Row> rows;
    std::vector<std::wstring> details;
    const std::wstring base =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
    size_t total = 0;
    for (const std::wstring& guid : view.Subkeys(base)) {
        const std::wstring countKey = base + L"\\" + guid + L"\\Count";
        for (const std::wstring& valueName : view.ValueNames(countKey)) {
            if (valueName.empty()) continue;
            const std::wstring decoded = Rot13(valueName);
            std::vector<BYTE> data;
            view.QueryBinary(countKey, valueName, data);
            DWORD runCount = 0;
            DWORD session = 0;
            DWORD focusCount = 0;
            DWORD focusTime = 0;
            if (data.size() >= 8) {
                std::memcpy(&session, data.data(), 4);
                std::memcpy(&runCount, data.data() + 4, 4);
            }
            std::wstring lastExec;
            if (data.size() >= 16) lastExec = LeFileTimeText(data.data() + 8, 8);
            if (data.size() >= 20) std::memcpy(&focusCount, data.data() + 16, 4);
            if (data.size() >= 24) std::memcpy(&focusTime, data.data() + 20, 4);
            std::wstring detail = Format(
                L"GUID        : %s\r\nProgram     : %s\r\nRun count   : %u\r\nLast exec   : %s\r\n"
                L"Session id  : %u\r\nFocus count : %u\r\nFocus time  : %u ms\r\n"
                L"Registry    : %s\r\nValue name  : %s\r\nRaw bytes   : %llu\r\n"
                L"Raw data    : %s",
                guid.c_str(), decoded.c_str(), runCount, lastExec.c_str(), session, focusCount,
                focusTime, countKey.c_str(), valueName.c_str(),
                static_cast<unsigned long long>(data.size()),
                wc::HexPreview(data.data(), static_cast<unsigned long>(data.size()), 72).c_str());
            rows.push_back(Row{decoded, std::to_wstring(runCount), lastExec, guid, L""});
            details.push_back(detail);
            ++total;
        }
    }
    if (total == 0) {
        rows.push_back(Row{L"(none found)", L"", L"", L"", L""});
        details.push_back(L"No UserAssist entries under SOFTWARE\\Microsoft\\Windows\\"
                          L"CurrentVersion\\Explorer\\UserAssist. Load an NTUSER.DAT hive or run "
                          L"as the target user.");
    }
    const std::wstring summary = Format(L"%zu UserAssist entr(y/ies) from %s", total, view.rootLabel.c_str());
    sink.Detailed(std::move(rows), std::move(details), true, summary);
    sink.Done(summary);
}


static void ParseRecentDocsKey(const RegView& view, const std::wstring& key, const std::wstring& type,
                               std::atomic<bool>& stop, std::vector<Row>& rows,
                               std::vector<std::wstring>& details) {
    std::vector<BYTE> mru;
    view.QueryBinary(key, L"MRUListEx", mru);
    const std::vector<int> order = DecodeMruListEx(mru);
    const std::wstring mruHex =
        wc::HexPreview(mru.data(), static_cast<unsigned long>(mru.size()), 64);
    const std::wstring keyInfo = L"Registry : " + key + L"\r\n" +
                                 L"MRUListEx: " + (mruHex.empty() ? L"-" : mruHex) +
                                 Format(L" (%llu byte(s))\r\n", static_cast<unsigned long long>(mru.size()));
    if (order.empty()) {
        for (const std::wstring& v : view.ValueNames(key)) {
            if (v == L"MRUListEx") continue;
            std::vector<BYTE> data;
            std::wstring path;
            if (view.QueryBinary(key, v, data)) path = DecodePidlPath(data);
            if (path.empty()) path = view.QueryString(key, v);
            if (path.empty()) continue;
            rows.push_back(Row{type, path, L"-", L"", L""});
            details.push_back(Format(L"Type     : %s\r\nValue    : %s\r\nPath     : %s\r\n",
                                     type.c_str(), v.c_str(), path.c_str()) +
                              keyInfo +
                              Format(L"Value size: %llu byte(s)\r\nRaw data : %s", 
                                     static_cast<unsigned long long>(data.size()),
                                     wc::HexPreview(data.data(), static_cast<unsigned long>(data.size()),
                                                    64).c_str()));
        }
        return;
    }
    for (size_t k = 0; k < order.size(); ++k) {
        if (stop.load()) break;
        const std::wstring vname = std::to_wstring(order[k]);
        std::vector<BYTE> data;
        std::wstring path;
        if (view.QueryBinary(key, vname, data)) path = DecodePidlPath(data);
        if (path.empty()) path = view.QueryString(key, vname);
        if (path.empty()) continue;
        rows.push_back(Row{type, path, std::to_wstring(k + 1), L"", L""});
        details.push_back(Format(L"Type     : %s\r\nMRU      : #%zu\r\nValue    : %s\r\nPath     : %s\r\n",
                                 type.c_str(), k + 1, vname.c_str(), path.c_str()) +
                          keyInfo +
                          Format(L"Value size: %llu byte(s)\r\nRaw data : %s",
                                 static_cast<unsigned long long>(data.size()),
                                 wc::HexPreview(data.data(), static_cast<unsigned long>(data.size()),
                                                64).c_str()));
    }
}

void RunRecentDocs(const Sink& sink, std::atomic<bool>& stop, const RegView& view) {
    std::vector<Row> rows;
    std::vector<std::wstring> details;
    const std::wstring base =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs";
    ParseRecentDocsKey(view, base, L"(all)", stop, rows, details);
    for (const std::wstring& ext : view.Subkeys(base)) {
        ParseRecentDocsKey(view, base + L"\\" + ext, ext, stop, rows, details);
    }
    if (rows.empty()) {
        rows.push_back(Row{L"(none found)", L"", L"", L"", L""});
        details.push_back(L"No RecentDocs under SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                          L"Explorer\\RecentDocs. Load an NTUSER.DAT hive or run as the target user.");
    }
    const std::wstring summary = Format(L"%zu RecentDocs entr(y/ies) from %s", rows.size(), view.rootLabel.c_str());
    sink.Detailed(std::move(rows), std::move(details), true, summary);
    sink.Done(summary);
}


void RunMru(const Sink& sink, std::atomic<bool>& stop, const RegView& view) {
    std::vector<Row> rows;
    std::vector<std::wstring> details;

    const std::wstring runKey =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU";
    const std::wstring runList = view.QueryString(runKey, L"MRUList");
    if (!runList.empty()) {
        for (size_t k = 0; k < runList.size(); ++k) {
            const wchar_t letter = runList[k];
            const std::wstring cmd = view.QueryString(runKey, std::wstring(1, letter));
            if (cmd.empty()) continue;
            rows.push_back(Row{L"Run", cmd, L"-", std::to_wstring(k + 1), L""});
            std::wstring detail = Format(
                L"Type     : RunMRU\r\nMRU      : #%zu\r\nValue    : %s\r\nCommand  : %s\r\n"
                L"Registry : %s\r\nMRUList  : %s\r\nKey written: %s",
                k + 1, std::wstring(1, letter).c_str(), cmd.c_str(), runKey.c_str(),
                runList.c_str(), view.LastWrite(runKey).c_str());
            details.push_back(std::move(detail));
        }
    }

    const wchar_t* cdBases[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU"};
    for (const wchar_t* base : cdBases) {
        const std::wstring kind = (std::wstring(base).find(L"LastVisited") != std::wstring::npos)
                                      ? L"LastVisited"
                                      : L"Open/Save";
        for (const std::wstring& ext : view.Subkeys(base)) {
            const std::wstring key = std::wstring(base) + L"\\" + ext;
            std::vector<BYTE> mru;
            view.QueryBinary(key, L"MRUListEx", mru);
            const std::vector<int> order = DecodeMruListEx(mru);
            const std::wstring keyInfo =
                L"Registry  : " + key + L"\r\n" +
                L"MRUListEx : " +
                (mru.empty() ? std::wstring(L"-")
                             : wc::HexPreview(mru.data(), static_cast<unsigned long>(mru.size()), 64)) +
                L"\r\n";
            if (order.empty()) {
                for (const std::wstring& v : view.ValueNames(key)) {
                    if (v == L"MRUListEx") continue;
                    std::vector<BYTE> data;
                    std::wstring path;
                    if (view.QueryBinary(key, v, data)) path = DecodePidlPath(data);
                    if (path.empty()) continue;
                    rows.push_back(Row{kind, ext, path, L"-", L""});
                    details.push_back(Format(L"Type      : %s (%s)\r\nValue     : %s\r\nPath      : %s\r\n",
                                             kind.c_str(), ext.c_str(), v.c_str(), path.c_str()) +
                                      keyInfo +
                                      Format(L"Value size: %llu byte(s)\r\nRaw data  : %s",
                                             static_cast<unsigned long long>(data.size()),
                                             wc::HexPreview(data.data(),
                                                            static_cast<unsigned long>(data.size()),
                                                            64).c_str()));
                }
                continue;
            }
            for (size_t k = 0; k < order.size(); ++k) {
                if (stop.load()) break;
                const std::wstring vname = std::to_wstring(order[k]);
                std::vector<BYTE> data;
                std::wstring path;
                if (view.QueryBinary(key, vname, data)) path = DecodePidlPath(data);
                if (path.empty()) continue;
                rows.push_back(Row{kind, ext, path, std::to_wstring(k + 1), L""});
                details.push_back(Format(L"Type      : %s (%s)\r\nMRU       : #%zu\r\nValue     : %s\r\n"
                                         L"Path      : %s\r\n",
                                         kind.c_str(), ext.c_str(), k + 1, vname.c_str(), path.c_str()) +
                                  keyInfo +
                                  Format(L"Value size: %llu byte(s)\r\nRaw data  : %s",
                                         static_cast<unsigned long long>(data.size()),
                                         wc::HexPreview(data.data(),
                                                        static_cast<unsigned long>(data.size()),
                                                        64).c_str()));
            }
        }
    }

    if (rows.empty()) {
        rows.push_back(Row{L"(none found)", L"", L"", L"", L""});
        details.push_back(L"No MRU data under Explorer\\RunMRU or ComDlg32. Load an NTUSER.DAT "
                          L"hive or run as the target user.");
    }
    const std::wstring summary = Format(L"%zu MRU entr(y/ies) from %s", rows.size(), view.rootLabel.c_str());
    sink.Detailed(std::move(rows), std::move(details), true, summary);
    sink.Done(summary);
}

}
