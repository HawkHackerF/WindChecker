#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include "artifacts.h"

#include <aclapi.h>
#include <bcrypt.h>
#include <propsys.h>
#include <propvarutil.h>
#include <wincodec.h>

#include <algorithm>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "propsys.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "windowscodecs.lib")

namespace {

// ---------------------------------------------------------------- file helpers

std::wstring FileOwnerText(const std::wstring& path) {
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                              &owner, nullptr, nullptr, nullptr, &descriptor) != ERROR_SUCCESS) {
        return L"";
    }
    std::wstring result;
    wchar_t name[256] = {};
    wchar_t domain[256] = {};
    DWORD nameLength = 256;
    DWORD domainLength = 256;
    SID_NAME_USE use = SidTypeUnknown;
    if (LookupAccountSidW(nullptr, owner, name, &nameLength, domain, &domainLength, &use)) {
        result = domain[0] ? std::wstring(domain) + L"\\" + name : std::wstring(name);
    }
    if (descriptor) LocalFree(descriptor);
    return result;
}

std::wstring AttributesText(DWORD attributes) {
    struct Flag { DWORD value; const wchar_t* name; };
    static const Flag flags[] = {
        {FILE_ATTRIBUTE_READONLY, L"Read-only"},
        {FILE_ATTRIBUTE_HIDDEN, L"Hidden"},
        {FILE_ATTRIBUTE_SYSTEM, L"System"},
        {FILE_ATTRIBUTE_ARCHIVE, L"Archive"},
        {FILE_ATTRIBUTE_TEMPORARY, L"Temporary"},
        {FILE_ATTRIBUTE_SPARSE_FILE, L"Sparse"},
        {FILE_ATTRIBUTE_REPARSE_POINT, L"Reparse point"},
        {FILE_ATTRIBUTE_COMPRESSED, L"Compressed"},
        {FILE_ATTRIBUTE_OFFLINE, L"Offline"},
        {FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, L"Not indexed"},
        {FILE_ATTRIBUTE_ENCRYPTED, L"Encrypted"},
        {FILE_ATTRIBUTE_INTEGRITY_STREAM, L"Integrity stream"},
        {FILE_ATTRIBUTE_NO_SCRUB_DATA, L"No scrub"},
    };
    std::wstring text;
    for (const Flag& flag : flags) {
        if ((attributes & flag.value) == 0) continue;
        if (!text.empty()) text += L", ";
        text += flag.name;
    }
    if (text.empty()) text = L"Normal";
    return text;
}

std::wstring VersionInfoText(const std::wstring& path) {
    DWORD ignored = 0;
    DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (size == 0) return L"";
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())) return L"";

    std::wstring text;
    struct Lang { WORD language; WORD codepage; };
    Lang* translations = nullptr;
    UINT length = 0;
    if (VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation",
                       reinterpret_cast<LPVOID*>(&translations), &length) &&
        length >= sizeof(Lang)) {
        static const wchar_t* keys[] = {
            L"CompanyName", L"FileDescription", L"FileVersion", L"ProductName", L"ProductVersion",
            L"InternalName", L"OriginalFilename", L"LegalCopyright", L"PrivateBuild",
            L"SpecialBuild", L"Comments"};
        for (const wchar_t* key : keys) {
            for (UINT i = 0; i < length / sizeof(Lang); ++i) {
                wchar_t block[160] = {};
                swprintf_s(block, L"\\StringFileInfo\\%04x%04x\\%s", translations[i].language,
                           translations[i].codepage, key);
                wchar_t* value = nullptr;
                UINT valueLength = 0;
                if (!VerQueryValueW(data.data(), block, reinterpret_cast<LPVOID*>(&value),
                                    &valueLength) ||
                    !value || valueLength == 0) {
                    continue;
                }
                std::wstring trimmed = Trim(value);
                if (trimmed.empty()) continue;
                text += Format(L"%-18s: %s\r\n", key, trimmed.c_str());
                break;
            }
        }
    }
    VS_FIXEDFILEINFO* fixed = nullptr;
    UINT fixedLength = 0;
    if (VerQueryValueW(data.data(), L"\\", reinterpret_cast<LPVOID*>(&fixed), &fixedLength) &&
        fixed && fixedLength >= sizeof(VS_FIXEDFILEINFO)) {
        text += Format(L"%-18s: %u.%u.%u.%u\r\n", L"File version",
                       HIWORD(fixed->dwFileVersionMS), LOWORD(fixed->dwFileVersionMS),
                       HIWORD(fixed->dwFileVersionLS), LOWORD(fixed->dwFileVersionLS));
        text += Format(L"%-18s: %u.%u.%u.%u\r\n", L"Product version",
                       HIWORD(fixed->dwProductVersionMS), LOWORD(fixed->dwProductVersionMS),
                       HIWORD(fixed->dwProductVersionLS), LOWORD(fixed->dwProductVersionLS));
    }
    return text;
}

std::wstring AttributesAndTimes(const std::wstring& path, DWORD attributes,
                                const FILETIME& created, const FILETIME& modified,
                                const FILETIME& accessed) {
    std::wstring text;
    text += L"Attributes    : " + AttributesText(attributes) + L"\r\n";
    text += L"Created       : " + FileTimeText(created) + L"\r\n";
    text += L"Modified      : " + FileTimeText(modified) + L"\r\n";
    text += L"Accessed      : " + FileTimeText(accessed) + L"\r\n";
    std::wstring owner = FileOwnerText(path);
    if (!owner.empty()) text += L"Owner         : " + owner + L"\r\n";
    return text;
}

std::wstring HashesText(const std::wstring& path) {
    std::wstring text;
    std::vector<BYTE> digest;
    if (HashFileDigest(path, BCRYPT_MD5_ALGORITHM, digest)) {
        text += L"MD5           : " + HexLower(digest) + L"\r\n";
    } else {
        text += L"MD5           : (unreadable)\r\n";
    }
    digest.clear();
    if (HashFileDigest(path, BCRYPT_SHA1_ALGORITHM, digest)) {
        text += L"SHA-1         : " + HexLower(digest) + L"\r\n";
    }
    digest.clear();
    if (HashFileDigest(path, BCRYPT_SHA256_ALGORITHM, digest)) {
        text += L"SHA-256       : " + HexLower(digest) + L"\r\n";
    }
    digest.clear();
    if (HashFileDigest(path, BCRYPT_SHA512_ALGORITHM, digest)) {
        text += L"SHA-512       : " + HexLower(digest) + L"\r\n";
    }
    return text;
}

struct Digests {
    std::wstring md5;
    std::wstring sha1;
    std::wstring sha256;
};

Digests ComputeDigests(const std::wstring& path) {
    Digests digests;
    std::vector<BYTE> digest;
    if (HashFileDigest(path, BCRYPT_MD5_ALGORITHM, digest)) digests.md5 = HexLower(digest);
    digest.clear();
    if (HashFileDigest(path, BCRYPT_SHA1_ALGORITHM, digest)) digests.sha1 = HexLower(digest);
    digest.clear();
    if (HashFileDigest(path, BCRYPT_SHA256_ALGORITHM, digest)) digests.sha256 = HexLower(digest);
    return digests;
}

// ---------------------------------------------------------------- metadata names

const wchar_t* ExifTagName(int id) {
    switch (id) {
    case 0x0100: return L"ImageWidth";
    case 0x0101: return L"ImageLength";
    case 0x0102: return L"BitsPerSample";
    case 0x0103: return L"Compression";
    case 0x0106: return L"PhotometricInterpretation";
    case 0x010E: return L"ImageDescription";
    case 0x010F: return L"Make";
    case 0x0110: return L"Model";
    case 0x0111: return L"StripOffsets";
    case 0x0112: return L"Orientation";
    case 0x0115: return L"SamplesPerPixel";
    case 0x011A: return L"XResolution";
    case 0x011B: return L"YResolution";
    case 0x011C: return L"PlanarConfiguration";
    case 0x0128: return L"ResolutionUnit";
    case 0x0131: return L"Software";
    case 0x0132: return L"DateTime";
    case 0x013B: return L"Artist";
    case 0x013E: return L"WhitePoint";
    case 0x013F: return L"PrimaryChromaticities";
    case 0x0201: return L"JPEGInterchangeFormat";
    case 0x0202: return L"JPEGInterchangeFormatLength";
    case 0x0211: return L"YCbCrCoefficients";
    case 0x0212: return L"YCbCrSubSampling";
    case 0x0213: return L"YCbCrPositioning";
    case 0x0214: return L"ReferenceBlackWhite";
    case 0x8298: return L"Copyright";
    case 0x829A: return L"ExposureTime";
    case 0x829D: return L"FNumber";
    case 0x8769: return L"ExifIFDPointer";
    case 0x8825: return L"GPSInfoIFDPointer";
    case 0x8822: return L"ExposureProgram";
    case 0x8824: return L"SpectralSensitivity";
    case 0x8827: return L"ISOSpeedRatings";
    case 0x8828: return L"OECF";
    case 0x8830: return L"SensitivityType";
    case 0x8832: return L"RecommendedExposureIndex";
    case 0x9000: return L"ExifVersion";
    case 0x9003: return L"DateTimeOriginal";
    case 0x9004: return L"DateTimeDigitized";
    case 0x9010: return L"OffsetTime";
    case 0x9011: return L"OffsetTimeOriginal";
    case 0x9101: return L"ComponentsConfiguration";
    case 0x9102: return L"CompressedBitsPerPixel";
    case 0x9201: return L"ShutterSpeedValue";
    case 0x9202: return L"ApertureValue";
    case 0x9203: return L"BrightnessValue";
    case 0x9204: return L"ExposureBiasValue";
    case 0x9205: return L"MaxApertureValue";
    case 0x9206: return L"SubjectDistance";
    case 0x9207: return L"MeteringMode";
    case 0x9208: return L"LightSource";
    case 0x9209: return L"Flash";
    case 0x920A: return L"FocalLength";
    case 0x9214: return L"SubjectArea";
    case 0x927C: return L"MakerNote";
    case 0x9286: return L"UserComment";
    case 0x9290: return L"SubSecTime";
    case 0x9291: return L"SubSecTimeOriginal";
    case 0x9292: return L"SubSecTimeDigitized";
    case 0xA000: return L"FlashpixVersion";
    case 0xA001: return L"ColorSpace";
    case 0xA002: return L"PixelXDimension";
    case 0xA003: return L"PixelYDimension";
    case 0xA004: return L"RelatedSoundFile";
    case 0xA20B: return L"FlashEnergy";
    case 0xA20E: return L"FocalPlaneXResolution";
    case 0xA20F: return L"FocalPlaneYResolution";
    case 0xA210: return L"FocalPlaneResolutionUnit";
    case 0xA214: return L"SubjectLocation";
    case 0xA215: return L"ExposureIndex";
    case 0xA217: return L"SensingMethod";
    case 0xA300: return L"FileSource";
    case 0xA301: return L"SceneType";
    case 0xA302: return L"CFAPattern";
    case 0xA401: return L"CustomRendered";
    case 0xA402: return L"ExposureMode";
    case 0xA403: return L"WhiteBalance";
    case 0xA404: return L"DigitalZoomRatio";
    case 0xA405: return L"FocalLengthIn35mmFilm";
    case 0xA406: return L"SceneCaptureType";
    case 0xA407: return L"GainControl";
    case 0xA408: return L"Contrast";
    case 0xA409: return L"Saturation";
    case 0xA40A: return L"Sharpness";
    case 0xA40B: return L"DeviceSettingDescription";
    case 0xA40C: return L"SubjectDistanceRange";
    case 0xA420: return L"ImageUniqueID";
    case 0xA430: return L"CameraOwnerName";
    case 0xA431: return L"BodySerialNumber";
    case 0xA432: return L"LensSpecification";
    case 0xA433: return L"LensMake";
    case 0xA434: return L"LensModel";
    case 0xA435: return L"LensSerialNumber";
    case 0xA500: return L"Gamma";
    default: return nullptr;
    }
}

const wchar_t* GpsTagName(int id) {
    switch (id) {
    case 0: return L"GPSVersionID";
    case 1: return L"GPSLatitudeRef";
    case 2: return L"GPSLatitude";
    case 3: return L"GPSLongitudeRef";
    case 4: return L"GPSLongitude";
    case 5: return L"GPSAltitudeRef";
    case 6: return L"GPSAltitude";
    case 7: return L"GPSTimeStamp";
    case 8: return L"GPSSatellites";
    case 9: return L"GPSStatus";
    case 10: return L"GPSMeasureMode";
    case 11: return L"GPSDOP";
    case 12: return L"GPSSpeedRef";
    case 13: return L"GPSSpeed";
    case 14: return L"GPSTrackRef";
    case 15: return L"GPSTrack";
    case 16: return L"GPSImgDirectionRef";
    case 17: return L"GPSImgDirection";
    case 18: return L"GPSMapDatum";
    case 23: return L"GPSDestBearingRef";
    case 24: return L"GPSDestBearing";
    case 27: return L"GPSProcessingMethod";
    case 28: return L"GPSAreaInformation";
    case 29: return L"GPSDateStamp";
    case 30: return L"GPSDifferential";
    default: return nullptr;
    }
}

std::wstring AnnotateName(const std::wstring& path) {
    size_t marker = path.rfind(L"{ushort=");
    if (marker == std::wstring::npos) return path;
    int id = _wtoi(path.c_str() + marker + 8);
    bool gps = path.find(L"{ushort=34853}") != std::wstring::npos;
    const wchar_t* name = gps ? GpsTagName(id) : ExifTagName(id);
    if (!name) return path;
    return path + L"  (" + name + L")";
}

// ---------------------------------------------------------------- PROPVARIANT

std::wstring VariantText(const PROPVARIANT& var) {
    if (var.vt == VT_FILETIME) {
        ULARGE_INTEGER value{};
        value.LowPart = var.filetime.dwLowDateTime;
        value.HighPart = var.filetime.dwHighDateTime;
        return value.QuadPart == 0 ? L"(zero)" : FileTimeText(var.filetime);
    }
    if (var.vt == (VT_VECTOR | VT_UI1)) {
        static const wchar_t* kHex = L"0123456789ABCDEF";
        std::wstring text;
        for (ULONG i = 0; i < var.caub.cElems && i < 64; ++i) {
            BYTE byte = var.caub.pElems[i];
            text.push_back(kHex[byte >> 4]);
            text.push_back(kHex[byte & 0x0F]);
            if (i + 1 < var.caub.cElems) text.push_back(L' ');
        }
        if (var.caub.cElems > 64) text += L" \u2026";
        return text;
    }
    if (var.vt == (VT_VECTOR | VT_R8)) {
        std::wstring text;
        for (ULONG i = 0; i < var.cadbl.cElems; ++i) {
            if (!text.empty()) text += L", ";
            text += Format(L"%g", var.cadbl.pElems[i]);
        }
        return text;
    }
    if (var.vt == (VT_VECTOR | VT_UI8)) {
        // WIC stores EXIF rationals as packed 64-bit values: low dword = numerator, high = divisor.
        std::wstring text;
        for (ULONG i = 0; i < var.cauh.cElems; ++i) {
            ULARGE_INTEGER value = var.cauh.pElems[i];
            double numerator = static_cast<double>(value.LowPart);
            double denominator = value.HighPart ? static_cast<double>(value.HighPart) : 1.0;
            if (!text.empty()) text += L", ";
            text += Format(L"%g", numerator / denominator);
        }
        return text;
    }
    if (var.vt == (VT_VECTOR | VT_LPWSTR)) {
        std::wstring text;
        for (ULONG i = 0; i < var.calpwstr.cElems; ++i) {
            if (!text.empty()) text += L", ";
            if (var.calpwstr.pElems[i]) text += var.calpwstr.pElems[i];
        }
        return text;
    }
    PWSTR text = nullptr;
    if (SUCCEEDED(PropVariantToStringAlloc(var, &text)) && text) {
        std::wstring result = Trim(text);
        CoTaskMemFree(text);
        return result;
    }
    return L"";
}

bool QueryProp(IWICMetadataQueryReader* reader, const wchar_t* name, PROPVARIANT& var) {
    PropVariantInit(&var);
    if (!reader) return false;
    return SUCCEEDED(reader->GetMetadataByName(name, &var)) && var.vt != VT_EMPTY;
}

std::wstring PropText(IWICMetadataQueryReader* reader, const wchar_t* name) {
    PROPVARIANT var;
    if (!QueryProp(reader, name, var)) return L"";
    std::wstring text = VariantText(var);
    PropVariantClear(&var);
    return text;
}

std::wstring PropTextAny(IWICMetadataQueryReader* reader,
                         std::initializer_list<const wchar_t*> names) {
    for (const wchar_t* name : names) {
        std::wstring text = PropText(reader, name);
        if (!text.empty()) return text;
    }
    return L"";
}

bool PropDouble(IWICMetadataQueryReader* reader, const wchar_t* name, double& value) {
    PROPVARIANT var;
    if (!QueryProp(reader, name, var)) return false;
    double result = 0;
    bool ok = SUCCEEDED(PropVariantToDouble(var, &result));
    PropVariantClear(&var);
    if (ok) value = result;
    return ok;
}

std::wstring GpsCoordinate(IWICMetadataQueryReader* reader,
                           std::initializer_list<const wchar_t*> coordinates,
                           std::initializer_list<const wchar_t*> references) {
    std::wstring text;
    for (const wchar_t* coordinate : coordinates) {
        PROPVARIANT var;
        if (!QueryProp(reader, coordinate, var)) continue;
        if (var.vt == (VT_VECTOR | VT_R8) && var.cadbl.cElems >= 3) {
            const double* part = var.cadbl.pElems;
            text = Format(L"%.0f\u00B0 %.0f' %.2f\"", part[0], part[1], part[2]);
        } else {
            text = VariantText(var);
        }
        PropVariantClear(&var);
        if (!text.empty()) break;
    }
    if (text.empty()) return text;
    std::wstring suffix = PropTextAny(reader, references);
    if (!suffix.empty()) text += L" " + suffix;
    return text;
}

std::wstring OrientationText(IWICMetadataQueryReader* reader) {
    PROPVARIANT var;
    if (!QueryProp(reader, L"System.Photo.Orientation", var)) return L"";
    std::wstring text;
    if (var.vt == VT_UI2) {
        switch (var.uiVal) {
        case 1: text = L"Normal (0\u00B0)"; break;
        case 2: text = L"Mirrored horizontally"; break;
        case 3: text = L"Rotated 180\u00B0"; break;
        case 4: text = L"Mirrored vertically"; break;
        case 5: text = L"Mirrored and rotated 90\u00B0 CW"; break;
        case 6: text = L"Rotated 90\u00B0 CW"; break;
        case 7: text = L"Mirrored and rotated 90\u00B0 CCW"; break;
        case 8: text = L"Rotated 90\u00B0 CCW"; break;
        default: text = Format(L"%u", var.uiVal); break;
        }
    } else {
        text = VariantText(var);
    }
    PropVariantClear(&var);
    return text;
}

std::wstring DumpField(const std::wstring& dump, const wchar_t* tag) {
    std::wstring needle = L"(" + std::wstring(tag) + L") = ";
    size_t at = dump.find(needle);
    if (at == std::wstring::npos) return L"";
    at += needle.size();
    size_t end = dump.find(L"\r\n", at);
    std::wstring value = dump.substr(at, end == std::wstring::npos ? std::wstring::npos : end - at);
    return Trim(value);
}

bool ParseDouble(const std::wstring& text, double& value);

std::wstring GpsFromDump(const std::wstring& raw, const std::wstring& reference) {
    std::vector<double> parts;
    std::wstring text = raw;
    for (wchar_t& ch : text) {
        if (ch == L';') ch = L',';
    }
    size_t start = 0;
    while (start < text.size() && parts.size() < 3) {
        size_t end = text.find(L',', start);
        std::wstring piece =
            Trim(text.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start));
        double value = 0;
        if (ParseDouble(piece, value)) parts.push_back(value);
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    if (parts.size() < 3) return L"";
    std::wstring result = Format(L"%.0f\u00B0 %.0f' %.2f\"", parts[0], parts[1], parts[2]);
    if (!reference.empty()) result += L" " + reference;
    return result;
}

bool ParseDouble(const std::wstring& text, double& value) {
    if (text.empty()) return false;
    wchar_t* end = nullptr;
    double parsed = wcstod(text.c_str(), &end);
    if (end == text.c_str()) return false;
    value = parsed;
    return true;
}

std::wstring ExposureFromDump(const std::wstring& dump) {
    std::wstring text;
    std::wstring iso = DumpField(dump, L"ISOSpeedRatings");
    if (iso.empty()) iso = DumpField(dump, L"PhotographicSensitivity");
    if (!iso.empty()) text = L"ISO " + iso;
    double value = 0;
    if (ParseDouble(DumpField(dump, L"FNumber"), value) && value > 0) {
        if (!text.empty()) text += L" \u00B7 ";
        text += Format(L"f/%.1f", value);
    }
    if (ParseDouble(DumpField(dump, L"ExposureTime"), value) && value > 0) {
        if (!text.empty()) text += L" \u00B7 ";
        if (value >= 1.0) text += Format(L"%.1f s", value);
        else text += Format(L"1/%.0f s", 1.0 / value);
    }
    if (ParseDouble(DumpField(dump, L"FocalLength"), value) && value > 0) {
        if (!text.empty()) text += L" \u00B7 ";
        text += Format(L"%.0f mm", value);
    }
    return text;
}

std::wstring ExposureText(IWICMetadataQueryReader* reader) {
    std::wstring text;
    std::wstring iso = PropText(reader, L"System.Photo.ISOSpeed");
    if (!iso.empty()) text += L"ISO " + iso;
    double value = 0;
    if (PropDouble(reader, L"System.Photo.FNumber", value) && value > 0) {
        if (!text.empty()) text += L" \u00B7 ";
        text += Format(L"f/%.1f", value);
    }
    if (PropDouble(reader, L"System.Photo.ExposureTime", value) && value > 0) {
        if (!text.empty()) text += L" \u00B7 ";
        if (value >= 1.0) text += Format(L"%.1f s", value);
        else text += Format(L"1/%.0f s", 1.0 / value);
    }
    if (PropDouble(reader, L"System.Photo.FocalLength", value) && value > 0) {
        if (!text.empty()) text += L" \u00B7 ";
        text += Format(L"%.0f mm", value);
    }
    return text;
}

// ---------------------------------------------------------------- WIC

std::wstring ContainerName(const GUID& format) {
    if (IsEqualGUID(format, GUID_ContainerFormatBmp)) return L"BMP";
    if (IsEqualGUID(format, GUID_ContainerFormatGif)) return L"GIF";
    if (IsEqualGUID(format, GUID_ContainerFormatIco)) return L"ICO";
    if (IsEqualGUID(format, GUID_ContainerFormatJpeg)) return L"JPEG";
    if (IsEqualGUID(format, GUID_ContainerFormatPng)) return L"PNG";
    if (IsEqualGUID(format, GUID_ContainerFormatTiff)) return L"TIFF";
    if (IsEqualGUID(format, GUID_ContainerFormatWmp)) return L"JPEG XR";
    if (IsEqualGUID(format, GUID_ContainerFormatDds)) return L"DDS";
    return L"Image";
}

void DumpMetadataBlock(IWICMetadataQueryReader* reader, const std::wstring& prefix, int depth,
                       std::wstring& out, int& lines, int maxLines) {
    if (!reader || depth > 12 || lines >= maxLines) return;
    IEnumString* enumerator = nullptr;
    if (FAILED(reader->GetEnumerator(&enumerator)) || !enumerator) return;
    LPOLESTR raw = nullptr;
    while (lines < maxLines && enumerator->Next(1, &raw, nullptr) == S_OK) {
        std::wstring name = raw ? raw : L"";
        if (raw) CoTaskMemFree(raw);
        raw = nullptr;
        if (name.empty()) continue;
        PROPVARIANT var;
        PropVariantInit(&var);
        if (SUCCEEDED(reader->GetMetadataByName(name.c_str(), &var))) {
            std::wstring full;
            if (prefix.empty()) full = name;
            else if (name[0] == L'/') full = prefix + name;
            else full = prefix + L"/" + name;
            if (var.vt == VT_UNKNOWN && var.punkVal) {
                IWICMetadataQueryReader* child = nullptr;
                if (SUCCEEDED(var.punkVal->QueryInterface(IID_PPV_ARGS(&child))) && child) {
                    out += AnnotateName(full) + L"\r\n";
                    ++lines;
                    DumpMetadataBlock(child, full, depth + 1, out, lines, maxLines);
                    child->Release();
                }
            } else {
                std::wstring value = VariantText(var);
                out += AnnotateName(full);
                out += L" = ";
                out += value;
                out += L"\r\n";
                ++lines;
            }
        }
        PropVariantClear(&var);
    }
    enumerator->Release();
}

struct ImageInfo {
    bool image = false;
    std::wstring format;
    unsigned width = 0;
    unsigned height = 0;
    std::wstring dateTaken;
    std::wstring camera;
    std::wstring lens;
    std::wstring exposure;
    std::wstring gps;
    std::wstring orientation;
    std::wstring dump;
};

ImageInfo ReadImageInfo(IWICImagingFactory* factory, const std::wstring& path) {
    ImageInfo info;
    if (!factory) return info;
    IWICBitmapDecoder* decoder = nullptr;
    if (FAILED(factory->CreateDecoderFromFilename(path.c_str(), nullptr, GENERIC_READ,
                                                  WICDecodeMetadataCacheOnDemand, &decoder)) ||
        !decoder) {
        return info;
    }
    IWICBitmapFrameDecode* frame = nullptr;
    if (FAILED(decoder->GetFrame(0, &frame)) || !frame) {
        decoder->Release();
        return info;
    }
    info.image = true;
    UINT width = 0;
    UINT height = 0;
    if (SUCCEEDED(frame->GetSize(&width, &height))) {
        info.width = width;
        info.height = height;
    }
    GUID container{};
    if (SUCCEEDED(decoder->GetContainerFormat(&container))) info.format = ContainerName(container);

    IWICMetadataQueryReader* reader = nullptr;
    if (SUCCEEDED(frame->GetMetadataQueryReader(&reader)) && reader) {
        info.dateTaken = PropText(reader, L"System.Photo.DateTaken");
        std::wstring make = PropText(reader, L"System.Photo.CameraManufacturer");
        std::wstring model = PropText(reader, L"System.Photo.CameraModel");
        if (!make.empty() && !model.empty()) {
            info.camera = ContainsInsensitive(model, make) ? model : make + L" " + model;
        } else {
            info.camera = make.empty() ? model : make;
        }
        info.lens = PropTextAny(reader, {L"System.Photo.LensModel",
                                         L"/app1/{ushort=34665}/{ushort=42036}",
                                         L"/ifd/exif/{ushort=42036}"});
        if (info.lens.empty()) info.lens = PropText(reader, L"System.Photo.LensManufacturer");
        info.exposure = ExposureText(reader);
        std::wstring latitude = GpsCoordinate(
            reader, {L"System.GPS.Latitude", L"/app1/{ushort=34853}/{ushort=2}",
                     L"/ifd/gps/{ushort=2}"},
            {L"System.GPS.LatitudeRef", L"/app1/{ushort=34853}/{ushort=1}",
             L"/ifd/gps/{ushort=1}"});
        std::wstring longitude = GpsCoordinate(
            reader, {L"System.GPS.Longitude", L"/app1/{ushort=34853}/{ushort=4}",
                     L"/ifd/gps/{ushort=4}"},
            {L"System.GPS.LongitudeRef", L"/app1/{ushort=34853}/{ushort=3}",
             L"/ifd/gps/{ushort=3}"});
        if (!latitude.empty() && !longitude.empty()) info.gps = latitude + L", " + longitude;
        else info.gps = latitude.empty() ? longitude : latitude;
        info.orientation = OrientationText(reader);
        int lines = 0;
        DumpMetadataBlock(reader, L"", 0, info.dump, lines, 4000);

        // The property-system view does not expose every EXIF tag on every decoder, so fall back
        // to the raw values already collected in the metadata tree.
        if (info.lens.empty()) info.lens = DumpField(info.dump, L"LensModel");
        std::wstring exposureFromDump = ExposureFromDump(info.dump);
        if (!exposureFromDump.empty()) {
            if (exposureFromDump.find(L"ISO") == std::wstring::npos) {
                std::wstring iso = PropText(reader, L"System.Photo.ISOSpeed");
                if (!iso.empty()) exposureFromDump = L"ISO " + iso + L" \u00B7 " + exposureFromDump;
            }
            info.exposure = exposureFromDump;
        }
        if (info.gps.empty()) {
            std::wstring lat = GpsFromDump(DumpField(info.dump, L"GPSLatitude"),
                                           DumpField(info.dump, L"GPSLatitudeRef"));
            std::wstring lon = GpsFromDump(DumpField(info.dump, L"GPSLongitude"),
                                           DumpField(info.dump, L"GPSLongitudeRef"));
            if (lat.empty()) lat = DumpField(info.dump, L"GPSLatitude");
            if (lon.empty()) lon = DumpField(info.dump, L"GPSLongitude");
            if (!lat.empty() && !lon.empty()) info.gps = lat + L", " + lon;
            else info.gps = lat.empty() ? lon : lat;
        }
        reader->Release();
    }
    frame->Release();
    decoder->Release();
    return info;
}

bool LooksLikePortableExecutable(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    char magic[2] = {};
    DWORD read = 0;
    bool ok = ReadFile(file, magic, 2, &read, nullptr) && read == 2;
    CloseHandle(file);
    return ok && magic[0] == 'M' && magic[1] == 'Z';
}

bool LooksLikeImage(const std::wstring& path) {
    std::wstring lower = ToLower(path);
    size_t dot = lower.rfind(L'.');
    if (dot == std::wstring::npos) return false;
    std::wstring extension = lower.substr(dot);
    static const wchar_t* extensions[] = {
        L".jpg", L".jpeg", L".jpe", L".png", L".gif", L".bmp", L".tif", L".tiff",
        L".ico", L".heic", L".heif", L".webp", L".avif", L".dng", L".cr2", L".cr3",
        L".nef", L".arw", L".orf", L".rw2", L".jfif", L".jxr", L".wdp", L".dds"};
    for (const wchar_t* candidate : extensions) {
        if (extension == candidate) return true;
    }
    return false;
}

template <typename Callback>
void WalkFiles(const std::wstring& root, bool recursive, std::atomic<bool>& stop, Callback&& callback) {
    std::vector<std::wstring> stack;
    stack.push_back(root);
    while (!stack.empty()) {
        if (stop.load()) break;
        std::wstring folder = stack.back();
        stack.pop_back();
        WIN32_FIND_DATAW data{};
        HANDLE find = FindFirstFileW((folder + L"\\*").c_str(), &data);
        if (find == INVALID_HANDLE_VALUE) continue;
        do {
            if (data.cFileName[0] == L'.' &&
                (data.cFileName[1] == 0 ||
                 (data.cFileName[1] == L'.' && data.cFileName[2] == 0))) {
                continue;
            }
            std::wstring full = folder + L"\\" + data.cFileName;
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (recursive && !(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                    stack.push_back(full);
                }
                continue;
            }
            if (!callback(full, data)) {
                FindClose(find);
                return;
            }
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }
}

unsigned long long FileBytes(const WIN32_FIND_DATAW& data) {
    return (static_cast<unsigned long long>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
}

void FlushBatch(const Sink& sink, std::vector<Row>& rows, std::vector<std::wstring>& details) {
    if (rows.empty()) return;
    sink.Detailed(std::move(rows), std::move(details), false);
    rows.clear();
    details.clear();
}

} // namespace

// ---------------------------------------------------------------- file hashes

void RunFileHashScan(const Sink& sink, std::atomic<bool>& stop, FileHashConfig config) {
    HRESULT comInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    std::vector<Row> rows;
    std::vector<std::wstring> details;
    rows.reserve(128);
    details.reserve(128);

    IWICImagingFactory* factory = nullptr;
    CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                     IID_PPV_ARGS(&factory));

    unsigned long long total = 0;
    unsigned long long signedCount = 0;
    unsigned long long unsignedCount = 0;
    unsigned long long nonPeCount = 0;

    WalkFiles(config.folder, config.recursive, stop, [&](const std::wstring& path,
                                                          const WIN32_FIND_DATAW& data) {
        if (stop.load()) return false;
        ++total;
        sink.Status(Format(L"Hashing %s \u00b7 %s file(s)", PathFileName(path).c_str(),
                           CommaNumber(total).c_str()),
                    -1);

        Digests digests;
        if (config.hashContents) digests = ComputeDigests(path);

        SignatureInfo signature;
        const bool portableExecutable = config.verifySignature && LooksLikePortableExecutable(path);
        if (portableExecutable) {
            signature = GetSignatureInfo(path);
        } else if (config.verifySignature) {
            signature.status = L"not a PE file";
        }

        std::wstring signatureText = signature.status.empty() ? L"-" : signature.status;
        std::wstring signerText = signature.signer.empty() ? L"-" : signature.signer;
        if (portableExecutable) {
            if (signature.valid) ++signedCount;
            else ++unsignedCount;
        } else if (config.verifySignature) {
            ++nonPeCount;
        }

        unsigned long long bytes = FileBytes(data);
        Row row;
        row.push_back(PathFileName(path));
        row.push_back(SizeText(bytes));
        row.push_back(FileTimeText(data.ftLastWriteTime));
        row.push_back(digests.sha256.empty() ? L"-" : digests.sha256);
        row.push_back(digests.sha1.empty() ? L"-" : digests.sha1);
        row.push_back(digests.md5.empty() ? L"-" : digests.md5);
        row.push_back(signatureText);
        row.push_back(signerText);
        rows.push_back(std::move(row));

        std::wstring detail;
        detail += L"File          : " + path + L"\r\n";
        detail += L"Name          : " + std::wstring(data.cFileName) + L"\r\n";
        size_t dot = path.rfind(L'.');
        if (dot != std::wstring::npos && dot > path.rfind(L'\\')) {
            detail += L"Extension     : " + path.substr(dot) + L"\r\n";
        }
        detail += L"Size          : " + SizeText(bytes) +
                  Format(L" (%s bytes)\r\n", CommaNumber(bytes).c_str());
        detail += AttributesAndTimes(path, data.dwFileAttributes, data.ftCreationTime,
                                     data.ftLastWriteTime, data.ftLastAccessTime);
        if (config.hashContents) {
            detail += L"\r\n--- hashes ---\r\n";
            detail += HashesText(path);
        }

        if (config.verifySignature) {
            detail += L"\r\n--- Authenticode signature ---\r\n";
            if (portableExecutable) {
                detail += SignatureReportText(signature, path);
            } else {
                detail += L"File        : " + path + L"\r\n";
                detail += L"Status      : not a PE file (Authenticode applies to executables only)\r\n";
            }
        }

        std::wstring version = VersionInfoText(path);
        if (!version.empty()) {
            detail += L"\r\n--- version information ---\r\n" + version;
        }

        std::wstring streams = AlternateStreamsReport(path);
        if (!streams.empty()) {
            detail += L"\r\n--- alternate data streams ---\r\n" + streams;
        }

        if (factory && LooksLikeImage(path)) {
            ImageInfo image = ReadImageInfo(factory, path);
            if (image.image) {
                detail += L"\r\n--- image metadata ---\r\n";
                detail += Format(L"Format        : %s\r\n", image.format.c_str());
                detail += Format(L"Dimensions    : %u x %u\r\n", image.width, image.height);
                if (!image.dateTaken.empty()) detail += L"Date taken    : " + image.dateTaken + L"\r\n";
                if (!image.camera.empty()) detail += L"Camera        : " + image.camera + L"\r\n";
                if (!image.lens.empty()) detail += L"Lens          : " + image.lens + L"\r\n";
                if (!image.exposure.empty()) detail += L"Exposure      : " + image.exposure + L"\r\n";
                if (!image.gps.empty()) detail += L"GPS           : " + image.gps + L"\r\n";
                if (!image.dump.empty()) detail += L"\r\n" + image.dump;
            }
        }
        details.push_back(std::move(detail));

        if (rows.size() >= 128) FlushBatch(sink, rows, details);
        return true;
    });

    if (factory) factory->Release();
    if (SUCCEEDED(comInit)) CoUninitialize();
    FlushBatch(sink, rows, details);

    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s file(s) inspected.", CommaNumber(total).c_str()));
    } else if (total == 0) {
        sink.Done(L"No file was found in " + config.folder + L".");
    } else {
        sink.Done(Format(L"Completed. %s file(s) hashed \u00b7 %s signed \u00b7 %s unsigned \u00b7 "
                         L"%s non-PE",
                         CommaNumber(total).c_str(), CommaNumber(signedCount).c_str(),
                         CommaNumber(unsignedCount).c_str(), CommaNumber(nonPeCount).c_str()));
    }
}

// ---------------------------------------------------------------- image metadata

void RunImageMetadataScan(const Sink& sink, std::atomic<bool>& stop, ImageMetaConfig config) {
    HRESULT comInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    std::vector<Row> rows;
    std::vector<std::wstring> details;
    rows.reserve(64);
    details.reserve(64);

    IWICImagingFactory* factory = nullptr;
    CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                     IID_PPV_ARGS(&factory));

    unsigned long long total = 0;
    unsigned long long images = 0;
    unsigned long long withGps = 0;
    unsigned long long withExif = 0;

    WalkFiles(config.folder, config.recursive, stop, [&](const std::wstring& path,
                                                          const WIN32_FIND_DATAW& data) {
        if (stop.load()) return false;
        if (!LooksLikeImage(path)) return true;
        ++total;
        sink.Status(Format(L"Reading metadata %s \u00b7 %s image(s)",
                           PathFileName(path).c_str(), CommaNumber(images).c_str()),
                    -1);

        ImageInfo image = ReadImageInfo(factory, path);
        if (!image.image) return true;
        ++images;
        if (!image.gps.empty()) ++withGps;
        if (!image.dump.empty()) ++withExif;

        unsigned long long bytes = FileBytes(data);
        Row row;
        row.push_back(PathFileName(path));
        row.push_back(image.format);
        row.push_back(Format(L"%u x %u", image.width, image.height));
        row.push_back(SizeText(bytes));
        row.push_back(image.dateTaken.empty() ? L"-" : image.dateTaken);
        row.push_back(image.camera.empty() ? L"-" : image.camera);
        row.push_back(image.lens.empty() ? L"-" : image.lens);
        row.push_back(image.exposure.empty() ? L"-" : image.exposure);
        row.push_back(image.gps.empty() ? L"-" : image.gps);
        rows.push_back(std::move(row));

        std::wstring detail;
        detail += L"File          : " + path + L"\r\n";
        detail += L"Format        : " + (image.format.empty() ? L"-" : image.format) + L"\r\n";
        detail += Format(L"Dimensions    : %u x %u\r\n", image.width, image.height);
        detail += L"Size          : " + SizeText(bytes) +
                  Format(L" (%s bytes)\r\n", CommaNumber(bytes).c_str());
        detail += L"Created       : " + FileTimeText(data.ftCreationTime) + L"\r\n";
        detail += L"Modified      : " + FileTimeText(data.ftLastWriteTime) + L"\r\n";
        detail += L"Accessed      : " + FileTimeText(data.ftLastAccessTime) + L"\r\n";
        detail += L"Attributes    : " + AttributesText(data.dwFileAttributes) + L"\r\n";
        detail += L"Date taken    : " + (image.dateTaken.empty() ? L"-" : image.dateTaken) + L"\r\n";
        detail += L"Camera        : " + (image.camera.empty() ? L"-" : image.camera) + L"\r\n";
        detail += L"Lens          : " + (image.lens.empty() ? L"-" : image.lens) + L"\r\n";
        detail += L"Exposure      : " + (image.exposure.empty() ? L"-" : image.exposure) + L"\r\n";
        detail += L"GPS           : " + (image.gps.empty() ? L"-" : image.gps) + L"\r\n";
        detail += L"Orientation   : " + (image.orientation.empty() ? L"-" : image.orientation) + L"\r\n";
        detail += L"\r\n--- full metadata (" +
                  CommaNumber(static_cast<unsigned long long>(image.dump.size())) +
                  L" char(s)) ---\r\n";
        detail += image.dump.empty() ? L"(this file carries no embedded metadata)\r\n" : image.dump;
        details.push_back(std::move(detail));

        if (rows.size() >= 64) FlushBatch(sink, rows, details);
        return true;
    });

    if (factory) factory->Release();
    if (SUCCEEDED(comInit)) CoUninitialize();
    FlushBatch(sink, rows, details);

    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s image(s) read.", CommaNumber(images).c_str()));
    } else if (images == 0) {
        sink.Done(Format(L"No readable image was found in %s (%s candidate file(s) checked).",
                         config.folder.c_str(), CommaNumber(total).c_str()));
    } else {
        sink.Done(Format(L"Completed. %s image(s) \u00b7 %s with metadata \u00b7 %s with GPS",
                         CommaNumber(images).c_str(), CommaNumber(withExif).c_str(),
                         CommaNumber(withGps).c_str()));
    }
}
