#include "common.h"

#include <wincrypt.h>
#include <bcrypt.h>
#include <mscat.h>
#include <softpub.h>
#include <wintrust.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace {

std::wstring SignatureStatusText(LONG status, DWORD lastError) {
    switch (status) {
    case ERROR_SUCCESS:
        return L"valid signature";
    case TRUST_E_NOSIGNATURE:
        if (lastError == TRUST_E_NOSIGNATURE || lastError == TRUST_E_SUBJECT_FORM_UNKNOWN ||
            lastError == TRUST_E_PROVIDER_UNKNOWN) {
            return L"no signature";
        }
        return L"no signature";
    case TRUST_E_EXPLICIT_DISTRUST:
        return L"explicitly distrusted";
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        return L"signature present, not trusted";
    case CRYPT_E_SECURITY_SETTINGS:
        return L"blocked by security settings";
    case TRUST_E_BAD_DIGEST:
        return L"invalid signature (bad digest)";
    case CERT_E_EXPIRED:
        return L"signature expired";
    case CERT_E_UNTRUSTEDROOT:
        return L"untrusted root certificate";
    case CERT_E_CHAINING:
        return L"certificate chain could not be built";
    case CRYPT_E_REVOKED:
        return L"certificate revoked";
    default:
        return Format(L"invalid (0x%08lX)", static_cast<unsigned long>(status));
    }
}

bool HashFileWith(const std::wstring& path, LPCWSTR algorithm, std::vector<BYTE>& digest,
                  std::wstring& error) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<BYTE> object;
    bool ok = false;

    auto cleanup = [&]() {
        if (hash) BCryptDestroyHash(hash);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    };

    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, algorithm, nullptr, 0);
    if (status != 0) {
        error = Format(L"BCryptOpenAlgorithmProvider failed (0x%08lX)", static_cast<unsigned long>(status));
        return false;
    }
    DWORD objectLength = 0;
    DWORD result = 0;
    status = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength),
                               sizeof(objectLength), &result, 0);
    if (status != 0) {
        error = L"BCryptGetProperty failed";
        cleanup();
        return false;
    }
    object.resize(objectLength);
    status = BCryptCreateHash(alg, &hash, object.data(), objectLength, nullptr, 0, 0);
    if (status != 0) {
        error = L"BCryptCreateHash failed";
        cleanup();
        return false;
    }

    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = Format(L"cannot open file (%lu)", GetLastError());
        cleanup();
        return false;
    }

    std::vector<BYTE> buffer(1 << 20);
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            error = Format(L"read failed (%lu)", GetLastError());
            break;
        }
        if (read == 0) {
            ok = true;
            break;
        }
        status = BCryptHashData(hash, buffer.data(), read, 0);
        if (status != 0) {
            error = Format(L"BCryptHashData failed (0x%08lX)", static_cast<unsigned long>(status));
            break;
        }
    }
    CloseHandle(file);

    if (ok) {
        DWORD hashLength = 0;
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength),
                          sizeof(hashLength), &result, 0);
        digest.assign(hashLength, 0);
        status = BCryptFinishHash(hash, digest.data(), hashLength, 0);
        if (status != 0) {
            error = Format(L"BCryptFinishHash failed (0x%08lX)", static_cast<unsigned long>(status));
            ok = false;
        }
    }
    cleanup();
    return ok;
}

std::wstring HexDigest(const std::vector<BYTE>& digest) {
    static const wchar_t* kHex = L"0123456789abcdef";
    std::wstring text;
    text.reserve(digest.size() * 2);
    for (BYTE byte : digest) {
        text.push_back(kHex[byte >> 4]);
        text.push_back(kHex[byte & 0x0F]);
    }
    return text;
}

struct CertChainEntry {
    std::wstring subject;
    std::wstring issuer;
    std::wstring thumbprint;
    std::wstring serial;
    std::wstring notBefore;
    std::wstring notAfter;
    bool selfSigned = false;
};

std::wstring CertName(PCCERT_CONTEXT cert, DWORD flags) {
    DWORD size = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, nullptr, 0);
    if (size <= 1) return L"";
    std::wstring text(size, L'\0');
    if (CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, text.data(), size) <= 1) {
        return L"";
    }
    while (!text.empty() && text.back() == L'\0') text.pop_back();
    return text;
}

std::wstring CertThumbprint(PCCERT_CONTEXT cert) {
    DWORD size = 0;
    if (!CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, nullptr, &size) || size == 0) {
        return L"";
    }
    std::vector<BYTE> hash(size);
    if (!CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, hash.data(), &size)) return L"";
    hash.resize(size);
    static const wchar_t* kHex = L"0123456789ABCDEF";
    std::wstring text;
    text.reserve(hash.size() * 2);
    for (BYTE byte : hash) {
        text.push_back(kHex[byte >> 4]);
        text.push_back(kHex[byte & 0x0F]);
    }
    return text;
}

std::wstring CertSerial(PCCERT_CONTEXT cert) {
    const CRYPT_INTEGER_BLOB& serial = cert->pCertInfo->SerialNumber;
    static const wchar_t* kHex = L"0123456789ABCDEF";
    std::wstring text;
    for (DWORD i = 0; i < serial.cbData; ++i) {
        BYTE byte = serial.pbData[serial.cbData - 1 - i];
        text.push_back(kHex[byte >> 4]);
        text.push_back(kHex[byte & 0x0F]);
    }
    while (text.size() > 2 && text[0] == L'0' && text[1] == L'0') text.erase(0, 2);
    return text;
}

CertChainEntry DescribeCert(PCCERT_CONTEXT cert) {
    CertChainEntry entry;
    entry.subject = CertName(cert, 0);
    entry.issuer = CertName(cert, CERT_NAME_ISSUER_FLAG);
    entry.thumbprint = CertThumbprint(cert);
    entry.serial = CertSerial(cert);
    entry.notBefore = FileTimeText(cert->pCertInfo->NotBefore);
    entry.notAfter = FileTimeText(cert->pCertInfo->NotAfter);
    entry.selfSigned = CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                  &cert->pCertInfo->Subject,
                                                  &cert->pCertInfo->Issuer) != 0;
    return entry;
}

struct VerifyOutcome {
    LONG status = TRUST_E_NOSIGNATURE;
    DWORD lastError = 0;
    std::wstring publisher;
    std::wstring source;
    std::wstring catalogPath;
    std::vector<CertChainEntry> chain;
};

VerifyOutcome RunVerify(WINTRUST_DATA& data) {
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    VerifyOutcome outcome;
    outcome.status = WinVerifyTrust(nullptr, &action, &data);
    outcome.lastError = GetLastError();

    if (data.hWVTStateData) {
        CRYPT_PROVIDER_DATA* provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        if (provider) {
            CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0);
            if (signer) {
                for (DWORD index = 0;; ++index) {
                    CRYPT_PROVIDER_CERT* cert = WTHelperGetProvCertFromChain(signer, index);
                    if (!cert || !cert->pCert) break;
                    CertChainEntry entry = DescribeCert(cert->pCert);
                    if (index == 0) outcome.publisher = entry.subject;
                    outcome.chain.push_back(std::move(entry));
                }
            }
        }
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &action, &data);
    }
    return outcome;
}

VerifyOutcome VerifyEmbedded(const std::wstring& path) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;

    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    VerifyOutcome outcome = RunVerify(data);
    outcome.source = L"Embedded in the file";
    return outcome;
}

VerifyOutcome VerifyCatalog(const std::wstring& path) {
    VerifyOutcome outcome;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return outcome;

    HCATADMIN admin = nullptr;
    bool acquired = CryptCATAdminAcquireContext2(&admin, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0;
    if (!acquired) acquired = CryptCATAdminAcquireContext(&admin, nullptr, 0) != 0;
    if (!acquired) {
        CloseHandle(file);
        return outcome;
    }

    DWORD hashLength = 0;
    if (!CryptCATAdminCalcHashFromFileHandle2(admin, file, &hashLength, nullptr, 0) &&
        !CryptCATAdminCalcHashFromFileHandle(file, &hashLength, nullptr, 0)) {
        CryptCATAdminReleaseContext(admin, 0);
        CloseHandle(file);
        return outcome;
    }

    std::vector<BYTE> hash(hashLength);
    if (!CryptCATAdminCalcHashFromFileHandle2(admin, file, &hashLength, hash.data(), 0) &&
        !CryptCATAdminCalcHashFromFileHandle(file, &hashLength, hash.data(), 0)) {
        CryptCATAdminReleaseContext(admin, 0);
        CloseHandle(file);
        return outcome;
    }

    HCATINFO info = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), hashLength, 0, nullptr);
    if (!info) {
        CryptCATAdminReleaseContext(admin, 0);
        CloseHandle(file);
        return outcome;
    }

    CATALOG_INFO catalog{};
    catalog.cbStruct = sizeof(catalog);
    if (CryptCATCatalogInfoFromContext(info, &catalog, 0)) {
        static const wchar_t* kHex = L"0123456789ABCDEF";
        std::wstring tag;
        tag.reserve(hash.size() * 2);
        for (BYTE byte : hash) {
            tag.push_back(kHex[byte >> 4]);
            tag.push_back(kHex[byte & 0x0F]);
        }

        WINTRUST_CATALOG_INFO catalogInfo{};
        catalogInfo.cbStruct = sizeof(catalogInfo);
        catalogInfo.pcwszCatalogFilePath = catalog.wszCatalogFile;
        catalogInfo.pcwszMemberTag = tag.c_str();
        catalogInfo.pcwszMemberFilePath = path.c_str();
        catalogInfo.hMemberFile = file;
        catalogInfo.pbCalculatedFileHash = hash.data();
        catalogInfo.cbCalculatedFileHash = hashLength;
        catalogInfo.hCatAdmin = admin;

        WINTRUST_DATA data{};
        data.cbStruct = sizeof(data);
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_CATALOG;
        data.pCatalog = &catalogInfo;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
        outcome = RunVerify(data);
        outcome.catalogPath = catalog.wszCatalogFile;
        outcome.source = L"Catalog: " + std::wstring(catalog.wszCatalogFile);
    }

    CryptCATAdminReleaseCatalogContext(admin, info, 0);
    CryptCATAdminReleaseContext(admin, 0);
    CloseHandle(file);
    return outcome;
}

std::wstring ReadSmallStream(const std::wstring& fullPath, size_t limit) {
    HANDLE file = CreateFileW(fullPath.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return L"";
    std::string bytes(limit, '\0');
    DWORD read = 0;
    ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    CloseHandle(file);
    bytes.resize(read);
    if (bytes.size() >= 2 && static_cast<BYTE>(bytes[0]) == 0xFF && static_cast<BYTE>(bytes[1]) == 0xFE) {
        return std::wstring(reinterpret_cast<const wchar_t*>(bytes.data() + 2), (bytes.size() - 2) / 2);
    }
    return Utf8ToWide(bytes);
}

}

SignatureInfo GetSignatureInfo(const std::wstring& path) {
    SignatureInfo info;
    if (path.empty()) {
        info.status = L"(no path)";
        return info;
    }
    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        info.status = L"file not found";
        return info;
    }
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        info.status = L"(directory)";
        return info;
    }

    VerifyOutcome outcome = VerifyEmbedded(path);
    if (outcome.status == TRUST_E_NOSIGNATURE) {
        VerifyOutcome catalog = VerifyCatalog(path);
        if (catalog.status != TRUST_E_NOSIGNATURE) outcome = catalog;
    }

    info.status = SignatureStatusText(outcome.status, outcome.lastError);
    info.valid = outcome.status == ERROR_SUCCESS;
    info.certificateLocation = outcome.source.empty() ? L"-" : outcome.source;

    if (!info.valid && outcome.chain.empty()) info.certificateLocation = L"None";
    info.catalogPath = outcome.catalogPath;
    if (!outcome.chain.empty()) {
        const CertChainEntry& leaf = outcome.chain.front();
        info.signer = leaf.subject;
        info.issuer = leaf.issuer;
        info.thumbprint = leaf.thumbprint;
        info.serial = leaf.serial;
        info.notBefore = leaf.notBefore;
        info.notAfter = leaf.notAfter;
        info.selfSigned = leaf.selfSigned;
    }
    for (size_t i = 0; i < outcome.chain.size(); ++i) {
        const CertChainEntry& entry = outcome.chain[i];
        std::wstring line = Format(L"[%d] %s\r\n", static_cast<int>(i),
                                   entry.subject.empty() ? L"(unnamed)" : entry.subject.c_str());
        line += L"    Issuer     : " + (entry.issuer.empty() ? L"-" : entry.issuer) + L"\r\n";
        line += L"    Valid      : " + entry.notBefore + L" \u2192 " + entry.notAfter + L"\r\n";
        line += L"    Thumbprint : " + entry.thumbprint + L"\r\n";
        line += L"    Serial     : " + entry.serial + L"\r\n";
        line += L"    Self-signed: " + std::wstring(entry.selfSigned ? L"yes" : L"no") + L"\r\n";
        info.chain.push_back(std::move(line));
    }
    return info;
}

std::wstring FileSignatureText(const std::wstring& path) {
    SignatureInfo info = GetSignatureInfo(path);
    if (!info.signer.empty() && info.valid) return info.status + L" \u00B7 " + info.signer;
    if (!info.signer.empty() && info.status != L"no signature") {
        return info.status + L" \u00B7 " + info.signer;
    }
    return info.status;
}

std::wstring SignatureReportText(const SignatureInfo& info, const std::wstring& path) {
    std::wstring text;
    text += L"File        : " + path + L"\r\n";
    text += L"Status      : " + info.status + L"\r\n";
    text += L"Trusted     : " + std::wstring(info.valid ? L"yes (chains to a trusted root)" : L"no") + L"\r\n";
    text += L"Certificate : " + info.certificateLocation + L"\r\n";
    text += L"Signer      : " + (info.signer.empty() ? L"-" : info.signer) + L"\r\n";
    text += L"Issuer      : " + (info.issuer.empty() ? L"-" : info.issuer) + L"\r\n";
    text += L"Self-signed : " + std::wstring(info.selfSigned ? L"yes" : L"no") + L"\r\n";
    text += L"Valid from  : " + (info.notBefore.empty() ? L"-" : info.notBefore) + L"\r\n";
    text += L"Valid to    : " + (info.notAfter.empty() ? L"-" : info.notAfter) + L"\r\n";
    text += L"Thumbprint  : " + (info.thumbprint.empty() ? L"-" : info.thumbprint) + L"\r\n";
    text += L"Serial      : " + (info.serial.empty() ? L"-" : info.serial) + L"\r\n";
    text += Format(L"\r\n--- certificate chain (%d) ---\r\n", static_cast<int>(info.chain.size()));
    if (info.chain.empty()) {
        text += L"(no certificate chain; the file is not signed)\r\n";
    } else {
        for (const std::wstring& line : info.chain) text += line;
    }
    return text;
}

std::wstring CertificateReport(const std::wstring& path) {
    return SignatureReportText(GetSignatureInfo(path), path);
}

std::wstring HashFileReport(const std::wstring& path) {
    std::wstring text = L"File      : " + path + L"\r\n";
    WIN32_FILE_ATTRIBUTE_DATA attributes{};
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes)) {
        unsigned long long bytes = (static_cast<unsigned long long>(attributes.nFileSizeHigh) << 32) |
                                   attributes.nFileSizeLow;
        text += L"Size      : " + SizeText(bytes) + Format(L" (%s bytes)\r\n", CommaNumber(bytes).c_str());
        text += L"Modified  : " + FileTimeText(attributes.ftLastWriteTime) + L"\r\n";
        text += L"Created   : " + FileTimeText(attributes.ftCreationTime) + L"\r\n";
    } else {
        text += L"Size      : (file could not be opened)\r\n";
    }

    auto started = std::chrono::steady_clock::now();
    std::vector<BYTE> digest;
    std::wstring error;
    if (HashFileWith(path, BCRYPT_SHA256_ALGORITHM, digest, error)) {
        text += L"SHA-256   : " + HexDigest(digest) + L"\r\n";
    } else {
        text += L"SHA-256   : failed \u00B7 " + error + L"\r\n";
    }
    digest.clear();
    error.clear();
    if (HashFileWith(path, BCRYPT_MD5_ALGORITHM, digest, error)) {
        text += L"MD5       : " + HexDigest(digest) + L"\r\n";
    } else {
        text += L"MD5       : failed \u00B7 " + error + L"\r\n";
    }
    long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - started).count();
    text += L"Elapsed   : " + CommaNumber(static_cast<unsigned long long>(ms)) + L" ms\r\n";
    text += L"Signature : " + FileSignatureText(path) + L"\r\n";
    return text;
}

bool HashFileDigest(const std::wstring& path, const wchar_t* algorithm,
                    std::vector<unsigned char>& digest) {
    std::wstring error;
    return HashFileWith(path, algorithm, digest, error);
}

std::wstring HexLower(const std::vector<unsigned char>& digest) { return HexDigest(digest); }

std::wstring AlternateStreamsReport(const std::wstring& path) {
    std::wstring text = L"File    : " + path + L"\r\n\r\n";

    WIN32_FIND_STREAM_DATA stream{};
    HANDLE find = FindFirstStreamW(path.c_str(), FindStreamInfoStandard, &stream, 0);
    if (find == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_HANDLE_EOF) {
            text += L"No alternate data streams. Only the unnamed :$DATA stream exists.\r\n";
        } else {
            text += Format(L"Stream enumeration failed (%lu).\r\n", error);
        }
        return text;
    }

    int count = 0;
    std::vector<std::pair<std::wstring, unsigned long long>> streams;
    do {
        std::wstring name = stream.cStreamName;
        unsigned long long size = static_cast<unsigned long long>(stream.StreamSize.QuadPart);
        streams.emplace_back(name, size);
        ++count;
    } while (FindNextStreamW(find, &stream));
    FindClose(find);

    text += Format(L"Streams : %d\r\n\r\n", count);
    for (const auto& item : streams) {
        bool unnamed = item.first == L"::$DATA" || item.first == L":$DATA";
        text += Format(L"%-24s %12s  %s\r\n", unnamed ? L"(default data)" : item.first.c_str(),
                       SizeText(item.second).c_str(),
                       unnamed ? L"main file content" : L"alternate data stream");
    }

    for (const auto& item : streams) {
        if (item.first == L"::$DATA" || item.first == L":$DATA") continue;
        if (ToLower(item.first).find(L"zone.identifier") == std::wstring::npos) continue;
        std::wstring content = ReadSmallStream(path + item.first, 4096);
        if (content.empty()) continue;
        text += L"\r\n--- " + item.first + L" (mark-of-the-web) ---\r\n";
        text += content;
        if (content.back() != L'\n') text += L"\r\n";
    }
    return text;
}
