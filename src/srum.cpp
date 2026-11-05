#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include "common.h"
#include "artifacts.h"

#include <esent.h>
#include <oleauto.h>
#include <sddl.h>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "esent.lib")

namespace {

const wchar_t* kSrumRegistry = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SRUM";
const wchar_t* kSrumExtensions = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SRUM\\Extensions";
const wchar_t* kSrumDatabase = L"C:\\Windows\\System32\\sru\\SRUDB.dat";

std::wstring RegText(HKEY root, const wchar_t* subkey, const wchar_t* name) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return L"";
    std::wstring result;
    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) == ERROR_SUCCESS && size > 0 &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
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

DWORD RegNumber(HKEY root, const wchar_t* subkey, const wchar_t* name, DWORD fallback) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return fallback;
    DWORD type = 0;
    DWORD size = sizeof(DWORD);
    DWORD value = fallback;
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(&value), &size) != ERROR_SUCCESS ||
        type != REG_DWORD) {
        value = fallback;
    }
    RegCloseKey(key);
    return value;
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

std::wstring ExpandPath(const std::wstring& value) {
    if (value.empty()) return value;
    wchar_t buffer[2048] = {};
    DWORD needed = ExpandEnvironmentStringsW(value.c_str(), buffer, 2048);
    if (!needed || needed > 2048) return value;
    return buffer;
}

std::wstring OleDateText(double value) {
    if (value <= 0.0) return L"";
    SYSTEMTIME st{};
    if (!VariantTimeToSystemTime(value, &st)) return Format(L"%.6f", value);
    return Format(L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour,
                  st.wMinute, st.wSecond);
}

std::wstring HexPreview(const BYTE* data, unsigned long length, unsigned long maximum = 48) {
    std::wstring text;
    unsigned long count = length < maximum ? length : maximum;
    for (unsigned long i = 0; i < count; ++i) {
        if (i) text += L" ";
        text += Format(L"%02X", data[i]);
    }
    if (length > count) text += L" \u2026";
    return text;
}

std::wstring GuidText(const BYTE* data, unsigned long length) {
    if (length < 16) return HexPreview(data, length);
    GUID guid{};
    std::memcpy(&guid, data, 16);
    wchar_t text[64] = {};
    StringFromGUID2(guid, text, 64);
    return text;
}

bool LooksLikeUtf16(const BYTE* data, unsigned long length) {
    if (length < 4 || (length % 2) != 0) return false;
    unsigned long total = length / 2;
    unsigned long ascii = 0;
    for (unsigned long i = 0; i + 1 < length; i += 2) {
        if (data[i + 1] == 0 && data[i] >= 0x20 && data[i] < 0x7F) ++ascii;
    }
    return ascii * 10 >= total * 8;
}

std::wstring Utf16BlobText(const BYTE* data, unsigned long length) {
    std::wstring text(reinterpret_cast<const wchar_t*>(data), length / 2);
    while (!text.empty() && (text.back() == 0 || text.back() == L'\r' || text.back() == L'\n')) {
        text.pop_back();
    }
    return text;
}

std::wstring SidText(const BYTE* data, unsigned long length) {
    if (length < 8) return L"";
    PSID sid = const_cast<BYTE*>(data);
    if (!IsValidSid(sid)) return L"";
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text)) return L"";
    std::wstring result = text;
    LocalFree(text);
    return result;
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

DWORD EsePageSize(const std::wstring& path) {
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return 4096;
    BYTE header[512] = {};
    DWORD read = 0;
    DWORD pageSize = 4096;
    if (ReadFile(handle, header, sizeof(header), &read, nullptr) && read >= 512) {
        DWORD value = 0;
        std::memcpy(&value, header + 0xEC, sizeof(value));
        if (value == 2048 || value == 4096 || value == 8192 || value == 16384 || value == 32768) {
            pageSize = value;
        }
    }
    CloseHandle(handle);
    return pageSize;
}

struct EseColumn {
    std::wstring name;
    JET_COLUMNDEF def{};
};

struct EseTable {
    std::wstring name;
    std::vector<EseColumn> columns;
};

struct EseDatabase {
    JET_INSTANCE instance = JET_instanceNil;
    JET_SESID sesid = JET_sesidNil;
    JET_DBID dbid = JET_dbidNil;
    bool attached = false;
    bool initialized = false;
    std::wstring path;

    ~EseDatabase() { Close(); }

    bool Open(const std::wstring& database, const std::wstring& workFolder, std::wstring& error) {
        path = database;
        const DWORD pageSize = EsePageSize(database);
        std::wstring workDir = workFolder;
        if (!workDir.empty() && workDir.back() != L'\\') workDir += L'\\';
        std::wstring instanceName = Format(L"WindCheckerSrum_%lu_%llu",
                                           GetCurrentProcessId(), GetTickCount64());
        JET_ERR status = JetCreateInstance2W(&instance, instanceName.c_str(), L"WindChecker SRUM", 0);
        if (status < 0) {
            error = Format(L"JetCreateInstance failed (%ld).", status);
            return false;
        }
        JetSetSystemParameterW(&instance, JET_sesidNil, JET_paramDatabasePageSize, pageSize, nullptr);
        JetSetSystemParameterW(&instance, JET_sesidNil, JET_paramRecovery, 0, L"off");
        JetSetSystemParameterW(&instance, JET_sesidNil, JET_paramTempPath, 0, workDir.c_str());
        JetSetSystemParameterW(&instance, JET_sesidNil, JET_paramSystemPath, 0, workDir.c_str());
        JetSetSystemParameterW(&instance, JET_sesidNil, JET_paramLogFilePath, 0, workDir.c_str());
        JetSetSystemParameterW(&instance, JET_sesidNil, JET_paramCircularLog, 1, nullptr);
        JetSetSystemParameterW(&instance, JET_sesidNil, JET_paramNoInformationEvent, 1, nullptr);

        status = JetInit(&instance);
        if (status < 0) {
            error = Format(L"JetInit failed (%ld).", status);
            return false;
        }
        initialized = true;

        status = JetBeginSessionW(instance, &sesid, nullptr, nullptr);
        if (status < 0) {
            error = Format(L"JetBeginSession failed (%ld).", status);
            return false;
        }
        status = JetAttachDatabaseW(sesid, database.c_str(), JET_bitDbReadOnly);
        if (status < 0) {
            error = Format(L"JetAttachDatabase failed (%ld). The database may be locked by the SRU service.", status);
            return false;
        }
        attached = true;
        status = JetOpenDatabaseW(sesid, database.c_str(), nullptr, &dbid, JET_bitDbReadOnly);
        if (status < 0) {
            error = Format(L"JetOpenDatabase failed (%ld).", status);
            return false;
        }
        return true;
    }

    void Close() {
        if (sesid != JET_sesidNil) {
            if (dbid != JET_dbidNil) {
                JetCloseDatabase(sesid, dbid, 0);
                dbid = JET_dbidNil;
            }
            if (attached) {
                JetDetachDatabaseW(sesid, path.c_str());
                attached = false;
            }
            JetEndSession(sesid, 0);
            sesid = JET_sesidNil;
        }
        if (initialized) {
            JetTerm(instance);
            initialized = false;
            instance = JET_instanceNil;
        }
    }

    std::vector<std::wstring> Tables() {
        std::vector<std::wstring> names;
        JET_OBJECTLIST list{};
        list.cbStruct = sizeof(list);
        if (JetGetObjectInfoW(sesid, dbid, JET_objtypTable, nullptr, nullptr, &list, sizeof(list),
                              JET_ObjInfoList) < 0) {
            return names;
        }
        if (JetMove(sesid, list.tableid, JET_MoveFirst, 0) >= 0) {
            do {
                wchar_t name[256] = {};
                unsigned long length = 0;
                if (JetRetrieveColumn(sesid, list.tableid, list.columnidobjectname, name,
                                      sizeof(name) - 2, &length, 0, nullptr) < 0) {
                    break;
                }
                name[length / 2] = 0;
                names.emplace_back(name);
            } while (JetMove(sesid, list.tableid, JET_MoveNext, 0) >= 0);
        }
        JetCloseTable(sesid, list.tableid);
        return names;
    }

    bool Columns(JET_TABLEID table, std::vector<EseColumn>& columns) {
        JET_COLUMNLIST list{};
        list.cbStruct = sizeof(list);
        if (JetGetTableColumnInfoW(sesid, table, nullptr, &list, sizeof(list), JET_ColInfoList) < 0) {
            return false;
        }
        if (JetMove(sesid, list.tableid, JET_MoveFirst, 0) >= 0) {
            do {
                wchar_t name[256] = {};
                unsigned long length = 0;
                if (JetRetrieveColumn(sesid, list.tableid, list.columnidcolumnname, name,
                                      sizeof(name) - 2, &length, 0, nullptr) < 0) {
                    break;
                }
                name[length / 2] = 0;

                EseColumn column;
                column.name = name;
                column.def.cbStruct = sizeof(JET_COLUMNDEF);
                if (JetGetTableColumnInfoW(sesid, table, name, &column.def, sizeof(column.def),
                                           JET_ColInfo) < 0) {
                    continue;
                }
                columns.push_back(std::move(column));
            } while (JetMove(sesid, list.tableid, JET_MoveNext, 0) >= 0);
        }
        JetCloseTable(sesid, list.tableid);
        return !columns.empty();
    }

    bool Raw(JET_TABLEID table, const EseColumn& column, std::vector<BYTE>& out) {
        out.assign(64 * 1024, 0);
        unsigned long length = 0;
        if (JetRetrieveColumn(sesid, table, column.def.columnid, out.data(),
                              static_cast<unsigned long>(out.size()), &length, 0, nullptr) < 0) {
            out.clear();
            return false;
        }
        out.resize(length);
        return true;
    }

    std::wstring Value(JET_TABLEID table, const EseColumn& column, unsigned long& length) {
        static thread_local std::vector<BYTE> buffer(256 * 1024);
        length = 0;
        JET_ERR status = JetRetrieveColumn(sesid, table, column.def.columnid, buffer.data(),
                                           static_cast<unsigned long>(buffer.size()), &length, 0, nullptr);
        if (status < 0) {
            length = 0;
            return L"";
        }
        if (!length) return L"";

        const BYTE* data = buffer.data();
        const JET_COLTYP type = column.def.coltyp;
        switch (type) {
        case JET_coltypBit:
        case JET_coltypUnsignedByte:
            return Format(L"%u", static_cast<unsigned>(data[0]));
        case JET_coltypShort: {
            short value = 0;
            std::memcpy(&value, data, 2);
            return Format(L"%d", value);
        }
        case JET_coltypUnsignedShort: {
            unsigned short value = 0;
            std::memcpy(&value, data, 2);
            return Format(L"%u", value);
        }
        case JET_coltypLong: {
            long value = 0;
            std::memcpy(&value, data, 4);
            return Format(L"%ld", value);
        }
        case JET_coltypUnsignedLong: {
            unsigned long value = 0;
            std::memcpy(&value, data, 4);
            return Format(L"%lu", value);
        }
        case JET_coltypLongLong:
        case JET_coltypCurrency: {
            long long value = 0;
            std::memcpy(&value, data, 8);
            return Format(L"%lld", value);
        }
        case JET_coltypUnsignedLongLong: {
            unsigned long long value = 0;
            std::memcpy(&value, data, 8);
            return Format(L"%llu", value);
        }
        case JET_coltypIEEESingle: {
            float value = 0;
            std::memcpy(&value, data, 4);
            return Format(L"%g", value);
        }
        case JET_coltypIEEEDouble:
            return Format(L"%g", *reinterpret_cast<const double*>(data));
        case JET_coltypDateTime: {
            double value = 0;
            std::memcpy(&value, data, 8);
            return OleDateText(value);
        }
        case JET_coltypGUID:
            return GuidText(data, length);
        case JET_coltypText:
        case JET_coltypLongText: {
            if (column.def.cp == 1200) {
                return Trim(std::wstring(reinterpret_cast<const wchar_t*>(data), length / 2));
            }
            std::string narrow(reinterpret_cast<const char*>(data), length);
            return Trim(Utf8ToWide(narrow));
        }
        case JET_coltypBinary:
        case JET_coltypLongBinary: {
            if (length == 8) {
                unsigned long long value = 0;
                std::memcpy(&value, data, 8);
                if (column.name.size() >= 4 &&
                    (column.name.find(L"Time") != std::wstring::npos)) {
                    FILETIME fileTime{};
                    fileTime.dwLowDateTime = static_cast<DWORD>(value & 0xFFFFFFFF);
                    fileTime.dwHighDateTime = static_cast<DWORD>(value >> 32);
                    std::wstring text = FileTimeText(fileTime);
                    if (!text.empty()) return text;
                }
                if (column.name.find(L"Size") != std::wstring::npos ||
                    column.name.find(L"Bytes") != std::wstring::npos) {
                    return Format(L"%llu", value);
                }
            }
            if (LooksLikeUtf16(data, length)) return Utf16BlobText(data, length);
            return HexPreview(data, length);
        }
        default:
            return HexPreview(data, length);
        }
    }
};

std::wstring NormalizeTableName(const std::wstring& name) {
    std::wstring text = ToLower(name);
    return text;
}

std::wstring ResolveId(const std::map<long, std::pair<int, std::wstring>>& ids, long index) {
    auto found = ids.find(index);
    if (found == ids.end()) return L"";
    const std::wstring& text = found->second.second;
    if (text.empty()) return L"";
    return text;
}

std::wstring AppDisplay(const std::wstring& raw) {
    if (raw.find(L'!') == std::wstring::npos) return raw;
    std::vector<std::wstring> parts;
    size_t start = 0;
    for (;;) {
        size_t end = raw.find(L'!', start);
        if (end == std::wstring::npos) {
            parts.push_back(raw.substr(start));
            break;
        }
        parts.push_back(raw.substr(start, end - start));
        start = end + 1;
    }
    std::wstring exe;
    std::wstring suffix;
    for (const std::wstring& part : parts) {
        if (part.empty()) continue;
        if (exe.empty() && part.size() > 4 &&
            _wcsicmp(part.c_str() + part.size() - 4, L".exe") == 0) {
            exe = part;
        } else if (part.front() == L'[') {
            suffix = part;
        }
    }
    if (exe.empty()) return raw;
    return suffix.empty() ? exe : exe + L" " + suffix;
}

}

void RunSrumExplorer(const Sink& sink, std::atomic<bool>& stop) {
    std::vector<Row> rows;
    std::vector<std::wstring> details;

    auto add = [&](const std::wstring& section, const std::wstring& item, const std::wstring& value,
                   const std::wstring& detail = L"") {
        if (value.empty()) return;
        rows.push_back(Row{section, item, value, L"", L""});
        details.push_back(detail);
    };

    std::map<std::wstring, std::wstring> providers;
    for (const std::wstring& guid : RegSubkeys(HKEY_LOCAL_MACHINE, kSrumExtensions)) {
        std::wstring key = std::wstring(kSrumExtensions) + L"\\" + guid;
        std::wstring name = RegText(HKEY_LOCAL_MACHINE, key.c_str(), L"");
        std::wstring dll = ExpandPath(RegText(HKEY_LOCAL_MACHINE, key.c_str(), L"DllName"));
        DWORD flags = RegNumber(HKEY_LOCAL_MACHINE, key.c_str(), L"CapabilityFlags", 0);
        DWORD tier2 = RegNumber(HKEY_LOCAL_MACHINE, key.c_str(), L"Tier2MaxEntries", 0);

        std::wstring value = name;
        if (!dll.empty()) value += L" \u00B7 " + PathFileName(dll);
        std::wstring detail = L"Provider GUID: " + guid + L"\r\n";
        detail += L"Provider name: " + name + L"\r\n";
        detail += L"DLL: " + dll + L"\r\n";
        if (flags) detail += Format(L"Capability flags: %lu\r\n", flags);
        if (tier2) detail += Format(L"Tier-2 max entries: %lu\r\n", tier2);
        detail += L"Registry key: HKLM\\" + key + L"\r\n";
        providers[NormalizeTableName(guid)] = name;
        add(L"SRUM configuration", guid, value, detail);
    }
    if (providers.empty()) {
        add(L"SRUM configuration", L"Extensions", L"Not registered on this system");
    }

    std::wstring databasePath = kSrumDatabase;
    std::wstring custom = RegText(HKEY_LOCAL_MACHINE, kSrumRegistry, L"DatabasePath");
    if (!custom.empty()) databasePath = ExpandPath(custom);

    WIN32_FILE_ATTRIBUTE_DATA fileInfo{};
    if (GetFileAttributesExW(databasePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
        ULARGE_INTEGER size{};
        size.LowPart = fileInfo.nFileSizeLow;
        size.HighPart = fileInfo.nFileSizeHigh;
        add(L"SRUM configuration", L"Database", databasePath + L" \u00B7 " + SizeText(size.QuadPart),
            L"Path: " + databasePath + L"\r\nSize: " + SizeText(size.QuadPart) +
                L"\r\nCreated: " + FileTimeText(fileInfo.ftCreationTime) +
                L"\r\nModified: " + FileTimeText(fileInfo.ftLastWriteTime));
    } else {
        add(L"SRUM configuration", L"Database", databasePath + L" \u00B7 not readable",
            L"The SRU database is missing or the process cannot read it. Run WindChecker as Administrator.");
    }

    wchar_t tempRoot[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempRoot);
    std::wstring workDir = std::wstring(tempRoot) + Format(L"WindCheckerSrum_%lu", GetCurrentProcessId());
    CreateDirectoryW(workDir.c_str(), nullptr);
    std::wstring copyPath = workDir + L"\\SRUDB.dat";

    bool copied = CopyLockedFile(databasePath, copyPath);
    std::wstring openError;
    EseDatabase database;
    bool opened = false;
    if (copied) {
        opened = database.Open(copyPath, workDir, openError);
        if (!opened) {
            database.Close();
            opened = database.Open(databasePath, workDir, openError);
        }
    } else {
        openError = L"The database could not be copied; the file is locked by the SRU service.";
        opened = database.Open(databasePath, workDir, openError);
    }

    if (!opened) {
        add(L"SRUM database", L"Open failed", openError);
        sink.Detailed(std::move(rows), std::move(details), true,
                      Format(L"SRUM registry read \u00B7 database unavailable: %s", openError.c_str()));
        sink.Done(Format(L"Completed with errors. %s SRUM configuration item(s); database unavailable.",
                         CommaNumber(rows.size()).c_str()));
        database.Close();
        DeleteFileW(copyPath.c_str());
        RemoveDirectoryW(workDir.c_str());
        return;
    }

    std::vector<std::wstring> tables = database.Tables();
    add(L"SRUM database", L"Tables", Format(L"%zu table(s) in %s", tables.size(), databasePath.c_str()));

    std::map<long, std::pair<int, std::wstring>> ids;
    {
        JET_TABLEID table = JET_tableidNil;
        if (JetOpenTableW(database.sesid, database.dbid, L"SruDbIdMapTable", nullptr, 0, 0, &table) >= 0) {
            std::vector<EseColumn> columns;
            database.Columns(table, columns);
            int indexColumn = -1, typeColumn = -1, blobColumn = -1;
            for (size_t i = 0; i < columns.size(); ++i) {
                if (columns[i].name == L"IdIndex") indexColumn = static_cast<int>(i);
                else if (columns[i].name == L"IdType") typeColumn = static_cast<int>(i);
                else if (columns[i].name == L"IdBlob") blobColumn = static_cast<int>(i);
            }
            if (indexColumn >= 0 && typeColumn >= 0 && blobColumn >= 0 &&
                JetSetTableSequential(database.sesid, table, 0) >= 0 &&
                JetMove(database.sesid, table, JET_MoveFirst, 0) >= 0) {
                std::vector<BYTE> blob;
                do {
                    unsigned long length = 0;
                    std::wstring indexText = database.Value(table, columns[indexColumn], length);
                    std::wstring typeText = database.Value(table, columns[typeColumn], length);
                    long index = _wtoi(indexText.c_str());
                    int type = _wtoi(typeText.c_str());

                    std::wstring text;
                    if (database.Raw(table, columns[blobColumn], blob) && !blob.empty()) {
                        if (type == 3) {
                            text = SidText(blob.data(), static_cast<unsigned long>(blob.size()));
                        } else if (LooksLikeUtf16(blob.data(), static_cast<unsigned long>(blob.size()))) {
                            text = Utf16BlobText(blob.data(), static_cast<unsigned long>(blob.size()));
                        } else {
                            text = HexPreview(blob.data(), static_cast<unsigned long>(blob.size()), 24);
                        }
                    }
                    ids[index] = {type, text};
                } while (JetMove(database.sesid, table, JET_MoveNext, 0) >= 0);
                JetResetTableSequential(database.sesid, table, 0);
            }
            JetCloseTable(database.sesid, table);
        }
    }
    add(L"SRUM database", L"Identity map", Format(L"%zu application / user mapping(s)", ids.size()));

    unsigned long long records = 0;
    constexpr unsigned long long kRecordLimit = 150000;
    std::vector<Row> tableRows;
    std::vector<std::wstring> tableDetails;

    for (const std::wstring& tableName : tables) {
        if (stop.load()) break;
        JET_TABLEID table = JET_tableidNil;
        if (JetOpenTableW(database.sesid, database.dbid, tableName.c_str(), nullptr, 0, 0, &table) < 0) {
            continue;
        }
        std::vector<EseColumn> columns;
        database.Columns(table, columns);

        std::wstring normalized = NormalizeTableName(tableName);
        bool longTerm = false;
        if (normalized.size() > 2 && normalized.compare(normalized.size() - 2, 2, L"lt") == 0) {
            std::wstring base = normalized.substr(0, normalized.size() - 2);
            if (providers.count(base)) {
                normalized = base;
                longTerm = true;
            }
        }
        std::wstring provider = providers.count(normalized) ? providers[normalized] : L"";
        std::wstring label = provider.empty() ? tableName : provider;
        if (longTerm) label += L" \u00B7 long term";

        std::wstring schema;
        for (const EseColumn& column : columns) {
            schema += L"  " + column.name + Format(L"  (type %u, max %lu)\r\n", column.def.coltyp,
                                                   column.def.cbMax);
        }
        tableRows.push_back(Row{L"Table", label, Format(L"%zu column(s)", columns.size()), L"", L""});
        tableDetails.push_back(L"Table: " + tableName + L"\r\n" +
                               (provider.empty() ? L"Provider: (not registered)\r\n"
                                                 : L"Provider: " + provider + L"\r\n") +
                               Format(L"Columns: %zu\r\n\r\n", columns.size()) + schema);

        if (tableName.rfind(L"MSys", 0) == 0) {
            JetCloseTable(database.sesid, table);
            continue;
        }

        int appColumn = -1, userColumn = -1, timeColumn = -1, idColumn = -1;
        for (size_t i = 0; i < columns.size(); ++i) {
            if (columns[i].name == L"AppId") appColumn = static_cast<int>(i);
            else if (columns[i].name == L"UserId") userColumn = static_cast<int>(i);
            else if (columns[i].name == L"TimeStamp") timeColumn = static_cast<int>(i);
            else if (columns[i].name == L"AutoIncId") idColumn = static_cast<int>(i);
        }
        if (timeColumn < 0) {
            for (size_t i = 0; i < columns.size(); ++i) {
                if (columns[i].name.find(L"Time") != std::wstring::npos) {
                    timeColumn = static_cast<int>(i);
                    break;
                }
            }
        }

        if (JetSetTableSequential(database.sesid, table, 0) < 0 ||
            JetMove(database.sesid, table, JET_MoveFirst, 0) < 0) {
            JetCloseTable(database.sesid, table);
            continue;
        }

        do {
            if (stop.load()) break;
            if (records >= kRecordLimit) break;

            std::wstring timeText;
            std::wstring appText;
            std::wstring userText;
            std::wstring recordText;
            std::wstring detail;
            detail += L"Table      : " + tableName + L"\r\n";
            if (!provider.empty()) detail += L"Provider   : " + provider + L"\r\n";

            for (size_t i = 0; i < columns.size(); ++i) {
                unsigned long length = 0;
                std::wstring value = database.Value(table, columns[i], length);
                if (static_cast<int>(i) == timeColumn) timeText = value;
                if (static_cast<int>(i) == idColumn) recordText = value;

                std::wstring labelText = columns[i].name;
                if (static_cast<int>(i) == appColumn) {
                    long index = _wtoi(value.c_str());
                    std::wstring name = ResolveId(ids, index);
                    if (!name.empty()) {
                        appText = AppDisplay(name);
                        value += L" \u00B7 " + name;
                    }
                } else if (static_cast<int>(i) == userColumn) {
                    long index = _wtoi(value.c_str());
                    std::wstring name = ResolveId(ids, index);
                    if (!name.empty()) {
                        userText = name;
                        value += L" \u00B7 " + name;
                    }
                }

                detail += labelText;
                if (labelText.size() < 24) detail.append(24 - labelText.size(), L' ');
                detail += L": " + (value.empty() ? std::wstring(L"-") : value) + L"\r\n";
            }

            rows.push_back(Row{label, timeText, appText, userText, recordText});
            details.push_back(detail);
            ++records;
        } while (JetMove(database.sesid, table, JET_MoveNext, 0) >= 0);

        JetResetTableSequential(database.sesid, table, 0);
        JetCloseTable(database.sesid, table);
        if (records >= kRecordLimit) break;
    }

    for (size_t i = 0; i < tableRows.size(); ++i) {
        rows.push_back(std::move(tableRows[i]));
        details.push_back(std::move(tableDetails[i]));
    }

    database.Close();
    DeleteFileW(copyPath.c_str());
    RemoveDirectoryW(workDir.c_str());

    const std::wstring summary =
        Format(L"%s record(s) across %zu SRUM table(s) \u00B7 %zu provider(s)%s",
               CommaNumber(records).c_str(), tables.size(), providers.size(),
               records >= kRecordLimit ? L" \u00B7 record limit reached" : L"");
    sink.Detailed(std::move(rows), std::move(details), true, summary, 100);
    sink.Done(summary);
}
