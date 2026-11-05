#ifndef WINCHECKER_ESE_H
#define WINCHECKER_ESE_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <esent.h>
#include <oleauto.h>
#include <sddl.h>
#include <windows.h>

#include <string>
#include <vector>

#include "common.h"

namespace wc {

inline std::wstring OleDateText(double value) {
    if (value <= 0.0) return L"";
    SYSTEMTIME st{};
    if (!VariantTimeToSystemTime(value, &st)) return Format(L"%.6f", value);
    return Format(L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour,
                  st.wMinute, st.wSecond);
}

inline std::wstring HexPreview(const BYTE* data, unsigned long length, unsigned long maximum = 48) {
    std::wstring text;
    unsigned long count = length < maximum ? length : maximum;
    for (unsigned long i = 0; i < count; ++i) {
        if (i) text += L" ";
        text += Format(L"%02X", data[i]);
    }
    if (length > count) text += L" \u2026";
    return text;
}

inline std::wstring GuidText(const BYTE* data, unsigned long length) {
    if (length < 16) return HexPreview(data, length);
    GUID guid{};
    std::memcpy(&guid, data, 16);
    wchar_t text[64] = {};
    StringFromGUID2(guid, text, 64);
    return text;
}

inline bool LooksLikeUtf16(const BYTE* data, unsigned long length) {
    if (length < 4 || (length % 2) != 0) return false;
    unsigned long total = length / 2;
    unsigned long ascii = 0;
    for (unsigned long i = 0; i + 1 < length; i += 2) {
        if (data[i + 1] == 0 && data[i] >= 0x20 && data[i] < 0x7F) ++ascii;
    }
    return ascii * 10 >= total * 8;
}

inline std::wstring Utf16BlobText(const BYTE* data, unsigned long length) {
    std::wstring text(reinterpret_cast<const wchar_t*>(data), length / 2);
    while (!text.empty() && (text.back() == 0 || text.back() == L'\r' || text.back() == L'\n')) {
        text.pop_back();
    }
    return text;
}

inline std::wstring SidText(const BYTE* data, unsigned long length) {
    if (length < 8) return L"";
    PSID sid = const_cast<BYTE*>(data);
    if (!IsValidSid(sid)) return L"";
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text)) return L"";
    std::wstring result = text;
    LocalFree(text);
    return result;
}

inline DWORD EsePageSize(const std::wstring& path) {
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
        std::wstring instanceName = Format(L"WindCheckerEse_%lu_%llu",
                                          GetCurrentProcessId(), GetTickCount64());
        JET_ERR status = JetCreateInstance2W(&instance, instanceName.c_str(), L"WindChecker ESE", 0);
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
            error = Format(L"JetAttachDatabase failed (%ld). The database may be locked.", status);
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
                if (column.name.size() >= 4 && column.name.find(L"Time") != std::wstring::npos) {
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

}

#endif
