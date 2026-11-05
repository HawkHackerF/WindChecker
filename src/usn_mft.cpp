#include "artifacts.h"
#include "carve.h"
#include "search.h"

#include <winioctl.h>

#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace {

std::wstring FileTimeFromU64(unsigned long long value) {
    if (!value) return L"";
    FILETIME ft{};
    ft.dwLowDateTime = static_cast<DWORD>(value & 0xFFFFFFFFULL);
    ft.dwHighDateTime = static_cast<DWORD>(value >> 32);
    return FileTimeText(ft);
}

std::wstring ReferenceText(unsigned long long value) {
    return Format(L"0x%016llX", value);
}

std::wstring ReasonsText(DWORD mask) {
    struct Entry {
        DWORD bit;
        const wchar_t* name;
    };
    static const Entry table[] = {
        {0x00000001, L"Data overwrite"},
        {0x00000002, L"Data extend"},
        {0x00000004, L"Data truncate"},
        {0x00000010, L"Named data overwrite"},
        {0x00000020, L"Named data extend"},
        {0x00000040, L"Named data truncate"},
        {0x00000100, L"File created"},
        {0x00000200, L"File deleted"},
        {0x00000400, L"EA changed"},
        {0x00000800, L"Security changed"},
        {0x00001000, L"Rename old name"},
        {0x00002000, L"Rename new name"},
        {0x00004000, L"Indexable changed"},
        {0x00008000, L"Basic info changed"},
        {0x00010000, L"Hard link changed"},
        {0x00020000, L"Compression changed"},
        {0x00040000, L"Encryption changed"},
        {0x00080000, L"Object ID changed"},
        {0x00100000, L"Reparse point changed"},
        {0x00200000, L"Stream changed"},
        {0x00400000, L"Transacted changed"},
        {0x00800000, L"Integrity changed"},
        {0x80000000, L"Close"},
    };
    std::wstring text;
    for (const Entry& entry : table) {
        if (!(mask & entry.bit)) continue;
        if (!text.empty()) text += L", ";
        text += entry.name;
    }
    if (text.empty()) text = Format(L"0x%08X", mask);
    return text;
}

void FlushRows(const Sink& sink, std::vector<Row>& pending) {
    if (pending.empty()) return;
    sink.Rows(std::move(pending), false);
    pending.clear();
    pending.reserve(256);
}

void FlushRows(const Sink& sink, std::vector<Row>& pending, std::vector<std::wstring>& details) {
    if (pending.empty()) return;
    sink.Detailed(std::move(pending), std::move(details), false);
    pending.clear();
    pending.reserve(256);
    details.clear();
    details.reserve(256);
}

void AddUsnRecord(const Sink& sink, std::vector<Row>& pending, std::vector<std::wstring>& details,
                  const std::wstring& volume, const USN_RECORD_V2& record) {
    if (record.FileNameLength == 0 || (record.FileNameLength % 2) != 0) return;
    std::wstring name(reinterpret_cast<const wchar_t*>(record.FileName),
                      record.FileNameLength / sizeof(wchar_t));
    if (name.empty()) return;

    Row row;
    row.reserve(8);
    row.push_back(volume);
    row.push_back(FileTimeFromU64(static_cast<unsigned long long>(record.TimeStamp.QuadPart)));
    row.push_back(std::move(name));
    row.push_back(ReasonsText(record.Reason));
    row.push_back(ReferenceText(record.FileReferenceNumber));
    row.push_back(ReferenceText(record.ParentFileReferenceNumber));
    row.push_back(AttributesText(record.FileAttributes));
    row.push_back(Format(L"%llu", static_cast<unsigned long long>(record.Usn)));

    std::wstring detail;
    detail += L"Volume        : " + volume + L"\r\n";
    detail += L"File name     : " + name + L"\r\n";
    detail += L"Change time   : " +
              FileTimeFromU64(static_cast<unsigned long long>(record.TimeStamp.QuadPart)) + L"\r\n";
    detail += L"Reason        : " + ReasonsText(record.Reason) + L"\r\n";
    detail += Format(L"Reason mask   : 0x%08X\r\n", record.Reason);
    detail += L"Attributes    : " + AttributesText(record.FileAttributes) + L"\r\n";
    detail += Format(L"Attributes raw: 0x%08X\r\n", record.FileAttributes);
    detail += L"USN           : " + Format(L"%llu",
                                          static_cast<unsigned long long>(record.Usn)) + L"\r\n";
    detail += L"File ID       : " + ReferenceText(record.FileReferenceNumber) +
              Format(L" (record %llu, sequence %u)\r\n",
                     static_cast<unsigned long long>(record.FileReferenceNumber & 0x0000FFFFFFFFFFFFULL),
                     static_cast<unsigned int>(record.FileReferenceNumber >> 48));
    detail += L"Parent ID     : " + ReferenceText(record.ParentFileReferenceNumber) +
              Format(L" (record %llu, sequence %u)\r\n",
                     static_cast<unsigned long long>(record.ParentFileReferenceNumber & 0x0000FFFFFFFFFFFFULL),
                     static_cast<unsigned int>(record.ParentFileReferenceNumber >> 48));
    detail += Format(L"Source info   : 0x%08X\r\n", record.SourceInfo);
    detail += Format(L"Security ID   : %lu\r\n", record.SecurityId);
    detail += Format(L"Record length : %u byte(s)\r\n", record.RecordLength);
    detail += Format(L"Version       : %u.%u\r\n", record.MajorVersion, record.MinorVersion);
    detail += Format(L"Name bytes    : %u\r\n", record.FileNameLength);

    pending.push_back(std::move(row));
    details.push_back(std::move(detail));
}

bool ReadUsnJournal(const Sink& sink, std::atomic<bool>& stop, const std::wstring& volume,
                    unsigned long long limit, unsigned long long& parsed,
                    unsigned long long& shown) {
    std::wstring path = L"\\\\.\\" + volume;
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        sink.Status(Format(L"%s \u00B7 cannot open the volume (error %lu)",
                           volume.c_str(), GetLastError()));
        return false;
    }

    USN_JOURNAL_DATA_V0 journal{};
    DWORD returned = 0;
    bool haveJournal = DeviceIoControl(handle, FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
                                       &journal, sizeof(journal), &returned, nullptr) != FALSE;

    std::vector<BYTE> buffer(1u << 20);
    std::vector<Row> pending;
    std::vector<std::wstring> detailPending;
    pending.reserve(256);
    detailPending.reserve(256);

    if (haveJournal) {
        READ_USN_JOURNAL_DATA_V1 request{};
        request.StartUsn = journal.FirstUsn;
        request.ReasonMask = 0xFFFFFFFF;
        request.ReturnOnlyOnClose = 0;
        request.Timeout = 0;
        request.BytesToWaitFor = 0;
        request.UsnJournalID = journal.UsnJournalID;
        request.MinMajorVersion = 2;
        request.MaxMajorVersion = 2;

        while (!stop.load()) {
            DWORD bytes = 0;
            if (!DeviceIoControl(handle, FSCTL_READ_USN_JOURNAL, &request, sizeof(request),
                                 buffer.data(), static_cast<DWORD>(buffer.size()),
                                 &bytes, nullptr)) {
                break;
            }
            if (bytes < sizeof(USN)) break;

            USN next = 0;
            std::memcpy(&next, buffer.data(), sizeof(next));
            BYTE* cursor = buffer.data() + sizeof(USN);
            BYTE* end = buffer.data() + bytes;

            while (cursor + sizeof(USN_RECORD_V2) <= end) {
                auto* record = reinterpret_cast<USN_RECORD_V2*>(cursor);
                if (record->RecordLength == 0 || cursor + record->RecordLength > end) break;
                if (record->MajorVersion == 2) {
                    ++parsed;
                    AddUsnRecord(sink, pending, detailPending, volume, *record);
                    ++shown;
                    if (pending.size() >= 200) {
                        FlushRows(sink, pending, detailPending);
                        sink.Status(Format(L"%s \u00B7 parsed %s \u00B7 shown %s",
                                           volume.c_str(), CommaNumber(parsed).c_str(),
                                           CommaNumber(shown).c_str()));
                    }
                    if (limit && shown >= limit) {
                        FlushRows(sink, pending, detailPending);
                        CloseHandle(handle);
                        return true;
                    }
                }
                cursor += record->RecordLength;
            }
            FlushRows(sink, pending, detailPending);
            if (parsed % 2000 < 200) {
                sink.Status(Format(L"%s \u00B7 parsed %s \u00B7 shown %s",
                                   volume.c_str(), CommaNumber(parsed).c_str(),
                                   CommaNumber(shown).c_str()));
            }
            if (next == 0 || next == request.StartUsn) break;
            request.StartUsn = next;
        }
    } else {

        MFT_ENUM_DATA_V0 request{};
        request.StartFileReferenceNumber = 0;
        request.LowUsn = 0;
        request.HighUsn = 0x7FFFFFFFFFFFFFFFLL;
        while (!stop.load()) {
            DWORD bytes = 0;
            if (!DeviceIoControl(handle, FSCTL_ENUM_USN_DATA, &request, sizeof(request),
                                 buffer.data(), static_cast<DWORD>(buffer.size()),
                                 &bytes, nullptr)) {
                break;
            }
            if (bytes <= sizeof(USN)) break;
            DWORDLONG next = 0;
            std::memcpy(&next, buffer.data(), sizeof(next));
            BYTE* cursor = buffer.data() + sizeof(USN);
            BYTE* end = buffer.data() + bytes;
            while (cursor + sizeof(USN_RECORD_V2) <= end) {
                auto* record = reinterpret_cast<USN_RECORD_V2*>(cursor);
                if (record->RecordLength == 0 || cursor + record->RecordLength > end) break;
                if (record->MajorVersion == 2) {
                    ++parsed;
                    AddUsnRecord(sink, pending, detailPending, volume, *record);
                    ++shown;
                    if (pending.size() >= 200) FlushRows(sink, pending, detailPending);
                    if (limit && shown >= limit) {
                        FlushRows(sink, pending, detailPending);
                        CloseHandle(handle);
                        return true;
                    }
                }
                cursor += record->RecordLength;
            }
            FlushRows(sink, pending, detailPending);
            sink.Status(Format(L"%s \u00B7 parsed %s \u00B7 shown %s",
                               volume.c_str(), CommaNumber(parsed).c_str(),
                               CommaNumber(shown).c_str()));
            if (next == 0 || next == request.StartFileReferenceNumber) break;
            request.StartFileReferenceNumber = next;
        }
    }

    FlushRows(sink, pending, detailPending);
    CloseHandle(handle);
    return true;
}

struct DataRun {
    uint64_t vcn = 0;
    uint64_t lcn = 0;
    uint64_t clusters = 0;
    bool sparse = false;
};

struct MftRecordInfo {
    std::wstring name;
    WORD flags = 0;
    unsigned long long created = 0;
    unsigned long long modified = 0;
    unsigned long long changed = 0;
    unsigned long long accessed = 0;
    uint64_t baseRecord = 0;
    uint64_t parentRecord = 0;
    uint64_t nameSize = 0;
    uint64_t dataSize = 0;
    bool hasData = false;
    bool residentData = false;
    size_t residentOffset = 0;
    size_t residentLength = 0;
    std::vector<DataRun> runs;
};

bool DecodeRunList(const BYTE* p, size_t available, std::vector<DataRun>& runs) {
    uint64_t vcn = 0;
    int64_t lcn = 0;
    size_t pos = 0;
    while (pos < available) {
        const BYTE header = p[pos++];
        if (header == 0) return true;
        const size_t lengthBytes = header & 0x0F;
        const size_t offsetBytes = header >> 4;
        if (lengthBytes == 0 || lengthBytes > 8 || offsetBytes > 8) return false;
        if (pos + lengthBytes + offsetBytes > available) return false;

        uint64_t length = 0;
        for (size_t i = 0; i < lengthBytes; ++i) {
            length |= static_cast<uint64_t>(p[pos + i]) << (8 * i);
        }
        pos += lengthBytes;

        DataRun run;
        if (offsetBytes == 0) {
            run.sparse = true;
        } else {
            uint64_t raw = 0;
            for (size_t i = 0; i < offsetBytes; ++i) {
                raw |= static_cast<uint64_t>(p[pos + i]) << (8 * i);
            }
            const uint64_t signBit = 1ull << (offsetBytes * 8 - 1);
            if (raw & signBit) raw |= ~((signBit << 1) - 1);
            lcn += static_cast<int64_t>(raw);
            run.lcn = static_cast<uint64_t>(lcn);
        }
        pos += offsetBytes;

        if (length == 0) continue;
        run.vcn = vcn;
        run.clusters = length;
        runs.push_back(run);
        vcn += length;
    }
    return true;
}

bool ReadVolumeAt(HANDLE handle, uint64_t offset, BYTE* out, size_t length, size_t sector) {
    if (sector == 0) sector = 512;
    const uint64_t alignedOffset = offset - (offset % sector);
    const size_t lead = static_cast<size_t>(offset - alignedOffset);
    const size_t need = lead + length;
    const size_t alignedLength = (need + sector - 1) / sector * sector;

    std::vector<BYTE> buffer;
    BYTE* target = out;
    if (lead != 0 || alignedLength != length) {
        buffer.resize(alignedLength);
        target = buffer.data();
    }

    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(alignedOffset);
    if (!SetFilePointerEx(handle, position, nullptr, FILE_BEGIN)) return false;
    DWORD got = 0;
    if (!ReadFile(handle, target, static_cast<DWORD>(alignedLength), &got, nullptr) ||
        got < need) {
        return false;
    }
    if (target != out) std::memcpy(out, target + lead, length);
    return true;
}

struct RunReader {
    HANDLE handle = nullptr;
    size_t sector = 512;
    uint64_t cluster = 0;
    const std::vector<DataRun>* runs = nullptr;

    bool ReadAt(uint64_t offset, BYTE* out, size_t length) const {
        while (length) {
            bool matched = false;
            for (const DataRun& run : *runs) {
                const uint64_t start = run.vcn * cluster;
                const uint64_t end = start + run.clusters * cluster;
                if (offset < start || offset >= end) continue;
                const size_t take = static_cast<size_t>(
                    std::min<uint64_t>(length, end - offset));
                if (run.sparse) {
                    std::memset(out, 0, take);
                } else if (!ReadVolumeAt(handle, run.lcn * cluster + (offset - start),
                                         out, take, sector)) {
                    return false;
                }
                offset += take;
                out += take;
                length -= take;
                matched = true;
                break;
            }
            if (!matched) return false;
        }
        return true;
    }
};

bool ReadRecordData(HANDLE handle, size_t sector, uint64_t cluster, size_t recordSize,
                    const BYTE* record, const MftRecordInfo& info, std::vector<BYTE>& out) {
    if (!info.hasData) return false;
    if (info.residentData) {
        if (info.residentOffset > recordSize ||
            info.residentLength > recordSize - info.residentOffset) {
            return false;
        }
        out.assign(record + info.residentOffset, record + info.residentOffset + info.residentLength);
        return !out.empty();
    }

    const uint64_t limit = std::min<uint64_t>(info.dataSize, CarvedMaxFile());
    if (limit == 0 || info.runs.empty()) return false;
    out.resize(static_cast<size_t>(limit));

    size_t written = 0;
    for (const DataRun& run : info.runs) {
        if (written >= limit) break;
        const uint64_t start = run.vcn * cluster;
        if (start >= limit) break;
        const size_t take = static_cast<size_t>(std::min<uint64_t>(
            limit - start, run.clusters * cluster));
        if (take == 0) continue;
        if (run.sparse) {
            std::memset(out.data() + start, 0, take);
        } else if (!ReadVolumeAt(handle, run.lcn * cluster, out.data() + start, take, sector)) {
            return false;
        }
        written = static_cast<size_t>(std::min<uint64_t>(limit, start + take));
    }
    out.resize(written);
    return written > 0;
}

bool ParseMftRecord(const BYTE* record, size_t size, MftRecordInfo& info, bool collectRuns = true) {
    if (size < 48 || std::memcmp(record, "FILE", 4) != 0) return false;

    WORD firstAttribute = 0;
    WORD flags = 0;
    std::memcpy(&firstAttribute, record + 20, sizeof(firstAttribute));
    std::memcpy(&flags, record + 22, sizeof(flags));
    std::memcpy(&info.baseRecord, record + 32, sizeof(info.baseRecord));
    info.flags = flags;

    bool haveLongName = false;
    size_t position = firstAttribute;
    while (position + 24 <= size) {
        DWORD type = 0;
        DWORD length = 0;
        std::memcpy(&type, record + position, sizeof(type));
        std::memcpy(&length, record + position + 4, sizeof(length));
        if (type == 0 || type == 0xFFFFFFFF || length < 24) break;
        if (position + length > size) break;

        BYTE nonResident = record[position + 8];
        if (!nonResident) {
            DWORD valueLength = 0;
            WORD valueOffset = 0;
            std::memcpy(&valueLength, record + position + 16, sizeof(valueLength));
            std::memcpy(&valueOffset, record + position + 20, sizeof(valueOffset));
            if (valueOffset <= length && valueLength <= length - valueOffset &&
                position + valueOffset + valueLength <= size) {
                const BYTE* value = record + position + valueOffset;
                if (type == 0x10 && valueLength >= 32) {
                    std::memcpy(&info.created, value, 8);
                    std::memcpy(&info.modified, value + 8, 8);
                    std::memcpy(&info.changed, value + 16, 8);
                    std::memcpy(&info.accessed, value + 24, 8);
                } else if (type == 0x30 && valueLength >= 66) {
                    BYTE nameLength = value[64];
                    BYTE nameSpace = value[65];
                    if (66 + static_cast<size_t>(nameLength) * 2 <= valueLength) {
                        std::wstring name(reinterpret_cast<const wchar_t*>(value + 66), nameLength);

                        if (!name.empty() && (info.name.empty() || (haveLongName == false && nameSpace != 2))) {
                            info.name = std::move(name);
                            haveLongName = nameSpace != 2;
                        }
                        if (valueLength >= 64) {
                            uint64_t parent = 0;
                            uint64_t realSize = 0;
                            std::memcpy(&parent, value, sizeof(parent));
                            std::memcpy(&realSize, value + 48, sizeof(realSize));
                            info.parentRecord = parent & 0x0000FFFFFFFFFFFFull;
                            if (realSize) info.nameSize = realSize;
                        }
                    }
                } else if (type == 0x80 && valueLength) {

                    const BYTE nameLength = record[position + 9];
                    if (nameLength == 0) {
                        info.hasData = true;
                        info.residentData = true;
                        info.residentOffset = position + valueOffset;
                        info.residentLength = valueLength;
                        info.dataSize = valueLength;
                    }
                }
            }
        } else if (type == 0x80) {
            const BYTE nameLength = record[position + 9];
            WORD runOffset = 0;
            std::memcpy(&runOffset, record + position + 32, sizeof(runOffset));
            uint64_t realSize = 0;
            std::memcpy(&realSize, record + position + 48, sizeof(realSize));
            if (nameLength == 0 && runOffset >= 64 && runOffset < length) {
                info.hasData = true;
                info.residentData = false;
                info.dataSize = realSize;
                info.runs.clear();
                if (collectRuns) DecodeRunList(record + position + runOffset, length - runOffset,
                                               info.runs);
            }
        }
        position += length;
    }
    return !info.name.empty();
}

bool ReadMftVolume(const Sink& sink, std::atomic<bool>& stop, const std::wstring& volume,
                   unsigned long long limit, unsigned long long& scanned,
                   unsigned long long& shown) {
    std::wstring path = L"\\\\.\\" + volume;
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        sink.Status(Format(L"%s \u00B7 cannot open the raw volume (error %lu)",
                           volume.c_str(), GetLastError()));
        return false;
    }

    BYTE boot[512] = {};
    DWORD bytes = 0;
    if (!ReadFile(handle, boot, sizeof(boot), &bytes, nullptr) || bytes < 512) {
        CloseHandle(handle);
        return false;
    }
    WORD bytesPerSector = 0;
    BYTE sectorsPerCluster = 0;
    unsigned long long mftLcn = 0;
    signed char clustersPerRecord = 0;
    std::memcpy(&bytesPerSector, boot + 11, sizeof(bytesPerSector));
    sectorsPerCluster = boot[13];
    std::memcpy(&mftLcn, boot + 48, sizeof(mftLcn));
    clustersPerRecord = static_cast<signed char>(boot[64]);
    if (bytesPerSector < 256 || sectorsPerCluster == 0) {
        CloseHandle(handle);
        return false;
    }

    unsigned long long recordSize = clustersPerRecord > 0
        ? static_cast<unsigned long long>(clustersPerRecord) * bytesPerSector * sectorsPerCluster
        : (1ULL << static_cast<unsigned int>(-clustersPerRecord));
    if (recordSize < 256 || recordSize > 65536) recordSize = 1024;

    LARGE_INTEGER offset{};
    offset.QuadPart = static_cast<LONGLONG>(mftLcn * bytesPerSector * sectorsPerCluster);
    if (!SetFilePointerEx(handle, offset, nullptr, FILE_BEGIN)) {
        CloseHandle(handle);
        return false;
    }

    std::vector<BYTE> record(static_cast<size_t>(recordSize));
    std::vector<Row> pending;
    std::vector<std::wstring> detailPending;
    pending.reserve(256);
    detailPending.reserve(256);
    unsigned long long recordIndex = 0;

    while (!stop.load()) {
        if (limit && scanned >= limit) break;
        DWORD read = 0;
        if (!ReadFile(handle, record.data(), static_cast<DWORD>(record.size()), &read, nullptr) ||
            read < record.size()) {
            break;
        }

        MftRecordInfo info;
        if (ParseMftRecord(record.data(), record.size(), info)) {
            Row row;
            row.reserve(8);
            row.push_back(volume);
            row.push_back(Format(L"%llu", recordIndex));
            row.push_back(std::move(info.name));
            row.push_back((info.flags & 0x0002) ? L"Directory" : L"File");
            row.push_back((info.flags & 0x0001) ? L"In use" : L"Deleted / unused");
            row.push_back(FileTimeFromU64(info.created));
            row.push_back(FileTimeFromU64(info.modified));
            row.push_back(FileTimeFromU64(info.changed ? info.changed : info.accessed));
            std::wstring mftDetail;
            mftDetail += L"Record index : " + Format(L"%llu", recordIndex) + L"\r\n";
            mftDetail += L"Name         : " + info.name + L"\r\n";
            mftDetail += L"Type         : " + (std::wstring((info.flags & 0x0002) ? L"Directory" : L"File")) + L"\r\n";
            mftDetail += L"State        : " + (std::wstring((info.flags & 0x0001) ? L"In use" : L"Deleted / unused")) + L"\r\n";
            mftDetail += Format(L"Flags (raw)  : 0x%04X\r\n", info.flags);
            mftDetail += L"Parent record: 0x" + Format(L"%016llX", info.parentRecord) + L"\r\n";
            mftDetail += L"Base record  : 0x" + Format(L"%016llX", info.baseRecord) + L"\r\n";
            mftDetail += L"Created      : " + FileTimeFromU64(info.created) + L"\r\n";
            mftDetail += L"Modified     : " + FileTimeFromU64(info.modified) + L"\r\n";
            mftDetail += L"Changed      : " + FileTimeFromU64(info.changed) + L"\r\n";
            mftDetail += L"Accessed     : " + FileTimeFromU64(info.accessed) + L"\r\n";
            mftDetail += L"Name length  : " + (info.nameSize ? Format(L"%llu byte(s)", info.nameSize) : L"-") + L"\r\n";
            mftDetail += L"Data size    : " + (info.dataSize ? SizeText(info.dataSize) : L"-") + L"\r\n";
            mftDetail += L"Data stream  : " + (info.hasData ? (info.residentData ? L"resident (" + Format(L"%zu byte(s)", info.residentLength) + L")" : L"non-resident") : L"none") + L"\r\n";
            if (!info.runs.empty()) {
                mftDetail += Format(L"Data runs    : %zu extent(s)\r\n", info.runs.size());
                for (size_t r = 0; r < info.runs.size() && r < 8; ++r) {
                    const DataRun& run = info.runs[r];
                    mftDetail += L"  #" + Format(L"%zu", r + 1) + L" VCN " + Format(L"%llu", run.vcn) +
                                 L" LCN " + Format(L"%llu", run.lcn) + L" " +
                                 Format(L"%llu", run.clusters) + L" cluster(s)" +
                                 (run.sparse ? L" (sparse)" : L"") + L"\r\n";
                }
            }
            pending.push_back(std::move(row));
            detailPending.push_back(std::move(mftDetail));
            ++shown;
        }

        ++recordIndex;
        ++scanned;
        if (pending.size() >= 200) FlushRows(sink, pending, detailPending);
        if (scanned % 1000 == 0) {
            sink.Status(Format(L"%s \u00B7 read %s records \u00B7 shown %s",
                               volume.c_str(), CommaNumber(scanned).c_str(),
                               CommaNumber(shown).c_str()));
        }
    }

    FlushRows(sink, pending, detailPending);
    CloseHandle(handle);
    return true;
}

bool ApplyFixups(BYTE* record, size_t size, size_t sector) {
    if (sector < 2 || size < 8) return false;
    WORD usaOffset = 0;
    WORD usaCount = 0;
    std::memcpy(&usaOffset, record + 4, sizeof(usaOffset));
    std::memcpy(&usaCount, record + 6, sizeof(usaCount));
    if (usaCount < 2 || usaOffset + static_cast<size_t>(usaCount) * 2 > size) return false;
    WORD usn = 0;
    std::memcpy(&usn, record + usaOffset, sizeof(usn));
    for (WORD i = 1; i < usaCount; ++i) {
        const size_t end = static_cast<size_t>(i) * sector;
        if (end > size) break;
        WORD check = 0;
        std::memcpy(&check, record + end - 2, sizeof(check));
        if (check != usn) return false;
        std::memcpy(record + end - 2, record + usaOffset + i * 2, sizeof(WORD));
    }
    return true;
}

bool OpenRawVolume(const std::wstring& volume, HANDLE& handle, size_t& sector, uint64_t& cluster,
                   uint64_t& mftLcn, size_t& recordSize) {
    handle = INVALID_HANDLE_VALUE;
    const std::wstring path = L"\\\\.\\" + volume;
    handle = CreateFileW(path.c_str(), GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                         OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;

    BYTE boot[512] = {};
    DWORD got = 0;
    LARGE_INTEGER zero{};
    SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN);
    if (!ReadFile(handle, boot, sizeof(boot), &got, nullptr) || got < 512 ||
        std::memcmp(boot + 3, "NTFS    ", 8) != 0) {
        CloseHandle(handle);
        handle = INVALID_HANDLE_VALUE;
        return false;
    }

    WORD bytesPerSector = 0;
    std::memcpy(&bytesPerSector, boot + 11, sizeof(bytesPerSector));
    const BYTE sectorsPerCluster = boot[13];
    std::memcpy(&mftLcn, boot + 48, sizeof(mftLcn));
    const signed char clustersPerRecord = static_cast<signed char>(boot[64]);
    if (bytesPerSector < 256 || sectorsPerCluster == 0) {
        CloseHandle(handle);
        handle = INVALID_HANDLE_VALUE;
        return false;
    }
    sector = bytesPerSector;
    cluster = static_cast<uint64_t>(bytesPerSector) * sectorsPerCluster;
    recordSize = clustersPerRecord > 0
        ? static_cast<size_t>(clustersPerRecord) * cluster
        : (static_cast<size_t>(1) << static_cast<unsigned int>(-clustersPerRecord));
    if (recordSize < 256 || recordSize > 65536) recordSize = 1024;
    return true;
}

}

namespace {

struct MftEntry {
    uint64_t index = 0;
    uint64_t parent = 0;
    uint64_t dataSize = 0;
    unsigned long long created = 0;
    unsigned long long modified = 0;
    std::wstring name;
    bool directory = false;
    bool live = false;
    bool hasData = false;
};

struct MftRecoverResult {
    unsigned long long files = 0;
    unsigned long long folders = 0;
    unsigned long long deleted = 0;
    unsigned long long inUse = 0;
    unsigned long long skipped = 0;
    unsigned long long inspected = 0;
    unsigned long long listed = 0;
    unsigned long long withData = 0;
    bool stopped = false;
    std::wstring error;
};

std::wstring BuildEntryPath(const std::vector<MftEntry>& entries,
                            const std::unordered_map<uint64_t, size_t>& byIndex, size_t pos) {
    std::vector<size_t> chain;
    size_t current = pos;
    bool orphan = false;
    for (int depth = 0; depth < 64; ++depth) {
        chain.push_back(current);
        const uint64_t parent = entries[current].parent;
        if (parent == 5 || parent == 0 || parent == entries[current].index) break;
        auto found = byIndex.find(parent);
        if (found == byIndex.end()) {
            orphan = true;
            break;
        }
        if (found->second == current) break;
        if (!entries[found->second].directory) {
            orphan = true;
            break;
        }
        current = found->second;
    }
    std::wstring path;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        const MftEntry& entry = entries[*it];
        if (entry.index == 5) continue;
        if (!path.empty()) path += L'\\';
        path += entry.name;
    }
    if (orphan) path = L"?\\" + path;
    return path;
}

MftRecoverResult RecoverMftIntoStore(const Sink& sink, std::atomic<bool>& stop,
                                     const MftRecoverConfig& config) {
    MftRecoverResult result;
    std::wstring volume = config.volume;
    while (!volume.empty() && (volume.back() == L'\\' || volume.back() == L'/')) volume.pop_back();
    if (volume.size() == 1) volume += L":";
    if (volume.empty()) {
        result.error = L"Choose a volume first.";
        return result;
    }

    HANDLE handle = INVALID_HANDLE_VALUE;
    size_t sector = 512;
    uint64_t cluster = 4096;
    uint64_t mftLcn = 0;
    size_t recordSize = 1024;
    if (!OpenRawVolume(volume, handle, sector, cluster, mftLcn, recordSize)) {
        result.error = Format(L"%s \u00B7 cannot read the $MFT (open the raw NTFS volume as Administrator).",
                              volume.c_str());
        return result;
    }

    std::vector<BYTE> record(recordSize);
    if (!ReadVolumeAt(handle, mftLcn * cluster, record.data(), recordSize, sector)) {
        CloseHandle(handle);
        result.error = Format(L"%s \u00B7 cannot read $MFT record 0.", volume.c_str());
        return result;
    }
    std::vector<BYTE> fixed = record;
    ApplyFixups(fixed.data(), fixed.size(), sector);
    MftRecordInfo mftInfo;
    if (!ParseMftRecord(fixed.data(), fixed.size(), mftInfo) || mftInfo.runs.empty() ||
        mftInfo.dataSize < recordSize) {
        CloseHandle(handle);
        result.error = Format(L"%s \u00B7 the $MFT run list is unreadable.", volume.c_str());
        return result;
    }

    const uint64_t records = mftInfo.dataSize / recordSize;
    const uint64_t limit = config.limitRecords ? std::min<uint64_t>(records, config.limitRecords)
                                               : records;
    RunReader reader;
    reader.handle = handle;
    reader.sector = sector;
    reader.cluster = cluster;
    reader.runs = &mftInfo.runs;

    constexpr uint64_t kBlockRecords = 256;
    std::vector<BYTE> block;
    uint64_t blockStart = 0;
    uint64_t blockCount = 0;

    std::vector<MftEntry> entries;
    entries.reserve(static_cast<size_t>(std::min<uint64_t>(limit, 400000)));
    std::unordered_map<uint64_t, size_t> byIndex;

    for (uint64_t index = 0; index < limit; ++index) {
        if (stop.load()) {
            result.stopped = true;
            break;
        }
        if (index < blockStart || index >= blockStart + blockCount) {
            blockStart = index;
            blockCount = std::min<uint64_t>(kBlockRecords, limit - index);
            block.resize(static_cast<size_t>(blockCount * recordSize));
            if (!reader.ReadAt(index * recordSize, block.data(), block.size())) {
                blockCount = 0;
                break;
            }
        }
        BYTE* current = block.data() + (index - blockStart) * recordSize;
        ++result.inspected;
        if (std::memcmp(current, "FILE", 4) != 0) {
            ++result.skipped;
            continue;
        }
        ApplyFixups(current, recordSize, sector);

        MftRecordInfo info;
        if (!ParseMftRecord(current, recordSize, info, false)) {
            ++result.skipped;
            continue;
        }
        if (info.baseRecord != 0 || info.name.empty()) {
            ++result.skipped;
            continue;
        }
        MftEntry entry;
        entry.index = index;
        entry.parent = info.parentRecord;
        entry.dataSize = info.dataSize;
        entry.created = info.created;
        entry.modified = info.modified;
        entry.name = info.name;
        entry.directory = (info.flags & 0x0002) != 0;
        entry.live = (info.flags & 0x0001) != 0;
        entry.hasData = info.hasData;
        byIndex[index] = entries.size();
        entries.push_back(std::move(entry));

        if ((index & 0x3FF) == 0) {
            sink.Status(Format(L"%s \u00B7 %s of %s MFT records indexed",
                               volume.c_str(), CommaNumber(index).c_str(),
                               CommaNumber(limit).c_str()));
        }
    }

    sink.Status(Format(L"%s \u00B7 resolving %s paths\u2026", volume.c_str(),
                       CommaNumber(entries.size()).c_str()));
    std::vector<std::wstring> paths(entries.size());
    std::vector<size_t> order(entries.size());
    for (size_t i = 0; i < entries.size(); ++i) {
        paths[i] = BuildEntryPath(entries, byIndex, i);
        order[i] = i;
    }
    std::sort(order.begin(), order.end(), [&](size_t left, size_t right) {
        const int cmp = _wcsicmp(paths[left].c_str(), paths[right].c_str());
        if (cmp != 0) return cmp < 0;
        return entries[left].index < entries[right].index;
    });

    sink.Status(Format(L"%s \u00B7 emitting %s entries\u2026", volume.c_str(),
                       CommaNumber(order.size()).c_str()));
    unsigned long long emitted = 0;
    for (size_t slot : order) {
        if (stop.load()) {
            result.stopped = true;
            break;
        }
        const MftEntry& entry = entries[slot];
        if (paths[slot].empty()) {
            ++result.skipped;
            continue;
        }
        if (config.deletedOnly && entry.live) {
            ++result.skipped;
            continue;
        }
        const std::wstring source = Format(L"%s \u00B7 MFT #%llu", volume.c_str(),
                                           static_cast<unsigned long long>(entry.index));
        const std::wstring state = entry.live ? L"in use" : L"deleted";
        const std::wstring created = FileTimeFromU64(entry.created);
        const std::wstring modified = FileTimeFromU64(entry.modified);

        if (entry.directory) {
            if (CarvedAddEntry(paths[slot], L"Folder", source, state, created, modified, 0, {},
                               true)) {
                ++result.folders;
                ++result.listed;
                if (entry.live) ++result.inUse; else ++result.deleted;
            } else {
                ++result.skipped;
            }
            continue;
        }

        std::vector<BYTE> data;
        bool complete = false;
        const uint64_t want = std::min<uint64_t>(entry.dataSize, CarvedMaxFile());
        if (entry.hasData && want > 0 &&
            CarvedHasRoom(static_cast<size_t>(std::min<uint64_t>(want, SIZE_MAX)))) {
            std::vector<BYTE> raw(recordSize);
            MftRecordInfo info;
            if (reader.ReadAt(entry.index * recordSize, raw.data(), raw.size())) {
                ApplyFixups(raw.data(), raw.size(), sector);
                if (ParseMftRecord(raw.data(), raw.size(), info) &&
                    ReadRecordData(handle, sector, cluster, recordSize, raw.data(), info, data)) {
                    complete = data.size() >= want;
                    if (!complete) ++result.skipped;
                    ++result.withData;
                } else {
                    data.clear();
                }
            }
        }

        if (CarvedAddEntry(paths[slot], L"", source, state, created, modified,
                           entry.dataSize, std::move(data), complete)) {
            ++result.files;
            ++result.listed;
            if (entry.live) ++result.inUse; else ++result.deleted;
        } else {
            ++result.skipped;
        }

        ++emitted;
        if ((emitted & 0x3FF) == 0) {
            sink.Status(Format(L"%s \u00B7 %s of %s entries emitted \u00B7 %s listed",
                               volume.c_str(), CommaNumber(emitted).c_str(),
                               CommaNumber(order.size()).c_str(),
                               CommaNumber(result.listed).c_str()));
        }
    }
    CloseHandle(handle);
    return result;
}

}

void RunMftRecover(const Sink& sink, std::atomic<bool>& stop, MftRecoverConfig config) {
    CarvedClear();
    MftRecoverResult result = RecoverMftIntoStore(sink, stop, config);
    if (!result.error.empty()) {
        sink.Error(result.error);
        return;
    }

    std::vector<Row> rows = CarvedRows();
    std::wstring summary = Format(
        L"%s item(s) from the %s $MFT \u00B7 %s file(s) \u00B7 %s folder(s) \u00B7 %s deleted "
        L"\u00B7 %s in use",
        CommaNumber(rows.size()).c_str(), config.volume.c_str(),
        CommaNumber(result.files).c_str(), CommaNumber(result.folders).c_str(),
        CommaNumber(result.deleted).c_str(), CommaNumber(result.inUse).c_str());
    if (result.withData < result.files) {
        summary += Format(L" \u00B7 %s with content",
                          CommaNumber(result.withData).c_str());
    }
    if (stop.load() || result.stopped) summary += L" \u00B7 stopped";
    if (rows.empty()) {
        summary = Format(L"Nothing recovered \u00B7 %s MFT records inspected \u00B7 %s skipped",
                         CommaNumber(result.inspected).c_str(),
                         CommaNumber(result.skipped).c_str());
    }
    sink.Detailed(std::move(rows), CarvedDetails(), true, summary, 100);
    sink.Done(summary);
}

void RunCarvingScan(const Sink& sink, std::atomic<bool>& stop, CarveConfig carve,
                    MftRecoverConfig mft) {
    CarvedClear();

    MftRecoverResult mftResult = RecoverMftIntoStore(sink, stop, mft);
    uint64_t carvedBytes = 0;
    bool carvedStopped = false;
    if (!stop.load()) {
        sink.Status(L"Carving file signatures from the raw volume\u2026");
        CarveIntoStore(sink, stop, carve, carvedBytes, carvedStopped);
    }

    std::vector<Row> rows = CarvedRows();
    std::wstring summary = Format(
        L"%s item(s) \u00B7 $MFT: %s file(s), %s folder(s), %s deleted \u00B7 %s scanned for signatures%s",
        CommaNumber(rows.size()).c_str(), CommaNumber(mftResult.files).c_str(),
        CommaNumber(mftResult.folders).c_str(), CommaNumber(mftResult.deleted).c_str(),
        SizeText(carvedBytes).c_str(), (stop.load() || carvedStopped) ? L" \u00B7 stopped" : L"");
    if (!mftResult.error.empty()) summary += L" \u00B7 " + mftResult.error;
    sink.Detailed(std::move(rows), CarvedDetails(), true, summary, 100);
    sink.Done(summary);
}

void RunUsnJournal(const Sink& sink, std::atomic<bool>& stop, UsnConfig config) {    unsigned long long parsed = 0;
    unsigned long long shown = 0;
    bool limitReached = false;
    for (const std::wstring& volume : config.volumes) {
        if (stop.load()) break;
        if (config.limit && shown >= config.limit) {
            limitReached = true;
            break;
        }
        if (!ReadUsnJournal(sink, stop, volume, config.limit, parsed, shown)) {
            if (stop.load()) break;
            sink.Status(Format(L"%s \u00B7 journal unavailable; continuing with the next volume.",
                               volume.c_str()));
        }
        if (config.limit && shown >= config.limit) {
            limitReached = true;
            break;
        }
    }
    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s USN records retained.", CommaNumber(shown).c_str()));
    } else if (limitReached) {
        sink.Done(Format(L"Limit reached. Displayed %s USN records.", CommaNumber(shown).c_str()));
    } else {
        sink.Done(Format(L"Completed. Parsed %s USN records; displayed %s.",
                         CommaNumber(parsed).c_str(), CommaNumber(shown).c_str()));
    }
}

void RunMftScan(const Sink& sink, std::atomic<bool>& stop, MftConfig config) {
    unsigned long long scanned = 0;
    unsigned long long shown = 0;
    bool limitReached = false;
    for (const std::wstring& volume : config.volumes) {
        if (stop.load()) break;
        if (config.limit && scanned >= config.limit) {
            limitReached = true;
            break;
        }
        if (!ReadMftVolume(sink, stop, volume, config.limit, scanned, shown)) {
            if (stop.load()) break;
            sink.Status(Format(L"%s \u00B7 raw MFT read failed; continuing with the next volume.",
                               volume.c_str()));
        }
        if (config.limit && scanned >= config.limit) {
            limitReached = true;
            break;
        }
    }
    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s MFT records retained.", CommaNumber(shown).c_str()));
    } else if (limitReached) {
        sink.Done(Format(L"Limit reached. Inspected %s MFT records; displayed %s.",
                         CommaNumber(scanned).c_str(), CommaNumber(shown).c_str()));
    } else {
        sink.Done(Format(L"Completed. Inspected %s MFT records; displayed %s.",
                         CommaNumber(scanned).c_str(), CommaNumber(shown).c_str()));
    }
}
