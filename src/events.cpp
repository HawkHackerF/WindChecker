#include "artifacts.h"
#include "evtx.h"

#include <winevt.h>

#include <algorithm>
#include <cwctype>
#include <sddl.h>

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "advapi32.lib")

std::wstring EvtxDecode(const std::wstring& text) {
    std::wstring out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] != L'&') {
            out.push_back(text[i]);
            continue;
        }
        struct Entity {
            const wchar_t* name;
            wchar_t value;
        };
        static const Entity entities[] = {
            {L"&amp;", L'&'}, {L"&lt;", L'<'}, {L"&gt;", L'>'},
            {L"&quot;", L'"'}, {L"&apos;", L'\''},
        };
        bool replaced = false;
        for (const Entity& entity : entities) {
            size_t length = wcslen(entity.name);
            if (text.compare(i, length, entity.name) == 0) {
                out.push_back(entity.value);
                i += length - 1;
                replaced = true;
                break;
            }
        }
        if (!replaced) out.push_back(text[i]);
    }
    return out;
}

std::wstring EvtxAttribute(const std::wstring& xml, const std::wstring& element,
                           const std::wstring& attribute) {
    size_t position = xml.find(L"<" + element);
    if (position == std::wstring::npos) return L"";
    size_t tagEnd = xml.find(L'>', position);
    if (tagEnd == std::wstring::npos) return L"";
    std::wstring tag = xml.substr(position, tagEnd - position);

    size_t search = 0;
    while ((search = tag.find(attribute, search)) != std::wstring::npos) {
        bool leftBoundary = search == 0 || iswspace(tag[search - 1]) || tag[search - 1] == L'<';
        size_t after = search + attribute.size();
        while (after < tag.size() && iswspace(tag[after])) ++after;
        if (!leftBoundary || after >= tag.size() || tag[after] != L'=') {
            search += attribute.size();
            continue;
        }
        ++after;
        while (after < tag.size() && iswspace(tag[after])) ++after;
        if (after >= tag.size()) return L"";
        wchar_t quote = tag[after];
        if (quote != L'"' && quote != L'\'') return L"";
        size_t valueEnd = tag.find(quote, after + 1);
        if (valueEnd == std::wstring::npos) return L"";
        return EvtxDecode(tag.substr(after + 1, valueEnd - after - 1));
    }
    return L"";
}

std::wstring EvtxElement(const std::wstring& xml, const std::wstring& element) {
    size_t position = xml.find(L"<" + element);
    if (position == std::wstring::npos) return L"";
    size_t tagEnd = xml.find(L'>', position);
    if (tagEnd == std::wstring::npos) return L"";
    size_t close = xml.find(L"</" + element + L">", tagEnd);
    if (close == std::wstring::npos) return L"";
    return EvtxDecode(xml.substr(tagEnd + 1, close - tagEnd - 1));
}

namespace {

std::wstring TagAttribute(const std::wstring& tag, const std::wstring& attribute) {
    size_t search = 0;
    while ((search = tag.find(attribute, search)) != std::wstring::npos) {
        bool leftBoundary = search == 0 || iswspace(tag[search - 1]) || tag[search - 1] == L'<';
        size_t after = search + attribute.size();
        while (after < tag.size() && iswspace(tag[after])) ++after;
        if (!leftBoundary || after >= tag.size() || tag[after] != L'=') {
            search += attribute.size();
            continue;
        }
        ++after;
        while (after < tag.size() && iswspace(tag[after])) ++after;
        if (after >= tag.size()) return L"";
        wchar_t quote = tag[after];
        if (quote != L'"' && quote != L'\'') return L"";
        size_t valueEnd = tag.find(quote, after + 1);
        if (valueEnd == std::wstring::npos) return L"";
        return EvtxDecode(tag.substr(after + 1, valueEnd - after - 1));
    }
    return L"";
}

void AppendField(std::wstring& text, const std::wstring& name, const std::wstring& value,
                 size_t width) {
    if (value.empty()) return;
    text += name;
    if (name.size() < width) text.append(width - name.size(), L' ');
    text += L" : " + value + L"\r\n";
}

}

std::wstring EvtxDataText(const std::wstring& xml) {
    std::wstring text;
    size_t position = 0;
    while ((position = xml.find(L"<Data", position)) != std::wstring::npos) {
        size_t tagEnd = xml.find(L'>', position);
        if (tagEnd == std::wstring::npos) break;
        if (tagEnd > position && xml[tagEnd - 1] == L'/') {
            position = tagEnd + 1;
            continue;
        }
        size_t close = xml.find(L"</Data>", tagEnd);
        if (close == std::wstring::npos) break;
        std::wstring tag = xml.substr(position, tagEnd - position);
        std::wstring value = EvtxDecode(xml.substr(tagEnd + 1, close - tagEnd - 1));
        value = Trim(value);
        if (!value.empty()) {
            std::wstring name = TagAttribute(tag, L"Name");
            if (!name.empty()) value = name + L"=" + value;
            if (!text.empty()) text += L" | ";
            text += value;
        }
        position = close + 7;
    }
    std::wstring computer = EvtxElement(xml, L"Computer");
    if (!computer.empty()) {
        if (!text.empty()) text += L" | ";
        text += L"computer " + computer;
    }
    if (text.size() > 1400) text.resize(1400);
    return text;
}

std::wstring EvtxStamp(const std::wstring& xml) {
    std::wstring stamp = EvtxAttribute(xml, L"TimeCreated", L"SystemTime");
    if (stamp.empty()) return L"";
    std::replace(stamp.begin(), stamp.end(), L'T', L' ');
    if (!stamp.empty() && stamp.back() == L'Z') {
        stamp.pop_back();
        stamp += L" UTC";
    }
    return stamp;
}

std::vector<EvtxField> EvtxDataFields(const std::wstring& xml) {
    std::vector<EvtxField> fields;
    size_t position = 0;
    int unnamed = 0;
    while ((position = xml.find(L"<Data", position)) != std::wstring::npos) {
        size_t tagEnd = xml.find(L'>', position);
        if (tagEnd == std::wstring::npos) break;
        if (tagEnd > position && xml[tagEnd - 1] == L'/') {
            position = tagEnd + 1;
            continue;
        }
        size_t close = xml.find(L"</Data>", tagEnd);
        if (close == std::wstring::npos) break;
        std::wstring tag = xml.substr(position, tagEnd - position);
        EvtxField field;
        field.name = TagAttribute(tag, L"Name");
        field.value = EvtxDecode(xml.substr(tagEnd + 1, close - tagEnd - 1));
        if (field.name.empty()) field.name = Format(L"Data[%d]", unnamed++);
        fields.push_back(std::move(field));
        position = close + 7;
    }
    return fields;
}

std::wstring EvtxFullDetail(const std::wstring& xml) {
    std::wstring text;
    text += L"Provider     : " + EvtxAttribute(xml, L"Provider", L"Name") + L"\r\n";
    text += L"Event ID     : " + EvtxElement(xml, L"EventID") + L"\r\n";
    text += L"Version      : " + EvtxElement(xml, L"Version") + L"\r\n";
    text += L"Level        : " + EvtxElement(xml, L"Level") + L"\r\n";
    text += L"Task         : " + EvtxElement(xml, L"Task") + L"\r\n";
    text += L"Opcode       : " + EvtxElement(xml, L"Opcode") + L"\r\n";
    text += L"Keywords     : " + EvtxElement(xml, L"Keywords") + L"\r\n";
    text += L"Record ID    : " + EvtxElement(xml, L"EventRecordID") + L"\r\n";
    text += L"Time created : " + EvtxStamp(xml) + L"\r\n";
    text += L"Process ID   : " + EvtxAttribute(xml, L"Execution", L"ProcessID") + L"\r\n";
    text += L"Thread ID    : " + EvtxAttribute(xml, L"Execution", L"ThreadID") + L"\r\n";
    text += L"Channel      : " + EvtxElement(xml, L"Channel") + L"\r\n";
    text += L"Computer     : " + EvtxElement(xml, L"Computer") + L"\r\n";
    text += L"User ID      : " + EvtxAttribute(xml, L"Security", L"UserID") + L"\r\n";
    text += L"Activity ID  : " + EvtxAttribute(xml, L"Correlation", L"ActivityID") + L"\r\n";
    text += L"Related ID   : " + EvtxAttribute(xml, L"Correlation", L"RelatedActivityID") + L"\r\n";

    std::vector<EvtxField> fields = EvtxDataFields(xml);
    size_t width = 0;
    for (const EvtxField& field : fields) width = (std::max)(width, field.name.size());
    if (width > 34) width = 34;
    if (width < 12) width = 12;
    text += Format(L"\r\n--- event data (%s field(s)) ---\r\n", CommaNumber(fields.size()).c_str());
    for (const EvtxField& field : fields) AppendField(text, field.name, field.value, width);

    size_t userAt = xml.find(L"<UserData>");
    if (userAt != std::wstring::npos) {
        size_t userEnd = xml.find(L"</UserData>", userAt);
        if (userEnd != std::wstring::npos) {
            std::wstring user = xml.substr(userAt + 10, userEnd - userAt - 10);
            user = Trim(user);
            if (!user.empty()) text += L"\r\n--- user data ---\r\n" + user + L"\r\n";
        }
    }

    if (xml.size() <= 8192) {
        text += L"\r\n--- raw XML ---\r\n" + xml;
    } else {
        text += Format(L"\r\n--- raw XML (%s bytes, open the record in Event Viewer for the full body) ---\r\n",
                       CommaNumber(xml.size()).c_str());
        text += xml.substr(0, 8192) + L"\r\n\u2026";
    }
    return text;
}

bool EvtxRender(EVT_HANDLE event, std::wstring& xml) {
    DWORD used = 0;
    DWORD properties = 0;
    if (EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &properties)) return false;
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || used == 0) return false;
    xml.assign(used / sizeof(wchar_t) + 1, L'\0');
    if (!EvtRender(nullptr, event, EvtRenderEventXml,
                   static_cast<DWORD>(xml.size() * sizeof(wchar_t)),
                   xml.data(), &used, &properties)) {
        return false;
    }
    xml.resize(wcslen(xml.c_str()));
    return true;
}

namespace {

void FlushRows(const Sink& sink, std::vector<Row>& pending, std::vector<std::wstring>& details) {
    if (pending.empty()) return;
    sink.Detailed(std::move(pending), std::move(details), false);
    pending.clear();
    pending.reserve(128);
    details.clear();
    details.reserve(128);
}

std::wstring FieldValue(const std::vector<EvtxField>& fields, const wchar_t* name) {
    for (const EvtxField& field : fields) {
        if (_wcsicmp(field.name.c_str(), name) == 0) return field.value;
    }
    return L"";
}

std::wstring FieldValueAny(const std::vector<EvtxField>& fields,
                           std::initializer_list<const wchar_t*> names) {
    for (const wchar_t* name : names) {
        std::wstring value = FieldValue(fields, name);
        if (!value.empty()) return value;
    }
    return L"";
}

std::wstring RdpEventMeaning(const std::wstring& id) {
    int value = _wtoi(id.c_str());
    switch (value) {
        case 21: return L"Session logon succeeded";
        case 22: return L"Shell start notification received";
        case 23: return L"Session logoff succeeded";
        case 24: return L"Session disconnected";
        case 25: return L"Session reconnection succeeded";
        case 39: return L"Session disconnected by another session";
        case 40: return L"Session disconnected with a reason code";
        case 41: return L"Session begin";
        case 42: return L"Session end";
        case 1149: return L"Remote Desktop user authentication succeeded";
        case 1148: return L"Remote Desktop authentication attempt";
        case 131: return L"Remote Desktop licensing mode changed";
        default: return L"";
    }
}

}

std::vector<std::wstring> ListEventChannels() {
    std::vector<std::wstring> channels;
    EVT_HANDLE enumeration = EvtOpenChannelEnum(nullptr, 0);
    if (!enumeration) return channels;
    std::vector<wchar_t> buffer(1024);
    DWORD used = 0;
    while (EvtNextChannelPath(enumeration, static_cast<DWORD>(buffer.size()), buffer.data(), &used)) {
        channels.emplace_back(buffer.data());
    }
    EvtClose(enumeration);
    std::sort(channels.begin(), channels.end(),
              [](const std::wstring& left, const std::wstring& right) {
                  return _wcsicmp(left.c_str(), right.c_str()) < 0;
              });
    return channels;
}

void RunEventLogs(const Sink& sink, std::atomic<bool>& stop, EventsConfig config) {
    int limit = config.limitPerChannel > 0 ? config.limitPerChannel : 1000;
    unsigned long long total = 0;
    int channelIndex = 0;
    int channelCount = static_cast<int>(config.channels.size());

    for (const std::wstring& channel : config.channels) {
        if (stop.load()) break;
        ++channelIndex;
        const bool rdpChannel = channel.find(L"TerminalServices") != std::wstring::npos;
        sink.Status(Format(L"%s \u00B7 reading channel %d/%d \u00B7 %s events shown",
                           channel.c_str(), channelIndex, channelCount,
                           CommaNumber(total).c_str()));
        if (channelCount > 0) {
            int progress = channelIndex * 100 / channelCount;
            sink.Status(Format(L"%s \u00B7 %d/%d channels \u00B7 %s events shown",
                               channel.c_str(), channelIndex, channelCount,
                               CommaNumber(total).c_str()), progress);
        }

        EVT_HANDLE query = EvtQuery(nullptr, channel.c_str(), L"*",
                                    EvtQueryChannelPath | EvtQueryReverseDirection);
        if (!query) continue;

        std::vector<Row> pending;
        std::vector<std::wstring> details;
        pending.reserve(128);
        details.reserve(128);
        int channelRows = 0;
        EVT_HANDLE events[32] = {};
        DWORD returned = 0;
        while (!stop.load() && channelRows < limit) {
            if (!EvtNext(query, 32, events, 1000, 0, &returned)) break;
            for (DWORD i = 0; i < returned && channelRows < limit; ++i) {
                std::wstring xml;
                if (EvtxRender(events[i], xml)) {
                    ++channelRows;
                    ++total;
                    std::wstring eventId = EvtxElement(xml, L"EventID");
                    Row row;
                    row.reserve(6);
                    row.push_back(EvtxStamp(xml));
                    row.push_back(channel);
                    row.push_back(eventId);
                    row.push_back(EvtxAttribute(xml, L"Provider", L"Name"));
                    row.push_back(EvtxElement(xml, L"Level"));
                    std::wstring detail;
                    if (rdpChannel) {
                        size_t slash = channel.find_last_of(L'/');
                        if (slash != std::wstring::npos) row[1] = channel.substr(slash + 1);
                        std::vector<EvtxField> fields = EvtxDataFields(xml);
                        std::wstring user = FieldValueAny(fields, {L"User", L"UserName", L"TargetUserName"});
                        std::wstring domain = FieldValueAny(fields, {L"Domain", L"TargetDomainName"});
                        std::wstring address = FieldValueAny(fields, {L"Address", L"Source Network Address",
                                                                      L"SourceNetworkAddress", L"IPAddress"});
                        std::wstring session = FieldValueAny(fields, {L"SessionID", L"SessionId", L"Session"});
                        std::wstring reason = FieldValueAny(fields, {L"Reason", L"ReasonCode"});
                        std::wstring logonType = FieldValueAny(fields, {L"LogonType", L"Logon Type"});
                        std::wstring meaning = RdpEventMeaning(eventId);

                        std::wstring summary;
                        auto append = [&](const std::wstring& value) {
                            if (value.empty()) return;
                            if (!summary.empty()) summary += L" \u00B7 ";
                            summary += value;
                        };
                        append(meaning.empty() ? L"Terminal Services event" : meaning);
                        append(user);
                        append(address);
                        append(session.empty() ? L"" : L"session " + session);
                        row.push_back(summary);

                        detail += L"--- what happened ---\r\n";
                        detail += L"Event        : " + (eventId.empty() ? L"?" : eventId) + L"\r\n";
                        detail += L"Meaning      : " + (meaning.empty() ? L"Terminal Services event" : meaning) + L"\r\n";
                        if (!user.empty()) {
                            detail += L"User         : " + user;
                            if (!domain.empty()) detail += L" (" + domain + L")";
                            detail += L"\r\n";
                        }
                        if (!address.empty()) detail += L"Source host  : " + address + L"\r\n";
                        if (!session.empty()) detail += L"Session ID   : " + session + L"\r\n";
                        if (!logonType.empty()) detail += L"Logon type   : " + logonType + L"\r\n";
                        if (!reason.empty()) detail += L"Reason       : " + reason + L"\r\n";
                        detail += L"\r\n" + EvtxFullDetail(xml);
                    } else {
                        row.push_back(EvtxDataText(xml));
                        detail = EvtxFullDetail(xml);
                    }
                    pending.push_back(std::move(row));
                    details.push_back(std::move(detail));
                    if (pending.size() >= 100) FlushRows(sink, pending, details);
                }
                EvtClose(events[i]);
                events[i] = nullptr;
            }
            if (returned < 32) break;
        }
        for (EVT_HANDLE event : events) {
            if (event) EvtClose(event);
        }
        EvtClose(query);
        FlushRows(sink, pending, details);
    }

    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s event records retained.", CommaNumber(total).c_str()));
    } else {
        sink.Done(Format(L"Completed. Displayed %s Windows event log records.",
                         CommaNumber(total).c_str()));
    }
}

namespace {

// Turn a string SID (S-1-5-...) into DOMAIN\account when possible.
std::wstring ResolveSid(const std::wstring& sid) {
    if (sid.size() < 4 || sid[0] != L'S' || sid[1] != L'-') return sid;
    PSID psid = nullptr;
    if (!ConvertStringSidToSidW(sid.c_str(), &psid)) return sid;
    wchar_t name[256] = {};
    wchar_t domain[256] = {};
    DWORD nameLength = 256;
    DWORD domainLength = 256;
    SID_NAME_USE use = SidTypeUnknown;
    std::wstring result = sid;
    if (LookupAccountSidW(nullptr, psid, name, &nameLength, domain, &domainLength, &use)) {
        result = name;
        if (domain[0]) result = std::wstring(domain) + L"\\" + name;
    }
    LocalFree(psid);
    return result;
}

std::wstring LevelName(const std::wstring& level) {
    switch (_wtoi(level.c_str())) {
        case 1: return L"Critical";
        case 2: return L"Error";
        case 3: return L"Warning";
        case 4: return L"Information";
        case 5: return L"Verbose";
        default: return level;
    }
}

// Human meaning for the event IDs that matter most in forensic triage.
std::wstring EventMeaning(const std::wstring& id) {
    switch (_wtoi(id.c_str())) {
        case 4624: return L"An account was successfully logged on";
        case 4625: return L"An account failed to log on";
        case 4634: return L"An account was logged off";
        case 4647: return L"User initiated logoff";
        case 4648: return L"A logon was attempted using explicit credentials";
        case 4672: return L"Special privileges assigned to new logon";
        case 4776: return L"Credential validation was performed";
        case 4740: return L"A user account was locked out";
        case 4767: return L"A user account was unlocked";
        case 4720: return L"A user account was created";
        case 4722: return L"A user account was enabled";
        case 4723: return L"An attempt was made to change an account password";
        case 4724: return L"An attempt was made to reset an account password";
        case 4725: return L"A user account was disabled";
        case 4726: return L"A user account was deleted";
        case 4728: return L"A member was added to a security-enabled global group";
        case 4732: return L"A member was added to a security-enabled local group";
        case 4756: return L"A member was added to a security-enabled universal group";
        case 4738: return L"A user account was changed";
        case 4688: return L"A new process has been created";
        case 4689: return L"A process has exited";
        case 4697: return L"A service was installed in the system";
        case 1102: return L"The audit log was cleared";
        case 104: return L"The event log was cleared";
        case 6005: return L"The Event log service was started";
        case 6006: return L"The Event log service was stopped";
        case 6013: return L"System uptime";
        case 6008: return L"The previous system shutdown was unexpected";
        case 1074: return L"The system is shutting down or restarting";
        case 7045: return L"A service was installed in the system";
        case 4103: return L"PowerShell module logging";
        case 4104: return L"PowerShell script block logging";
        case 400: return L"The PowerShell engine started";
        case 403: return L"The PowerShell engine stopped";
        case 1: return L"Sysmon process creation";
        case 3: return L"Sysmon network connection";
        case 7: return L"Sysmon image loaded";
        case 8: return L"Sysmon remote thread created";
        case 11: return L"Sysmon file created";
        case 13: return L"Sysmon registry value set";
        default: return L"";
    }
}

std::wstring BuildEventXPath(const EventViewerConfig& config) {
    std::wstring sys;
    if (!config.eventIds.empty()) {
        std::wstring ids;
        for (size_t i = 0; i < config.eventIds.size(); ++i) {
            if (i) ids += L" or ";
            ids += L"EventID=" + std::to_wstring(config.eventIds[i]);
        }
        sys += L"(" + ids + L")";
    }
    if (config.level > 0) {
        if (!sys.empty()) sys += L" and ";
        sys += L"Level=" + std::to_wstring(config.level);
    }
    if (!config.provider.empty()) {
        std::wstring provider = config.provider;
        std::wstring escaped;
        for (wchar_t c : provider) {
            if (c == L'\'') escaped += L"''";
            else escaped += c;
        }
        if (!sys.empty()) sys += L" and ";
        sys += L"Provider[@Name='" + escaped + L"']";
    }
    if (sys.empty()) return L"*";
    return L"*[System[" + sys + L"]]";
}

}  // namespace

void RunEventViewer(const Sink& sink, std::atomic<bool>& stop, EventViewerConfig config) {
    const int limit = config.limitPerChannel > 0 ? config.limitPerChannel : 2000;
    const std::wstring xpath = BuildEventXPath(config);
    const int channelCount = static_cast<int>(config.channels.size());
    unsigned long long total = 0;
    int skipped = 0;
    int channelIndex = 0;

    for (const std::wstring& channel : config.channels) {
        if (stop.load()) break;
        ++channelIndex;
        if (channelCount > 0) {
            sink.Status(Format(L"%s \u00B7 %d/%d channels \u00B7 %s events shown",
                               channel.c_str(), channelIndex, channelCount,
                               CommaNumber(total).c_str()),
                        channelIndex * 100 / channelCount);
        }

        EVT_HANDLE query = EvtQuery(nullptr, channel.c_str(), xpath.c_str(),
                                    EvtQueryChannelPath | EvtQueryReverseDirection);
        if (!query) {
            ++skipped;
            continue;
        }

        std::vector<Row> pending;
        std::vector<std::wstring> details;
        pending.reserve(128);
        details.reserve(128);
        int channelRows = 0;
        EVT_HANDLE events[32] = {};
        DWORD returned = 0;
        while (!stop.load() && channelRows < limit) {
            if (!EvtNext(query, 32, events, 1000, 0, &returned)) break;
            for (DWORD i = 0; i < returned && channelRows < limit; ++i) {
                std::wstring xml;
                if (EvtxRender(events[i], xml)) {
                    ++channelRows;
                    ++total;
                    const std::wstring eventId = EvtxElement(xml, L"EventID");
                    const std::wstring level = LevelName(EvtxElement(xml, L"Level"));
                    const std::wstring provider = EvtxAttribute(xml, L"Provider", L"Name");
                    std::wstring channelName = EvtxElement(xml, L"Channel");
                    if (channelName.empty()) channelName = channel;

                    std::vector<EvtxField> fields = EvtxDataFields(xml);
                    std::wstring user = FieldValueAny(fields, {L"TargetUserName", L"SubjectUserName",
                                                               L"UserName", L"AccountName", L"User"});
                    const std::wstring domain = FieldValueAny(fields, {L"TargetDomainName",
                                                                       L"SubjectDomainName", L"Domain"});
                    const std::wstring logonType = FieldValueAny(fields, {L"LogonType", L"Logon Type"});
                    const std::wstring address = FieldValueAny(fields, {L"IpAddress", L"Source Network Address",
                                                                        L"SourceNetworkAddress", L"WorkstationName",
                                                                        L"Workstation"});
                    const std::wstring process = FieldValueAny(fields, {L"NewProcessName", L"ProcessName",
                                                                        L"ImageFileName", L"CommandLine"});
                    if (!user.empty() && !domain.empty()) user = domain + L"\\" + user;
                    if (user.empty()) user = EvtxAttribute(xml, L"Security", L"UserID");
                    user = ResolveSid(user);

                    const std::wstring meaning = EventMeaning(eventId);

                    std::wstring message;
                    auto append = [&](const std::wstring& value) {
                        if (value.empty()) return;
                        if (!message.empty()) message += L" \u00B7 ";
                        message += value;
                    };
                    append(meaning);
                    append(user.empty() ? L"" : L"user " + user);
                    append(address.empty() ? L"" : L"from " + address);
                    append(logonType.empty() ? L"" : L"logon type " + logonType);
                    append(process);
                    if (message.empty()) message = EvtxDataText(xml);

                    std::wstring detail;
                    detail += L"--- what happened ---\r\n";
                    detail += L"Event        : " + (eventId.empty() ? L"?" : eventId);
                    if (!meaning.empty()) detail += L"  (" + meaning + L")";
                    detail += L"\r\n";
                    detail += L"Channel      : " + channelName + L"\r\n";
                    detail += L"Level        : " + (level.empty() ? L"-" : level) + L"\r\n";
                    detail += L"Provider     : " + provider + L"\r\n";
                    if (!user.empty()) detail += L"User         : " + user + L"\r\n";
                    if (!address.empty()) detail += L"Source       : " + address + L"\r\n";
                    if (!logonType.empty()) detail += L"Logon type   : " + logonType + L"\r\n";
                    if (!process.empty()) detail += L"Process      : " + process + L"\r\n";
                    detail += L"\r\n" + EvtxFullDetail(xml);

                    pending.push_back(Row{EvtxStamp(xml), channelName, eventId, level, provider, user, message});
                    details.push_back(std::move(detail));
                    if (pending.size() >= 100) FlushRows(sink, pending, details);
                }
                EvtClose(events[i]);
                events[i] = nullptr;
            }
            if (returned < 32) break;
        }
        for (EVT_HANDLE event : events) {
            if (event) EvtClose(event);
        }
        EvtClose(query);
        FlushRows(sink, pending, details);
    }

    std::wstring skippedText;
    if (skipped > 0) skippedText = Format(L" \u00B7 %d channel(s) unreadable (run as administrator)", skipped);
    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s event record(s) retained.", CommaNumber(total).c_str()));
    } else {
        sink.Done(Format(L"Completed. %s event record(s) from %d channel(s)%s.",
                         CommaNumber(total).c_str(), channelCount, skippedText.c_str()));
    }
}
