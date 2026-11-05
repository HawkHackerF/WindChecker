#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include "artifacts.h"

#include <sddl.h>
#include <winsvc.h>

#include <algorithm>

namespace {

std::wstring JoinList(const std::vector<std::wstring>& items, const wchar_t* separator) {
    std::wstring text;
    for (const std::wstring& item : items) {
        if (!text.empty()) text += separator;
        text += item;
    }
    return text;
}

std::wstring ServiceStateText(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED: return L"stopped";
    case SERVICE_START_PENDING: return L"start pending";
    case SERVICE_STOP_PENDING: return L"stop pending";
    case SERVICE_RUNNING: return L"running";
    case SERVICE_CONTINUE_PENDING: return L"continue pending";
    case SERVICE_PAUSE_PENDING: return L"pause pending";
    case SERVICE_PAUSED: return L"paused";
    default: return Format(L"state %lu", state);
    }
}

std::wstring ServiceStartText(DWORD start) {
    switch (start) {
    case SERVICE_BOOT_START: return L"boot";
    case SERVICE_SYSTEM_START: return L"system";
    case SERVICE_AUTO_START: return L"auto";
    case SERVICE_DEMAND_START: return L"demand";
    case SERVICE_DISABLED: return L"disabled";
    default: return Format(L"0x%lX", start);
    }
}

std::wstring ServiceTypeText(DWORD type) {
    std::vector<std::wstring> parts;
    if (type & SERVICE_KERNEL_DRIVER) parts.push_back(L"kernel driver");
    if (type & SERVICE_FILE_SYSTEM_DRIVER) parts.push_back(L"file system driver");
    if (type & SERVICE_ADAPTER) parts.push_back(L"adapter");
    if (type & SERVICE_RECOGNIZER_DRIVER) parts.push_back(L"recognizer driver");
    if (type & SERVICE_WIN32_OWN_PROCESS) parts.push_back(L"own process");
    if (type & SERVICE_WIN32_SHARE_PROCESS) parts.push_back(L"shared process");
    if (type & 0x00000040) parts.push_back(L"user service");
    if (type & 0x00000080) parts.push_back(L"user service instance");
    if (type & SERVICE_INTERACTIVE_PROCESS) parts.push_back(L"interactive");
    if (type & 0x00000200) parts.push_back(L"packaged");
    if (parts.empty()) return Format(L"0x%08lX", type);
    return JoinList(parts, L" + ");
}

std::wstring ErrorControlText(DWORD control) {
    switch (control) {
    case SERVICE_ERROR_IGNORE: return L"ignore";
    case SERVICE_ERROR_NORMAL: return L"normal";
    case SERVICE_ERROR_SEVERE: return L"severe";
    case SERVICE_ERROR_CRITICAL: return L"critical";
    default: return Format(L"0x%lX", control);
    }
}

std::wstring ControlsText(DWORD controls) {
    std::vector<std::wstring> parts;
    if (controls & SERVICE_ACCEPT_STOP) parts.push_back(L"stop");
    if (controls & SERVICE_ACCEPT_PAUSE_CONTINUE) parts.push_back(L"pause/continue");
    if (controls & SERVICE_ACCEPT_SHUTDOWN) parts.push_back(L"shutdown");
    if (controls & SERVICE_ACCEPT_PARAMCHANGE) parts.push_back(L"param change");
    if (controls & SERVICE_ACCEPT_NETBINDCHANGE) parts.push_back(L"netbind change");
    if (controls & SERVICE_ACCEPT_HARDWAREPROFILECHANGE) parts.push_back(L"hardware profile");
    if (controls & SERVICE_ACCEPT_POWEREVENT) parts.push_back(L"power event");
    if (controls & SERVICE_ACCEPT_SESSIONCHANGE) parts.push_back(L"session change");
    if (controls & SERVICE_ACCEPT_PRESHUTDOWN) parts.push_back(L"preshutdown");
    if (controls & SERVICE_ACCEPT_TIMECHANGE) parts.push_back(L"time change");
    if (controls & SERVICE_ACCEPT_TRIGGEREVENT) parts.push_back(L"trigger event");
    if (parts.empty()) return L"none";
    return JoinList(parts, L", ");
}

std::wstring FailureActionText(SC_ACTION_TYPE type) {
    switch (type) {
    case SC_ACTION_NONE: return L"none";
    case SC_ACTION_RESTART: return L"restart";
    case SC_ACTION_REBOOT: return L"reboot";
    case SC_ACTION_RUN_COMMAND: return L"run command";
    default: return Format(L"0x%X", static_cast<unsigned>(type));
    }
}

std::wstring SidTypeText(DWORD type) {
    switch (type) {
    case SERVICE_SID_TYPE_NONE: return L"none";
    case SERVICE_SID_TYPE_UNRESTRICTED: return L"unrestricted";
    case SERVICE_SID_TYPE_RESTRICTED: return L"restricted";
    default: return Format(L"0x%lX", type);
    }
}

std::wstring LaunchProtectedText(DWORD level) {
    switch (level) {
    case SERVICE_LAUNCH_PROTECTED_NONE: return L"none";
    case SERVICE_LAUNCH_PROTECTED_WINDOWS: return L"windows";
    case SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT: return L"windows light";
    case SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT: return L"antimalware light";
    default: return Format(L"0x%lX", level);
    }
}

std::wstring GuidText(const GUID& guid) {
    return Format(L"{%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                  guid.Data1, guid.Data2, guid.Data3,
                  guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                  guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

std::wstring TriggerTypeText(DWORD type) {
    switch (type) {
    case SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL: return L"device interface arrival";
    case SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY: return L"IP address availability";
    case SERVICE_TRIGGER_TYPE_DOMAIN_JOIN: return L"domain join";
    case SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT: return L"firewall port event";
    case SERVICE_TRIGGER_TYPE_GROUP_POLICY: return L"group policy";
    case SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT: return L"network endpoint";
    case SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE: return L"system state change";
    case SERVICE_TRIGGER_TYPE_CUSTOM: return L"custom";
    case SERVICE_TRIGGER_TYPE_AGGREGATE: return L"aggregate";
    default: return Format(L"type %lu", type);
    }
}

std::wstring TriggerActionText(DWORD action) {
    switch (action) {
    case SERVICE_TRIGGER_ACTION_SERVICE_START: return L"start";
    case SERVICE_TRIGGER_ACTION_SERVICE_STOP: return L"stop";
    default: return Format(L"action %lu", action);
    }
}

std::wstring ExpandEnvironment(const std::wstring& text) {
    if (text.empty()) return text;
    DWORD needed = ExpandEnvironmentStringsW(text.c_str(), nullptr, 0);
    if (!needed) return text;
    std::wstring expanded(needed, L'\0');
    DWORD written = ExpandEnvironmentStringsW(text.c_str(), expanded.data(), needed);
    if (!written || written > needed) return text;
    expanded.resize(written - 1);
    return expanded;
}

std::wstring ResolveServicePath(const std::wstring& raw) {
    std::wstring text = Trim(raw);
    if (text.empty()) return L"";
    if (text.size() >= 2 && text.front() == L'"' && text.back() == L'"') {
        text = text.substr(1, text.size() - 2);
    }
    if (text.rfind(L"\\??\\", 0) == 0) {
        text = text.substr(4);
    } else if (text.rfind(L"\\\\?\\", 0) == 0) {
        text = text.substr(4);
    }
    if (text.rfind(L"\\SystemRoot\\", 0) == 0) {
        wchar_t windows[MAX_PATH] = {};
        GetWindowsDirectoryW(windows, MAX_PATH);
        text = std::wstring(windows) + text.substr(11);
    } else if (text.rfind(L"System32\\", 0) == 0 || text.rfind(L"system32\\", 0) == 0 ||
               text.rfind(L"System32/", 0) == 0) {
        wchar_t windows[MAX_PATH] = {};
        GetWindowsDirectoryW(windows, MAX_PATH);
        text = std::wstring(windows) + L"\\" + text;
    }
    return ExpandEnvironment(text);
}

std::wstring ServiceBinaryPath(const std::wstring& command) {
    std::wstring text = Trim(command);
    if (text.empty()) return L"";
    if (text.front() == L'"') {
        size_t close = text.find(L'"', 1);
        if (close != std::wstring::npos) return ResolveServicePath(text.substr(0, close + 1));
    }
    std::wstring full = ResolveServicePath(text);
    if (GetFileAttributesW(full.c_str()) != INVALID_FILE_ATTRIBUTES) return full;
    size_t space = text.find(L' ');
    while (space != std::wstring::npos) {
        std::wstring head = ResolveServicePath(text.substr(0, space));
        if (GetFileAttributesW(head.c_str()) != INVALID_FILE_ATTRIBUTES) return head;
        space = text.find(L' ', space + 1);
    }
    return full;
}

std::wstring ReadServiceDll(const std::wstring& name) {
    const std::wstring key = L"SYSTEM\\CurrentControlSet\\Services\\" + name + L"\\Parameters";
    wchar_t buffer[2048] = {};
    DWORD size = sizeof(buffer);
    DWORD type = 0;
    if (RegGetValueW(HKEY_LOCAL_MACHINE, key.c_str(), L"ServiceDll",
                     RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, &type, buffer, &size) != ERROR_SUCCESS) {
        return L"";
    }
    return ExpandEnvironment(buffer);
}

std::wstring ServiceRegistryKey(const std::wstring& name) {
    return L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\" + name;
}

std::wstring QueryString(DWORD level, SC_HANDLE service) {
    DWORD needed = 0;
    QueryServiceConfig2W(service, level, nullptr, 0, &needed);
    if (!needed) return L"";
    std::vector<BYTE> buffer(needed + 64);
    if (!QueryServiceConfig2W(service, level, buffer.data(),
                              static_cast<DWORD>(buffer.size()), &needed)) {
        return L"";
    }
    auto* text = reinterpret_cast<LPWSTR>(buffer.data());
    return text ? std::wstring(text) : L"";
}

std::wstring ServiceSddl(SC_HANDLE service) {
    DWORD needed = 0;
    QueryServiceObjectSecurity(service, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                            DACL_SECURITY_INFORMATION,
                               nullptr, 0, &needed);
    if (!needed) return L"";
    std::vector<BYTE> buffer(needed + 64);
    if (!QueryServiceObjectSecurity(service, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                                 DACL_SECURITY_INFORMATION,
                                    buffer.data(), static_cast<DWORD>(buffer.size()), &needed)) {
        return L"";
    }
    LPWSTR sddl = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            buffer.data(), SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &sddl, nullptr)) {
        return L"";
    }
    std::wstring text = sddl ? sddl : L"";
    if (sddl) LocalFree(sddl);
    return text;
}

std::vector<std::wstring> MultiString(const wchar_t* value) {
    std::vector<std::wstring> items;
    if (!value) return items;
    const wchar_t* cursor = value;
    while (*cursor) {
        items.emplace_back(cursor);
        cursor += wcslen(cursor) + 1;
    }
    return items;
}

std::vector<std::wstring> DependentServices(SC_HANDLE service) {
    std::vector<std::wstring> names;
    DWORD needed = 0;
    DWORD count = 0;
    if (EnumDependentServicesW(service, SERVICE_STATE_ALL, nullptr, 0, &needed, &count)) {
        return names;
    }
    if (GetLastError() != ERROR_MORE_DATA || !needed) return names;
    std::vector<BYTE> buffer(needed + 64);
    auto* items = reinterpret_cast<LPENUM_SERVICE_STATUSW>(buffer.data());
    if (!EnumDependentServicesW(service, SERVICE_STATE_ALL, items,
                                static_cast<DWORD>(buffer.size()), &needed, &count)) {
        return names;
    }
    for (DWORD i = 0; i < count; ++i) {
        if (items[i].lpServiceName) names.emplace_back(items[i].lpServiceName);
    }
    return names;
}

std::wstring TriggerReport(SC_HANDLE service) {
    DWORD needed = 0;
    QueryServiceConfig2W(service, SERVICE_CONFIG_TRIGGER_INFO, nullptr, 0, &needed);
    if (!needed) return L"";
    std::vector<BYTE> buffer(needed + 64);
    auto* info = reinterpret_cast<SERVICE_TRIGGER_INFO*>(buffer.data());
    if (!QueryServiceConfig2W(service, SERVICE_CONFIG_TRIGGER_INFO, buffer.data(),
                              static_cast<DWORD>(buffer.size()), &needed)) {
        return L"";
    }
    std::wstring text;
    for (DWORD i = 0; i < info->cTriggers; ++i) {
        const SERVICE_TRIGGER& trigger = info->pTriggers[i];
        text += Format(L"  #%lu %s \u00B7 %s", i + 1,
                       TriggerActionText(trigger.dwAction).c_str(),
                       TriggerTypeText(trigger.dwTriggerType).c_str());
        if (trigger.pTriggerSubtype) text += L" \u00B7 " + GuidText(*trigger.pTriggerSubtype);
        text += L"\r\n";
        for (DWORD d = 0; d < trigger.cDataItems; ++d) {
            const SERVICE_TRIGGER_SPECIFIC_DATA_ITEM& item = trigger.pDataItems[d];
            text += Format(L"      data %lu \u00B7 type %lu \u00B7 %lu byte(s)\r\n",
                           d + 1, item.dwDataType, item.cbData);
            if (item.pData && item.cbData) {
                if (item.dwDataType == SERVICE_TRIGGER_DATA_TYPE_STRING) {
                    text += L"      " + std::wstring(reinterpret_cast<const wchar_t*>(item.pData)) + L"\r\n";
                } else if (item.dwDataType == SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY &&
                           item.cbData >= sizeof(DWORD)) {
                    text += Format(L"      %lu\r\n", *reinterpret_cast<const DWORD*>(item.pData));
                } else if (item.dwDataType == SERVICE_TRIGGER_DATA_TYPE_LEVEL && item.cbData) {
                    text += Format(L"      %u\r\n", static_cast<unsigned>(item.pData[0]));
                }
            }
        }
    }
    return text;
}

std::wstring FailureReport(SC_HANDLE service) {
    DWORD needed = 0;
    QueryServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, nullptr, 0, &needed);
    if (!needed) return L"";
    std::vector<BYTE> buffer(needed + 64);
    auto* actions = reinterpret_cast<SERVICE_FAILURE_ACTIONSW*>(buffer.data());
    if (!QueryServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, buffer.data(),
                              static_cast<DWORD>(buffer.size()), &needed)) {
        return L"";
    }
    std::wstring text;
    text += Format(L"Reset period : %lu second(s)\r\n", actions->dwResetPeriod);
    if (actions->lpRebootMsg && actions->lpRebootMsg[0]) {
        text += L"Reboot message: " + std::wstring(actions->lpRebootMsg) + L"\r\n";
    }
    if (actions->lpCommand && actions->lpCommand[0]) {
        text += L"Command      : " + std::wstring(actions->lpCommand) + L"\r\n";
    }
    for (DWORD i = 0; i < actions->cActions; ++i) {
        text += Format(L"Action %lu     : %s after %lu ms\r\n", i + 1,
                       FailureActionText(actions->lpsaActions[i].Type).c_str(),
                       actions->lpsaActions[i].Delay);
    }
    return text;
}

struct ServiceEntry {
    std::wstring name;
    std::wstring display;
    std::wstring typeText;
    std::wstring stateText;
    std::wstring startText;
    std::wstring account;
    DWORD pid = 0;
    std::wstring processName;
    std::wstring binary;
    std::wstring description;
    std::wstring detail;
    bool driver = false;
};

void AddService(SC_HANDLE manager, const wchar_t* serviceName, const wchar_t* displayName,
                const SERVICE_STATUS_PROCESS& status, ServiceEntry& entry,
                std::vector<ServiceEntry>& out) {
    if (!serviceName || !serviceName[0]) return;
    entry.name = serviceName;
    entry.display = displayName && displayName[0] ? displayName : serviceName;
    entry.pid = status.dwProcessId;
    entry.stateText = ServiceStateText(status.dwCurrentState);
    entry.typeText = ServiceTypeText(status.dwServiceType);
    entry.driver = (status.dwServiceType & (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER |
                                            SERVICE_ADAPTER | SERVICE_RECOGNIZER_DRIVER)) != 0;

    SC_HANDLE service = OpenServiceW(manager, serviceName,
                                     SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL |
                                         SERVICE_ENUMERATE_DEPENDENTS);
    std::wstring configText;
    std::wstring descriptionText;
    std::wstring delayedText;
    std::wstring failureText;
    std::wstring failureFlagText;
    std::wstring sidText;
    std::wstring privilegesText;
    std::wstring preshutdownText;
    std::wstring triggerText;
    std::wstring launchText;
    std::wstring sddlText;
    std::wstring dependentsText;
    std::wstring dllText;
    std::wstring loadGroup;
    DWORD tagId = 0;
    DWORD errorControl = 0;

    if (service) {
        DWORD configSize = 0;
        QueryServiceConfigW(service, nullptr, 0, &configSize);
        std::vector<BYTE> config(configSize ? configSize : 8192);
        auto* info = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data());
        if (QueryServiceConfigW(service, info, static_cast<DWORD>(config.size()), &configSize)) {
            entry.binary = ServiceBinaryPath(info->lpBinaryPathName ? info->lpBinaryPathName : L"");
            entry.account = info->lpServiceStartName ? info->lpServiceStartName : L"";
            entry.startText = ServiceStartText(info->dwStartType);
            errorControl = info->dwErrorControl;
            tagId = info->dwTagId;
            loadGroup = info->lpLoadOrderGroup ? info->lpLoadOrderGroup : L"";
            std::vector<std::wstring> deps = MultiString(info->lpDependencies);
            if (!deps.empty()) configText = JoinList(deps, L", ");
        }

        descriptionText = QueryString(SERVICE_CONFIG_DESCRIPTION, service);

        DWORD delayed = 0;
        DWORD delayedSize = sizeof(delayed);
        if (QueryServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                                 reinterpret_cast<LPBYTE>(&delayed), delayedSize, &delayedSize)) {
            delayedText = delayed ? L"yes" : L"no";
        }

        failureText = FailureReport(service);

        BOOL failureFlag = FALSE;
        DWORD flagSize = sizeof(failureFlag);
        if (QueryServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                                 reinterpret_cast<LPBYTE>(&failureFlag), flagSize, &flagSize)) {
            failureFlagText = failureFlag ? L"yes" : L"no";
        }

        DWORD sidType = 0;
        DWORD sidSize = sizeof(sidType);
        if (QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
                                 reinterpret_cast<LPBYTE>(&sidType), sidSize, &sidSize)) {
            sidText = SidTypeText(sidType);
        }

        DWORD privilegesNeeded = 0;
        QueryServiceConfig2W(service, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, nullptr, 0,
                             &privilegesNeeded);
        if (privilegesNeeded) {
            std::vector<BYTE> privileges(privilegesNeeded + 64);
            auto* info = reinterpret_cast<SERVICE_REQUIRED_PRIVILEGES_INFOW*>(privileges.data());
            if (QueryServiceConfig2W(service, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
                                     privileges.data(), static_cast<DWORD>(privileges.size()),
                                     &privilegesNeeded)) {
                std::vector<std::wstring> items = MultiString(info->pmszRequiredPrivileges);
                privilegesText = items.empty() ? L"none" : JoinList(items, L", ");
            }
        }

        DWORD preshutdown = 0;
        DWORD preshutdownSize = sizeof(preshutdown);
        if (QueryServiceConfig2W(service, SERVICE_CONFIG_PRESHUTDOWN_INFO,
                                 reinterpret_cast<LPBYTE>(&preshutdown), preshutdownSize,
                                 &preshutdownSize)) {
            preshutdownText = Format(L"%lu ms", preshutdown);
        }

        triggerText = TriggerReport(service);

        DWORD launch = 0;
        DWORD launchSize = sizeof(launch);
        if (QueryServiceConfig2W(service, SERVICE_CONFIG_LAUNCH_PROTECTED,
                                 reinterpret_cast<LPBYTE>(&launch), launchSize, &launchSize)) {
            launchText = LaunchProtectedText(launch);
        }

        sddlText = ServiceSddl(service);

        std::vector<std::wstring> dependents = DependentServices(service);
        if (!dependents.empty()) dependentsText = JoinList(dependents, L", ");

        dllText = ReadServiceDll(entry.name);
        CloseServiceHandle(service);
    }

    if (entry.startText.empty()) entry.startText = L"-";
    entry.description = descriptionText;
    for (wchar_t& ch : entry.description) {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t') ch = L' ';
    }
    if (entry.account.empty()) entry.account = L"-";

    ProcInfo process;
    if (entry.pid) {
        process = GetProcInfo(entry.pid);
        entry.processName = process.name;
    }

    std::wstring fileSize;
    std::wstring fileModified;
    if (!entry.binary.empty()) {
        WIN32_FILE_ATTRIBUTE_DATA data{};
        if (GetFileAttributesExW(entry.binary.c_str(), GetFileExInfoStandard, &data)) {
            unsigned long long bytes = (static_cast<unsigned long long>(data.nFileSizeHigh) << 32) |
                                       data.nFileSizeLow;
            fileSize = SizeText(bytes);
            fileModified = FileTimeText(data.ftLastWriteTime);
        }
    }

    std::wstring detail;
    detail += L"Service      : " + entry.name + L"\r\n";
    detail += L"Display name : " + entry.display + L"\r\n";
    if (!entry.description.empty()) {
        detail += L"Description  : " + entry.description + L"\r\n";
    }
    detail += L"Registry key : " + ServiceRegistryKey(entry.name) + L"\r\n";
    detail += L"Type         : " + entry.typeText + Format(L" (0x%08lX)\r\n", status.dwServiceType);
    detail += L"State        : " + entry.stateText + L"\r\n";
    detail += L"Start type   : " + entry.startText;
    if (!delayedText.empty() && entry.startText == L"auto") {
        detail += L" \u00B7 delayed auto start " + delayedText;
    }
    detail += L"\r\n";
    detail += L"Error control: " + ErrorControlText(errorControl) + L"\r\n";
    detail += L"Controls     : " + ControlsText(status.dwControlsAccepted) + L"\r\n";
    detail += L"Account      : " + entry.account + L"\r\n";
    if (!loadGroup.empty()) detail += L"Load group   : " + loadGroup + L"\r\n";
    if (tagId) detail += Format(L"Tag id       : %lu\r\n", tagId);
    if (status.dwServiceFlags & SERVICE_RUNS_IN_SYSTEM_PROCESS) {
        detail += L"Flags        : runs inside the system process\r\n";
    }
    if (status.dwWin32ExitCode) {
        detail += Format(L"Exit code    : %lu", status.dwWin32ExitCode);
        if (status.dwServiceSpecificExitCode) {
            detail += Format(L" \u00B7 service specific %lu", status.dwServiceSpecificExitCode);
        }
        detail += L"\r\n";
    }
    if (status.dwCheckPoint) {
        detail += Format(L"Checkpoint   : %lu \u00B7 wait hint %lu ms\r\n",
                         status.dwCheckPoint, status.dwWaitHint);
    }

    detail += L"\r\n--- binary ---\r\n";
    detail += L"Image path   : " + (entry.binary.empty() ? L"(not set)" : entry.binary) + L"\r\n";
    if (!dllText.empty()) detail += L"Service DLL  : " + dllText + L"\r\n";
    if (!fileSize.empty()) {
        detail += L"File size    : " + fileSize + L"\r\n";
        detail += L"File modified: " + fileModified + L"\r\n";
    } else if (!entry.binary.empty()) {
        detail += L"File         : not readable\r\n";
    }

    detail += L"\r\n--- process ---\r\n";
    if (entry.pid) {
        detail += Format(L"Process id   : %lu (0x%04lX)\r\n", entry.pid, entry.pid);
        detail += L"Process name : " + (process.name.empty() ? L"(unknown)" : process.name) + L"\r\n";
        if (!process.path.empty()) detail += L"Process path : " + process.path + L"\r\n";
        if (!process.user.empty()) detail += L"Process owner: " + process.user + L"\r\n";
        if (!process.started.empty()) detail += L"Process start: " + process.started + L"\r\n";
        if (!process.cmd.empty()) detail += L"Command line : " + process.cmd + L"\r\n";
    } else {
        detail += L"Process id   : 0 (not running)\r\n";
    }

    detail += L"\r\n--- dependencies ---\r\n";
    detail += L"Depends on   : " + (configText.empty() ? L"(none)" : configText) + L"\r\n";
    detail += L"Dependents   : " + (dependentsText.empty() ? L"(none)" : dependentsText) + L"\r\n";

    detail += L"\r\n--- recovery ---\r\n";
    detail += failureText.empty() ? L"(no failure actions)\r\n" : failureText;
    if (!failureFlagText.empty()) {
        detail += L"Failure actions on non-crash failures: " + failureFlagText + L"\r\n";
    }

    detail += L"\r\n--- hardening ---\r\n";
    detail += L"Service SID  : " + (sidText.empty() ? L"(not reported)" : sidText) + L"\r\n";
    detail += L"Privileges   : " + (privilegesText.empty() ? L"(none required)" : privilegesText) + L"\r\n";
    detail += L"Preshutdown  : " + (preshutdownText.empty() ? L"(not reported)" : preshutdownText) + L"\r\n";
    detail += L"Launch prot. : " + (launchText.empty() ? L"(not reported)" : launchText) + L"\r\n";
    if (!sddlText.empty()) detail += L"Security     : " + sddlText + L"\r\n";

    detail += L"\r\n--- triggers ---\r\n";
    detail += triggerText.empty() ? L"(none)\r\n" : triggerText;

    entry.detail = std::move(detail);
    out.push_back(std::move(entry));
}

void EnumerateType(SC_HANDLE manager, DWORD serviceType,
                   std::vector<ServiceEntry>& out, std::set<std::wstring>& seen,
                   std::atomic<bool>& stop) {
    DWORD needed = 0;
    DWORD returned = 0;
    DWORD resume = 0;
    std::vector<BYTE> buffer(256 * 1024);
    for (;;) {
        if (stop.load()) return;
        BOOL ok = EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, serviceType,
                                        SERVICE_STATE_ALL, buffer.data(),
                                        static_cast<DWORD>(buffer.size()), &needed, &returned,
                                        &resume, nullptr);
        if (!ok) {
            DWORD error = GetLastError();
            if (error == ERROR_MORE_DATA) {
                buffer.resize(needed + 32768);
                continue;
            }
            return;
        }
        auto* items = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());
        for (DWORD i = 0; i < returned; ++i) {
            if (stop.load()) return;
            const wchar_t* name = items[i].lpServiceName;
            if (!name || !name[0]) continue;
            if (!seen.insert(ToLower(name)).second) continue;
            ServiceEntry entry;
            AddService(manager, name, items[i].lpDisplayName, items[i].ServiceStatusProcess,
                       entry, out);
        }
        if (needed <= buffer.size()) break;
        buffer.resize(needed + 32768);
    }
}

}

std::vector<KernelModuleInfo> KernelModules() {
    std::vector<KernelModuleInfo> modules;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return modules;
    using QueryFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    auto query = reinterpret_cast<QueryFn>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!query) return modules;

    std::vector<BYTE> buffer(1 << 20);
    LONG status = -1;
    for (int attempt = 0; attempt < 10; ++attempt) {
        ULONG needed = 0;
        status = query(11, buffer.data(), static_cast<ULONG>(buffer.size()), &needed);
        if (status >= 0) break;
        if (needed > buffer.size()) buffer.resize(needed + 65536);
        else buffer.resize(buffer.size() * 2);
    }
    if (status < 0) return modules;

    struct ModuleInfo {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    };
    struct ModuleList {
        ULONG NumberOfModules;
        ModuleInfo Modules[1];
    };

    auto* list = reinterpret_cast<ModuleList*>(buffer.data());
    modules.reserve(list->NumberOfModules);
    for (ULONG i = 0; i < list->NumberOfModules; ++i) {
        const ModuleInfo& module = list->Modules[i];
        std::string raw(reinterpret_cast<const char*>(module.FullPathName));
        KernelModuleInfo info;
        info.path = ResolveServicePath(Utf8ToWide(raw));
        info.base = reinterpret_cast<unsigned long long>(module.ImageBase);
        info.size = module.ImageSize;
        modules.push_back(std::move(info));
    }
    return modules;
}

std::wstring KernelDriverReport() {
    const std::vector<KernelModuleInfo> modules = KernelModules();
    if (modules.empty()) return L"SystemModuleInformation is not available.";

    std::vector<std::wstring> lines;
    lines.reserve(modules.size());
    for (const KernelModuleInfo& module : modules) {
        std::wstring line = Format(L"0x%016llX  %10s  %s",
                                   module.base, SizeText(module.size).c_str(),
                                   module.path.c_str());
        if (GetFileAttributesW(module.path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            line += L"  (not on disk)";
        }
        lines.push_back(std::move(line));
    }
    std::sort(lines.begin(), lines.end());
    std::wstring text = Format(L"%lu kernel module(s) loaded\r\n\r\n", modules.size());
    text += L"base address           size  path\r\n";
    for (const std::wstring& line : lines) text += line + L"\r\n";
    return text;
}

void RunServiceViewer(const Sink& sink, std::atomic<bool>& stop, ServiceConfig config) {
    sink.Status(L"Opening the service control manager\u2026");

    DWORD access = SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, access);
    if (!manager) {
        sink.Error(Format(L"OpenSCManager failed (%lu). Run as Administrator to read every service.",
                          GetLastError()));
        return;
    }

    std::vector<ServiceEntry> entries;
    std::set<std::wstring> seen;
    EnumerateType(manager, SERVICE_WIN32, entries, seen, stop);
    if (config.drivers) {
        EnumerateType(manager, SERVICE_DRIVER, entries, seen, stop);
    }
    EnumerateType(manager, 0x00000040, entries, seen, stop);
    CloseServiceHandle(manager);

    if (stop.load()) {
        sink.Done(L"Stopped. No service list was produced.");
        return;
    }

    if (config.runningOnly) {
        entries.erase(std::remove_if(entries.begin(), entries.end(), [](const ServiceEntry& entry) {
                          return entry.stateText != L"running";
                      }),
                      entries.end());
    }

    std::sort(entries.begin(), entries.end(), [](const ServiceEntry& a, const ServiceEntry& b) {
        return ToLower(a.name) < ToLower(b.name);
    });

    int running = 0;
    int drivers = 0;
    for (const ServiceEntry& entry : entries) {
        if (entry.stateText == L"running") ++running;
        if (entry.driver) ++drivers;
    }

    std::vector<Row> rows;
    std::vector<std::wstring> details;
    rows.reserve(24);
    details.reserve(24);
    unsigned long long emitted = 0;
    bool first = true;

    auto flush = [&]() {
        if (rows.empty()) return;
        sink.Detailed(std::move(rows), std::move(details), first);
        first = false;
        rows.clear();
        details.clear();
        rows.reserve(24);
        details.reserve(24);
    };

    const size_t total = entries.size();
    for (size_t i = 0; i < total; ++i) {
        if (stop.load()) break;
        const ServiceEntry& entry = entries[i];
        Row row;
        row.reserve(10);
        row.push_back(entry.name);
        row.push_back(entry.display);
        row.push_back(entry.typeText);
        row.push_back(entry.stateText);
        row.push_back(entry.startText);
        row.push_back(entry.account);
        row.push_back(entry.pid ? Format(L"%lu", entry.pid) : L"-");
        row.push_back(entry.processName.empty() ? L"-" : entry.processName);
        row.push_back(entry.binary.empty() ? L"-" : entry.binary);
        row.push_back(entry.description);
        rows.push_back(std::move(row));
        details.push_back(entry.detail);
        ++emitted;
        if (rows.size() >= 24) flush();
        if ((i % 16) == 0 || i + 1 == total) {
            sink.Status(Format(L"Reading service %s/%s \u00B7 %s",
                               CommaNumber(i + 1).c_str(), CommaNumber(total).c_str(),
                               entry.name.c_str()),
                        static_cast<int>((i + 1) * 100 / total));
        }
    }
    flush();

    std::wstring summary = Format(L"%s service(s) \u00B7 %s running \u00B7 %s driver(s)",
                                  CommaNumber(emitted).c_str(),
                                  CommaNumber(running).c_str(),
                                  CommaNumber(drivers).c_str());
    if (stop.load()) summary += L" \u00B7 stopped";
    sink.Done(summary);
}
