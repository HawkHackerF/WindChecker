#include "artifacts.h"

#include <algorithm>
#include <map>

namespace {

std::wstring NormalizePath(const std::wstring& raw) {
    std::wstring path = Trim(raw);
    if (path.size() > 4 && path.compare(0, 4, L"\\??\\") == 0) {
        path = path.substr(4);
    } else if (path.size() > 12 && _wcsnicmp(path.c_str(), L"\\SystemRoot\\", 12) == 0) {
        wchar_t root[MAX_PATH] = {};
        GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
        path = std::wstring(root[0] ? root : L"C:\\Windows") + L"\\" + path.substr(12);
    } else if (_wcsnicmp(path.c_str(), L"System32\\", 9) == 0) {
        wchar_t root[MAX_PATH] = {};
        GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
        path = std::wstring(root[0] ? root : L"C:\\Windows") + L"\\" + path;
    }
    if (!path.empty() && path[0] == L'"') {
        size_t close = path.find(L'"', 1);
        path = close == std::wstring::npos ? path.substr(1) : path.substr(1, close - 1);
    }
    return path;
}

std::wstring ImageFromCommand(const std::wstring& command) {
    std::wstring text = NormalizePath(command);
    if (text.empty()) return L"";
    std::wstring lower = ToLower(text);
    size_t exe = lower.find(L".exe");
    if (exe == std::wstring::npos) exe = lower.find(L".sys");
    if (exe == std::wstring::npos) exe = lower.find(L".dll");
    if (exe != std::wstring::npos) return text.substr(0, exe + 4);
    size_t space = text.find(L' ');
    return space == std::wstring::npos ? text : text.substr(0, space);
}

void AddProcessImages(std::map<std::wstring, std::wstring>& targets, std::atomic<bool>& stop) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (stop.load()) break;
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
            if (!process) continue;
            wchar_t path[1024] = {};
            DWORD size = 1024;
            if (QueryFullProcessImageNameW(process, 0, path, &size) && path[0]) {
                std::wstring lower = ToLower(path);
                targets.emplace(lower, path);
            }
            CloseHandle(process);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

void AddModules(std::map<std::wstring, std::wstring>& targets, std::atomic<bool>& stop) {
    HANDLE processes = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processes == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(processes, &entry)) {
        do {
            if (stop.load()) break;
            HANDLE modules = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                      entry.th32ProcessID);
            if (modules == INVALID_HANDLE_VALUE) continue;
            MODULEENTRY32W module{};
            module.dwSize = sizeof(module);
            if (Module32FirstW(modules, &module)) {
                do {
                    if (!module.szExePath[0]) continue;
                    std::wstring lower = ToLower(module.szExePath);
                    targets.emplace(lower, module.szExePath);
                } while (Module32NextW(modules, &module));
            }
            CloseHandle(modules);
        } while (Process32NextW(processes, &entry));
    }
    CloseHandle(processes);
}

void AddServiceImages(std::map<std::wstring, std::wstring>& targets, DWORD serviceType,
                      std::atomic<bool>& stop) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!manager) return;
    DWORD needed = 0;
    DWORD returned = 0;
    DWORD resume = 0;
    std::vector<BYTE> buffer(128 * 1024);
    for (;;) {
        if (stop.load()) break;
        BOOL ok = EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, serviceType, SERVICE_STATE_ALL,
                                        buffer.data(), static_cast<DWORD>(buffer.size()), &needed,
                                        &returned, &resume, nullptr);
        if (!ok) {
            if (GetLastError() == ERROR_MORE_DATA) {
                buffer.resize(needed + 16384);
                continue;
            }
            break;
        }
        auto* items = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());
        for (DWORD i = 0; i < returned; ++i) {
            SC_HANDLE service = OpenServiceW(manager, items[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (!service) continue;
            DWORD size = 0;
            QueryServiceConfigW(service, nullptr, 0, &size);
            std::vector<BYTE> config(size ? size : 8192);
            auto* info = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data());
            if (QueryServiceConfigW(service, info, static_cast<DWORD>(config.size()), &size) &&
                info->lpBinaryPathName) {
                std::wstring image = ImageFromCommand(info->lpBinaryPathName);
                if (!image.empty()) {
                    std::wstring lower = ToLower(image);
                    targets.emplace(lower, image);
                }
            }
            CloseServiceHandle(service);
        }
        if (needed <= buffer.size()) break;
        buffer.resize(needed + 16384);
    }
    CloseServiceHandle(manager);
}

int RankOf(const SignatureInfo& info) {
    if (!info.valid) return 0;
    if (info.selfSigned) return 1;
    return 2;
}

std::wstring ShortStatus(const SignatureInfo& info) {
    if (info.valid) return info.selfSigned ? L"valid (self-signed)" : L"valid";
    if (info.status == L"no signature") return L"unsigned";
    return info.status;
}

Row RowForSignature(const SignatureInfo& info, const std::wstring& path) {
    Row row;
    row.reserve(8);
    row.push_back(ShortStatus(info));
    row.push_back(PathFileName(path));
    row.push_back(info.signer.empty() ? L"-" : info.signer);
    row.push_back(info.issuer.empty() ? L"-" : info.issuer);
    row.push_back(info.selfSigned ? L"yes" : L"no");
    row.push_back(info.notAfter.empty() ? L"-" : info.notAfter);
    row.push_back(info.certificateLocation.empty() ? L"-" : info.certificateLocation);
    row.push_back(path);
    return row;
}

}

void RunSignatureScan(const Sink& sink, std::atomic<bool>& stop, SignatureConfig config) {
    std::map<std::wstring, std::wstring> targets;

    if (config.processes) {
        sink.Status(L"Collecting running process images\u2026");
        AddProcessImages(targets, stop);
    }
    if (config.modules && !stop.load()) {
        sink.Status(L"Collecting loaded modules\u2026");
        AddModules(targets, stop);
    }
    if (config.services && !stop.load()) {
        sink.Status(L"Collecting service and driver images\u2026");
        AddServiceImages(targets, SERVICE_WIN32, stop);
        AddServiceImages(targets, SERVICE_DRIVER, stop);
    }

    for (auto it = targets.begin(); it != targets.end();) {
        if (GetFileAttributesW(it->second.c_str()) == INVALID_FILE_ATTRIBUTES) {
            it = targets.erase(it);
        } else {
            ++it;
        }
    }

    if (stop.load()) {
        sink.Done(L"Stopped. Signature scan was cancelled.");
        return;
    }
    if (targets.empty()) {
        sink.Done(L"Completed. No file was selected for signature verification.");
        return;
    }

    struct Verified {
        SignatureInfo info;
        std::wstring path;
    };

    std::vector<std::pair<std::wstring, std::wstring>> entries(targets.begin(), targets.end());
    std::vector<Verified> results(entries.size());

    unsigned threads = std::thread::hardware_concurrency();
    if (threads == 0) threads = 4;
    if (threads > 12) threads = 12;
    if (threads > entries.size()) threads = static_cast<unsigned>(entries.size());

    std::atomic<size_t> next{0};
    std::atomic<size_t> done{0};
    std::atomic<size_t> alive{threads};
    std::mutex completedMutex;
    std::vector<size_t> completed;

    bool firstBatch = true;
    auto emit = [&](const std::vector<size_t>& indexes) {
        if (indexes.empty()) return;
        std::vector<Row> rows;
        std::vector<std::wstring> details;
        rows.reserve(indexes.size());
        details.reserve(indexes.size());
        for (size_t index : indexes) {
            const Verified& item = results[index];
            if (item.path.empty()) continue;
            rows.push_back(RowForSignature(item.info, item.path));
            details.push_back(SignatureReportText(item.info, item.path));
        }
        if (rows.empty()) return;
        sink.Detailed(std::move(rows), std::move(details), firstBatch);
        firstBatch = false;
    };

    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (unsigned t = 0; t < threads; ++t) {
        pool.emplace_back([&]() {
            for (;;) {
                if (stop.load()) break;
                size_t index = next.fetch_add(1);
                if (index >= entries.size()) break;
                results[index].info = GetSignatureInfo(entries[index].second);
                results[index].path = entries[index].second;
                done.fetch_add(1);
                {
                    std::lock_guard<std::mutex> lock(completedMutex);
                    completed.push_back(index);
                }
            }
            alive.fetch_sub(1);
        });
    }

    while (alive.load() != 0) {
        std::vector<size_t> ready;
        {
            std::lock_guard<std::mutex> lock(completedMutex);
            ready.swap(completed);
        }
        emit(ready);
        size_t finished = done.load();
        sink.Status(Format(L"Verifying %s/%s \u00B7 %s", CommaNumber(finished).c_str(),
                           CommaNumber(entries.size()).c_str(),
                           finished < entries.size() ? PathFileName(entries[finished].second).c_str() : L"\u2026"),
                    entries.empty() ? 0 : static_cast<int>(finished * 100 / entries.size()));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    for (std::thread& worker : pool) {
        if (worker.joinable()) worker.join();
    }
    {
        std::vector<size_t> ready;
        {
            std::lock_guard<std::mutex> lock(completedMutex);
            ready.swap(completed);
        }
        emit(ready);
    }

    std::vector<size_t> verified;
    verified.reserve(results.size());
    unsigned long long unsignedCount = 0;
    unsigned long long selfSignedCount = 0;
    for (size_t i = 0; i < results.size(); ++i) {
        if (results[i].path.empty()) continue;
        verified.push_back(i);
        if (!results[i].info.valid) ++unsignedCount;
        if (results[i].info.selfSigned) ++selfSignedCount;
    }

    if (verified.empty()) {
        sink.Done(L"Stopped. Signature scan was cancelled.");
        return;
    }
    if (stop.load()) {
        sink.Done(Format(L"Stopped. %s file(s) verified.", CommaNumber(verified.size()).c_str()));
        return;
    }

    std::stable_sort(verified.begin(), verified.end(), [&](size_t left, size_t right) {
        int a = RankOf(results[left].info);
        int b = RankOf(results[right].info);
        if (a != b) return a < b;
        return _wcsicmp(PathFileName(results[left].path).c_str(),
                        PathFileName(results[right].path).c_str()) < 0;
    });

    std::vector<Row> rows;
    std::vector<std::wstring> details;
    rows.reserve(verified.size());
    details.reserve(verified.size());
    for (size_t index : verified) {
        rows.push_back(RowForSignature(results[index].info, results[index].path));
        details.push_back(SignatureReportText(results[index].info, results[index].path));
    }
    sink.Detailed(std::move(rows), std::move(details), true);

    sink.Done(Format(L"Completed. %s file(s) verified \u00B7 %s unsigned or invalid \u00B7 %s self-signed",
                     CommaNumber(verified.size()).c_str(), CommaNumber(unsignedCount).c_str(),
                     CommaNumber(selfSignedCount).c_str()));
}
