#pragma once
#include "common.h"
#include "carve.h"

struct UsnConfig {
    std::vector<std::wstring> volumes;
    unsigned long long limit = 100000;
};

void RunUsnJournal(const Sink& sink, std::atomic<bool>& stop, UsnConfig config);

struct MftConfig {
    std::vector<std::wstring> volumes;
    unsigned long long limit = 250000;
};

void RunMftScan(const Sink& sink, std::atomic<bool>& stop, MftConfig config);

struct MftRecoverConfig {
    std::wstring volume;
    bool deletedOnly = true;
    unsigned long long limitRecords = 0;
};

void RunMftRecover(const Sink& sink, std::atomic<bool>& stop, MftRecoverConfig config);

void RunCarvingScan(const Sink& sink, std::atomic<bool>& stop, CarveConfig carve,
                    MftRecoverConfig mft);

struct EventsConfig {
    std::vector<std::wstring> channels;
    int limitPerChannel = 1000;
};

std::vector<std::wstring> ListEventChannels();
void RunEventLogs(const Sink& sink, std::atomic<bool>& stop, EventsConfig config);

struct EventViewerConfig {
    std::vector<std::wstring> channels;
    std::vector<int> eventIds;      // empty = any event id
    int level = 0;                  // 0 = any, 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose
    std::wstring provider;          // empty = any provider
    int limitPerChannel = 2000;
};

void RunEventViewer(const Sink& sink, std::atomic<bool>& stop, EventViewerConfig config);

struct PrefetchConfig {
    std::wstring folder;
    int maxFiles = 0;
    bool details = true;
    bool recent = true;
};

void RunPrefetchRecent(const Sink& sink, std::atomic<bool>& stop, PrefetchConfig config);

struct StringsConfig {
    std::vector<std::wstring> volumes;
    int minLength = 4;
    unsigned long long limitBytes = 0;
    bool utf16 = true;
    bool ascii = true;
};

void RunDiskStrings(const Sink& sink, std::atomic<bool>& stop, StringsConfig config);

struct PowerShellConfig {
    bool allUsers = true;
    bool systemProfile = true;
};

void RunPowerShellHistory(const Sink& sink, std::atomic<bool>& stop, PowerShellConfig config);

struct ProcessConfig {
    bool modules = true;
    bool services = true;
};

void RunProcessExplorer(const Sink& sink, std::atomic<bool>& stop, ProcessConfig config);

std::wstring KernelDriverReport();

struct KernelModuleInfo {
    std::wstring path;
    unsigned long long base = 0;
    unsigned long size = 0;
};

std::vector<KernelModuleInfo> KernelModules();

struct ServiceConfig {
    bool drivers = true;
    bool runningOnly = false;
};

void RunServiceViewer(const Sink& sink, std::atomic<bool>& stop, ServiceConfig config);

void RunComputerInfo(const Sink& sink, std::atomic<bool>& stop);

void RunSrumExplorer(const Sink& sink, std::atomic<bool>& stop);

void RunAmCacheViewer(const Sink& sink, std::atomic<bool>& stop);

struct PersistenceConfig {
    bool registry = true;
    bool services = true;
    bool tasks = true;
    bool folders = true;
};

void RunPersistenceAudit(const Sink& sink, std::atomic<bool>& stop, PersistenceConfig config);

void RunStartupInventory(const Sink& sink, std::atomic<bool>& stop);

struct ExecConfig {
    bool shimcache = true;
    bool usb = true;
    bool recycle = true;
};

void RunExecutionDevices(const Sink& sink, std::atomic<bool>& stop, ExecConfig config);

struct SignatureConfig {
    bool processes = true;
    bool modules = true;
    bool services = true;
};

void RunSignatureScan(const Sink& sink, std::atomic<bool>& stop, SignatureConfig config);

void RunThumbcacheScan(const Sink& sink, std::atomic<bool>& stop);
bool ReadThumbcacheImage(const std::wstring& cachePath, unsigned long long entryOffset,
                         std::vector<unsigned char>& data);

void RunWmiSubscriptions(const Sink& sink, std::atomic<bool>& stop);
void RunNetworkArtifacts(const Sink& sink, std::atomic<bool>& stop);
void RunDefenderLogs(const Sink& sink, std::atomic<bool>& stop);
void RunActivitiesCache(const Sink& sink, std::atomic<bool>& stop);
void RunCrashDumps(const Sink& sink, std::atomic<bool>& stop);
void RunNotificationDatabase(const Sink& sink, std::atomic<bool>& stop);

struct FileHashConfig {
    std::wstring folder;
    bool recursive = true;
    bool hashContents = true;
    bool verifySignature = true;
};

void RunFileHashScan(const Sink& sink, std::atomic<bool>& stop, FileHashConfig config);

struct ImageMetaConfig {
    std::wstring folder;
    bool recursive = true;
};

void RunImageMetadataScan(const Sink& sink, std::atomic<bool>& stop, ImageMetaConfig config);
