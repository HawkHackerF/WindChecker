#pragma once
#include "common.h"

struct CarvedFile {
    std::wstring name;
    std::wstring type;
    std::wstring ext;
    std::wstring source;
    std::wstring origin;
    std::wstring captured;
    std::wstring state;
    std::wstring created;
    std::wstring modified;
    size_t size = 0;
    bool complete = false;
    bool hasData = false;
    std::vector<BYTE> data;
};

std::vector<CarvedFile> CarvedSnapshot();
std::vector<Row> CarvedRows();
std::vector<std::wstring> CarvedDetails();
size_t CarvedCount();
void CarvedClear();

std::vector<std::wstring> CarvedNames();
bool CarvedCopy(const std::wstring& name, CarvedFile& out);

struct CarveSource {
    std::wstring path;
    std::wstring label;
    bool raw = false;
};

struct CarveConfig {
    std::vector<CarveSource> sources;
    uint64_t limitBytes = 1024ull << 20;
};

void RunDiskCarve(const Sink& sink, std::atomic<bool>& stop, CarveConfig config);

size_t CarveIntoStore(const Sink& sink, std::atomic<bool>& stop, const CarveConfig& config,
                      uint64_t& total, bool& stopped);

std::vector<Row> CarvedRows();
std::vector<std::wstring> CarvedDetails();

bool CarvedAddEntry(const std::wstring& name, const std::wstring& type,
                    const std::wstring& source, const std::wstring& state,
                    const std::wstring& created, const std::wstring& modified,
                    uint64_t logicalSize, std::vector<BYTE> data, bool complete);

bool CarvedHasRoom(size_t size);

size_t CarvedMaxFile();
size_t CarvedMaxFiles();

class Carver {
public:

    void FeedTcp(const std::string& flow, uint32_t seq, const BYTE* data, size_t length,
                 const std::wstring& source, const std::wstring& destination);

    void FeedDatagram(const std::string& flow, const BYTE* data, size_t length,
                      const std::wstring& source, const std::wstring& destination);

    void FeedDisk(const std::string& flow, uint32_t seq, const BYTE* data, size_t length,
                  const std::wstring& label);

    void ResetFlow(const std::string& flow);

    void Finalize();
    void Reset();

private:
    struct Flow {
        std::vector<BYTE> buffer;
        uint32_t nextSeq = 0;
        bool haveSeq = false;
        std::wstring source;
        std::wstring origin;
        std::wstring captured;
        size_t scanFrom = 0;
        std::set<size_t> carved;
        std::map<size_t, int> pending;
    };
    std::map<std::string, Flow> flows_;

    std::map<std::string, std::wstring> requests_;
    void Append(Flow& flow, uint32_t seq, const BYTE* data, size_t length);
    void Scan(Flow& flow);
};
