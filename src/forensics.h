#ifndef WINCHECKER_FORENSICS_H
#define WINCHECKER_FORENSICS_H

#include <windows.h>

#include <atomic>
#include <string>
#include <vector>

#include "common.h"

namespace fc {

struct RegView {
    HKEY root = nullptr;
    std::wstring rootLabel = L"HKLM";
    std::wstring prefix = L"";

    bool OpenKey(const std::wstring& subkey, HKEY& out) const;
    std::wstring QueryString(const std::wstring& subkey, const std::wstring& value) const;
    bool QueryBinary(const std::wstring& subkey, const std::wstring& value, std::vector<BYTE>& out) const;
    std::wstring LastWrite(const std::wstring& subkey) const;
    std::vector<std::wstring> Subkeys(const std::wstring& subkey) const;
    std::vector<std::wstring> ValueNames(const std::wstring& subkey) const;
};

RegView LiveHklm();
RegView LiveHkcu();

std::wstring Rot13(const std::wstring& text);
std::vector<int> DecodeMruListEx(const std::vector<BYTE>& data);
std::wstring DecodePidlPath(const std::vector<BYTE>& pidl);
std::wstring SidToAccount(const std::wstring& sid);
std::wstring LeFileTimeText(const BYTE* data, size_t size);
std::wstring LeFileTimeText(const std::vector<BYTE>& data);

void RunUsbHistory(const Sink& sink, std::atomic<bool>& stop, const RegView& view);
void RunBamDam(const Sink& sink, std::atomic<bool>& stop, const RegView& view);
void RunUserAssist(const Sink& sink, std::atomic<bool>& stop, const RegView& view);
void RunRecentDocs(const Sink& sink, std::atomic<bool>& stop, const RegView& view);
void RunMru(const Sink& sink, std::atomic<bool>& stop, const RegView& view);

}

#endif
