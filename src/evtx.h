#pragma once
#include <windows.h>
#include <winevt.h>

#include <string>
#include <vector>

struct EvtxField {
    std::wstring name;
    std::wstring value;
};

std::wstring EvtxDecode(const std::wstring& text);
std::wstring EvtxAttribute(const std::wstring& xml, const std::wstring& element,
                           const std::wstring& attribute);
std::wstring EvtxElement(const std::wstring& xml, const std::wstring& element);
std::wstring EvtxDataText(const std::wstring& xml);
std::wstring EvtxStamp(const std::wstring& xml);
std::vector<EvtxField> EvtxDataFields(const std::wstring& xml);
std::wstring EvtxFullDetail(const std::wstring& xml);
bool EvtxRender(EVT_HANDLE event, std::wstring& xml);
