#include "network.h"

#include <algorithm>

namespace {

std::wstring TcpStateText(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_CLOSED: return L"CLOSED";
    case MIB_TCP_STATE_LISTEN: return L"LISTENING";
    case MIB_TCP_STATE_SYN_SENT: return L"SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD: return L"SYN_RECEIVED";
    case MIB_TCP_STATE_ESTAB: return L"ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1: return L"FIN_WAIT_1";
    case MIB_TCP_STATE_FIN_WAIT2: return L"FIN_WAIT_2";
    case MIB_TCP_STATE_CLOSE_WAIT: return L"CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING: return L"CLOSING";
    case MIB_TCP_STATE_LAST_ACK: return L"LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT: return L"TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB: return L"DELETE_TCB";
    default: return Format(L"%lu", state);
    }
}

std::wstring NetStateText(DWORD state) {
    switch (state) {
    case NlnsReachable: return L"Reachable";
    case NlnsStale: return L"Stale";
    case NlnsDelay: return L"Delay";
    case NlnsProbe: return L"Probe";
    case NlnsPermanent: return L"Permanent";
    default: return L"Unreachable";
    }
}

std::wstring MacText(const BYTE* address, size_t length) {
    std::wstring text;
    for (size_t i = 0; i < length && i < 8; ++i) {
        if (!text.empty()) text += L"-";
        text += Format(L"%02x", address[i]);
    }
    return text.empty() ? L"-" : text;
}

std::wstring Join(const std::vector<std::wstring>& parts) {
    std::wstring text;
    for (const auto& part : parts) {
        if (part.empty()) continue;
        if (!text.empty()) text += L",";
        text += part;
    }
    return text;
}

std::wstring SockaddrText(const SOCKADDR* address) {
    if (!address) return L"";
    wchar_t text[INET6_ADDRSTRLEN] = {};
    if (address->sa_family == AF_INET) {
        InetNtopW(AF_INET, &reinterpret_cast<const sockaddr_in*>(address)->sin_addr, text, INET6_ADDRSTRLEN);
    } else if (address->sa_family == AF_INET6) {
        InetNtopW(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr, text, INET6_ADDRSTRLEN);
    }
    return text;
}

std::wstring UdpEndpoint(const SOCKADDR_INET& address, DWORD port) {
    if (address.si_family == AF_INET) {
        IN_ADDR v4{};
        v4.S_un.S_addr = address.Ipv4.sin_addr.S_un.S_addr;
        return Format(L"%s:%u", IpText(reinterpret_cast<const BYTE*>(&v4), AF_INET).c_str(), ntohs(static_cast<u_short>(port)));
    }
    if (address.si_family == AF_INET6) {
        return Format(L"[%s]:%u", IpText(address.Ipv6.sin6_addr.u.Byte, AF_INET6).c_str(), ntohs(static_cast<u_short>(port)));
    }
    return L"*:*";
}

bool DuplicateInterface(const std::wstring& name) {
    static const wchar_t* tags[] = {
        L"LightWeight Filter", L"Packet Driver", L"QoS Packet Scheduler",
        L"Native WiFi Filter", L"Virtual WiFi Filter", L"-WFP"
    };
    for (const wchar_t* tag : tags) if (name.find(tag) != std::wstring::npos) return true;
    return false;
}

std::wstring DetailJoin(const std::vector<std::wstring>& parts) {
    std::wstring text;
    for (const auto& part : parts) {
        if (part.empty()) continue;
        if (!text.empty()) text += L" \u00B7 ";
        text += part;
    }
    return text;
}

}

NetSnapshot NetworkCollector::Collect() {
    NetSnapshot snapshot;
    auto now = std::chrono::steady_clock::now();
    bool heavy = heavyAt_.time_since_epoch().count() == 0 ||
                 std::chrono::duration_cast<std::chrono::seconds>(now - heavyAt_).count() >= 8;
    if (heavy) {
        if (config_.dns) dnsCache_ = GetDnsCache();
        if (config_.arp) {
            arpCache_.clear();
            PMIB_IPNET_TABLE2 table = nullptr;
            if (GetIpNetTable2(AF_UNSPEC, &table) == NO_ERROR && table) {
                for (ULONG i = 0; i < table->NumEntries; ++i) {
                    const MIB_IPNET_ROW2& row = table->Table[i];
                    ArpEntry entry;
                    entry.ip = SockaddrText(reinterpret_cast<const SOCKADDR*>(&row.Address));
                    entry.mac = MacText(row.PhysicalAddress, row.PhysicalAddressLength);
                    entry.state = NetStateText(row.State);
                    if (!entry.ip.empty()) arpCache_.push_back(std::move(entry));
                }
                FreeMibTable(table);
            }
        }
        heavyAt_ = now;
    }

    std::unordered_map<std::wstring, std::wstring> dnsMap;
    for (const auto& entry : dnsCache_) {
        if (!entry.data.empty() && !dnsMap.count(entry.data)) dnsMap[entry.data] = entry.name;
    }

    std::wstring stamp = NowStamp();
    auto names = SnapshotProcessNames();
    auto addConnectionDetail = [&](std::vector<std::wstring>& detail, const std::wstring& remoteIp, bool publicLookup,
                                   USHORT remotePort, DWORD pid, const std::wstring& procLabel) {
        if (!detail.empty()) return;
        if (!remoteIp.empty() && remoteIp != L"*" && remoteIp != L"0.0.0.0" && remoteIp != L"::") {
            auto cached = dnsMap.find(remoteIp);
            if (cached != dnsMap.end() && !cached->second.empty()) detail.push_back(cached->second);
            if (config_.full) {
                std::wstring reverse = ReverseName(WideToUtf8(remoteIp));
                if (!reverse.empty() && (cached == dnsMap.end() || cached->second != reverse)) detail.push_back(reverse);
                std::wstring asn = AsnInfo(WideToUtf8(remoteIp));
                if (!asn.empty()) detail.push_back(asn);
                RequestReverse(WideToUtf8(remoteIp));
                RequestAsn(WideToUtf8(remoteIp));
            }
        }
        if (config_.full) {
            std::wstring service = PortService(remotePort);
            if (!service.empty()) detail.push_back(service);
            ProcInfo info = GetProcInfo(pid);
            if (!info.path.empty()) detail.push_back(info.path);
            if (!info.user.empty()) detail.push_back(info.user);
            if (!info.cmd.empty()) detail.push_back(info.cmd.substr(0, 300));
            if (!info.started.empty()) detail.push_back(L"started " + info.started);
        }
        (void)procLabel;
        (void)publicLookup;
    };

    if (config_.tcp) {
        auto collect = [&](ULONG family, auto tableType, auto rowCast, auto localEndpoint, auto remoteEndpoint, auto stateOf, auto pidOf) {
            DWORD size = 0;
            GetExtendedTcpTable(nullptr, &size, FALSE, family, tableType, 0);
            if (!size) return;
            std::vector<BYTE> buffer(size);
            if (GetExtendedTcpTable(buffer.data(), &size, FALSE, family, tableType, 0) != NO_ERROR) return;
            auto* table = reinterpret_cast<decltype(rowCast(buffer.data()))>(buffer.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& row = table->table[i];
                std::wstring local = localEndpoint(row);
                std::wstring remote = remoteEndpoint(row);
                DWORD pid = pidOf(row);
                std::wstring proc = names.count(pid) ? names[pid] : L"";
                std::wstring label = proc.empty() ? Format(L"PID %lu", pid) : Format(L"%s (%lu)", proc.c_str(), pid);
                std::vector<std::wstring> detail;
                std::wstring remoteIp = remote;
                size_t colon = remote.rfind(L':');
                USHORT port = 0;
                if (colon != std::wstring::npos) {
                    remoteIp = remote.substr(0, colon);
                    port = static_cast<USHORT>(_wtoi(remote.substr(colon + 1).c_str()));
                }
                if (remoteIp.size() > 2 && remoteIp.front() == L'[') remoteIp = remoteIp.substr(1, remoteIp.size() - 2);
                addConnectionDetail(detail, remoteIp, true, port, pid, label);
                snapshot.rows.push_back({stamp, L"TCP", local, remote, stateOf(row), label, DetailJoin(detail)});
            }
        };
        collect(AF_INET, TCP_TABLE_OWNER_PID_ALL,
                [](BYTE* data) { return reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(data); },
                [](const MIB_TCPROW_OWNER_PID& row) {
                    SOCKADDR_INET address{};
                    address.si_family = AF_INET;
                    address.Ipv4.sin_addr.S_un.S_addr = row.dwLocalAddr;
                    return EndpointText(address, ntohs(static_cast<u_short>(row.dwLocalPort)));
                },
                [](const MIB_TCPROW_OWNER_PID& row) {
                    SOCKADDR_INET address{};
                    address.si_family = AF_INET;
                    address.Ipv4.sin_addr.S_un.S_addr = row.dwRemoteAddr;
                    return EndpointText(address, ntohs(static_cast<u_short>(row.dwRemotePort)));
                },
                [](const MIB_TCPROW_OWNER_PID& row) { return TcpStateText(row.dwState); },
                [](const MIB_TCPROW_OWNER_PID& row) { return row.dwOwningPid; });
        collect(AF_INET6, TCP_TABLE_OWNER_PID_ALL,
                [](BYTE* data) { return reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(data); },
                [](const MIB_TCP6ROW_OWNER_PID& row) {
                    SOCKADDR_INET address{};
                    address.si_family = AF_INET6;
                    memcpy(address.Ipv6.sin6_addr.u.Byte, row.ucLocalAddr, 16);
                    return EndpointText(address, ntohs(static_cast<u_short>(row.dwLocalPort)));
                },
                [](const MIB_TCP6ROW_OWNER_PID& row) {
                    SOCKADDR_INET address{};
                    address.si_family = AF_INET6;
                    memcpy(address.Ipv6.sin6_addr.u.Byte, row.ucRemoteAddr, 16);
                    return EndpointText(address, ntohs(static_cast<u_short>(row.dwRemotePort)));
                },
                [](const MIB_TCP6ROW_OWNER_PID& row) { return TcpStateText(row.dwState); },
                [](const MIB_TCP6ROW_OWNER_PID& row) { return row.dwOwningPid; });
    }

    if (config_.udp) {
        auto collect = [&](ULONG family, auto tableType, auto rowCast, auto rowLocal, auto rowPid) {
            DWORD size = 0;
            GetExtendedUdpTable(nullptr, &size, FALSE, family, tableType, 0);
            if (!size) return;
            std::vector<BYTE> buffer(size);
            if (GetExtendedUdpTable(buffer.data(), &size, FALSE, family, tableType, 0) != NO_ERROR) return;
            auto* table = reinterpret_cast<decltype(rowCast(buffer.data()))>(buffer.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& row = table->table[i];
                std::wstring local = rowLocal(row);
                DWORD pid = rowPid(row);
                std::wstring proc = names.count(pid) ? names[pid] : L"";
                std::wstring label = proc.empty() ? Format(L"PID %lu", pid) : Format(L"%s (%lu)", proc.c_str(), pid);
                std::vector<std::wstring> detail;
                if (config_.full) {
                    ProcInfo info = GetProcInfo(pid);
                    if (!info.path.empty()) detail.push_back(info.path);
                    if (!info.user.empty()) detail.push_back(info.user);
                    if (!info.cmd.empty()) detail.push_back(info.cmd.substr(0, 300));
                    if (!info.started.empty()) detail.push_back(L"started " + info.started);
                }
                snapshot.rows.push_back({stamp, L"UDP", local, L"*:*", L"Bound", label, DetailJoin(detail)});
            }
        };
        collect(AF_INET, UDP_TABLE_OWNER_PID,
                [](BYTE* data) { return reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(data); },
                [](const MIB_UDPROW_OWNER_PID& row) {
                    SOCKADDR_INET address{};
                    address.si_family = AF_INET;
                    address.Ipv4.sin_addr.S_un.S_addr = row.dwLocalAddr;
                    return UdpEndpoint(address, row.dwLocalPort);
                },
                [](const MIB_UDPROW_OWNER_PID& row) { return row.dwOwningPid; });
        collect(AF_INET6, UDP_TABLE_OWNER_PID,
                [](BYTE* data) { return reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(data); },
                [](const MIB_UDP6ROW_OWNER_PID& row) {
                    SOCKADDR_INET address{};
                    address.si_family = AF_INET6;
                    memcpy(address.Ipv6.sin6_addr.u.Byte, row.ucLocalAddr, 16);
                    return UdpEndpoint(address, row.dwLocalPort);
                },
                [](const MIB_UDP6ROW_OWNER_PID& row) { return row.dwOwningPid; });
    }

    if (config_.dns) {
        for (const auto& entry : dnsCache_) {
            std::wstring type;
            switch (entry.type) {
            case DNS_TYPE_A: type = L"A"; break;
            case DNS_TYPE_AAAA: type = L"AAAA"; break;
            case DNS_TYPE_CNAME: type = L"CNAME"; break;
            case DNS_TYPE_PTR: type = L"PTR"; break;
            case DNS_TYPE_NS: type = L"NS"; break;
            case DNS_TYPE_MX: type = L"MX"; break;
            case DNS_TYPE_SRV: type = L"SRV"; break;
            case DNS_TYPE_TEXT: type = L"TXT"; break;
            default: type = Format(L"%u", entry.type); break;
            }
            snapshot.rows.push_back({stamp, L"DNS", entry.name, entry.data, L"Cached", L"",
                                     Format(L"%s \u00B7 TTL %us", type.c_str(), entry.ttl)});
        }
    }

    if (config_.arp) {
        for (const auto& entry : arpCache_) {
            std::wstring detail;
            if (config_.full) {
                detail = ReverseName(WideToUtf8(entry.ip));
                if (detail.empty() && IsPublicIp(WideToUtf8(entry.ip))) detail = AsnInfo(WideToUtf8(entry.ip));
                RequestReverse(WideToUtf8(entry.ip));
                RequestAsn(WideToUtf8(entry.ip));
            }
            snapshot.rows.push_back({stamp, L"ARP", entry.ip, entry.mac, entry.state, L"", detail});
        }
    }

    if (config_.adapters) {
        ULONG size = 16 * 1024;
        std::unique_ptr<BYTE[]> buffer(new BYTE[size]);
        ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS;
        ULONG result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get()), &size);
        if (result == ERROR_BUFFER_OVERFLOW) {
            buffer.reset(new BYTE[size]);
            result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                          reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get()), &size);
        }
        if (result == NO_ERROR) {
            for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get()); adapter; adapter = adapter->Next) {
                std::vector<std::wstring> v4, v6;
                for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
                    std::wstring address = SockaddrText(unicast->Address.lpSockaddr);
                    if (address.empty()) continue;
                    if (unicast->Address.lpSockaddr->sa_family == AF_INET) v4.push_back(address);
                    else v6.push_back(address);
                }
                std::vector<std::wstring> gateway, dns;
                for (auto* gw = adapter->FirstGatewayAddress; gw; gw = gw->Next) {
                    std::wstring address = SockaddrText(gw->Address.lpSockaddr);
                    if (!address.empty()) gateway.push_back(address);
                }
                for (auto* server = adapter->FirstDnsServerAddress; server; server = server->Next) {
                    std::wstring address = SockaddrText(server->Address.lpSockaddr);
                    if (!address.empty()) dns.push_back(address);
                }
                std::wstring status = adapter->OperStatus == IfOperStatusUp ? L"Up" : L"Disconnected";
                std::wstring mac = MacText(adapter->PhysicalAddress, adapter->PhysicalAddressLength);
                std::wstring detail = Format(L"GW %s \u00B7 DNS %s \u00B7 MAC %s",
                                             gateway.empty() ? L"-" : Join(gateway).c_str(),
                                             dns.empty() ? L"-" : Join(dns).c_str(),
                                             mac.c_str());
                if (!v6.empty()) detail += L" \u00B7 IPv6 " + Join(v6);
                snapshot.rows.push_back({stamp, L"Interface", adapter->FriendlyName, Join(v4), status,
                                         adapter->Description, detail});
            }
        }
    }

    if (config_.traffic) {
        PMIB_IF_TABLE2 table = nullptr;
        if (GetIfTable2(&table) == NO_ERROR && table) {
            auto now2 = std::chrono::steady_clock::now();
            double window = previousAt_.time_since_epoch().count() ? std::chrono::duration<double>(now2 - previousAt_).count()
                                                                   : config_.interval;
            if (window <= 0.0) window = config_.interval;
            for (ULONG i = 0; i < table->NumEntries; ++i) {
                const MIB_IF_ROW2& row = table->Table[i];
                std::wstring name = row.Description;
                if (name.empty()) name = row.Alias;
                if (DuplicateInterface(name)) continue;
                bool up = row.OperStatus == IfOperStatusUp;
                if (!up && !row.InOctets && !row.OutOctets) continue;
                uint64_t key = static_cast<uint64_t>(row.InterfaceLuid.Value);
                auto found = previousTraffic_.find(key);
                std::wstring rate;
                if (found == previousTraffic_.end()) {
                    rate = config_.realtime ? L"measuring\u2026" : L"\u2014";
                } else {
                    uint64_t inDelta = row.InOctets - found->second.first;
                    uint64_t outDelta = row.OutOctets - found->second.second;
                    double inRate = static_cast<double>(inDelta) / window;
                    double outRate = static_cast<double>(outDelta) / window;
                    snapshot.inRate += inRate;
                    snapshot.outRate += outRate;
                    rate = Format(L"In %s/s \u00B7 Out %s/s", SizeText(static_cast<unsigned long long>(inRate)).c_str(),
                                  SizeText(static_cast<unsigned long long>(outRate)).c_str());
                }
                previousTraffic_[key] = {row.InOctets, row.OutOctets};
                snapshot.rows.push_back({stamp, L"Traffic", name, rate, up ? L"Up" : L"Down", L"",
                                         Format(L"Total received %s \u00B7 sent %s",
                                                SizeText(row.InOctets).c_str(), SizeText(row.OutOctets).c_str())});
            }
            previousAt_ = now2;
            FreeMibTable(table);
        }
    }
    return snapshot;
}
