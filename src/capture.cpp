#include "capture.h"

#include <mstcpip.h>

#include <algorithm>

namespace {

constexpr size_t kMaxPacket = 65535;

std::wstring TlsSni(const BYTE* data, size_t length) {
    if (length < 43 || data[0] != 0x16 || data[5] != 0x01) return L"";
    size_t index = 9 + 2 + 32;
    if (index >= length) return L"";
    index += 1 + data[index];
    if (index + 2 > length) return L"";
    index += 2 + ((data[index] << 8) | data[index + 1]);
    if (index >= length) return L"";
    index += 1 + data[index];
    if (index + 2 > length) return L"";
    size_t total = (data[index] << 8) | data[index + 1];
    index += 2;
    size_t end = std::min(length, index + total);
    while (index + 4 <= end) {
        unsigned kind = (data[index] << 8) | data[index + 1];
        size_t size = (data[index + 2] << 8) | data[index + 3];
        index += 4;
        if (kind == 0) {
            size_t pos = index + 2;
            while (pos + 3 <= index + size) {
                unsigned type = data[pos];
                size_t nameLength = (data[pos + 1] << 8) | data[pos + 2];
                pos += 3;
                if (type == 0 && pos + nameLength <= length) {
                    return Utf8ToWide(std::string(reinterpret_cast<const char*>(data + pos), nameLength));
                }
                pos += nameLength;
            }
            return L"";
        }
        index += size;
    }
    return L"";
}

std::wstring HexText(const BYTE* data, size_t length, size_t limit = 32) {
    std::wstring text = Format(L"binary %llu B \u00B7 ", static_cast<unsigned long long>(length));
    size_t count = std::min(length, limit);
    for (size_t i = 0; i < count; ++i) {
        if (i) text += L" ";
        text += Format(L"%02x", data[i]);
    }
    return text;
}

std::wstring HexDump(const BYTE* data, size_t length, size_t limit) {
    std::wstring text;
    size_t count = std::min(length, limit);
    for (size_t offset = 0; offset < count; offset += 16) {
        text += Format(L"%08llX  ", static_cast<unsigned long long>(offset));
        size_t line = std::min<size_t>(16, count - offset);
        for (size_t i = 0; i < 16; ++i) {
            if (i < line) text += Format(L"%02X ", data[offset + i]);
            else text += L"   ";
        }
        text += L" ";
        for (size_t i = 0; i < line; ++i) {
            BYTE value = data[offset + i];
            text.push_back(value >= 0x20 && value < 0x7F ? static_cast<wchar_t>(value) : L'.');
        }
        text += L"\n";
    }
    if (count < length) {
        text += Format(L"... %s more bytes\n", CommaNumber(length - count).c_str());
    }
    return text;
}

std::wstring PayloadPreview(const BYTE* data, size_t length) {
    if (!data || !length) return L"";
    size_t sample = std::min<size_t>(length, 400);
    int wideLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                         reinterpret_cast<const char*>(data), static_cast<int>(sample), nullptr, 0);
    if (wideLength <= 0) return HexText(data, length);
    std::wstring text(static_cast<size_t>(wideLength), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                        reinterpret_cast<const char*>(data), static_cast<int>(sample), text.data(), wideLength);
    size_t printable = 0;
    for (wchar_t ch : text) {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t' || (ch >= 0x20 && ch != 0x7F)) ++printable;
    }
    if (printable * 10 < text.size() * 9) return HexText(data, length);
    std::wstring clean;
    bool space = false;
    for (wchar_t ch : text) {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t' || ch == L' ') {
            space = true;
            continue;
        }
        if (ch < 0x20 || ch == 0x7F) continue;
        if (space && !clean.empty()) clean.push_back(L' ');
        space = false;
        clean.push_back(ch);
    }
    if (clean.size() > 320) clean.resize(320);
    return clean.empty() ? HexText(data, length) : clean;
}

std::wstring DnsQuestion(const BYTE* data, size_t length, uint16_t& qtype, bool& response) {
    if (length < 12) return L"";
    response = (data[2] & 0x80) != 0;
    if (((data[4] << 8) | data[5]) == 0) return L"";
    size_t pos = 12;
    std::wstring name;
    while (pos < length) {
        BYTE label = data[pos++];
        if (!label) break;
        if ((label & 0xC0) == 0xC0) { ++pos; break; }
        if (pos + label > length) return L"";
        name += Utf8ToWide(std::string(reinterpret_cast<const char*>(data + pos), label));
        pos += label;
        name += L".";
    }
    if (!name.empty() && name.back() == L'.') name.pop_back();
    qtype = (pos + 2 <= length) ? static_cast<uint16_t>((data[pos] << 8) | data[pos + 1]) : 0;
    return name;
}

std::wstring DnsTypeText(uint16_t type) {
    switch (type) {
    case 1: return L"A";
    case 2: return L"NS";
    case 5: return L"CNAME";
    case 6: return L"SOA";
    case 12: return L"PTR";
    case 15: return L"MX";
    case 16: return L"TXT";
    case 28: return L"AAAA";
    case 33: return L"SRV";
    case 65: return L"HTTPS";
    default: return Format(L"%u", type);
    }
}

std::wstring IcmpText(BYTE type) {
    switch (type) {
    case 0: return L"echo reply";
    case 3: return L"destination unreachable";
    case 4: return L"source quench";
    case 5: return L"redirect";
    case 8: return L"echo request";
    case 9: return L"router advertisement";
    case 10: return L"router solicitation";
    case 11: return L"time exceeded";
    case 12: return L"parameter problem";
    case 13: return L"timestamp request";
    case 14: return L"timestamp reply";
    default: return Format(L"type %u", type);
    }
}

std::wstring IpProtocolText(int protocol) {
    switch (protocol) {
    case 1: return L"ICMP";
    case 2: return L"IGMP";
    case 6: return L"TCP";
    case 17: return L"UDP";
    case 47: return L"GRE";
    case 50: return L"ESP";
    case 51: return L"AH";
    case 89: return L"OSPF";
    case 132: return L"SCTP";
    default: return Format(L"IP %d", protocol);
    }
}

struct PortTable {
    std::map<std::pair<int, USHORT>, DWORD> entries;
    std::chrono::steady_clock::time_point at{};

    void Refresh() {
        entries.clear();
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size) {
            std::vector<BYTE> buffer(size);
            if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i)
                    entries[{0, ntohs(static_cast<u_short>(table->table[i].dwLocalPort))}] = table->table[i].dwOwningPid;
            }
        }
        size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size) {
            std::vector<BYTE> buffer(size);
            if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                auto* table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i)
                    entries[{0, ntohs(static_cast<u_short>(table->table[i].dwLocalPort))}] = table->table[i].dwOwningPid;
            }
        }
        size = 0;
        GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (size) {
            std::vector<BYTE> buffer(size);
            if (GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i)
                    entries[{1, ntohs(static_cast<u_short>(table->table[i].dwLocalPort))}] = table->table[i].dwOwningPid;
            }
        }
        size = 0;
        GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        if (size) {
            std::vector<BYTE> buffer(size);
            if (GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                auto* table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i)
                    entries[{1, ntohs(static_cast<u_short>(table->table[i].dwLocalPort))}] = table->table[i].dwOwningPid;
            }
        }
        at = std::chrono::steady_clock::now();
    }

    DWORD Find(int proto, USHORT port) {
        auto found = entries.find({proto, port});
        return found == entries.end() ? 0 : found->second;
    }
};

std::wstring Ip4Text(const BYTE* address) {
    IN_ADDR value{};
    memcpy(&value, address, 4);
    wchar_t text[INET_ADDRSTRLEN] = {};
    InetNtopW(AF_INET, &value, text, INET_ADDRSTRLEN);
    return text;
}

std::wstring JoinedEndpoint(const std::wstring& ip, USHORT port) {
    if (!port) return ip;
    return Format(L"%s:%u", ip.c_str(), port);
}

std::string FlowKeyFor(const std::wstring& source, USHORT sourcePort,
                       const std::wstring& destination, USHORT destinationPort) {
    return WideToUtf8(Format(L"%s:%u>%s:%u", source.c_str(), sourcePort,
                             destination.c_str(), destinationPort));
}

struct PacketProcessor {
    PacketConfig config;
    Sink sink;
    std::atomic<bool>* stopPtr = nullptr;
    std::vector<Row> pending;
    std::vector<std::wstring> pendingDetails;
    PortTable ports;
    std::unordered_set<std::string> local;
    std::chrono::steady_clock::time_point localAt{};
    std::chrono::steady_clock::time_point flushAt = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point statusAt = std::chrono::steady_clock::now();
    uint64_t frames = 0;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t throttled = 0;
    int secondBucket = 0;
    int perSecond = 0;
    std::wstring engine = L"built-in";

    void RefreshLocal() {
        auto now = std::chrono::steady_clock::now();
        if (!local.empty() && now - localAt < std::chrono::seconds(30)) return;
        local.clear();
        for (const auto& address : LocalAddresses()) local.insert(WideToUtf8(address));
        localAt = now;
    }

    std::wstring StatusText() const {
        std::wstring text = Format(L"Live \u00B7 %llu frames \u00B7 %llu rows \u00B7 %s payload \u00B7 %s",
                                   static_cast<unsigned long long>(frames),
                                   static_cast<unsigned long long>(packets),
                                   SizeText(bytes).c_str(), engine.c_str());
        if (throttled) text += Format(L" \u00B7 %llu throttled", static_cast<unsigned long long>(throttled));
        return text;
    }

    void Flush(bool force) {
        auto now = std::chrono::steady_clock::now();
        if (!force && pending.size() < 100 && now - flushAt < std::chrono::milliseconds(250)) return;
        if (pending.empty() && now - statusAt < std::chrono::seconds(1)) return;
        Batch batch;
        batch.rows = std::move(pending);
        batch.details = std::move(pendingDetails);
        pending.clear();
        pendingDetails.clear();
        batch.status = StatusText();
        sink.Post(std::move(batch));
        flushAt = now;
        statusAt = now;
    }

    void Emit(const std::wstring& iface, const std::wstring& direction, const std::wstring& app,
              const std::wstring& source, const std::wstring& destination,
              size_t payloadSize, const std::wstring& proc, const std::wstring& preview,
              std::wstring detail = L"") {
        pending.push_back({
            NowStamp(), iface, direction, app, source, destination,
            payloadSize ? SizeText(payloadSize) : L"-", proc, preview
        });
        pendingDetails.push_back(std::move(detail));
        ++packets;
        bytes += payloadSize;
        if (pending.size() >= 100) Flush(false);
    }

    void Process(const BYTE* ip, size_t length, const std::wstring& iface) {
        ++frames;
        if (length < 20 || (ip[0] >> 4) != 4) return;
        size_t headerLength = (ip[0] & 0x0F) * 4;
        if (headerLength < 20 || length < headerLength) return;
        size_t totalLength = static_cast<size_t>((ip[2] << 8) | ip[3]);
        size_t ipLength = totalLength >= headerLength ? std::min(length, totalLength) : length;
        int protocol = ip[9];
        uint16_t fragment = static_cast<uint16_t>((ip[6] << 8) | ip[7]);
        bool fragmentOnly = (fragment & 0x1FFF) != 0;
        std::wstring source = Ip4Text(ip + 12);
        std::wstring destination = Ip4Text(ip + 16);
        const BYTE* l4 = ip + headerLength;
        size_t l4Length = ipLength - headerLength;

        const BYTE* payload = nullptr;
        size_t payloadLength = 0;
        std::wstring protoText = IpProtocolText(protocol);
        USHORT sourcePort = 0, destinationPort = 0;
        bool controlOnly = false;
        if (fragmentOnly) {
            payload = l4;
            payloadLength = l4Length;
        } else if (protocol == 6) {
            if (l4Length < 20) return;
            sourcePort = static_cast<USHORT>((l4[0] << 8) | l4[1]);
            destinationPort = static_cast<USHORT>((l4[2] << 8) | l4[3]);
            size_t tcpHeader = (l4[12] >> 4) * 4;
            if (tcpHeader < 20 || l4Length < tcpHeader) return;
            payload = l4 + tcpHeader;
            payloadLength = l4Length - tcpHeader;
            controlOnly = payloadLength == 0;
        } else if (protocol == 17) {
            if (l4Length < 8) return;
            sourcePort = static_cast<USHORT>((l4[0] << 8) | l4[1]);
            destinationPort = static_cast<USHORT>((l4[2] << 8) | l4[3]);
            size_t udpLength = static_cast<size_t>((l4[4] << 8) | l4[5]);
            if (udpLength < 8) return;
            payload = l4 + 8;
            payloadLength = std::min(l4Length - 8, udpLength - 8);
            controlOnly = payloadLength == 0;
        } else {
            payload = l4;
            payloadLength = l4Length;
            controlOnly = payloadLength == 0;
        }

        if (config.payloadOnly && controlOnly) return;

        RefreshLocal();
        int second = static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        if (second != secondBucket) { secondBucket = second; perSecond = 0; }
        if (++perSecond > 250) { ++throttled; return; }

        bool sourceLocal = local.count(WideToUtf8(source)) > 0;
        bool destinationLocal = local.count(WideToUtf8(destination)) > 0;
        std::wstring direction = sourceLocal && destinationLocal ? L"Local"
                                : sourceLocal ? L"Out" : destinationLocal ? L"In" : L"?";
        USHORT localPort = direction == L"Out" ? sourcePort
                         : direction == L"In" ? destinationPort
                         : (sourceLocal ? sourcePort : destinationPort);
        int protoKey = protocol == 6 ? 0 : 1;
        if (std::chrono::steady_clock::now() - ports.at > std::chrono::seconds(3)) {
            ports.Refresh();
            RefreshLocal();
        }
        DWORD pid = localPort ? ports.Find(protoKey, localPort) : 0;
        if (!pid && sourcePort) pid = ports.Find(protoKey, sourcePort);

        std::wstring proc;
        if (pid) {
            ProcInfo info = GetProcInfo(pid);
            proc = info.name.empty() ? Format(L"PID %lu", pid) : Format(L"%s (%lu)", info.name.c_str(), pid);
            if (config.fullLookup && !info.user.empty()) proc += L" \u00B7 " + info.user;
        }
        if (config.fullLookup) {
            std::wstring remote = direction == L"Out" ? destination : source;
            std::string remoteUtf8 = WideToUtf8(remote);
            std::wstring reverse = ReverseName(remoteUtf8);
            std::wstring asn = AsnInfo(remoteUtf8);
            if (!reverse.empty()) proc += L" \u00B7 " + reverse;
            if (!asn.empty()) proc += L" \u00B7 " + asn;
            if (!remote.empty() && remote != L"*") {
                RequestReverse(remoteUtf8);
                RequestAsn(remoteUtf8);
            }
        }

        std::wstring app;
        std::wstring preview;
        if (fragmentOnly) {
            app = L"IPv4 fragment";
            preview = HexText(payload, payloadLength, 24);
        } else if ((protocol == 17 && (sourcePort == 53 || destinationPort == 53 || sourcePort == 5353 || destinationPort == 5353)) ||
                   (protocol == 6 && (sourcePort == 53 || destinationPort == 53))) {
            const BYTE* dns = payload;
            size_t dnsLength = payloadLength;
            if (protocol == 6 && dnsLength > 2) {
                dns += 2;
                dnsLength -= 2;
            }
            uint16_t qtype = 0;
            bool response = false;
            std::wstring question = DnsQuestion(dns, dnsLength, qtype, response);
            if (!question.empty()) {
                app = Format(L"DNS %s %s %s", response ? L"response" : L"query", DnsTypeText(qtype).c_str(), question.c_str());
                preview = HexText(dns, dnsLength, 24);
            }
        }
        if (app.empty() && protocol == 1) {
            app = Format(L"ICMP %s", payloadLength >= 1 ? IcmpText(payload[0]).c_str() : L"message");
            if (payloadLength > 4) preview = PayloadPreview(payload + 4, payloadLength - 4);
        }
        if (app.empty() && protocol != 6 && protocol != 17) {
            app = protoText;
            if (protocol == 50) preview = L"encrypted ESP payload (content not readable)";
            else if (payloadLength) preview = PayloadPreview(payload, payloadLength);
        }
        if (app.empty() && payloadLength) {
            bool tlsRecord = payloadLength >= 5 && payload[1] == 0x03 && payload[2] <= 0x04 &&
                             (payload[0] == 0x14 || payload[0] == 0x15 ||
                              payload[0] == 0x16 || payload[0] == 0x17);
            if (tlsRecord && payload[0] == 0x16 && payloadLength > 5) {
                if (payload[5] == 1) {
                    std::wstring sni = TlsSni(payload, payloadLength);
                    app = sni.empty() ? L"TLS ClientHello" : L"TLS ClientHello \u00B7 SNI " + sni;
                } else {
                    app = L"TLS handshake";
                    preview = HexText(payload, payloadLength, 24);
                }
            } else if (tlsRecord && payload[0] == 0x17) {
                app = Format(L"TLS encrypted data \u00B7 %s", SizeText(payloadLength).c_str());
                preview = L"encrypted application data (content not readable without TLS keys)";
            } else if (tlsRecord && payload[0] == 0x15) {
                app = L"TLS alert";
                preview = HexText(payload, payloadLength, 24);
            } else if (tlsRecord && payload[0] == 0x14) {
                app = L"TLS change cipher spec";
            } else {
                preview = PayloadPreview(payload, payloadLength);
                bool httpMethod = payloadLength >= 4 &&
                    (memcmp(payload, "GET ", 4) == 0 || memcmp(payload, "POST", 4) == 0 ||
                     memcmp(payload, "HEAD", 4) == 0 || memcmp(payload, "PUT ", 4) == 0 ||
                     memcmp(payload, "DELE", 4) == 0 || memcmp(payload, "OPTI", 4) == 0 ||
                     memcmp(payload, "PATC", 4) == 0 || memcmp(payload, "CONN", 4) == 0);
                bool httpResponse = payloadLength >= 5 && memcmp(payload, "HTTP/", 5) == 0;
                if (httpMethod) {
                    std::wstring host;
                    std::wstring lower = ToLower(preview);
                    size_t at = lower.find(L"host:");
                    if (at != std::wstring::npos) {
                        size_t end = preview.find(L' ', at);
                        host = preview.substr(at + 5, end == std::wstring::npos ? std::wstring::npos : end - at - 5);
                        host = Trim(host);
                    }
                    app = L"HTTP request";
                    if (!host.empty()) app += L" \u00B7 " + host;
                } else if (httpResponse) {
                    app = L"HTTP response";
                } else {
                    app = protoText + L" payload";
                }
            }
        }
        if (app.empty()) app = payloadLength ? protoText + L" payload" : protoText + L" control (no payload)";

        std::wstring detail;
        if (payload && payloadLength) {
            detail = Format(L"Payload %s \u00B7 first %s shown\n\n",
                            SizeText(payloadLength).c_str(),
                            SizeText(std::min<size_t>(payloadLength, 512)).c_str());
            detail += HexDump(payload, payloadLength, 512);
        } else {
            detail = L"No payload in this packet (control packet).";
        }

        Emit(iface, direction, app,
             JoinedEndpoint(source, sourcePort), JoinedEndpoint(destination, destinationPort),
             payloadLength, proc, preview, std::move(detail));
    }
};

bool RunRawSockets(PacketProcessor& processor) {

    struct Interface {
        ULONG address = 0;
        std::wstring name;
    };
    std::vector<Interface> interfaces;
    std::set<ULONG> seen;
    ULONG size = 16 * 1024;
    std::unique_ptr<BYTE[]> adapterBuffer(new BYTE[size]);
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG result = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(adapterBuffer.get()), &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        adapterBuffer.reset(new BYTE[size]);
        result = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                      reinterpret_cast<IP_ADAPTER_ADDRESSES*>(adapterBuffer.get()), &size);
    }
    if (result == NO_ERROR) {
        for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(adapterBuffer.get()); adapter;
             adapter = adapter->Next) {
            if (adapter->OperStatus != IfOperStatusUp) continue;
            for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
                if (!unicast->Address.lpSockaddr ||
                    unicast->Address.lpSockaddr->sa_family != AF_INET) {
                    continue;
                }
                ULONG address = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr)
                                    ->sin_addr.S_un.S_addr;
                if (seen.insert(address).second) {
                    interfaces.push_back({address, adapter->FriendlyName ? adapter->FriendlyName : L"Ethernet"});
                }
                break;
            }
        }
    }
    ULONG loopback = htonl(INADDR_LOOPBACK);
    if (seen.insert(loopback).second) interfaces.push_back({loopback, L"Loopback"});

    std::vector<std::pair<SOCKET, std::wstring>> sockets;
    for (const auto& entry : interfaces) {
        SOCKET socket = ::socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if (socket == INVALID_SOCKET) continue;

        int receiveBuffer = 64 << 20;
        setsockopt(socket, SOL_SOCKET, SO_RCVBUF,
                   reinterpret_cast<const char*>(&receiveBuffer), sizeof(receiveBuffer));
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_addr.S_un.S_addr = entry.address;
        if (bind(socket, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
            closesocket(socket);
            continue;
        }
        DWORD enabled = RCVALL_ON;
        DWORD returned = 0;
        if (WSAIoctl(socket, SIO_RCVALL, &enabled, sizeof(enabled), nullptr, 0,
                     &returned, nullptr, nullptr) != 0) {
            closesocket(socket);
            continue;
        }
        u_long nonBlocking = 1;
        ioctlsocket(socket, FIONBIO, &nonBlocking);
        sockets.emplace_back(socket, entry.name);
    }
    if (sockets.empty()) return false;

    processor.engine = Format(L"built-in raw sockets \u00B7 %d interface(s) \u00B7 IPv4 + loopback",
                              static_cast<int>(sockets.size()));
    std::vector<BYTE> packet(kMaxPacket);
    while (!processor.stopPtr->load()) {
        fd_set readSet;
        FD_ZERO(&readSet);
        for (const auto& entry : sockets) FD_SET(entry.first, &readSet);
        timeval timeout{0, 500000};
        int ready = select(0, &readSet, nullptr, nullptr, &timeout);
        if (ready == SOCKET_ERROR) break;
        if (ready > 0) {
            for (const auto& entry : sockets) {
                if (!FD_ISSET(entry.first, &readSet)) continue;
                for (;;) {
                    int count = recv(entry.first, reinterpret_cast<char*>(packet.data()),
                                     static_cast<int>(packet.size()), 0);
                    if (count <= 0) break;
                    processor.Process(packet.data(), static_cast<size_t>(count), entry.second);
                    if (processor.stopPtr->load()) break;
                }
            }
        }
        processor.Flush(false);
    }
    processor.Flush(true);
    for (const auto& entry : sockets) {
        DWORD disabled = RCVALL_OFF;
        DWORD returned = 0;
        WSAIoctl(entry.first, SIO_RCVALL, &disabled, sizeof(disabled), nullptr, 0,
                 &returned, nullptr, nullptr);
        closesocket(entry.first);
    }
    return true;
}

}

void RunPacketCapture(const Sink& sink, std::atomic<bool>& stop, PacketConfig config) {
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    PacketProcessor processor;
    processor.config = config;
    processor.sink = sink;
    processor.stopPtr = &stop;

    if (!RunRawSockets(processor)) {
        sink.Error(L"Packet capture could not start. Run the application as Administrator "
                   L"so it can open raw sockets on every interface.");
        return;
    }
    sink.Done(Format(L"Stopped. Captured %llu frames, %llu rows (%s of payload).",
                     static_cast<unsigned long long>(processor.frames),
                     static_cast<unsigned long long>(processor.packets),
                     SizeText(processor.bytes).c_str()));
}
