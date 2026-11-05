#pragma once
#include "common.h"

struct PacketConfig {
    bool payloadOnly = true;
    bool fullLookup = true;
};

void RunPacketCapture(const Sink& sink, std::atomic<bool>& stop, PacketConfig config);
