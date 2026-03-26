#pragma once

#include <string>
#include "DataPacket.h"

class PacketLogger
{
public:

    static void log(const std::string& dir, const DataPacket& pkt
    );
};
