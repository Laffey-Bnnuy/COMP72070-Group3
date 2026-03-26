#pragma once
#include "DataPacket.h"

class PacketSerializer
{
public:

    static int size(const DataPacket& pkt)
    {
        return sizeof(PacketHeader)+ pkt.header.size + sizeof(PacketTail);
    }
};
