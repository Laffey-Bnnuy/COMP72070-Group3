#include "PacketLogger.h"
#include <iostream>

void PacketLogger::log(const std::string& dir, const DataPacket& pkt)
{
    std::cout << dir 
        << " type=" << pkt.header.type 
        << " seq=" << pkt.header.seq
        << " size=" << pkt.header.size
        << std::endl;
}
