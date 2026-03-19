#pragma once
#include <fstream>
#include <ctime>
#include <iostream>
#include "DataPacket.h"

class PacketLogger
{
public:

    static void log(std::string dir, DataPacket &pkt)
    {
        std::ofstream log("server_log.txt", std::ios::app);

        time_t now = time(0);

        log << ctime(&now)
            << " " << dir
            << " type=" << pkt.header.type
            << " seq=" << pkt.header.seq
            << " size=" << pkt.header.size
            << std::endl;
    }
};
