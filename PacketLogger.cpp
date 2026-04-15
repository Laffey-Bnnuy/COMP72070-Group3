#include "PacketLogger.h"
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

static std::string timestamp()
{
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%H:%M:%S");
    return ss.str();
}

static const char* packetTypeName(int type)
{
    switch (type)
    {
        case AUTH_REQUEST:  return "AUTH_REQUEST";
        case AUTH_RESPONSE: return "AUTH_RESPONSE";
        case CMD_REQUEST:   return "CMD_REQUEST";
        case CMD_RESPONSE:  return "CMD_RESPONSE";
        case FILE_DATA:     return "FILE_DATA";
        case ACK:           return "ACK";
        default:            return "UNKNOWN";
    }
}

void PacketLogger::log(const std::string& dir, const DataPacket& pkt)
{
    std::cout << "[" << timestamp() << "] "
        << (dir == "SEND" ? ">> SEND" : "<< RECV")
        << " | type=" << packetTypeName(pkt.header.type)
        << " seq=" << pkt.header.seq
        << " size=" << pkt.header.size
        << std::endl;
}
