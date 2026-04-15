#pragma once
#include <string>
#include <cstring>

#define MAX_PAYLOAD 8192

enum PacketType
{
    AUTH_REQUEST = 1,
    AUTH_RESPONSE,
    CMD_REQUEST,
    CMD_RESPONSE,
    FILE_DATA,
    ACK
};

struct PacketHeader
{
    int type;
    int seq;
    int size;
};

struct PacketTail
{
    unsigned int crc;
};

class DataPacket
{
public:

    PacketHeader header;
    char payload[MAX_PAYLOAD];
    PacketTail tail;

    DataPacket()
    {
        header.type = 0;
        header.seq = 0;
        header.size = 0;
        tail.crc = 0;
    }

};