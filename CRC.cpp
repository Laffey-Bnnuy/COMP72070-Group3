#include "CRC.h"

unsigned int simple_crc(char* data, int size)
{
    unsigned int c = 0;

    for (int i = 0; i < size; i++)
        c += (unsigned char)data[i];

    return c;
}

bool check_crc(DataPacket& pkt)
{
    unsigned int c = simple_crc(pkt.payload, pkt.header.size);

    return c == pkt.tail.crc;
}
