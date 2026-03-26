#include "FileTransfer.h"

#include <fstream>
#include <iostream>

#include "DataPacket.h"
#include "PacketSerializer.h"
#include "PacketLogger.h"
#include "CRC.h"

void sendFile(SSL* ssl, const std::string& name)
{
    std::ifstream file(name.c_str(),
        std::ios::binary);

    if (!file)
    {
        std::cout << "no file\n";
        return;
    }

    DataPacket pkt;
    int seq = 1;

    while (!file.eof())
    {
        file.read(pkt.payload, MAX_PAYLOAD);

        int bytes = file.gcount();

        if (bytes <= 0)
            break;

        pkt.header.type = FILE_DATA;

        pkt.header.seq = seq++;

        pkt.header.size = bytes;

        pkt.tail.crc = simple_crc(pkt.payload, bytes);

        SSL_write(ssl, &pkt, PacketSerializer::size(pkt));

        PacketLogger::log("SEND", pkt);
    }
}

void receiveFile(SSL* ssl, const std::string& name)
{
    std::ofstream file(name.c_str(), std::ios::binary);

    DataPacket pkt;

    while (true)
    {
        int r = SSL_read(ssl, &pkt, sizeof(pkt));

        if (r <= 0)
            break;

        if (pkt.header.type == FILE_DATA)
        {
            file.write(pkt.payload, pkt.header.size);
        }

        if (pkt.header.type == ACK)
            break;
    }
}
