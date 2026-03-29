#include "FileTransfer.h"

#include <fstream>
#include <iostream>

#include "DataPacket.h"
#include "PacketSerializer.h"
#include "PacketLogger.h"
#include "CRC.h"

const long long MAX_FILE_SIZE = 104857600; // 100 MB

bool sendFile(SSL* ssl, const std::string& name)
{
    std::ifstream file(name.c_str(),
        std::ios::binary);

    if (!file)
    {
        std::cout << "[ERROR] File not found: " << name << "\n";
        return false;
    }

    DataPacket pkt;
    int seq = 1;
    long long totalSent = 0;

    while (!file.eof())
    {
        file.read(pkt.payload, MAX_PAYLOAD);

        int bytes = file.gcount();

        if (bytes <= 0)
            break;

        totalSent += bytes;
        if (totalSent > MAX_FILE_SIZE)
        {
            std::cout << "[ERROR] File exceeds 100MB limit, aborting send\n";
            break;
        }

        pkt.header.type = FILE_DATA;

        pkt.header.seq = seq++;

        pkt.header.size = bytes;

        pkt.tail.crc = simple_crc(pkt.payload, bytes);

        SSL_write(ssl, &pkt, PacketSerializer::size(pkt));

        PacketLogger::log("SEND", pkt);
    }

    return true;
}

void receiveFile(SSL* ssl, const std::string& name)
{
    std::ofstream file(name.c_str(), std::ios::binary);

    DataPacket pkt;
    long long totalReceived = 0;

    while (true)
    {
        int r = SSL_read(ssl, &pkt, sizeof(pkt));

        if (r <= 0)
            break;

        if (pkt.header.type == FILE_DATA)
        {
            if (pkt.header.size < 0 || pkt.header.size > MAX_PAYLOAD)
            {
                std::cout << "[ERROR] Invalid payload size in FILE_DATA, aborting\n";
                break;
            }

            if (!check_crc(pkt))
            {
                std::cout << "[ERROR] CRC mismatch in FILE_DATA, aborting\n";
                break;
            }

            totalReceived += pkt.header.size;
            if (totalReceived > MAX_FILE_SIZE)
            {
                std::cout << "[ERROR] File exceeds 100MB limit, aborting receive\n";
                break;
            }

            file.write(pkt.payload, pkt.header.size);
        }

        if (pkt.header.type == ACK)
            break;
    }
}
