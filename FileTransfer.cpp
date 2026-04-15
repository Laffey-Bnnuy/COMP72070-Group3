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
    std::ifstream file(name.c_str(), std::ios::binary);

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
        int bytes = (int)file.gcount();

        if (bytes <= 0)
            break;

        totalSent += bytes;
        if (totalSent > MAX_FILE_SIZE)
        {
            std::cout << "[ERROR] File exceeds 100MB limit, aborting send\n";
            break;
        }

        pkt.header.type = FILE_DATA;
        pkt.header.seq  = seq++;
        pkt.header.size = bytes;
        pkt.tail.crc    = simple_crc(pkt.payload, bytes);

        // Send header, payload, then tail separately so that the dynamic
        // payload pointer is serialized correctly
        if (SSL_write(ssl, &pkt.header, sizeof(PacketHeader)) <= 0) return false;
        if (SSL_write(ssl, pkt.payload, pkt.header.size)      <= 0) return false;
        if (SSL_write(ssl, &pkt.tail,   sizeof(PacketTail))   <= 0) return false;

        PacketLogger::log("SEND", pkt);
    }

    return true;
}


void receiveFile(SSL* ssl, const std::string& name)
{
    std::ofstream file(name.c_str(), std::ios::binary);
    long long totalReceived = 0;

    while (true)
    {
        DataPacket pkt;

        // Read header
        int r = SSL_read(ssl, &pkt.header, sizeof(PacketHeader));
        if (r <= 0) break;

        if (pkt.header.type == ACK)
            break;

        if (pkt.header.type != FILE_DATA)
            continue;

        if (pkt.header.size < 0 || pkt.header.size > MAX_PAYLOAD)
        {
            std::cout << "[ERROR] Invalid payload size in FILE_DATA, aborting\n";
            break;
        }

        // Read payload
        if (pkt.header.size > 0)
        {
            r = SSL_read(ssl, pkt.payload, pkt.header.size);
            if (r <= 0) break;
        }

        // Read tail
        r = SSL_read(ssl, &pkt.tail, sizeof(PacketTail));
        if (r <= 0) break;

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
}
