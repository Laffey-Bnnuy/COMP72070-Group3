#include "CommandProcessor.h"

#include <iostream>
#include <fstream>
#include <cstring>

#include "DataPacket.h"
#include "PacketSerializer.h"
#include "PacketLogger.h"
#include "CRC.h"
#include "SocketHandler.h"

CommandProcessor::CommandProcessor(SocketHandler& socket)
    : sock(socket)
{
}

bool CommandProcessor::connectToServer(const std::string& host, int port)
{
    if (state.getState() != IDLE && state.getState() != DISCONNECTED)
    {
        std::cout << "[WARN] Already connected (state=" << state.label() << ")" << std::endl;
        return false;
    }

    state.setState(CONNECTING);
    std::cout << "[STATE] " << state.label() << std::endl;

    if (!sock.connectToHost(host, port))
    {
        state.setState(DISCONNECTED);
        std::cout << "[STATE] " << state.label() << std::endl;
        return false;
    }

    state.setState(AUTHENTICATING);
    std::cout << "[STATE] " << state.label() << std::endl;
    return true;
}

bool CommandProcessor::login(const std::string& username, const std::string& password)
{
    if (state.getState() != AUTHENTICATING)
    {
        std::cout << "[ERROR] login() called in wrong state: " << state.label() << std::endl;
        return false;
    }

    std::string credentials = username + ":" + password;

    if ((int)credentials.size() > MAX_PAYLOAD)
    {
        std::cout << "[ERROR] Credentials exceed MAX_PAYLOAD" << std::endl;
        return false;
    }

    DataPacket req{};
    req.header.type = AUTH_REQUEST;
    req.header.seq = 0;
    req.header.size = (int)credentials.size();
    memcpy(req.payload, credentials.c_str(), credentials.size());
    req.tail.crc = simple_crc(req.payload, req.header.size);

    if (!sock.sendPacket(req))
    {
        std::cout << "[ERROR] Failed to send AUTH_REQUEST" << std::endl;
        state.setState(DISCONNECTED);
        return false;
    }

    DataPacket resp{};
    if (!sock.recvPacket(resp))
    {
        std::cout << "[ERROR] No response to AUTH_REQUEST" << std::endl;
        state.setState(DISCONNECTED);
        return false;
    }

    if (resp.header.type != AUTH_RESPONSE)
    {
        std::cout << "[ERROR] Expected AUTH_RESPONSE, got type=" << resp.header.type << std::endl;
        return false;
    }

    std::string result(resp.payload, resp.header.size);

    if (result == "OK")
    {
        state.setState(AUTHENTICATED);
        std::cout << "[AUTH] Login successful" << std::endl;
        std::cout << "[STATE] " << state.label() << std::endl;
        return true;
    }
    else
    {
        std::cout << "[AUTH] Login failed (" << result << ")" << std::endl;
        return false;
    }
}

bool CommandProcessor::getFile(const std::string& remoteFilename,
    const std::string& localOutPath)
{
    if (state.getState() != AUTHENTICATED)
    {
        std::cout << "[ERROR] getFile() called in wrong state: " << state.label() << std::endl;
        return false;
    }

    std::string cmd = "GET " + remoteFilename;

    DataPacket req{};
    req.header.type = CMD_REQUEST;
    req.header.seq = 0;
    req.header.size = (int)cmd.size();
    memcpy(req.payload, cmd.c_str(), cmd.size());
    req.tail.crc = simple_crc(req.payload, req.header.size);

    state.setState(TRANSFERRING);
    std::cout << "[STATE] " << state.label() << std::endl;

    if (!sock.sendPacket(req))
    {
        std::cout << "[ERROR] Failed to send CMD_REQUEST" << std::endl;
        state.setState(AUTHENTICATED);
        return false;
    }

    std::ofstream outFile(localOutPath.c_str(), std::ios::binary);
    if (!outFile)
    {
        std::cout << "[ERROR] Cannot open local file for writing: " << localOutPath << std::endl;
        state.setState(AUTHENTICATED);
        return false;
    }

    long long totalReceived = 0;
    int       lastSeq = 0;
    bool      transferOk = false;

    while (true)
    {
        DataPacket pkt{};
        if (!sock.recvPacket(pkt))
        {
            std::cout << "[ERROR] Connection lost during file receive" << std::endl;
            break;
        }

        if (pkt.header.type == FILE_DATA)
        {
            if (pkt.header.size <= 0 || pkt.header.size > MAX_PAYLOAD)
            {
                std::cout << "[ERROR] Invalid FILE_DATA size=" << pkt.header.size << std::endl;
                break;
            }

            if (!check_crc(pkt))
            {
                std::cout << "[ERROR] CRC mismatch in chunk seq=" << pkt.header.seq << std::endl;
                break;
            }

            if (pkt.header.seq != lastSeq + 1)
                std::cout << "[WARN] Out-of-order chunk: expected seq="
                << (lastSeq + 1) << " got " << pkt.header.seq << std::endl;

            lastSeq = pkt.header.seq;
            totalReceived += pkt.header.size;
            outFile.write(pkt.payload, pkt.header.size);

            std::cout << "[XFER] Received chunk seq=" << pkt.header.seq
                << " size=" << pkt.header.size
                << " total=" << totalReceived << " bytes" << std::endl;
        }
        else if (pkt.header.type == CMD_RESPONSE)
        {
            std::string msg(pkt.payload, pkt.header.size);
            std::cout << "[INFO] CMD_RESPONSE: " << msg << std::endl;
            transferOk = (msg == "OK");
            break;
        }
        else
        {
            std::cout << "[WARN] Unexpected packet type=" << pkt.header.type << std::endl;
        }
    }

    outFile.close();

    if (transferOk)
        std::cout << "[INFO] File saved to " << localOutPath
        << " (" << totalReceived << " bytes)" << std::endl;
    else
        std::cout << "[ERROR] File transfer failed or was incomplete" << std::endl;

    state.setState(AUTHENTICATED);
    std::cout << "[STATE] " << state.label() << std::endl;
    return transferOk;
}

bool CommandProcessor::putFile(const std::string& localPath,
    const std::string& remoteFilename)
{
    if (state.getState() != AUTHENTICATED)
    {
        std::cout << "[ERROR] putFile() called in wrong state: " << state.label() << std::endl;
        return false;
    }

    std::ifstream inFile(localPath.c_str(), std::ios::binary);
    if (!inFile)
    {
        std::cout << "[ERROR] Cannot open local file: " << localPath << std::endl;
        return false;
    }

    std::string cmd = "PUT " + remoteFilename;

    DataPacket req{};
    req.header.type = CMD_REQUEST;
    req.header.seq = 0;
    req.header.size = (int)cmd.size();
    memcpy(req.payload, cmd.c_str(), cmd.size());
    req.tail.crc = simple_crc(req.payload, req.header.size);

    state.setState(TRANSFERRING);
    std::cout << "[STATE] " << state.label() << std::endl;

    if (!sock.sendPacket(req))
    {
        std::cout << "[ERROR] Failed to send CMD_REQUEST" << std::endl;
        state.setState(AUTHENTICATED);
        return false;
    }

    const long long MAX_FILE_SIZE = 104857600;
    long long totalSent = 0;
    int seq = 1;

    while (!inFile.eof())
    {
        DataPacket pkt{};
        inFile.read(pkt.payload, MAX_PAYLOAD);
        int bytes = (int)inFile.gcount();

        if (bytes <= 0) break;

        totalSent += bytes;
        if (totalSent > MAX_FILE_SIZE)
        {
            std::cout << "[ERROR] File exceeds 100 MB limit, aborting" << std::endl;
            break;
        }

        pkt.header.type = FILE_DATA;
        pkt.header.seq = seq++;
        pkt.header.size = bytes;
        pkt.tail.crc = simple_crc(pkt.payload, bytes);

        if (!sock.sendPacket(pkt))
        {
            std::cout << "[ERROR] Failed to send FILE_DATA chunk seq=" << pkt.header.seq << std::endl;
            state.setState(AUTHENTICATED);
            return false;
        }

        std::cout << "[XFER] Sent chunk seq=" << pkt.header.seq
            << " size=" << bytes
            << " total=" << totalSent << " bytes" << std::endl;
    }

    inFile.close();
    std::cout << "[INFO] All chunks sent (" << totalSent << " bytes)" << std::endl;

    DataPacket resp{};
    if (!sock.recvPacket(resp))
    {
        std::cout << "[ERROR] No CMD_RESPONSE received after PUT" << std::endl;
        state.setState(AUTHENTICATED);
        return false;
    }

    std::string msg(resp.payload, resp.header.size);
    std::cout << "[INFO] CMD_RESPONSE: " << msg << std::endl;

    state.setState(AUTHENTICATED);
    std::cout << "[STATE] " << state.label() << std::endl;
    return (msg == "OK");
}

void CommandProcessor::disconnect()
{
    sock.disconnect();
    state.setState(DISCONNECTED);
    std::cout << "[STATE] " << state.label() << std::endl;
}