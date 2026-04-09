#include "Server.h"

#include <iostream>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "FileTransfer.h"
#include "AuthHandler.h"
#include "CRC.h"

#include "DataPacket.h"
#include "PacketSerializer.h"
#include "PacketLogger.h"
#include "ServerStateMachine.h"
#include "AuthenticationManager.h"
#include "ServerMode.h"

#pragma comment(lib,"ws2_32.lib")


static bool serverSendPacket(SSL* ssl, const DataPacket& pkt)
{
    if (SSL_write(ssl, &pkt.header, sizeof(PacketHeader)) <= 0) return false;
    if (pkt.header.size > 0)
        if (SSL_write(ssl, pkt.payload, pkt.header.size) <= 0) return false;
    if (SSL_write(ssl, &pkt.tail, sizeof(PacketTail)) <= 0) return false;
    PacketLogger::log("SEND", pkt);
    return true;
}


static bool serverRecvPacket(SSL* ssl, DataPacket& pkt)
{
    // 1. Read header
    int r = SSL_read(ssl, &pkt.header, sizeof(PacketHeader));
    if (r <= 0) return false;

    // 2. Validate and read payload
    if (pkt.header.size < 0 || pkt.header.size > MAX_PAYLOAD)
    {
        std::cout << "[ERROR] Invalid payload size: " << pkt.header.size
                  << ", dropping connection" << std::endl;
        return false;
    }
    if (pkt.header.size > 0)
    {
        r = SSL_read(ssl, pkt.payload, pkt.header.size);
        if (r <= 0) return false;
    }

    // 3. Read tail
    r = SSL_read(ssl, &pkt.tail, sizeof(PacketTail));
    if (r <= 0) return false;

    PacketLogger::log("RECV", pkt);
    return true;
}

static DataPacket makeResponse(const char* msg)
{
    DataPacket resp;
    resp.header.type = CMD_RESPONSE;
    resp.header.seq  = 0;
    int len = (int)strlen(msg);
    memcpy(resp.payload, msg, len);
    resp.header.size = len;
    resp.tail.crc    = simple_crc(resp.payload, len);
    return resp;
}

bool Server::start()
{
    std::cout << "[INFO] Starting server..." << std::endl;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::cout << "[ERROR] WSAStartup failed!" << std::endl;
        return false;
    }

    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        std::cout << "[ERROR] SSL_CTX_new failed" << std::endl;
        return false;
    }

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        std::cout << "[ERROR] Failed to load certificate" << std::endl;
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        std::cout << "[ERROR] Failed to load private key" << std::endl;
        return false;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET)
    {
        std::cout << "[ERROR] Socket creation failed" << std::endl;
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(54000);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        std::cout << "[ERROR] Bind failed" << std::endl;
        return false;
    }
    std::cout << "[INFO] Socket bound to port 54000" << std::endl;

    if (listen(s, 1) == SOCKET_ERROR)
    {
        std::cout << "[ERROR] Listen failed" << std::endl;
        return false;
    }
    std::cout << "[INFO] Listening for incoming connections..." << std::endl;

    SOCKET c = accept(s, NULL, NULL);
    if (c == INVALID_SOCKET)
    {
        std::cout << "[ERROR] Accept failed" << std::endl;
        return false;
    }
    std::cout << "[INFO] Client connected" << std::endl;

    DWORD recvTimeout = 30000;
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (char*)&recvTimeout, sizeof(recvTimeout));

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, c);
    if (SSL_accept(ssl) <= 0)
    {
        std::cout << "[ERROR] SSL accept failed" << std::endl;
        return false;
    }
    std::cout << "[INFO] SSL handshake completed" << std::endl;

    ServerStateMachine state;
    AuthenticationManager auth;
    state.setState(CONNECTED);
    std::cout << "[STATE] Server state: CONNECTED" << std::endl;

    // Default = READWRITE
    ServerMode currentMode = MODE_READWRITE;
    std::cout << "[MODE] Server mode: READWRITE" << std::endl;

    while (true)
    {
        DataPacket pkt;

        if (!serverRecvPacket(ssl, pkt))
        {
            std::cout << "[INFO] Connection closed or read error" << std::endl;
            break;
        }

        if (!check_crc(pkt))
        {
            std::cout << "[ERROR] CRC mismatch, dropping packet" << std::endl;
            continue;
        }


        if (pkt.header.type == AUTH_REQUEST)
        {
            std::cout << "[INFO] Received AUTH_REQUEST" << std::endl;
            handleAuth(ssl, pkt, auth, state);
            std::cout << "[STATE] Current server state: "
                      << (state.getState() == AUTHENTICATED ? "AUTHENTICATED" : "CONNECTED")
                      << std::endl;
        }
        else if (pkt.header.type == CMD_REQUEST && state.getState() == AUTHENTICATED)
        {
            std::string cmd(pkt.payload, pkt.header.size);
            std::cout << "[INFO] Received CMD_REQUEST: " << cmd << std::endl;

            if (cmd.rfind("MODE ", 0) == 0)
            {
                state.setState(PROCESSING);
                std::cout << "[STATE] Server state: PROCESSING (mode change)" << std::endl;

                std::string modeName = cmd.substr(5);
                const char* responseMsg = nullptr;

                if (modeName == "READONLY")
                {
                    currentMode  = MODE_READONLY;
                    responseMsg  = "OK: mode set to READONLY";
                    std::cout << "[MODE] Server mode changed to: READONLY" << std::endl;
                }
                else if (modeName == "READWRITE")
                {
                    currentMode  = MODE_READWRITE;
                    responseMsg  = "OK: mode set to READWRITE";
                    std::cout << "[MODE] Server mode changed to: READWRITE" << std::endl;
                }
                else
                {
                    responseMsg = "ERR: unknown mode (use READONLY or READWRITE)";
                    std::cout << "[ERROR] Unknown mode: " << modeName << std::endl;
                }

                DataPacket resp = makeResponse(responseMsg);
                serverSendPacket(ssl, resp);

                state.setState(AUTHENTICATED);
                std::cout << "[STATE] Server state: AUTHENTICATED" << std::endl;
                continue;
            }
            if (cmd.length() <= 4)
            {
                std::cout << "[ERROR] Command too short, ignoring" << std::endl;
                continue;
            }

            std::string filepath = cmd.substr(4);
            if (filepath.find("..") != std::string::npos || filepath[0] == '/')
            {
                std::cout << "[ERROR] Blocked unsafe file path: " << filepath << std::endl;
                DataPacket resp = makeResponse("ERR: unsafe path");
                serverSendPacket(ssl, resp);
                continue;
            }

            state.setState(PROCESSING);
            std::cout << "[STATE] Server state: PROCESSING" << std::endl;

            bool   transferOk = false;
            bool   validCmd   = true;
            const char* responseMsg = nullptr;

            if (cmd.rfind("GET ", 0) == 0)
            {
                std::cout << "[INFO] Sending file: " << filepath << std::endl;
                transferOk = sendFile(ssl, filepath);
                responseMsg = transferOk ? "OK" : "ERR: file not found";
            }
            else if (cmd.rfind("PUT ", 0) == 0)
            {
                // reject writes in READONLY mode
                if (currentMode == MODE_READONLY)
                {
                    std::cout << "[WARN] PUT rejected: server is in READONLY mode" << std::endl;
                    responseMsg = "ERR: server is in READONLY mode";
                    transferOk  = false;
                }
                else
                {
                    std::cout << "[INFO] Receiving file: " << filepath << std::endl;
                    receiveFile(ssl, filepath);
                    transferOk  = true;
                    responseMsg = "OK";
                }
            }
            else
            {
                validCmd    = false;
                responseMsg = "ERR: unknown command";
                std::cout << "[ERROR] Unknown command: " << cmd << std::endl;
            }

            DataPacket resp = makeResponse(responseMsg);
            serverSendPacket(ssl, resp);
            std::cout << "[INFO] Sent response: " << responseMsg << std::endl;

            state.setState(AUTHENTICATED);
            std::cout << "[STATE] Server state: AUTHENTICATED" << std::endl;
        }
        else if (pkt.header.type == CMD_REQUEST && state.getState() != AUTHENTICATED)
        {
            std::cout << "[WARN] CMD_REQUEST rejected: not authenticated" << std::endl;
            DataPacket resp = makeResponse("ERR: not authenticated");
            serverSendPacket(ssl, resp);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);

    closesocket(c);
    closesocket(s);

    WSACleanup();

    std::cout << "[INFO] Server shutdown" << std::endl;

    return true;
}
