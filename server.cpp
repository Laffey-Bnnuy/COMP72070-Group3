#include "Server.h"

#include <iostream>
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

#pragma comment(lib,"ws2_32.lib")

bool Server::start()
{
    std::cout << "[INFO] Starting server..." << std::endl;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::cout << "[ERROR] WSAStartup failed!" << std::endl;
        return false;
    }
    std::cout << "[INFO] WSAStartup successful" << std::endl;

    SSL_library_init();
    SSL_load_error_strings();
    std::cout << "[INFO] OpenSSL initialized" << std::endl;

    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        std::cout << "[ERROR] SSL_CTX_new failed" << std::endl;
        return false;
    }
    std::cout << "[INFO] SSL context created" << std::endl;

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
    std::cout << "[INFO] Certificate and private key loaded" << std::endl;

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET)
    {
        std::cout << "[ERROR] Socket creation failed" << std::endl;
        return false;
    }
    std::cout << "[INFO] Socket created" << std::endl;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(54000);
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

    DataPacket pkt;

    while (true)
    {
        int r = SSL_read(ssl, &pkt, sizeof(pkt));
        if (r <= 0)
        {
            std::cout << "[INFO] Connection closed or read error" << std::endl;
            break;
        }

        PacketLogger::log("RECV", pkt);

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

            state.setState(PROCESSING);
            std::cout << "[STATE] Server state: PROCESSING" << std::endl;

            if (cmd.rfind("GET ", 0) == 0)
            {
                std::cout << "[INFO] Sending file: " << cmd.substr(4) << std::endl;
                sendFile(ssl, cmd.substr(4));
            }
            else if (cmd.rfind("PUT ", 0) == 0)
            {
                std::cout << "[INFO] Receiving file: " << cmd.substr(4) << std::endl;
                receiveFile(ssl, cmd.substr(4));
            }

            state.setState(AUTHENTICATED);
            std::cout << "[STATE] Server state: AUTHENTICATED" << std::endl;
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