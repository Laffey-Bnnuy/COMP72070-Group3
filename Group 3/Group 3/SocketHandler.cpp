
#include "SocketHandler.h"   
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "PacketSerializer.h"
#include "PacketLogger.h"

#pragma comment(lib, "ws2_32.lib")

static void printSSLErrors()
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0)
    {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cout << "[SSL] " << buf << std::endl;
    }
}

// Constructor / Destructor

SocketHandler::SocketHandler()
    : ctx(nullptr), ssl(nullptr), connected(false), sock(INVALID_SOCKET)
{
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        std::cout << "[ERROR] WSAStartup failed" << std::endl;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

SocketHandler::~SocketHandler()
{
    disconnect();
    WSACleanup();
    if (ctx) { SSL_CTX_free(ctx); ctx = nullptr; }
}

// connectToHost

bool SocketHandler::connectToHost(const std::string& host, int port)
{
    const SSL_METHOD* method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    if (!ctx)
    {
        std::cout << "[ERROR] SSL_CTX_new failed" << std::endl;
        printSSLErrors();
        return false;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock == INVALID_SOCKET)
    {
        std::cout << "[ERROR] socket() failed: " << WSAGetLastError() << std::endl;
        return false;
    }

    addrinfo hints{}, * res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char portStr[8];
    _itoa_s(port, portStr, 10);

    if (getaddrinfo(host.c_str(), portStr, &hints, &res) != 0 || !res)
    {
        std::cout << "[ERROR] getaddrinfo failed" << std::endl;
        return false;
    }

    int rc = connect(sock, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);

    if (rc == SOCKET_ERROR)
    {
        std::cout << "[ERROR] connect() failed: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        sock = INVALID_SOCKET;
        return false;
    }

    std::cout << "[INFO] Connected to " << host << ":" << port << std::endl;

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)sock);

    if (SSL_connect(ssl) <= 0)
    {
        std::cout << "[ERROR] SSL_connect failed" << std::endl;
        printSSLErrors();
        return false;
    }

    connected = true;
    return true;
}

// sendPacket

bool SocketHandler::sendPacket(const DataPacket& pkt)
{
    if (!connected || !ssl)
        return false;

    int bytes = PacketSerializer::size(pkt);
    int written = SSL_write(ssl, &pkt, bytes);

    if (written <= 0)
    {
        printSSLErrors();
        return false;
    }

    PacketLogger::log("SEND", pkt);
    return true;
}

// recvPacket

bool SocketHandler::recvPacket(DataPacket& pkt)
{
    if (!connected || !ssl)
        return false;

    int r = SSL_read(ssl, &pkt.header, sizeof(PacketHeader));
    if (r <= 0)
    {
        connected = false;
        return false;
    }

    int remaining = pkt.header.size + sizeof(PacketTail);
    r = SSL_read(ssl, pkt.payload, remaining);

    if (r <= 0)
    {
        connected = false;
        return false;
    }

    memcpy(&pkt.tail, pkt.payload + pkt.header.size, sizeof(PacketTail));

    PacketLogger::log("RECV", pkt);
    return true;
}

// disconnect

void SocketHandler::disconnect()
{
    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }

    if (sock != INVALID_SOCKET)
    {
        closesocket(sock);
        sock = INVALID_SOCKET;
    }

    connected = false;
}