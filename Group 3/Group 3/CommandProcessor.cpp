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

    // Server uses a self-signed cert so disable peer verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    sock = (unsigned long long)socket(AF_INET, SOCK_STREAM, 0);
    if ((SOCKET)sock == INVALID_SOCKET)
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
        std::cout << "[ERROR] getaddrinfo failed for " << host << std::endl;
        return false;
    }

    int rc = ::connect((SOCKET)sock, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);

    if (rc == SOCKET_ERROR)
    {
        std::cout << "[ERROR] connect() failed: " << WSAGetLastError() << std::endl;
        closesocket((SOCKET)sock);
        sock = INVALID_SOCKET;
        return false;
    }

    std::cout << "[INFO] TCP connection established to " << host << ":" << port << std::endl;

    DWORD timeout = 30000;
    setsockopt((SOCKET)sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)(SOCKET)sock);

    if (SSL_connect(ssl) <= 0)
    {
        std::cout << "[ERROR] SSL_connect failed" << std::endl;
        printSSLErrors();
        closesocket((SOCKET)sock);
        sock = INVALID_SOCKET;
        return false;
    }

    std::cout << "[INFO] TLS handshake completed (" << SSL_get_cipher(ssl) << ")" << std::endl;

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
        std::cout << "[ERROR] SSL_write failed" << std::endl;
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

    // Read header first
    int r = SSL_read(ssl, &pkt.header, sizeof(PacketHeader));
    if (r <= 0)
    {
        std::cout << "[INFO] Connection closed or recv timeout" << std::endl;
        connected = false;
        return false;
    }

    if (pkt.header.size < 0 || pkt.header.size > MAX_PAYLOAD)
    {
        std::cout << "[ERROR] Invalid header.size=" << pkt.header.size << std::endl;
        connected = false;
        return false;
    }

    // Read payload + tail
    int remaining = pkt.header.size + (int)sizeof(PacketTail);
    r = SSL_read(ssl, pkt.payload, remaining);
    if (r <= 0)
    {
        std::cout << "[ERROR] Failed to read payload+tail" << std::endl;
        connected = false;
        return false;
    }

    // Copy tail from end of buffer
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
    if ((SOCKET)sock != INVALID_SOCKET)
    {
        closesocket((SOCKET)sock);
        sock = INVALID_SOCKET;
    }
    connected = false;
}
