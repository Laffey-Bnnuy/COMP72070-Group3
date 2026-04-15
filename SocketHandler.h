#pragma once

#include <string>
#include <winsock2.h>
#include "DataPacket.h"

struct ssl_ctx_st;
struct ssl_st;
typedef ssl_ctx_st SSL_CTX;
typedef ssl_st     SSL;

class SocketHandler
{
public:
    SocketHandler();
    ~SocketHandler();

    bool connectToHost(const std::string& host, int port);
    bool sendPacket(const DataPacket& pkt);
    bool recvPacket(DataPacket& pkt);

    void disconnect();

    bool isConnected() const { return connected; }

private:
    SSL_CTX* ctx;
    SSL* ssl;
    bool connected;
    SOCKET sock;
};
