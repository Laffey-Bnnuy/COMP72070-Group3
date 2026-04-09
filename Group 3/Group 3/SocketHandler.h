#pragma once

#include <string>
#include <openssl/ssl.h>


class SocketHandler
{
public:

    SocketHandler();
    ~SocketHandler();

    // Establish TLS connection to host:port.

    bool connect(const std::string& host, int port);

    // Send exactly PacketSerializer::size(pkt) bytes.
  
    bool send(const DataPacket& pkt);

    // Block until a full DataPacket is received.

    bool recv(DataPacket& pkt);

    // Graceful TLS shutdown + socket close.
    void disconnect();

    bool isConnected() const { return connected; }

private:

    SSL_CTX* ctx;
    SSL*     ssl;
    bool     connected;


    unsigned long long sock; 
};
