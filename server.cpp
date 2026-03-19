#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "DataPacket.h"
#include "PacketSerializer.h"
#include "PacketLogger.h"
#include "ServerStateMachine.h"
#include "AuthenticationManager.h"

#pragma comment(lib,"ws2_32.lib")

// CRC
unsigned int simple_crc(char* data, int size)
{
    unsigned int c = 0;
    for (int i = 0; i < size; i++)
        c += (unsigned char)data[i];
    return c;
}


// FILE SEND

void sendFile(SSL* ssl, const std::string& name)
{
    std::ifstream file(name, std::ios::binary);

    if (!file)
    {
        std::cout << "File not found\n";
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

    pkt.header.type = ACK;
    pkt.header.size = 0;

    SSL_write(ssl, &pkt, PacketSerializer::size(pkt));

    std::cout << "File sent\n";
}


// FILE RECEIVE

void receiveFile(SSL* ssl, const std::string& name)
{
    std::ofstream file(name, std::ios::binary);

    DataPacket pkt;

    while (true)
    {
        int r = SSL_read(ssl, &pkt, sizeof(pkt));

        if (r <= 0)
            break;

        PacketLogger::log("RECV", pkt);

        if (pkt.header.type == FILE_DATA)
        {
            file.write(pkt.payload, pkt.header.size);
        }

        if (pkt.header.type == ACK)
            break;
    }

    file.close();

    std::cout << "File received\n";
}


// AUTH

bool handleAuth(SSL* ssl,
                DataPacket& pkt,
                AuthenticationManager& auth,
                ServerStateMachine& state)
{
    std::string data(pkt.payload, pkt.header.size);

    size_t pos = data.find(':');

    if (pos == std::string::npos)
        return false;

    std::string user = data.substr(0, pos);
    std::string pass = data.substr(pos + 1);

    DataPacket resp;

    if (auth.authenticate(user, pass))
    {
        resp.header.type = AUTH_RESPONSE;
        resp.header.size = 2;

        memcpy(resp.payload, "OK", 2);

        state.setState(AUTHENTICATED);

        std::cout << "Auth success\n";
    }
    else
    {
        resp.header.type = AUTH_RESPONSE;
        resp.header.size = 5;

        memcpy(resp.payload, "FAIL", 4);

        std::cout << "Auth fail\n";
    }

    resp.tail.crc = simple_crc(resp.payload, resp.header.size);

    SSL_write(ssl, &resp, PacketSerializer::size(resp));

    PacketLogger::log("SEND", resp);

    return state.getState() == AUTHENTICATED;
}


int main()
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx)
    {
        std::cout << "CTX failed\n";
        return 1;
    }

    if (SSL_CTX_use_certificate_file(ctx,
        "cert.pem",
        SSL_FILETYPE_PEM) <= 0)
    {
        std::cout << "Cert failed\n";
        return 1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx,
        "key.pem",
        SSL_FILETYPE_PEM) <= 0)
    {
        std::cout << "Key failed\n";
        return 1;
    }


    SOCKET server = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(54000);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server, (sockaddr*)&addr, sizeof(addr));
    listen(server, 1);

    std::cout << "Server listening...\n";

    SOCKET client = accept(server, NULL, NULL);

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    if (SSL_accept(ssl) <= 0)
    {
        std::cout << "SSL accept failed\n";
        return 1;
    }

    std::cout << "Client connected\n";


    ServerStateMachine state;
    AuthenticationManager auth;

    state.setState(CONNECTED);


    DataPacket pkt;


    while (true)
    {
        int r = SSL_read(ssl, &pkt, sizeof(pkt));

        if (r <= 0)
            break;

        PacketLogger::log("RECV", pkt);


        // AUTH

        if (pkt.header.type == AUTH_REQUEST)
        {
            handleAuth(ssl, pkt, auth, state);
        }


        // COMMAND

        else if (pkt.header.type == CMD_REQUEST &&
                 state.getState() == AUTHENTICATED)
        {
            std::string cmd(pkt.payload,
                            pkt.header.size);

            std::cout << "CMD: " << cmd << std::endl;

            state.setState(PROCESSING);


            // download request
            if (cmd.starts_with("GET "))
            {
                std::string file =
                    cmd.substr(4);

                sendFile(ssl, file);
            }

            // upload request
            else if (cmd.starts_with("PUT "))
            {
                std::string file =
                    cmd.substr(4);

                receiveFile(ssl, file);
            }

            state.setState(AUTHENTICATED);
        }
    }


    SSL_shutdown(ssl);
    SSL_free(ssl);

    closesocket(client);
    closesocket(server);

    SSL_CTX_free(ctx);

    WSACleanup();
}
