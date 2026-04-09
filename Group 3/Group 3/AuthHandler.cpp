#include "AuthHandler.h"

#include <string>

#include "DataPacket.h"
#include "PacketSerializer.h"
#include "PacketLogger.h"
#include "CRC.h"
#include "AuthenticationManager.h"
#include "ServerStateMachine.h"

bool handleAuth(SSL* ssl, DataPacket& pkt, AuthenticationManager& auth, ServerStateMachine& state)
{
    std::string data(pkt.payload, pkt.header.size);
    size_t pos = data.find(':');

    if (pos == std::string::npos)
        return false;

    std::string u = data.substr(0, pos);

    std::string p = data.substr(pos + 1);

    DataPacket resp{};

    if (auth.authenticate(u, p))
    {
        resp.header.type = AUTH_RESPONSE;

        resp.header.size = 2;

        memcpy(resp.payload, "OK", 2);

        state.setState(AUTHENTICATED);
    }
    else
    {
        resp.header.type = AUTH_RESPONSE;

        resp.header.size = 4;

        memcpy(resp.payload, "FAIL", 4);
    }

    resp.tail.crc = simple_crc(resp.payload, resp.header.size);

    SSL_write(ssl, &resp, PacketSerializer::size(resp));

    PacketLogger::log("SEND", resp);

    return true;
}
