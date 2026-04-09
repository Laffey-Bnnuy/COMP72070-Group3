#include "PacketUtils.h"
#include "DataPacket.h"
#include "PacketSerializer.h"
#include "PacketLogger.h"

void sendAck(SSL* ssl, int seq)
{
    DataPacket pkt{};

    pkt.header.type = ACK;
    pkt.header.seq = seq;
    pkt.header.size = 0;

    SSL_write(ssl, &pkt, PacketSerializer::size(pkt));

    PacketLogger::log("SEND", pkt);
}
