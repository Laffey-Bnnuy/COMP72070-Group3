#pragma once

#include <openssl/ssl.h>

class AuthenticationManager;
class ServerStateMachine;
struct DataPacket;

bool handleAuth(
    SSL* ssl,
    DataPacket& pkt,
    AuthenticationManager& auth,
    ServerStateMachine& state
);
