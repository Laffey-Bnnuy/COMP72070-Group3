#pragma once

#include <string>
#include <openssl/ssl.h>

void sendFile(SSL* ssl, const std::string& name
);

void receiveFile(SSL* ssl, const std::string& name
);
