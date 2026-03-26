#pragma once

#include <openssl/ssl.h>

void sendAck(SSL* ssl, int seq);
