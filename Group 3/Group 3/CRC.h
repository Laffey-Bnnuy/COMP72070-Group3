#pragma once
#include "DataPacket.h"

unsigned int simple_crc(char* data, int size);

bool check_crc(DataPacket& pkt);
