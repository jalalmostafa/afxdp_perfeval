#ifndef DQDK_IP4_ICMP_H
#define DQDK_IP4_ICMP_H

#include "datatypes.h"
#include <net/ethernet.h>

u8* icmp4_pong(struct ethhdr* frame, u32 len, u8* pong_reply);

#endif
