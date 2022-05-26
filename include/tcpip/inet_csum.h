#ifndef DQDK_INET_CSUM_H
#define DQDK_INET_CSUM_H

#include <linux/types.h>

extern __sum16 ip_fast_csum(const void* iph, unsigned int ihl);

#endif
