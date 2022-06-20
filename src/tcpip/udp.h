#ifndef DQDK_IP4_UDP_H
#define DQDK_IP4_UDP_H

#include "tcpip/ipv4.h"
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <limits.h>

#define udp_get_payload_size(frame, framelen) (framelen - (sizeof(struct ethhdr) + ip4_get_header_size((struct iphdr*)(frame + 1)) + sizeof(struct udphdr)))

always_inline bool udp_audit_checksum(struct udphdr* udp, u16 udplen)
{
    u8 segment[SHRT_MAX];
    struct udphdr* nhdr = (struct udphdr*)segment;

    if (udp->check == 0) {
        return true;
    }

    nhdr->check = 0;
    memcpy(segment + sizeof(struct udphdr), udp + 1, udplen - sizeof(struct udphdr));
    return inet_fast_csum(segment, udplen) == udp->check;
}

always_inline bool udp_audit(struct udphdr* udp, u16 udplen)
{
    if (ntohs(udp->len) != udplen || !udp_audit_checksum(udp, udplen)) {
        return false;
    }

    return true;
}

#endif
