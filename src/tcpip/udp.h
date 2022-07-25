#ifndef DQDK_IP4_UDP_H
#define DQDK_IP4_UDP_H

#include "tcpip/ipv4.h"
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <limits.h>

#define udp_get_payload_size(frame, framelen) (framelen - (sizeof(struct ethhdr) + ip4_get_header_size((struct iphdr*)(frame + 1)) + sizeof(struct udphdr)))

#define UDP_PSUEDOIPHDR_LEN 10
#define UDP_HDR_LEN sizeof(struct udphdr)
#define UDP_MAXDATA_LEN SHRT_MAX
#define UDP_MAX_LEN UDP_HDR_LEN + UDP_MAXDATA_LEN

always_inline int udp_audit_checksum(struct udphdr* udp, u32 src_ip, u32 dst_ip, u16 udplen)
{
    if (udp->check == 0) {
        return 1;
    }

    u16 rcvd_csum = udp->check;
    udp->check = 0;
    return udp_csum(src_ip, dst_ip, udplen, IPPROTO_UDP, (u16*)udp) == rcvd_csum;
}

always_inline int udp_audit(struct udphdr* udp, u32 src_ip, u32 dst_ip, u16 udplen)
{
    if (ntohs(udp->len) != udplen || !udp_audit_checksum(udp, src_ip, dst_ip, udplen)) {
        return 0;
    }

    return 1;
}

#endif
