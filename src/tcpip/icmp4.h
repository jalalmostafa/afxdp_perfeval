#ifndef DQDK_IP4_ICMP_H
#define DQDK_IP4_ICMP_H

#include "../dqdk.h"
#include "tcpip/inet_csum.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

always_inline int icmp4_pong(struct ethhdr* frame, u32 len, u8* pong_reply)
{
    struct iphdr* packet = (struct iphdr*)(frame + 1);
    struct icmphdr* icmp = (struct icmphdr*)(packet + 1);
    u8* data = (u8*)(icmp + 1);

    int datalen = len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct icmphdr);

    int icmplen = sizeof(struct icmphdr) + datalen;
    struct icmphdr* pong = (struct icmphdr*)(pong_reply + sizeof(struct ethhdr) + sizeof(struct iphdr));
    pong->type = ICMP_ECHOREPLY;
    pong->code = 0;
    pong->checksum = 0;
    pong->un.echo.id = icmp->un.echo.id;
    pong->un.echo.sequence = icmp->un.echo.sequence;
    memcpy((void*)(pong + 1), data, datalen);
    pong->checksum = inet_fast_csum(pong, 8 + datalen);

    struct iphdr* pong_packet = (struct iphdr*)(pong_reply + sizeof(struct ethhdr));
    pong_packet->daddr = packet->saddr;
    pong_packet->saddr = packet->daddr;
    pong_packet->protocol = IPPROTO_ICMP;
    pong_packet->ihl = 5;
    pong_packet->version = 4;
    pong_packet->ttl = 64;

    int pktlen = sizeof(struct iphdr) + icmplen;
    pong_packet->tot_len = htons(pktlen);
    pong_packet->tos = packet->tos;
    pong_packet->check = ip_fast_csum(pong_packet, pong_packet->ihl);

    struct ethhdr* pong_frame = (struct ethhdr*)pong_reply;
    memcpy(pong_frame->h_dest, frame->h_source, ETH_ALEN);
    memcpy(pong_frame->h_source, frame->h_dest, ETH_ALEN);
    pong_frame->h_proto = frame->h_proto;

    return 0;
}

#endif
