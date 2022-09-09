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

void log_frame(struct ethhdr* frame)
{
    int ethertype = ntohs(frame->h_proto);
    dlogv("[SRC MAC] %02X:%02X:%02X:%02X:%02X:%02X - [DST MAC] %02X:%02X:%02X:%02X:%02X:%02X - [PROTO] 0x%04X\n",
        frame->h_source[0], frame->h_source[1], frame->h_source[2], frame->h_source[3], frame->h_source[4], frame->h_source[5],
        frame->h_dest[0], frame->h_dest[1], frame->h_dest[2], frame->h_dest[3], frame->h_dest[4], frame->h_dest[5], ethertype);
}

void log_pingpong(struct iphdr* packet)
{
    __u32 saddr = ntohl(packet->saddr);
    __u32 daddr = ntohl(packet->daddr);
    dlogv("[PING]: %i.%i.%i.%i is pinging %i.%i.%i.%i\n", (saddr >> 24) & 0xFF,
        (saddr >> 16) & 0xFF, (saddr >> 8) & 0xFF, saddr & 0xFF,
        (daddr >> 24) & 0xFF, (daddr >> 16) & 0xFF, (daddr >> 8) & 0xFF,
        daddr & 0xFF);
}

void log_icmp(u8* frame)
{
    struct ethhdr* framehdr = (struct ethhdr*)frame;
    struct iphdr* packet = (struct iphdr*)(((struct ethhdr*)framehdr) + 1);
    log_frame(framehdr);
    log_pingpong(packet);
}

#endif
