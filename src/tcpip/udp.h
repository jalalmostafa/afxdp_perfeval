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

#define ETH_HDR_SIZE sizeof(struct ethhdr)
#define PKTGEN_HDR_OFFSET (ETH_HDR_SIZE + sizeof(struct iphdr) + sizeof(struct udphdr))
#define ETH_HDR_SIZE sizeof(struct ethhdr)
#define PKTGEN_HDR_SIZE sizeof(struct pktgen_hdr)
#define PKT_HDR_SIZE (ETH_HDR_SIZE + sizeof(struct iphdr) + sizeof(struct udphdr) + PKTGEN_HDR_SIZE)

#define MIN_PKT_SIZE 64
#define ETH_FCS_SIZE 4
#define PKT_SIZE (MIN_PKT_SIZE - ETH_FCS_SIZE)
#define IP_PKT_SIZE (PKT_SIZE - ETH_HDR_SIZE)
#define UDP_PKT_SIZE (IP_PKT_SIZE - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE (UDP_PKT_SIZE - (sizeof(struct udphdr) + PKTGEN_HDR_SIZE))

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

#define PKTGEN_MAGIC 0xbe9be955

struct pktgen_hdr {
    u32 pgh_magic;
    u32 seq_num;
    u64 ts_nano;
};

always_inline void* memset32_htonl(void* dest, u32 val, u32 size)
{
    u32* ptr = (u32*)dest;
    u32 i;

    val = htonl(val);

    // move 4 bytes to the nearest multiple of 4 that is smaller than size
    for (i = 0; i < (size & (~0x3)); i += 4) {
        ptr[i >> 2] = val;
    }

    for (; i < size; i++)
        ((char*)dest)[i] = ((char*)&val)[i & 3];
    return dest;
}

always_inline void udp_create_frame(u8* pkt_data, u8* daddr, u8* saddr, u16 pktsize)
{
    struct pktgen_hdr* pktgen_hdr;
    struct udphdr* udp_hdr;
    struct iphdr* ip_hdr;

    struct ethhdr* eth_hdr = (struct ethhdr*)pkt_data;

    udp_hdr = (struct udphdr*)(pkt_data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    ip_hdr = (struct iphdr*)(pkt_data + sizeof(struct ethhdr));
    pktgen_hdr = (struct pktgen_hdr*)(pkt_data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));

    /* ethernet header */
    memcpy(eth_hdr->h_dest, daddr, ETH_ALEN);
    memcpy(eth_hdr->h_source, saddr, ETH_ALEN);
    eth_hdr->h_proto = htons(ETH_P_IP);

    /* IP header */
    ip_hdr->version = IPVERSION;
    ip_hdr->ihl = 0x5; /* 20 byte header */
    ip_hdr->tos = 0x0;
    ip_hdr->tot_len = htons(pktsize - ETH_HDR_SIZE);
    ip_hdr->id = 0;
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = IPDEFTTL;
    ip_hdr->protocol = IPPROTO_UDP;
    ip_hdr->saddr = htonl(0x0a0a0a10);
    ip_hdr->daddr = htonl(0x0a0a0a20);

    /* IP header checksum */
    ip_hdr->check = 0;
    ip_hdr->check = ip_fast_csum((const void*)ip_hdr, ip_hdr->ihl);

    /* UDP header */
    udp_hdr->source = htons(0x1000);
    udp_hdr->dest = htons(0x1000);
    udp_hdr->len = htons(pktsize);

    pktgen_hdr->pgh_magic = htonl(PKTGEN_MAGIC);

    /* UDP data */
    memset32_htonl(pkt_data + PKT_HDR_SIZE, 0x12345678, pktsize);

    /* UDP header checksum */
    udp_hdr->check = 0;
    udp_hdr->check = udp_csum(ip_hdr->saddr, ip_hdr->daddr, pktsize, IPPROTO_UDP, (u16*)udp_hdr);
}

#endif
