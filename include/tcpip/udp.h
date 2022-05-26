#ifndef DQDK_IP4_UDP_H
#define DQDK_IP4_UDP_H

#define udp_get_payload_size(frame, framelen) (framelen - (sizeof(struct ethhdr) + ip4_get_header_size((struct iphdr*)(frame + 1)) + sizeof(struct udphdr)))

#endif
