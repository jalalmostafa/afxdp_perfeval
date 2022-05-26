#include "tcpip/inet_csum.h"

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline unsigned short from32to16(unsigned int x)
{
    /* add up 16-bit and 16-bit for 16+c bit */
    x = (x & 0xffff) + (x >> 16);
    /* add up carry.. */
    x = (x & 0xffff) + (x >> 16);
    return x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline unsigned int inet_csum(const unsigned char* buff, int len)
{
    unsigned int result = 0;
    int odd;

    if (len <= 0)
        goto out;
    odd = 1 & (unsigned long)buff;
    if (odd) {
#ifdef __LITTLE_ENDIAN
        result += (*buff << 8);
#else
        result = *buff;
#endif
        len--;
        buff++;
    }
    if (len >= 2) {
        if (2 & (unsigned long)buff) {
            result += *(unsigned short*)buff;
            len -= 2;
            buff += 2;
        }
        if (len >= 4) {
            const unsigned char* end = buff + ((unsigned int)len & ~3);
            unsigned int carry = 0;

            do {
                unsigned int w = *(unsigned int*)buff;

                buff += 4;
                result += carry;
                result += w;
                carry = (w > result);
            } while (buff < end);
            result += carry;
            result = (result & 0xffff) + (result >> 16);
        }
        if (len & 2) {
            result += *(unsigned short*)buff;
            buff += 2;
        }
    }
    if (len & 1)
#ifdef __LITTLE_ENDIAN
        result += *buff;
#else
        result += (*buff << 8);
#endif
    result = from32to16(result);
    if (odd)
        result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
    return result;
}

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *	This function code has been taken from
 *	Linux kernel lib/checksum.c
 */
inline __sum16 ip_fast_csum(const void* iph, unsigned int ihl)
{
    return (__sum16)~inet_csum(iph, ihl * 4);
}
