#include "../include/helper_functions.h"

//
// Created by electrix on 3/22/26.
//

uint16_t icmp_checksum(void *buf, int len) {
    uint32_t sum = 0;
    uint16_t *data = buf;

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    if (len == 1)
        sum += *(uint8_t*)data;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

void create_multicast_mac(struct in6_addr *target, uint8_t *mac) {
    mac[0] = 0x33;
    mac[1] = 0x33;
    mac[2] = 0xff;

    mac[3] = target->s6_addr[13];
    mac[4] = target->s6_addr[14];
    mac[5] = target->s6_addr[15];
}

void create_solicited_multicast(struct in6_addr *target, struct in6_addr *out) {
    memset(out, 0, sizeof(*out));

    out->s6_addr[0] = 0xff;
    out->s6_addr[1] = 0x02;

    out->s6_addr[11] = 0x01;
    out->s6_addr[12] = 0xff;

    out->s6_addr[13] = target->s6_addr[13];
    out->s6_addr[14] = target->s6_addr[14];
    out->s6_addr[15] = target->s6_addr[15];
}

uint16_t icmpv6_checksum(struct in6_addr *src,
                         struct in6_addr *dst,
                         uint8_t *icmp,
                         uint32_t icmp_len)
{
    uint8_t buffer[2048];
    memset(buffer, 0, sizeof(buffer));

    uint8_t *ptr = buffer;

    // ===== pseudo-header =====

    // source IPv6
    memcpy(ptr, src, 16);
    ptr += 16;

    // destination IPv6
    memcpy(ptr, dst, 16);
    ptr += 16;

    // payload length (4B!)
    uint32_t len = htonl(icmp_len);
    memcpy(ptr, &len, 4);
    ptr += 4;

    // 3 bytes zero
    *ptr++ = 0;
    *ptr++ = 0;
    *ptr++ = 0;

    // next header
    *ptr++ = 58;

    // ===== ICMPv6 payload =====
    memcpy(ptr, icmp, icmp_len);
    ptr += icmp_len;

    // ===== compute checksum =====
    return checksum((uint16_t *)buffer, ptr - buffer);
}

uint16_t checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *((uint8_t *)buf);
    }

    // fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}