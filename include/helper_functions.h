#include "main.h"

//
// Created by electrix on 3/22/26.
//

#ifndef IPK_HELPER_FUNCTIONS_H_H
#define IPK_HELPER_FUNCTIONS_H_H

uint16_t icmp_checksum(void *buf, int len);
void create_multicast_mac(struct in6_addr *target, uint8_t *mac);
void create_solicited_multicast(struct in6_addr *target, struct in6_addr *out);
uint16_t icmpv6_checksum(struct in6_addr *src,struct in6_addr *dst,uint8_t *icmp,uint32_t icmp_len);
uint16_t checksum(uint16_t *buf, int len);


#endif //IPK_HELPER_FUNCTIONS_H_H