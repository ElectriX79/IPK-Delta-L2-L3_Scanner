//
// Created by electrix on 3/13/26.
//

#include <netinet/in.h>

#ifndef IPK_MAIN_H
#define IPK_MAIN_H


struct ethernet_header {
    uint8_t ether_dest[6];
    uint8_t ether_src[6];
    uint16_t ether_type;
};

struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

struct arp_packet {
    struct ethernet_header ethernet; 
    struct arp_header arp;
};

struct subnet {
    int family;
    int prefix;
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    }ip;
    struct in_addr ipv4_broadcast;
    struct in6_addr ipv6_broadcast;
    uint64_t host_count;
};

struct program_interface {
    char *interface;
    uint8_t mac_addr[6];
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } ip;

    int timeout;
    struct subnet subnets[100];
    uint32_t subnet_count;
};

void argument_parser(int arg_count, char **argv, struct program_interface *config);




#endif //IPK_MAIN_H