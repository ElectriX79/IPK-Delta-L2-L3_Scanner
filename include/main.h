//
// Created by electrix on 3/13/26.
//

#include <netinet/in.h>
#include <stdbool.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h> /

#ifndef IPK_MAIN_H
#define IPK_MAIN_H

struct __attribute__((packed)) icmpv6_ns {
    uint8_t type;      // 135
    uint8_t code;      // 0
    uint16_t checksum;
    uint32_t reserved;
    struct in6_addr target;
};

struct __attribute__((packed)) icmpv6_na {
    uint8_t type;      // 136
    uint8_t code;
    uint16_t checksum;
    uint32_t flags;
    struct in6_addr target;
};

struct __attribute__((packed)) ndp_option {
    uint8_t type;
    uint8_t length; // in units of 8 bytes
};

struct __attribute__((packed)) ndp_opt_slla {
    uint8_t type;    // 1
    uint8_t length;  // 1 (8 bytes total)
    uint8_t mac[6];
};

struct __attribute__((packed)) ndp_opt_tlla {
    uint8_t type;    // 2
    uint8_t length;  // 1
    uint8_t mac[6];
};


struct __attribute__((packed)) icmpv6_echo {
    uint8_t type;      // 128 request, 129 reply
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};


struct __attribute__((packed)) ethernet_header {
    uint8_t ether_dest[6];
    uint8_t ether_src[6];
    uint16_t ether_type;
};

struct __attribute__((packed)) ndp_ns_packet {
    struct ethernet_header ethernet;
    struct ip6_hdr ipv6;
    struct icmpv6_ns ns;
    struct ndp_opt_slla option;
};

struct __attribute__((packed)) arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
};


struct __attribute__((packed)) arp_packet {
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
    uint64_t host_count;
};

struct program_interface {
    char *interface;
    uint8_t mac_addr[6];

    struct in_addr ipv4;
    struct in6_addr ipv6;


    int timeout;
    struct subnet subnets[100];
    uint64_t total_hostcount;
    uint32_t subnet_count;
};

struct host {
    int family;
    union {
        uint32_t ipv4;
        struct in6_addr ipv6;
    }ip;
    bool arp_ok;
    bool ndp_ok;
    bool icmp_ok;
    uint8_t mac_addr[6];

};

void argument_parser(int arg_count, char **argv, struct program_interface *config);




#endif //IPK_MAIN_H