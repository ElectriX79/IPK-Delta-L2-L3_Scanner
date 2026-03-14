//
// Created by electrix on 3/13/26.
//

#include <netinet/in.h>

#ifndef IPK_MAIN_H
#define IPK_MAIN_H

struct subnet {
    int family;
    int prefix;
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    };
    uint64_t host_count;
};

struct program_interface {
    char *interface;
    int timeout;
    struct subnet subnets[100];
    uint32_t subnet_count;
};

void argument_parser(int arg_count, char **argv, struct program_interface *config);




#endif //IPK_MAIN_H