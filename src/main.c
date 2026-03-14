#include "../include/main.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <sys/types.h>

void print_usage() {
    printf("-h/--help writes usage instructions to stdout and terminates with 0 exit code.\n");
    printf("-i eth0 (just one interface to scan through)\n");
    printf("If -i is specified without a value (and any other parameters are unspecified), a list of active interfaces is printed to stdout and the program terminates with 0 exit code (additional information beyond the interface list is welcome but not required).");printf("-w 3000 is the timeout in milliseconds to wait for a response during a single port scan. This parameter is optional, in its absence the value 1000 (i.e., one second) is used.\n");
    printf("-s 192.168.1.0/24 or -s fd00:cafe:0000:face::0/120 specifies which segments to scan using IPv4 or IPv6. There can be multiple segments to be scanned (i.e., the -s argument can be repeated when the program is called).\n");
    printf("The application must be able to infer the correct network address and the resulting number of hosts to be scanned from the user input of the -s argument.\n");
    printf("The application does not have to deal with the \"bloat\" of the -s argument input with respect to the number of hosts being scanned (e.g., too short netmask or prefix length, for instance -s 10.0.0.0/8) or the location of the segment being scanned (i.e., attempting to ARP scan a network to which the computer is not directly connected).\n");
    printf("All arguments can be in any order.\n");
}



void print_interfaces() {
    struct ifaddrs *ifaddr, *ifa;
    if(getifaddrs(&ifaddr)==-1) {
        fprintf(stderr,"getifaddrs");
    }
    ifa = ifaddr;
    while(ifa != NULL) {
        if(ifa->ifa_addr->sa_family == AF_PACKET) {
            char *name = ifa->ifa_name;
            printf("%s\n", name);
        }
        ifa=ifa->ifa_next;
    }
    freeifaddrs(ifaddr);
}

void subnet_address(char *ip_address, struct program_interface *config) {
    int ip_length = strlen(ip_address);

    if(strchr(ip_address, ':') != NULL) {
        // IPv6 address
        printf("");
    }



    else {
        // IPv4 address
        char *slash = strchr(ip_address, '/');
        if(!slash) {
            printf("Invalid subnet");
        }
        *slash = '\0';

        int prefix = atoi((slash+1));


        struct in_addr ipv4_binary;
        if(inet_pton(AF_INET,ip_address,&ipv4_binary) != 1) {
            perror("Invalid format of IPv4 address, Template: xxx.xxx.xxx.xxx/zz, where zz is prefix");
        }

        const uint32_t mask = (2^32 - 1) << (32-prefix);
        struct in_addr subnet_network;
        subnet_network.s_addr = mask & ipv4_binary.s_addr;


    }

}

void argument_parser(int arg_count, char **arguments, struct program_interface *config) {
    if (arg_count == 1) {
        fprintf(stderr, "Error: No arguments entered, please read usage:");
        print_usage();
        exit(1);
    }
    else if(arg_count == 2 && (strcmp(arguments[1],"-i") == 0)) {
        print_interfaces();
        exit(0);
    }

    int opt;
    while((opt = getopt(arg_count, arguments,"hi:w:s:")) != -1) {
        switch(opt) {
            case 'h':
                print_usage();
                exit(0);
            case 's':
                subnet_address(optarg, config);
            case 'w':
                config->interface = optarg;

            default:
        }
    }
}



int main(int argc, char **argv) {
    struct program_interface config;
    argument_parser(argc, argv, &config);

    return 0;

}