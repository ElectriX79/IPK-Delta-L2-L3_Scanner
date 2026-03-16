#include "../include/main.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
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


    if(strchr(ip_address, ':') != NULL) {
        // IPv6 address, TO DO XXXXXXXXXXXXXXXXXXXXXXXXXX
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

        if(prefix > 32 || prefix <0) {
            printf("Invalid prefix\n");
            exit(1);
        }

        struct in_addr ipv4_binary;
        struct in_addr ipv4_broadcast;
        if(inet_pton(AF_INET,ip_address,&ipv4_binary) != 1) {
            printf("Invalid format of IPv4 address, Template: xxx.xxx.xxx.xxx/zz, where zz is prefix\n");
        }
        const uint32_t mask = 0xFFFFFFFF << (32-prefix);
        struct in_addr subnet_network_address_ipv4;
        uint32_t ipv4_bin = ntohl(ipv4_binary.s_addr);
        subnet_network_address_ipv4.s_addr = mask & ipv4_bin;

        const uint32_t mask_broadcast = 0xFFFFFFFF >> (32-prefix);
        ipv4_broadcast.s_addr = ipv4_bin | mask_broadcast;
        ipv4_broadcast.s_addr = htonl(ipv4_broadcast.s_addr);


        subnet_network_address_ipv4.s_addr = htonl(subnet_network_address_ipv4.s_addr);

        uint64_t host_count = (1ULL<<(32-prefix)) -2;
        struct subnet *subnet_ptr = &config->subnets[config->subnet_count];
        char ip_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &subnet_network_address_ipv4, ip_addr,INET_ADDRSTRLEN);

        subnet_ptr->family = AF_INET;
        subnet_ptr->prefix = prefix;
        subnet_ptr->ip.ipv4 = subnet_network_address_ipv4;
        subnet_ptr->host_count = host_count;
        subnet_ptr->ipv4_broadcast = ipv4_broadcast;
        config->subnet_count++;

    }
}

void get_interface_info(struct program_interface *config) {

    struct ifaddrs *ifaddr, *ifa;
    if(getifaddrs(&ifaddr) == -1) {
        fprintf(stderr, "getifaddrs");
        exit(1);
     }
    for(ifa = ifaddr;ifa != NULL;ifa=ifa->ifa_next) {
        if(ifa->ifa_addr == NULL) {
            continue;
        }
        if(strcmp(ifa->ifa_name,config->interface) == 0) {
            if(ifa->ifa_addr->sa_family == AF_INET) {
                config->ip.ipv4 = ((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr;
            }
            else if(ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
                memcpy(config->mac_addr, s->sll_addr,6);
            }
        }
    }
    freeifaddrs(ifaddr);
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
            case 'i':
                config->interface = optarg;
                get_interface_info(config);
            default:
        }
    }
}

int create_raw_socket(struct program_interface *config, struct sockaddr_ll *device) {
    // Create raw socket for ARP
    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(sock_raw < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Setting neccessary metadata for kernel to specify which interface to use

    memset(device, 0, sizeof(struct sockaddr_ll));

    device->sll_family = AF_PACKET;
    device->sll_halen = ETH_ALEN;
    device->sll_ifindex = if_nametoindex(config->interface);
    if(device->sll_ifindex == 0) {
        perror("if_nametoindex");
        exit(EXIT_FAILURE);
    }

    return sock_raw;
}




int main(int argc, char **argv) {

    // Global interface to store relevant network configuration
    struct program_interface config = {0};

    // Setting default network settings
    config.subnet_count = 0;
    config.timeout = 1000;

    // Processing user input
    argument_parser(argc, argv, &config);

    // Getting MAC and IP address of source device
    get_interface_info(&config);

    // ARP, Ethernet header required for sending packets (IPv4)
    struct ethernet_header eth_hdr_ipv4; // For ipv4 address
    struct ethernet_header eth_hdr_ipv6; // For ipv6 address
    struct arp_header arp_hdr;

    //ARP Header initial configuration (used for every IP target)
    arp_hdr.htype = htons(ARPHRD_ETHER);
    arp_hdr.ptype = htons(ETH_P_IP);
    arp_hdr.hlen = ETH_ALEN;
    arp_hdr.plen = 4;
    arp_hdr.opcode = htons(ARPOP_REQUEST);

    memcpy(arp_hdr.sender_mac, config.mac_addr, 6);
    arp_hdr.sender_ip = config.ip.ipv4.s_addr;

    memset(arp_hdr.target_mac, 0,6);

    // Ethernet header initial configuration (ipv4)
    memset(eth_hdr_ipv4.ether_dest, 0xff, 6);
    memcpy(eth_hdr_ipv4.ether_src, config.mac_addr, 6);
    eth_hdr_ipv4.ether_type = htons(ETH_P_ARP);

    // Ethernet header initial configuration (ipv6)
    memset(eth_hdr_ipv6.ether_dest, 0xff, 6);
    memcpy(eth_hdr_ipv6.ether_src, config.mac_addr, 6);
    eth_hdr_ipv4.ether_type = htons(ETH_P_IPV6);

    // Creating raw socket for sending packets into network
    struct sockaddr_ll device;
    int sock_raw = create_raw_socket(&config, &device);

    return 0;

}