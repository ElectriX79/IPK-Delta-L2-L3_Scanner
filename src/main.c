#include "../include/main.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <sys/types.h>

void ipv6_to_solicited_multicast(struct in6_addr *target, struct in6_addr *multicast) {
    memset(multicast, 0, sizeof(struct in6_addr));

    multicast->s6_addr[0] = 0xff;
    multicast->s6_addr[1] = 0x02;
    multicast->s6_addr[11] = 0x01;
    multicast->s6_addr[12] = 0xff;

    multicast->s6_addr[13] = target->s6_addr[13];
    multicast->s6_addr[14] = target->s6_addr[14];
    multicast->s6_addr[15] = target->s6_addr[15];
}

void ipv6_multicast_to_mac(struct in6_addr *multicast, uint8_t *mac) {
    mac[0] = 0x33;
    mac[1] = 0x33;
    mac[2] = multicast->s6_addr[12];
    mac[3] = multicast->s6_addr[13];
    mac[4] = multicast->s6_addr[14];
    mac[5] = multicast->s6_addr[15];
}

uint16_t checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len) sum += *(uint8_t*)buf;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

uint16_t icmp6_checksum(struct ip6_hdr *ip6, uint8_t *icmp, int len) {
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t plen;
        uint8_t zero[3];
        uint8_t next;
    } pseudo;

    memset(&pseudo, 0, sizeof(pseudo));

    pseudo.src = ip6->ip6_src;
    pseudo.dst = ip6->ip6_dst;
    pseudo.plen = htonl(len);
    pseudo.next = 58;

    uint8_t buf[512];
    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), icmp, len);

    return checksum((uint16_t *)buf, sizeof(pseudo) + len);
}

void ndp_system(struct program_interface *config,
                int sock_raw,
                struct sockaddr_ll *device,
                struct host *hosts)
{
    uint32_t global_index = 0;

    for (uint32_t i = 0; i < config->subnet_count; i++) {

        struct subnet *s = &config->subnets[i];

        if (s->family != AF_INET6) {
            continue;
        }

        struct in6_addr base = s->ip.ipv6;

        // ===== SEND NDP =====
        for (uint64_t h = 0; h < s->host_count; h++) {

            struct in6_addr target = base;


            // increment last 64 bits (simple)
            uint64_t *low = (uint64_t *)&target.s6_addr[8];
            *low = htobe64(be64toh(*low) + h);

            // ===== BUILD PACKET =====
            uint8_t buffer[128] = {0};

            struct ethernet_header *eth = (struct ethernet_header *)buffer;
            struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + sizeof(struct ethernet_header));
            struct icmpv6_ns *ns = (struct icmpv6_ns *)(ip6 + 1);
            struct ndp_opt_slla *opt = (struct ndp_opt_slla *)(ns + 1);

            struct in6_addr multicast;
            ipv6_to_solicited_multicast(&target, &multicast);

            uint8_t dest_mac[6];
            ipv6_multicast_to_mac(&multicast, dest_mac);

            // Ethernet
            memcpy(eth->ether_dest, dest_mac, 6);
            memcpy(eth->ether_src, config->mac_addr, 6);
            eth->ether_type = htons(ETH_P_IPV6);

            // IPv6
            ip6->ip6_flow = htonl(6 << 28);
            ip6->ip6_plen = htons(sizeof(struct icmpv6_ns) + sizeof(struct ndp_opt_slla));
            ip6->ip6_nxt = 58;
            ip6->ip6_hlim = 255;

            ip6->ip6_src = config->ipv6;
            ip6->ip6_dst = multicast;

            // NS
            ns->type = 135;
            ns->code = 0;
            ns->checksum = 0;
            ns->reserved = 0;
            ns->target = target;

            // Option
            opt->type = 1;
            opt->length = 1;
            memcpy(opt->mac, config->mac_addr, 6);

            // Checksum
            ns->checksum = icmp6_checksum(ip6, (uint8_t *)ns,
                sizeof(struct icmpv6_ns) + sizeof(struct ndp_opt_slla));

            // Send
            sendto(sock_raw, buffer,
                sizeof(struct ethernet_header) + sizeof(struct ip6_hdr)
                + sizeof(struct icmpv6_ns) + sizeof(struct ndp_opt_slla),
                0,
                (struct sockaddr *)device,
                sizeof(*device));

            // store host
            hosts[global_index].family = AF_INET6;
            hosts[global_index].ip.ipv6 = target;
            hosts[global_index].ndp_ok = false;

            global_index++;
        }

        // ===== RECEIVE =====
        uint8_t recvbuf[1500];
        time_t start = time(NULL);

        while ((time(NULL) - start) * 1000 < config->timeout) {

            ssize_t len = recv(sock_raw, recvbuf, sizeof(recvbuf), 0);
            if (len <= 0) continue;

            struct ethernet_header *eth = (struct ethernet_header *)recvbuf;
            if (ntohs(eth->ether_type) != ETH_P_IPV6) continue;

            struct ip6_hdr *ip6 = (struct ip6_hdr *)(recvbuf + sizeof(struct ethernet_header));
            if (ip6->ip6_nxt != 58) continue;

            uint8_t *icmp = (uint8_t *)(ip6 + 1);

            if (icmp[0] != 136) continue; // NA

            struct icmpv6_na *na = (struct icmpv6_na *)icmp;

            // ===== FIND HOST =====
            for (uint32_t k = 0; k < global_index; k++) {

                if (hosts[k].family != AF_INET6) continue;

                if (memcmp(&hosts[k].ip.ipv6, &na->target, sizeof(struct in6_addr)) == 0) {

                    uint8_t *opt = (uint8_t *)(na + 1);

                    if (opt[0] == 2) {
                        memcpy(hosts[k].mac_addr, &opt[2], 6);
                        hosts[k].ndp_ok = true;
                    }

                    break;
                }
            }
        }
    }
}


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
        // IPv6 address
        char *slash = strchr(ip_address, '/');
        if(!slash) {
            fprintf(stderr, "Missing slash (prefix) in ip address");
            exit(EXIT_FAILURE);
        }
        *slash = '\0';
        int prefix = atoi(slash+1);

        if(prefix < 110 || prefix >= 128) {
            fprintf(stderr,"prefix too small, computationally difficult to process all hosts!!!");
            exit(EXIT_FAILURE);
        }
        uint64_t host_count = 1ULL << (128-prefix);

        struct in6_addr ipv6;

        int ret = inet_pton(AF_INET6,ip_address, &ipv6);
        if(ret == 0) {
            fprintf(stderr, "Invalid format of IPv6 address");
            exit(EXIT_FAILURE);
        }
        if(ret == -1) {
            perror("inet_pton");
            exit(EXIT_FAILURE);
        }
        uint32_t value;
        memcpy(&value, &ipv6.s6_addr[12],4);
        value = ntohl(value);
        const uint32_t mask = 0xFFFFFFFF << (128-prefix);
        value &= mask;
        value = htonl(value);
        memcpy(&ipv6.s6_addr[12],&value,4);

        struct subnet *ipv6_network_ptr = &config->subnets[config->subnet_count];

        ipv6_network_ptr->family = AF_INET6;
        ipv6_network_ptr->prefix = prefix;
        ipv6_network_ptr->ip.ipv6 = ipv6;
        ipv6_network_ptr->host_count = host_count;
        config->subnet_count++;
        config->total_hostcount += host_count;
    }

    else {
        // IPv4 address
        char *slash = strchr(ip_address, '/');
        if(!slash) {
            printf("Invalid subnet");
            exit(EXIT_FAILURE);
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
            perror("Invalid format of IPv4 address, Template: xxx.xxx.xxx.xxx/zz, where zz is prefix\n");
            exit(EXIT_FAILURE);
        }
        const uint32_t mask = 0xFFFFFFFF << (32-prefix);
        struct in_addr subnet_network_address_ipv4;
        uint32_t ipv4_bin = ntohl(ipv4_binary.s_addr);
        subnet_network_address_ipv4.s_addr = mask & ipv4_bin;

        const uint32_t mask_broadcast = 0xFFFFFFFF >> prefix;
        ipv4_broadcast.s_addr = ipv4_bin | mask_broadcast;
        ipv4_broadcast.s_addr = htonl(ipv4_broadcast.s_addr);

        subnet_network_address_ipv4.s_addr = htonl(subnet_network_address_ipv4.s_addr);

        uint64_t host_count = (1ULL<<(32-prefix)) -2;
        struct subnet *subnet_ptr = &config->subnets[config->subnet_count];


        subnet_ptr->family = AF_INET;
        subnet_ptr->prefix = prefix;
        subnet_ptr->ip.ipv4 = subnet_network_address_ipv4;
        subnet_ptr->host_count = host_count;
        subnet_ptr->ipv4_broadcast = ipv4_broadcast;
        config->subnet_count++;
        config->total_hostcount += host_count;

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
                config->ipv4 = ((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr;
            }
            else if(ifa->ifa_addr->sa_family == AF_INET6) {
                config->ipv6 = ((struct sockaddr_in6 *)(ifa->ifa_addr))->sin6_addr;
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
                break;
            case 'w':
                config->timeout = atoi(optarg);
                break;
            case 'i':
                config->interface = optarg;
                get_interface_info(config);

            default:
        }
    }
}

int create_raw_socket(struct program_interface *config, struct sockaddr_ll *device) {
    // Create raw socket for ARP
    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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
        fprintf(stderr, "Interface %s not found\n", config->interface);
        exit(EXIT_FAILURE);
    }

    return sock_raw;
}


void arp_system(struct program_interface *config, struct __attribute__((packed)) arp_packet *packet, int sock_raw, struct sockaddr_ll *device, struct host *hosts) {
    // Iterating through subnets (ipv4)
    uint32_t global_index = 0;
    for(uint32_t i = 0; i <config->subnet_count; i++) {
        struct subnet *s = &config->subnets[i];

        if(s->family != AF_INET) {
            continue;
        }
        uint32_t first = ntohl(s->ip.ipv4.s_addr) + 1;
        uint32_t last = ntohl(s->ipv4_broadcast.s_addr) - 1;

        // Iterating through every address of given subnet network

        for(uint32_t ip_target = first; ip_target < last; ip_target++) {
            packet->arp.target_ip = htonl(ip_target);
            ssize_t ret = sendto(sock_raw, packet,sizeof(*packet),0,(struct sockaddr *)device,sizeof(*device));
            if(ret < 0) {
                perror("sendto");
            }
            uint32_t idx = (ip_target-first) + global_index;
            if(idx >= config->total_hostcount) {
                fprintf(stderr, "Index out of bounds: %u\n", idx);
                continue;
            }
            hosts[idx].family = AF_INET;
            hosts[idx].arp_ok = false;


        }
        uint8_t buffer[100];
        time_t start = time(NULL);

        while((time(NULL) - start)*1000 < config->timeout) {

            ssize_t len = recvfrom(sock_raw, buffer, sizeof(buffer),0,NULL,NULL);

            if(len<0) {
                perror("recvfrom");
                continue;
            }
            struct arp_packet *pkt = (struct arp_packet *)buffer;

            if(ntohs(pkt->arp.opcode) != 2) {
                continue;
            }
            if(memcmp(pkt->arp.target_mac, config->mac_addr,6) != 0 || pkt->arp.target_ip != config->ipv4.s_addr) {
                continue;
            }
            uint32_t ip = ntohl(pkt->arp.sender_ip);
            if(ip < first || ip > last) {
                continue;
            }
            uint32_t index = (ip - first) + global_index;

            if(!hosts[index].arp_ok) {
                hosts[index].arp_ok = true;
                hosts[index].ip.ipv4 = ip;
                memcpy(hosts[index].mac_addr, pkt->arp.sender_mac,6);
            }
        }
        global_index+= s->host_count;
    }
}




int main(int argc, char **argv) {
        // Global interface to store relevant network configuration
        struct program_interface config = {0};

        // Setting default network settings
        config.subnet_count = 0;
        config.timeout = 1000;

        // Processing user input
        argument_parser(argc, argv, &config);

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
        arp_hdr.sender_ip = config.ipv4.s_addr;

        memset(arp_hdr.target_mac, 0,6);

        // Packet header containing Ethernet and ARP header merged (structure prepared to be sent by socket)
        struct arp_packet packet = {0};

        // Ethernet header initial configuration (ipv4)
        memset(eth_hdr_ipv4.ether_dest, 0xff, 6);
        memcpy(eth_hdr_ipv4.ether_src, config.mac_addr, 6);
        eth_hdr_ipv4.ether_type = htons(ETH_P_ARP);

        // Ethernet header initial configuration (ipv6)
        memset(eth_hdr_ipv6.ether_dest, 0xff, 6);
        memcpy(eth_hdr_ipv6.ether_src, config.mac_addr, 6);
        eth_hdr_ipv6.ether_type = htons(ETH_P_IPV6);

        // Packet header ethernet, arp frames being set
        packet.ethernet = eth_hdr_ipv4;
        packet.arp = arp_hdr;

        // Creating raw socket for sending packets into network
        struct sockaddr_ll device;
        int sock_raw = create_raw_socket(&config, &device);
        // Allocating space for every scanned host
        struct host *hosts = calloc(config.total_hostcount, sizeof(struct host));
        if(!hosts) {
            fprintf(stderr,"No hosts for scanning");
            exit(EXIT_FAILURE);
        }
        // Sending ARP and storing arp replies (ipv4)
        arp_system(&config, &packet, sock_raw, &device,hosts);

        ndp_system(&config, sock_raw, &device, hosts);
        for(int i = 0; i < config.total_hostcount;i++) {
            if(hosts[i].family == AF_INET) {
                if(hosts[i].arp_ok) {
                    printf("ARP: ok (%u)\n", hosts[i].ip.ipv4);
                }
                else {
                    printf("ARP: failed (%u)\n", hosts[i].ip.ipv4);
                }
            }
            else if(hosts[i].family == AF_INET6) {
                if(hosts[i].ndp_ok) {
                    printf("NDP: ok");
                }
                else {
                    printf("NDP: failed");
                }
            }

        }




        free(hosts);


        return 0;
}