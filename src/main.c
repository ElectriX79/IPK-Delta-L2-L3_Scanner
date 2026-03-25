#define _GNU_SOURCE
#include "../include/main.h"
#include "../include/helper_functions.h"

void print_usage() {
    printf("Usage:\n");
    printf("  ./ipk-L2L3-scan -i INTERFACE [-s SUBNET]... [-w TIMEOUT] [-h | --help]\n\n");

    printf("Options:\n");
    printf("  -i <interface>   Network interface to use\n");
    printf("                   If used alone, prints available interfaces\n\n");

    printf("  -s <subnet>      Subnet to scan (IPv4 or IPv6)\n");
    printf("                   Example: 192.168.1.0/24 or fd00::/120\n");
    printf("                   Can be used multiple times\n\n");

    printf("  -w <timeout>     Timeout in ms (default: 1000)\n\n");

    printf("  -h, --help       Show this help message\n");
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

        if(prefix < 110 || prefix > 128) {
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
        if (prefix == 32) {
            host_count = 1;
        }
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


void arp_system(struct program_interface *config,
                int sock_raw,
                struct sockaddr_ll *device,
                struct host *hosts)
{
    struct ethernet_header eth_hdr_ipv4;
    struct arp_header arp_hdr;

    // ===== ARP HEADER =====
    arp_hdr.htype = htons(ARPHRD_ETHER);
    arp_hdr.ptype = htons(ETH_P_IP);
    arp_hdr.hlen = ETH_ALEN;
    arp_hdr.plen = 4;
    arp_hdr.opcode = htons(ARPOP_REQUEST);

    memcpy(arp_hdr.sender_mac, config->mac_addr, 6);
    arp_hdr.sender_ip = config->ipv4.s_addr;
    memset(arp_hdr.target_mac, 0, 6);

    // ===== ETHERNET HEADER =====
    memset(eth_hdr_ipv4.ether_dest, 0xff, 6);
    memcpy(eth_hdr_ipv4.ether_src, config->mac_addr, 6);
    eth_hdr_ipv4.ether_type = htons(ETH_P_ARP);

    struct arp_packet packet = {0};
    packet.ethernet = eth_hdr_ipv4;
    packet.arp = arp_hdr;

    uint32_t global_index = 0;

    for (uint32_t i = 0; i < config->subnet_count; i++) {

        struct subnet *s = &config->subnets[i];

        if (s->family != AF_INET) {
            global_index += s->host_count;
            continue;
        }

        uint32_t first, last;

        // ===== EDGE CASES =====
        if (s->prefix == 32) {
            first = ntohl(s->ip.ipv4.s_addr);
            last  = first;
        }
        else if (s->prefix == 31) {
            first = ntohl(s->ip.ipv4.s_addr);
            last  = first + 1;
        }
        else {
            first = ntohl(s->ip.ipv4.s_addr) + 1;
            last  = ntohl(s->ipv4_broadcast.s_addr) - 1;
        }

        // ===== SEND =====
        for (uint64_t h = 0; h < s->host_count; h++) {

            uint32_t ip_target = first + h;
            uint32_t idx = global_index + h;

            if (idx >= config->total_hostcount) {
                fprintf(stderr, "Index out of bounds: %u\n", idx);
                continue;
            }

            packet.arp.target_ip = htonl(ip_target);

            ssize_t ret = sendto(sock_raw,&packet,sizeof(packet),0,(struct sockaddr *)device,sizeof(*device));

            if (ret < 0) {
                perror("sendto");
            }

            hosts[idx].family = AF_INET;
            hosts[idx].arp_ok = false;
            hosts[idx].ip.ipv4 = htonl(ip_target); // network order
        }

        // ===== RECEIVE =====
        uint8_t buffer[2048];
        time_t start = time(NULL);

        while ((time(NULL) - start) * 1000 < config->timeout) {

            ssize_t len = recvfrom(sock_raw, buffer, sizeof(buffer), 0, NULL, NULL);

            if (len < 0) {
                continue;
            }

            struct arp_packet *pkt = (struct arp_packet *)buffer;

            // only ARP reply
            if (ntohs(pkt->arp.opcode) != ARPOP_REPLY) {
                continue;
            }

            // must be for us
            if (memcmp(pkt->arp.target_mac, config->mac_addr, 6) != 0 ||
                pkt->arp.target_ip != config->ipv4.s_addr) {
                continue;
            }

            uint32_t ip = ntohl(pkt->arp.sender_ip);

            if (ip < first || ip > last) {
                continue;
            }

            uint32_t index = global_index + (ip - first);

            if (index >= config->total_hostcount) {
                continue;
            }

            if (!hosts[index].arp_ok) {
                hosts[index].arp_ok = true;
                hosts[index].ip.ipv4 = pkt->arp.sender_ip; // network order
                memcpy(hosts[index].mac_addr, pkt->arp.sender_mac, 6);
            }
        }

        global_index += s->host_count;
    }
}


void ndp_system(struct program_interface *config,
                struct sockaddr_ll *device,
                int sock_raw,
                struct host *hosts)
{
    struct ndp_pkt packet;
    memset(&packet, 0, sizeof(packet));

    // ===== Ethernet =====
    memcpy(packet.ethernet_hdr.ether_src, config->mac_addr, 6);
    packet.ethernet_hdr.ether_type = htons(ETH_P_IPV6);

    // ===== IPv6 =====
    packet.ip6_hdr.ver_tc_fl = htonl(6 << 28);
    packet.ip6_hdr.payload_length =
        htons(sizeof(struct icmp_v6) + sizeof(struct ndp_option));
    packet.ip6_hdr.next_header = 58;
    packet.ip6_hdr.hop_limit = 255;
    packet.ip6_hdr.source_ipv6 = config->ipv6;

    // ===== ICMPv6 =====
    packet.icmp_hdr.type = 135;
    packet.icmp_hdr.code = 0;
    packet.icmp_hdr.reserved = 0;

    // ===== NDP Option =====
    packet.ndp_options.type = 1;
    packet.ndp_options.length = 1;
    memcpy(packet.ndp_options.mac, config->mac_addr, 6);

    uint64_t global_index = 0;

    for (uint32_t i = 0; i < config->subnet_count; i++) {

        struct subnet *s = &config->subnets[i];

        // ================= SKIP IPv4 =================
        if (s->family != AF_INET6) {
            global_index += s->host_count;
            continue;
        }

        struct in6_addr current = s->ip.ipv6;

        // ================= SEND =================
        for (uint64_t h = 0; h < s->host_count; h++) {

            uint64_t idx = global_index + h;

            if (idx >= config->total_hostcount) {
                fprintf(stderr, "NDP index out of bounds: %lu\n", idx);
                continue;
            }

            // ===== uloženie hosta =====
            hosts[idx].family = AF_INET6;
            hosts[idx].ip.ipv6 = current;
            hosts[idx].ndp_ok = false;

            // ===== target =====
            packet.icmp_hdr.target = current;

            // ===== multicast IPv6 =====
            struct in6_addr multicast;
            memset(&multicast, 0, sizeof(multicast));

            multicast.s6_addr[0] = 0xff;
            multicast.s6_addr[1] = 0x02;
            multicast.s6_addr[11] = 0x01;
            multicast.s6_addr[12] = 0xff;
            multicast.s6_addr[13] = current.s6_addr[13];
            multicast.s6_addr[14] = current.s6_addr[14];
            multicast.s6_addr[15] = current.s6_addr[15];

            packet.ip6_hdr.destination_ipv6 = multicast;

            // ===== multicast MAC =====
            uint8_t multicast_mac[6] = {
                0x33, 0x33, 0xff,
                current.s6_addr[13],
                current.s6_addr[14],
                current.s6_addr[15]
            };

            memcpy(packet.ethernet_hdr.ether_dest, multicast_mac, 6);

            // ===== checksum =====
            packet.icmp_hdr.checksum = 0;
            packet.icmp_hdr.checksum = icmpv6_checksum(
                &packet.ip6_hdr.source_ipv6,
                &packet.ip6_hdr.destination_ipv6,
                (uint8_t *)&packet.icmp_hdr,
                sizeof(struct icmp_v6) + sizeof(struct ndp_option)
            );

            // ===== send =====
            if (sendto(sock_raw, &packet, sizeof(packet), 0,
                       (struct sockaddr *)device, sizeof(*device)) < 0) {
                perror("sendto");
            }

            // ===== increment IPv6 =====
            for (int b = 15; b >= 0; b--) {
                if (++current.s6_addr[b] != 0) break;
            }
        }

        // ================= RECEIVE =================
        uint8_t buffer[2048];
        time_t start = time(NULL);

        while ((time(NULL) - start) * 1000 < config->timeout) {

            ssize_t len = recv(sock_raw, buffer, sizeof(buffer), 0);
            if (len < 0) continue;

            struct ethernet_header *eth = (struct ethernet_header *)buffer;
            if (ntohs(eth->ether_type) != ETH_P_IPV6) continue;

            struct ipv6_header *ip6 =
                (struct ipv6_header *)(buffer + sizeof(struct ethernet_header));
            if (ip6->next_header != 58) continue;

            struct icmp_v6 *icmp =
                (struct icmp_v6 *)(buffer +
                                  sizeof(struct ethernet_header) +
                                  sizeof(struct ipv6_header));

            if (icmp->type != 136) continue; // NA

            struct in6_addr sender_ip = ip6->source_ipv6;

            uint8_t *opt_ptr = (uint8_t *)icmp + sizeof(struct icmp_v6);

            if (opt_ptr[0] != 2) continue;

            uint8_t *mac = &opt_ptr[2];

            // ===== MATCH HOST =====
            for (uint64_t k = global_index;
                 k < global_index + s->host_count;
                 k++) {

                if (hosts[k].family != AF_INET6) continue;

                if (memcmp(&hosts[k].ip.ipv6,
                           &sender_ip,
                           sizeof(struct in6_addr)) == 0) {

                    hosts[k].ndp_ok = true;
                    memcpy(hosts[k].mac_addr, mac, 6);
                    break;
                }
            }
        }

        global_index += s->host_count;
    }
}

void icmp_system(struct program_interface *config, struct host *hosts)
{
    int sock4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int sock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if (sock4 < 0 || sock6 < 0) {
        perror("ICMP socket");
        return;
    }

    // ===== SEND =====
    for (uint32_t i = 0; i < config->total_hostcount; i++) {

        hosts[i].icmp_ok = false;

        // ===== IPv4 =====
        if (hosts[i].family == AF_INET) {

            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = hosts[i].ip.ipv4;

            struct icmphdr icmp = {0};
            icmp.type = ICMP_ECHO;
            icmp.code = 0;
            icmp.un.echo.id = htons(1234);
            icmp.un.echo.sequence = htons(i);

            icmp.checksum = icmp_checksum(&icmp, sizeof(icmp));

            sendto(sock4, &icmp, sizeof(icmp), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
        }

        // ===== IPv6 =====
        else if (hosts[i].family == AF_INET6) {

            struct sockaddr_in6 addr6 = {0};
            addr6.sin6_family = AF_INET6;
            addr6.sin6_addr = hosts[i].ip.ipv6;

            struct icmp6_hdr icmp6 = {0};
            icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
            icmp6.icmp6_code = 0;
            icmp6.icmp6_id = htons(1234);
            icmp6.icmp6_seq = htons(i);

            sendto(sock6, &icmp6, sizeof(icmp6), 0,
                   (struct sockaddr*)&addr6, sizeof(addr6));
        }
    }

    // ===== RECEIVE =====
    uint8_t buffer[1500];

    struct timeval start, now;
    gettimeofday(&start, NULL);

    while (1) {

        gettimeofday(&now, NULL);
        int elapsed = (now.tv_sec - start.tv_sec) * 1000 +
                      (now.tv_usec - start.tv_usec) / 1000;

        if (elapsed > config->timeout)
            break;

        // ===== IPv4 RECV =====
        ssize_t len4 = recv(sock4, buffer, sizeof(buffer), MSG_DONTWAIT);

        if (len4 > 0) {

            if (len4 < sizeof(struct iphdr)) continue;

            struct iphdr *ip = (struct iphdr*)buffer;
            struct icmphdr *icmp = (struct icmphdr*)(buffer + ip->ihl * 4);

            if (icmp->type == ICMP_ECHOREPLY) {

                uint32_t src_ip = ip->saddr;

                for (uint32_t i = 0; i < config->total_hostcount; i++) {
                    if (hosts[i].family == AF_INET &&
                        hosts[i].ip.ipv4 == src_ip) {

                        hosts[i].icmp_ok = true;
                        break;
                    }
                }
            }
        }

        // ===== IPv6 RECV =====
        ssize_t len6 = recv(sock6, buffer, sizeof(buffer), MSG_DONTWAIT);

        if (len6 > 0) {

            if (len6 < sizeof(struct icmp6_hdr)) continue;

            struct icmp6_hdr *icmp6 = (struct icmp6_hdr*)buffer;

            if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {

                // pri IPv6 potrebujeme zdroj z recvfrom
                struct sockaddr_in6 addr6;
                socklen_t addrlen = sizeof(addr6);

                recvfrom(sock6, buffer, sizeof(buffer), MSG_DONTWAIT,
                         (struct sockaddr*)&addr6, &addrlen);

                for (uint32_t i = 0; i < config->total_hostcount; i++) {
                    if (hosts[i].family == AF_INET6 &&
                        memcmp(&hosts[i].ip.ipv6,
                               &addr6.sin6_addr,
                               sizeof(struct in6_addr)) == 0) {

                        hosts[i].icmp_ok = true;
                        break;
                    }
                }
            }
        }
    }

    close(sock4);
    close(sock6);
}

void mac_to_string_dash(uint8_t *mac, char *out) {
    sprintf(out, "%02x-%02x-%02x-%02x-%02x-%02x",
            mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
}

void print_output(struct program_interface *config, struct host *hosts) {

    char ip_str[INET6_ADDRSTRLEN];
    char net_str[INET6_ADDRSTRLEN];
    char mac_str[32];

    // ===== 1. SCANNING RANGES =====
    printf("Scanning ranges:\n");

    for (uint32_t i = 0; i < config->subnet_count; i++) {

        struct subnet *s = &config->subnets[i];

        if (s->family == AF_INET) {

            inet_ntop(AF_INET, &s->ip.ipv4, net_str, sizeof(net_str));
            printf("%s/%d %lu\n", net_str, s->prefix, s->host_count);

        } else if (s->family == AF_INET6) {

            inet_ntop(AF_INET6, &s->ip.ipv6, net_str, sizeof(net_str));
            printf("%s/%d %lu\n", net_str, s->prefix, s->host_count);
        }
    }

    printf("\n"); // PRESNE JEDEN PRÁZDNY RIADOK

    // ===== 2. SCAN RESULTS =====

    for (uint32_t i = 0; i < config->total_hostcount; i++) {

        // ===== IP =====
        if (hosts[i].family == AF_INET) {

            struct in_addr addr;
            addr.s_addr = hosts[i].ip.ipv4;
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

            printf("%s ", ip_str);

            // ===== ARP =====
            if (hosts[i].arp_ok) {
                mac_to_string_dash(hosts[i].mac_addr, mac_str);
                printf("arp OK (%s)", mac_str);
            } else {
                printf("arp FAIL");
            }

            // ===== ICMPv4 =====
            if (hosts[i].icmp_ok) {
                printf(", icmpv4 OK\n");
            } else {
                printf(", icmpv4 FAIL\n");
            }
        }

        else if (hosts[i].family == AF_INET6) {

            inet_ntop(AF_INET6, &hosts[i].ip.ipv6, ip_str, sizeof(ip_str));

            printf("%s ", ip_str);

            // ===== NDP =====
            if (hosts[i].ndp_ok) {
                mac_to_string_dash(hosts[i].mac_addr, mac_str);
                printf("ndp OK (%s)", mac_str);
            } else {
                printf("ndp FAIL");
            }

            // ===== ICMPv6 =====
            if (hosts[i].icmp_ok) {
                printf(", icmpv6 OK\n");
            } else {
                printf(", icmpv6 FAIL\n");
            }
        }
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
        arp_system(&config, sock_raw, &device,hosts);
        ndp_system(&config, &device, sock_raw, hosts);
        icmp_system(&config, hosts);
        print_output(&config, hosts);



        free(hosts);


        return 0;
}