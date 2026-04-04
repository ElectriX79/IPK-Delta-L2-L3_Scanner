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


/**
 * @brief Outputs every available network interface within device.
 * Function uses getifaddrs which returns linked list of all available network interfaces
 */
void print_interfaces() {
    struct ifaddrs *ifaddr, *ifa;
    if(getifaddrs(&ifaddr)==-1) {
        perror("getifaddrs");
    }
    ifa = ifaddr;
    while(ifa != NULL) {
        if(ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
            char *name = ifa->ifa_name;
            printf("%s\n", name);
        }
        ifa=ifa->ifa_next;
    }
    freeifaddrs(ifaddr);
}

/**
 * Parses subnet string (IPv4 or IPv6) and stores
 * computed network info into program configuration.
 *
 * The function:
 *  - detects whether the input is IPv4 or IPv6
 *  - extracts prefix length
 *  - computes network address
 *  - calculates number of hosts
 *  - stores everything into config->subnets
 *
 * IPv6 is limited to prefix >= 110 to avoid scanning extremely large networks.
 */
void subnet_address(char *ip_address, struct program_interface *config) {

    // If address contains ':' → IPv6, otherwise IPv4
    if(strchr(ip_address, ':') != NULL) {

        char *slash = strchr(ip_address, '/');
        if(!slash) {
            fprintf(stderr, "Missing prefix (/) in IP address\n");
            exit(EXIT_FAILURE);
        }

        *slash = '\0';
        int prefix = atoi(slash+1);

        // Prevent scanning too many IPv6 hosts
        if(prefix < 110 || prefix > 128) {
            fprintf(stderr,"IPv6 prefix too small\n");
            exit(EXIT_FAILURE);
        }

        uint64_t host_count = 1ULL << (128-prefix);

        struct in6_addr ipv6;

        // Convert string IPv6 → binary form
        int ret = inet_pton(AF_INET6, ip_address, &ipv6);
        if(ret <= 0) {
            perror("Invalid IPv6 address");
            exit(EXIT_FAILURE);
        }

        // Compute network address by clearing host bits
        // (only last 32 bits are modified here - simplified solution)
        uint32_t value;
        memcpy(&value, &ipv6.s6_addr[12], 4);

        value = ntohl(value);

        const uint32_t mask = 0xFFFFFFFF << (128 - prefix);
        value &= mask;

        value = htonl(value);
        memcpy(&ipv6.s6_addr[12], &value, 4);

        // Store subnet into config
        struct subnet *ptr = &config->subnets[config->subnet_count];

        ptr->family = AF_INET6;
        ptr->prefix = prefix;
        ptr->ip.ipv6 = ipv6;
        ptr->host_count = host_count;

        config->subnet_count++;
        config->total_hostcount += host_count;
    }

    else {
        // IPv4 branch

        char *slash = strchr(ip_address, '/');
        if(!slash) {
            printf("Invalid subnet\n");
            exit(EXIT_FAILURE);
        }

        *slash = '\0';
        int prefix = atoi((slash+1));

        if(prefix > 32 || prefix < 0) {
            printf("Invalid prefix\n");
            exit(1);
        }

        struct in_addr ipv4_binary;
        struct in_addr ipv4_broadcast;

        // Convert string IPv4 → binary
        if(inet_pton(AF_INET, ip_address, &ipv4_binary) != 1) {
            perror("Invalid IPv4 format");
            exit(EXIT_FAILURE);
        }

        uint32_t ipv4_bin = ntohl(ipv4_binary.s_addr);

        // Compute network address (zero host bits)
        const uint32_t mask = 0xFFFFFFFF << (32 - prefix);
        struct in_addr network;
        network.s_addr = htonl(mask & ipv4_bin);

        // Compute broadcast address (set host bits to 1)
        const uint32_t mask_broadcast = 0xFFFFFFFF >> prefix;
        ipv4_broadcast.s_addr = htonl(ipv4_bin | mask_broadcast);

        // Number of usable hosts (excluding network + broadcast)
        uint64_t host_count = (1ULL << (32 - prefix)) - 2;

        // Special case: /32 = single host
        if (prefix == 32) {
            host_count = 1;
        }

        struct subnet *ptr = &config->subnets[config->subnet_count];

        ptr->family = AF_INET;
        ptr->prefix = prefix;
        ptr->ip.ipv4 = network;
        ptr->host_count = host_count;
        ptr->ipv4_broadcast = ipv4_broadcast;

        config->subnet_count++;
        config->total_hostcount += host_count;
    }
}


/**
 * Retrieves IPv4, IPv6 and MAC address of selected network interface.
 * Uses getifaddrs() and searches for matching interface name.
 */
void get_interface_info(struct program_interface *config) {

    struct ifaddrs *ifaddr, *ifa;

    // Get linked list of all interfaces
    if(getifaddrs(&ifaddr) == -1) {
        fprintf(stderr, "getifaddrs\n");
        exit(1);
    }

    // Iterate through all interfaces
    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

        // Skip entries without address
        if(ifa->ifa_addr == NULL) {
            continue;
        }

        // Check if this is the interface we are looking for
        if(strcmp(ifa->ifa_name, config->interface) == 0) {

            // IPv4 address
            if(ifa->ifa_addr->sa_family == AF_INET) {
                config->ipv4 =
                    ((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr;
            }

            // IPv6 address
            else if(ifa->ifa_addr->sa_family == AF_INET6) {
                config->ipv6 =
                    ((struct sockaddr_in6 *)(ifa->ifa_addr))->sin6_addr;
            }

            // MAC address (link layer)
            else if(ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *s =
                    (struct sockaddr_ll *)ifa->ifa_addr;

                memcpy(config->mac_addr, s->sll_addr, 6);
            }
        }
    }

    freeifaddrs(ifaddr);
}

/**
 * Parses command-line arguments using getopt().
 *
 * Handles:
 *  - -i (interface)
 *  - -s (subnet, can be used multiple times)
 *  - -w (timeout)
 *  - -h (help)
 */
void argument_parser(int arg_count, char **arguments, struct program_interface *config) {

    // No arguments → show error + usage
    if (arg_count == 1) {
        fprintf(stderr, "Error: No arguments entered\n");
        print_usage();
        exit(1);
    }

    // Special case: only "-i" → list interfaces
    else if(arg_count == 2 && (strcmp(arguments[1], "-i") == 0)) {
        print_interfaces();
        exit(0);
    }

    int opt;

    // Process arguments using getopt
    while((opt = getopt(arg_count, arguments, "hi:w:s:")) != -1) {

        switch(opt) {

            // Help
            case 'h':
                print_usage();
                exit(0);

                // Subnet (can be repeated)
            case 's':
                subnet_address(optarg, config);
                break;

                // Timeout in ms
            case 'w':
                config->timeout = atoi(optarg);
                break;

                // Interface name
            case 'i':
                config->interface = optarg;

                // Immediately load interface info (IP, MAC)
                get_interface_info(config);
                break;

            default:
                // Unknown argument → ignore (getopt usually handles errors)
                break;
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


/**
 * Sends ARP requests to all IPv4 hosts and processes ARP replies.
 * Marks which hosts are alive and stores their MAC addresses.
 */
void arp_system(struct program_interface *config,
                int sock_raw,
                struct sockaddr_ll *device,
                struct host *hosts)
{
    struct ethernet_header eth_hdr_ipv4;
    struct arp_header arp_hdr;

    // ===== Prepare ARP header =====
    arp_hdr.htype = htons(ARPHRD_ETHER);
    arp_hdr.ptype = htons(ETH_P_IP);
    arp_hdr.hlen = ETH_ALEN;
    arp_hdr.plen = 4;
    arp_hdr.opcode = htons(ARPOP_REQUEST);

    memcpy(arp_hdr.sender_mac, config->mac_addr, 6);
    arp_hdr.sender_ip = config->ipv4.s_addr;
    memset(arp_hdr.target_mac, 0, 6); // unknown

    // ===== Prepare Ethernet header =====
    memset(eth_hdr_ipv4.ether_dest, 0xff, 6); // broadcast
    memcpy(eth_hdr_ipv4.ether_src, config->mac_addr, 6);
    eth_hdr_ipv4.ether_type = htons(ETH_P_ARP);

    // Combine headers into one packet
    struct arp_packet packet = {0};
    packet.ethernet = eth_hdr_ipv4;
    packet.arp = arp_hdr;

    uint32_t global_index = 0;

    // Iterate over all subnets
    for (uint32_t i = 0; i < config->subnet_count; i++) {

        struct subnet *s = &config->subnets[i];

        // Skip non-IPv4 subnets
        if (s->family != AF_INET) {
            global_index += s->host_count;
            continue;
        }

        uint32_t first, last;

        // Compute host range depending on prefix
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

        // ===== SEND ARP REQUESTS =====
        for (uint64_t h = 0; h < s->host_count; h++) {

            uint32_t ip_target = first + h;
            uint32_t idx = global_index + h;

            if (idx >= config->total_hostcount) {
                fprintf(stderr, "Index out of bounds: %u\n", idx);
                continue;
            }

            // Set target IP in ARP request
            packet.arp.target_ip = htonl(ip_target);

            // Send packet
            ssize_t ret = sendto(sock_raw, &packet, sizeof(packet), 0,
                                 (struct sockaddr *)device, sizeof(*device));

            if (ret < 0) {
                perror("sendto");
            }

            // Initialize host entry
            hosts[idx].family = AF_INET;
            hosts[idx].arp_ok = false;
            hosts[idx].ip.ipv4 = htonl(ip_target);
        }

        // ===== RECEIVE ARP REPLIES =====
        uint8_t buffer[2048];
        time_t start = time(NULL);

        // Wait for replies until timeout
        while ((time(NULL) - start) * 1000 < config->timeout) {

            ssize_t len = recvfrom(sock_raw, buffer, sizeof(buffer), 0, NULL, NULL);

            if (len < 0) {
                continue;
            }

            struct arp_packet *pkt = (struct arp_packet *)buffer;

            // Only ARP replies
            if (ntohs(pkt->arp.opcode) != ARPOP_REPLY) {
                continue;
            }

            // Check if reply is for our MAC and IP
            if (memcmp(pkt->arp.target_mac, config->mac_addr, 6) != 0 ||
                pkt->arp.target_ip != config->ipv4.s_addr) {
                continue;
            }

            uint32_t ip = ntohl(pkt->arp.sender_ip);

            // Ignore addresses outside current subnet
            if (ip < first || ip > last) {
                continue;
            }

            uint32_t index = global_index + (ip - first);

            if (index >= config->total_hostcount) {
                continue;
            }

            // Save result (only once)
            if (!hosts[index].arp_ok) {
                hosts[index].arp_ok = true;
                hosts[index].ip.ipv4 = pkt->arp.sender_ip;
                memcpy(hosts[index].mac_addr, pkt->arp.sender_mac, 6);
            }
        }

        global_index += s->host_count;
    }
}


/**
 * Sends NDP (Neighbor Discovery) requests for IPv6 hosts
 * and processes responses (Neighbor Advertisement).
 */
void ndp_system(struct program_interface *config,
                struct sockaddr_ll *device,
                int sock_raw,
                struct host *hosts)
{
    struct ndp_pkt packet;
    memset(&packet, 0, sizeof(packet));

    // ===== Ethernet header =====
    memcpy(packet.ethernet_hdr.ether_src, config->mac_addr, 6);
    packet.ethernet_hdr.ether_type = htons(ETH_P_IPV6);

    // ===== IPv6 header =====
    packet.ip6_hdr.ver_tc_fl = htonl(6 << 28); // version = 6
    packet.ip6_hdr.payload_length =
        htons(sizeof(struct icmp_v6) + sizeof(struct ndp_option));
    packet.ip6_hdr.next_header = 58; // ICMPv6
    packet.ip6_hdr.hop_limit = 255;  // must be 255 for NDP
    packet.ip6_hdr.source_ipv6 = config->ipv6;

    // ===== ICMPv6 (Neighbor Solicitation) =====
    packet.icmp_hdr.type = 135;
    packet.icmp_hdr.code = 0;
    packet.icmp_hdr.reserved = 0;

    // ===== NDP option (source MAC) =====
    packet.ndp_options.type = 1;
    packet.ndp_options.length = 1;
    memcpy(packet.ndp_options.mac, config->mac_addr, 6);

    uint64_t global_index = 0;

    // Iterate over all subnets
    for (uint32_t i = 0; i < config->subnet_count; i++) {

        struct subnet *s = &config->subnets[i];

        // Skip non-IPv6 subnets
        if (s->family != AF_INET6) {
            global_index += s->host_count;
            continue;
        }

        // Start from first host (network + 1)
        struct in6_addr current = s->ip.ipv6;
        for (int b = 15; b >= 0; b--) {
            if (++current.s6_addr[b] != 0) break;
        }

        // ===== SEND NDP REQUESTS =====
        for (uint64_t h = 0; h < s->host_count; h++) {

            uint64_t idx = global_index + h;

            if (idx >= config->total_hostcount) {
                fprintf(stderr, "NDP index out of bounds: %lu\n", idx);
                continue;
            }

            // Initialize host entry
            hosts[idx].family = AF_INET6;
            hosts[idx].ip.ipv6 = current;
            hosts[idx].ndp_ok = false;

            // Target address in ICMPv6
            packet.icmp_hdr.target = current;

            // Compute solicited-node multicast address (ff02::1:ffXX:XXXX)
            struct in6_addr multicast = {0};
            multicast.s6_addr[0]  = 0xff;
            multicast.s6_addr[1]  = 0x02;
            multicast.s6_addr[11] = 0x01;
            multicast.s6_addr[12] = 0xff;
            multicast.s6_addr[13] = current.s6_addr[13];
            multicast.s6_addr[14] = current.s6_addr[14];
            multicast.s6_addr[15] = current.s6_addr[15];

            packet.ip6_hdr.destination_ipv6 = multicast;

            // Convert multicast IPv6 → multicast MAC (33:33:ff:XX:XX:XX)
            uint8_t multicast_mac[6] = {
                0x33, 0x33, 0xff,
                current.s6_addr[13],
                current.s6_addr[14],
                current.s6_addr[15]
            };
            memcpy(packet.ethernet_hdr.ether_dest, multicast_mac, 6);

            // Compute ICMPv6 checksum
            packet.icmp_hdr.checksum = 0;
            packet.icmp_hdr.checksum = icmpv6_checksum(
                &packet.ip6_hdr.source_ipv6,
                &packet.ip6_hdr.destination_ipv6,
                (uint8_t *)&packet.icmp_hdr,
                sizeof(struct icmp_v6) + sizeof(struct ndp_option)
            );

            // Send packet
            if (sendto(sock_raw, &packet, sizeof(packet), 0,
                       (struct sockaddr *)device, sizeof(*device)) < 0) {
                perror("sendto");
            }

            // Increment IPv6 address
            for (int b = 15; b >= 0; b--) {
                if (++current.s6_addr[b] != 0) break;
            }
        }

        // ===== RECEIVE NDP RESPONSES =====
        uint8_t buffer[2048];

        struct timeval start, now;
        gettimeofday(&start, NULL);

        while (1) {

            // Check timeout (ms precision)
            gettimeofday(&now, NULL);
            int elapsed = (now.tv_sec  - start.tv_sec)  * 1000 +
                          (now.tv_usec - start.tv_usec) / 1000;

            if (elapsed > config->timeout) break;

            ssize_t len = recv(sock_raw, buffer, sizeof(buffer), MSG_DONTWAIT);
            if (len <= 0) continue;

            // Parse Ethernet header
            struct ethernet_header *eth = (struct ethernet_header *)buffer;
            if (ntohs(eth->ether_type) != ETH_P_IPV6) continue;

            // Parse IPv6 header
            struct ipv6_header *ip6 =
                (struct ipv6_header *)(buffer + sizeof(struct ethernet_header));
            if (ip6->next_header != 58) continue;

            // Parse ICMPv6
            struct icmp_v6 *icmp =
                (struct icmp_v6 *)(buffer +
                                   sizeof(struct ethernet_header) +
                                   sizeof(struct ipv6_header));

            // Only Neighbor Advertisement
            if (icmp->type != 136) continue;

            struct in6_addr target_ip = icmp->target;

            // Extract MAC from option (type 2)
            uint8_t *opt_ptr = (uint8_t *)icmp + sizeof(struct icmp_v6);
            uint8_t *mac = NULL;

            if (opt_ptr[0] == 2) {
                mac = &opt_ptr[2];
            }

            // Match response with our hosts
            for (uint64_t k = global_index;
                 k < global_index + s->host_count;
                 k++) {

                if (hosts[k].family != AF_INET6) continue;

                if (memcmp(&hosts[k].ip.ipv6,
                           &target_ip,
                           sizeof(struct in6_addr)) == 0) {

                    hosts[k].ndp_ok = true;

                    if (mac) {
                        memcpy(hosts[k].mac_addr, mac, 6);
                    }

                    break;
                }
            }
        }

        global_index += s->host_count;
    }
}


/**
 * Sends ICMP echo requests (ping) to all hosts and processes replies.
 * Works for both IPv4 (ICMP) and IPv6 (ICMPv6).
 */
void icmp_system(struct program_interface *config, struct host *hosts)
{
    // Create raw sockets for IPv4 and IPv6 ICMP
    int sock4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int sock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if (sock4 < 0 || sock6 < 0) {
        perror("ICMP socket");
        return;
    }

    // Bind sockets to selected interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, config->interface, IFNAMSIZ - 1);

    if (setsockopt(sock4, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        perror("SO_BINDTODEVICE sock4");
    }
    if (setsockopt(sock6, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        perror("SO_BINDTODEVICE sock6");
    }

    // ===== SEND ICMP REQUESTS =====
    for (uint32_t i = 0; i < config->total_hostcount; i++) {

        hosts[i].icmp_ok = false;

        // ===== IPv4 =====
        if (hosts[i].family == AF_INET) {

            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = hosts[i].ip.ipv4;

            // ICMP Echo Request
            struct icmphdr icmp = {0};
            icmp.type = ICMP_ECHO;
            icmp.code = 0;
            icmp.un.echo.id  = htons(1234);
            icmp.un.echo.sequence = htons(i);

            // Compute checksum
            icmp.checksum = icmp_checksum(&icmp, sizeof(icmp));

            sendto(sock4, &icmp, sizeof(icmp), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
        }

        // ===== IPv6 =====
        else if (hosts[i].family == AF_INET6) {

            struct sockaddr_in6 addr6 = {0};
            addr6.sin6_family   = AF_INET6;
            addr6.sin6_addr     = hosts[i].ip.ipv6;

            // Needed for link-local IPv6 addresses
            addr6.sin6_scope_id = if_nametoindex(config->interface);

            struct icmp6_hdr icmp6 = {0};
            icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
            icmp6.icmp6_code = 0;
            icmp6.icmp6_id   = htons(1234);
            icmp6.icmp6_seq  = htons(i);

            sendto(sock6, &icmp6, sizeof(icmp6), 0,
                   (struct sockaddr*)&addr6, sizeof(addr6));
        }
    }

    // ===== RECEIVE ICMP REPLIES =====
    uint8_t buffer[1500];

    struct timeval start, now;
    gettimeofday(&start, NULL);

    while (1) {

        // Check timeout
        gettimeofday(&now, NULL);
        int elapsed = (now.tv_sec  - start.tv_sec)  * 1000 +
                      (now.tv_usec - start.tv_usec) / 1000;

        if (elapsed > config->timeout) break;

        // ===== IPv4 RECEIVE =====
        ssize_t len4 = recv(sock4, buffer, sizeof(buffer), MSG_DONTWAIT);

        if (len4 > 0) {

            // Packet must contain at least IP header
            if (len4 < (ssize_t)sizeof(struct iphdr)) continue;

            struct iphdr   *ip   = (struct iphdr*)buffer;
            struct icmphdr *icmp = (struct icmphdr*)(buffer + ip->ihl * 4);

            // Only Echo Reply
            if (icmp->type == ICMP_ECHOREPLY) {

                uint32_t src_ip = ip->saddr;

                // Match reply with known hosts
                for (uint32_t i = 0; i < config->total_hostcount; i++) {
                    if (hosts[i].family == AF_INET &&
                        hosts[i].ip.ipv4 == src_ip) {

                        hosts[i].icmp_ok = true;
                        break;
                    }
                }
            }
        }

        // ===== IPv6 RECEIVE =====
        struct sockaddr_in6 addr6;
        socklen_t addrlen = sizeof(addr6);

        ssize_t len6 = recvfrom(sock6, buffer, sizeof(buffer), MSG_DONTWAIT,
                                (struct sockaddr*)&addr6, &addrlen);

        if (len6 > 0) {

            if (len6 < (ssize_t)sizeof(struct icmp6_hdr)) continue;

            struct icmp6_hdr *icmp6 = (struct icmp6_hdr*)buffer;

            // Only Echo Reply
            if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {

                // Match reply with known hosts
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

        // Network interface declaration
        struct sockaddr_ll device;

        // Socket for ARP system
        int sock_raw = create_raw_socket(&config, &device);

        // Host buffer
        struct host *hosts = calloc(config.total_hostcount, sizeof(struct host));
        if(!hosts) {
            fprintf(stderr,"No hosts for scanning");
            exit(EXIT_FAILURE);
        }
        // ARP engine
        arp_system(&config, sock_raw, &device,hosts);

        // NDP engine
        ndp_system(&config, &device, sock_raw, hosts);

        // ICMP engine
        icmp_system(&config, hosts);

        // Output engine
        print_output(&config, hosts);

        // memory deallocation
        free(hosts);

        return 0;
}