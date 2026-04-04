# IPK Project 1 – L2/L3 Scanner

This application scans network segments and detects active hosts on Layer 2 and Layer 3.  
It uses ARP (IPv4) and NDP (IPv6) for L2 discovery and ICMP/ICMPv4/ICMPv6 for L3 reachability.

The program is implemented in C and uses raw sockets with manually crafted packets.

---

## Build and Run

Build:
make

Run:
sudo ./ipk-L2L3-scan -i eth0 -s 192.168.1.0/24

Root privileges are required due to the use of raw sockets.

---

## Usage

./ipk-L2L3-scan -i INTERFACE [-s SUBNET]... [-w TIMEOUT] [-h | --help]

- -i <interface>  
  Network interface to use.  
  If used without additional parameters, prints available interfaces.

- -s <subnet>  
  Subnet to scan (IPv4 or IPv6).  
  Examples: 192.168.1.0/24, fd00::/120  
  Can be used multiple times.

- -w <timeout>  
  Timeout in milliseconds (default: 1000).

- -h, --help  
  Displays help and exits.

All arguments can be used in any order.

---

## Examples

./ipk-L2L3-scan -i eth0 -s 192.168.0.0/24  
./ipk-L2L3-scan -i eth0 -w 2000 -s 192.168.0.0/25 -s fd00::/120

---

## Architecture and Workflow

The application is divided into several logical parts:

- argument parsing and validation
- subnet processing (IPv4 and IPv6)
- interface information retrieval (IP, MAC)
- ARP scanning (IPv4)
- NDP scanning (IPv6)
- ICMP scanning (L3 reachability)
- output formatting

Workflow:
1. Parse CLI arguments
2. Load interface configuration
3. Generate target addresses from subnets
4. Send ARP/NDP requests
5. Collect responses
6. Send ICMP echo requests
7. Print results

---

## Implementation Details

- Ethernet, ARP, IPv6 and ICMP headers are constructed manually
- ARP uses broadcast Ethernet frames
- NDP uses ICMPv6 Neighbor Solicitation (type 135)
- IPv6 multicast addresses are generated 
- ICMPv4 uses raw sockets (IPPROTO_ICMP)
- ICMPv6 uses raw sockets (IPPROTO_ICMPV6)
- Checksums are computed manually
- Endianness is handled using htonl, ntohl
- No external packet crafting libraries (e.g., libnet) are used

---

## Output Format

The output consists of two sections:

1. Scanning ranges
2. Scan results

Example:

Scanning ranges:
192.168.0.0/30 2

192.168.0.1 arp OK (00-50-56-f1-c7-1b), icmpv4 OK
192.168.0.2 arp FAIL, icmpv4 FAIL

Each result contains:
- IP address
- ARP/NDP result (OK + MAC or FAIL)
- ICMP result (OK or FAIL)

---

## Testing

The application was tested in a controlled environment using Linux network namespaces
and real network interfaces.

1. Basic functionality tests

Tested correct behavior of CLI arguments:

./ipk-L2L3-scan -h
prints help and exits
./ipk-L2L3-scan -i
prints list of available interfaces
./ipk-L2L3-scan -i <interface>
loads interface information (IP, MAC)

Tested invalid inputs:

missing arguments
invalid subnet format
invalid prefix
2. IPv4 (ARP + ICMP) tests

Example:

./ipk-L2L3-scan -i eth0 -s 192.168.1.0/24

Verified:

ARP requests are sent to all hosts
ARP replies are correctly processed
MAC addresses are stored
ICMP echo requests are sent
ICMP replies mark hosts as reachable

Used tools:

tcpdump -i eth0 arp
tcpdump -i eth0 icmp
3. IPv6 (NDP + ICMPv6) tests

Example:

./ipk-L2L3-scan -i eth0 -s fd00::/120

Verified:

Neighbor Solicitation packets are sent
correct multicast addresses are generated
Neighbor Advertisement responses are processed
MAC addresses are extracted
ICMPv6 works correctly

Used tools:

tcpdump -i eth0 icmp6
4. Virtual network testing

Testing environment created using Linux network namespaces:

ip netns add ns1
ip netns add ns2

ip link add veth1 type veth peer name veth2

ip link set veth1 netns ns1
ip link set veth2 netns ns2

ip netns exec ns1 ip addr add 192.168.1.1/24 dev veth1
ip netns exec ns2 ip addr add 192.168.1.2/24 dev veth2

ip netns exec ns1 ip link set veth1 up
ip netns exec ns2 ip link set veth2 up

This allowed controlled testing of:

ARP replies
ICMP responses
multiple hosts simulation

---

## Limitations

- IPv6 scanning is limited to prefixes ≥ 110 to avoid excessive host counts
- The scanner is single-threaded
- Requires direct access to the target network (no routed scanning)

---


## Author

Samuel Chovan