# Changelog

## [1.0.0] - 2026-03-25

### Added
- Complete L2/L3 scanner implementation
- ARP scanning (IPv4)
- NDP scanning (IPv6)
- ICMPv4 and ICMPv6 support
- Output engine for formatted scan results
- IPv6 subnet parsing
- README documentation
- Makefile for building the project
- Test scripts for automated verification

### Improved
- Output formatting aligned with specification
- Handling of edge cases (/32, /31, /128 networks)
- Argument parsing and CLI usability
- Overall project structure and readability

---

## [0.5.0] - 2026-03-21

### Added
- ICMP scanning engine (IPv4 and IPv6)

---

## [0.4.0] - 2026-03-20

### Added
- NDP (Neighbor Discovery Protocol) implementation for IPv6

---

## [0.3.0] - 2026-03-19

### Added
- IPv6 subnet parsing support

---

## [0.2.0] - 2026-03-18

### Added
- ARP reply handling and host state tracking
- ARP request generation for all target IPs
- Ethernet and ARP packet crafting

---

## [0.1.0] - 2026-03-14

### Added
- IPv4 subnet processing
- Basic argument parsing
- Interface listing functionality

---

## [0.0.1] - 2026-03-13

### Added
- Initial project structure
- main.c setup
- .gitignore and repository cleanup