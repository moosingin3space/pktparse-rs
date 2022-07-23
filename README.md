# PktParse
This repository is just a bunch of packet parsing routines made with [nom](https://github.com/Geal/nom)
## Usage
Admitting your `packet.data` is an `[u8]`:
```rust
        if let Done(remaining, eth_frame) = ethernet::parse_ethernet_frame(packet.data) {
            if eth_frame.ethertype != EtherType::IPv4 {
                continue;
            }
            if let Done(remaining, ipv4_packet) = ipv4::parse_ipv4_header(remaining) {
```
For now the list of available parsers is rather short:
- ethernet (with optional VLAN tag)
- IPv4
- IPv6
- UDP
- TCP
- ICMP
... and we'll gladly accept contributions.

## Last changes

- IHL is not multiplied by 4 anymore
