#[macro_use]
extern crate nom;
extern crate pktparse;

mod tests {
    use nom::IResult::Done;
    use pktparse::{ethernet, ipv4, tcp};
    use pktparse::ipv4::{IPv4Header, IPv4Address, IPv4Protocol};
    use pktparse::ethernet::{EthernetFrame, MacAddress, EtherType};

    #[test]
    fn parse_tcp_packet() {
    
        let bytes = [
           0x45, 0x00, 0x00, 0x38, 0x76, 0xf4, 0x40, 0x00, 0x40, 0x06, 0x80, 0xd9, 0xc0, 0xa8, 0x00, 
           0x6c, 0xd0, 0x61, 0xb1, 0x7c, 0xb0, 0xc2, 0x00, 0x50, 0xb0, 0xee, 0x32, 0xa6, 0x04, 0x39, 
           0xae, 0xe6, 0x50, 0x18, 0x00, 0xe5, 0x76, 0x92, 0x00, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2f, 
           0x69, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x0a];
        
        if let Done(remaining, ip_hdr) = ipv4::parse_ipv4_header(&bytes) {
            if let Done(remaining, tcp_hdr) = tcp::parse_tcp_header(remaining) {
                assert_eq!(tcp_hdr.source_port, 45250);
                assert_eq!(tcp_hdr.dest_port, 80);
                assert_eq!(&remaining[..], b"GET /index.html\x0a");
            }
            else {
                assert!(false);
            }
        } else {
            assert!(false);
        }
    }
}
