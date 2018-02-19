//! Handles parsing of IPv4 headers

use nom::{IResult, be_u8};
use nom::Endianness::Big;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(Serialize, Deserialize))]
pub enum IPv4Protocol {
    HOPOPT,
    ICMP,
    IGMP,
    GGP,
    IPINIP,
    ST,
    TCP,
    CBT,
    EGP,
    IGP,
    BBNRCCMON,
    NVPII,
    PUP,
    ARGUS,
    EMCON,
    XNET,
    CHAOS,
    UDP,
    IPV6,
    Other(u8),
}
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(Serialize, Deserialize))]
pub struct IPv4Header {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub length: u16,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: IPv4Protocol,
    pub chksum: u16,
    pub source_addr: Ipv4Addr,
    pub dest_addr: Ipv4Addr,
}

fn to_ipv4_protocol(i: u8) -> Option<IPv4Protocol> {
    match i {
        0 => Some(IPv4Protocol::HOPOPT),
        1 => Some(IPv4Protocol::ICMP),
        2 => Some(IPv4Protocol::IGMP),
        3 => Some(IPv4Protocol::GGP),
        4 => Some(IPv4Protocol::IPINIP),
        5 => Some(IPv4Protocol::ST),
        6 => Some(IPv4Protocol::TCP),
        7 => Some(IPv4Protocol::CBT),
        8 => Some(IPv4Protocol::EGP),
        9 => Some(IPv4Protocol::IGP),
        10 => Some(IPv4Protocol::BBNRCCMON),
        11 => Some(IPv4Protocol::NVPII),
        12 => Some(IPv4Protocol::PUP),
        13 => Some(IPv4Protocol::ARGUS),
        14 => Some(IPv4Protocol::EMCON),
        15 => Some(IPv4Protocol::XNET),
        16 => Some(IPv4Protocol::CHAOS),
        17 => Some(IPv4Protocol::UDP),
        41 => Some(IPv4Protocol::IPV6),
        other => Some(IPv4Protocol::Other(other)),
    }
}

pub fn to_ipv4_address(i: &[u8]) -> Ipv4Addr {
    Ipv4Addr::from(array_ref![i, 0, 4].clone())
}

named!(two_nibbles<&[u8], (u8, u8)>, bits!(pair!(take_bits!(u8, 4), take_bits!(u8, 4))));
named!(flag_frag_offset<&[u8], (u8, u16)>, bits!(pair!(take_bits!(u8, 3), take_bits!(u16, 13))));
named!(protocol<&[u8], IPv4Protocol>, map_opt!(be_u8, to_ipv4_protocol));
named!(address<&[u8], Ipv4Addr>, map!(take!(4), to_ipv4_address));

named!(ipparse<&[u8], IPv4Header>,
       do_parse!(verihl : two_nibbles >>
              tos : be_u8 >>
              length : u16!(Big) >>
              id : u16!(Big) >>
              flagfragoffset : flag_frag_offset >>
              ttl : be_u8 >>
              proto : protocol >>
              chksum : u16!(Big) >>
              src_addr : address >>
              dst_addr : address >>
              ({ IPv4Header {
                  version: verihl.0,
                  ihl: verihl.1 << 2,
                  tos: tos,
                  length: length,
                  id: id,
                  flags: flagfragoffset.0,
                  fragment_offset: flagfragoffset.1,
                  ttl: ttl,
                  protocol: proto,
                  chksum: chksum,
                  source_addr: src_addr,
                  dest_addr : dst_addr,
              }})));

pub fn parse_ipv4_header(i: &[u8]) -> IResult<&[u8], IPv4Header> {
    ipparse(i)
}

#[cfg(test)]
mod tests {
    use super::{protocol, IPv4Protocol, ipparse, IPv4Header};
    use nom::IResult;
    use std::net::Ipv4Addr;
    const EMPTY_SLICE: &'static [u8] = &[];
    macro_rules! mk_protocol_test {
        ($func_name:ident, $bytes:expr, $correct_proto:expr) => (
            #[test]
            fn $func_name() {
                let bytes = $bytes;
                assert_eq!(protocol(&bytes), IResult::Done(EMPTY_SLICE, $correct_proto));
            }
        )
    }

    mk_protocol_test!(protocol_gets_icmp_correct, [1], IPv4Protocol::ICMP);
    mk_protocol_test!(protocol_gets_tcp_correct, [6], IPv4Protocol::TCP);
    mk_protocol_test!(protocol_gets_udp_correct, [17], IPv4Protocol::UDP);

    #[test]
    fn ipparse_gets_packet_correct() {
        let bytes = [0x45, /* IP version and length = 20 */
                     0x00, /* Differentiated services field */
                     0x05, 0xdc, /* Total length */
                     0x1a, 0xe6, /* Identification */
                     0x20, 0x00, /* flags and fragment offset */
                     0x40, /* TTL */
                     0x01, /* protocol */
                     0x22, 0xed, /* checksum */
                     0x0a, 0x0a, 0x01, 0x87, /* source IP */
                     0x0a, 0x0a, 0x01, 0xb4, /* destination IP */];

        let expectation = IPv4Header {
            version: 4,
            ihl: 20,
            tos: 0,
            length: 1500,
            id: 0x1ae6,
            flags: 0x01,
            fragment_offset: 0,
            ttl: 64,
            protocol: IPv4Protocol::ICMP,
            chksum: 0x22ed,
            source_addr: Ipv4Addr::new(10, 10, 1, 135),
            dest_addr: Ipv4Addr::new(10, 10, 1, 180),
        };
        assert_eq!(ipparse(&bytes), IResult::Done(EMPTY_SLICE, expectation));
    }
}
