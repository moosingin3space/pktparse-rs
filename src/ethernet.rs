//! Handles parsing of Ethernet headers

use nom::IResult;

#[derive(Debug, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);
#[derive(Debug, PartialEq, Eq)]
pub enum EtherType {
    IPv4,
    ARP,
    IPv6,
    VLAN
}
#[derive(Debug, PartialEq, Eq)]
pub struct EthernetFrame {
    pub source_mac : MacAddress,
    pub dest_mac   : MacAddress,
    pub ethertype  : EtherType
}

fn to_ethertype(i: u16) -> Option<EtherType> {
    match i {
        0x0800 => Some(EtherType::IPv4),
        0x0806 => Some(EtherType::ARP),
        0x8100 => Some(EtherType::VLAN),
        0x86DD => Some(EtherType::IPv6),
        _ => None
    }
}

fn to_mac_address(i: &[u8]) -> MacAddress {
    MacAddress(array_ref![i,0,6].clone())
}

named!(mac_address<&[u8], MacAddress>, map!(take!(6), to_mac_address));
named!(ethertype<&[u8], EtherType>, map_opt!(u16!(true), to_ethertype));
named!(ethernet_frame<&[u8], EthernetFrame>, chain!(
    dest_mac: mac_address ~ src_mac: mac_address ~ et: ethertype,
    || EthernetFrame{source_mac: src_mac, dest_mac: dest_mac, ethertype: et}
));

pub fn parse_ethernet_frame(i: &[u8]) -> IResult<&[u8], EthernetFrame> {
    ethernet_frame(i)
}

#[cfg(test)]
mod tests {
    use super::{mac_address, ethertype, ethernet_frame, MacAddress, EtherType, EthernetFrame};
    use nom::IResult;
    const EMPTY_SLICE : &'static [u8] = &[];
    #[test]
    fn mac_address_works() {
        let bytes = [0x9c, 0x5c, 0x8e, 0x90, 0xca, 0xfc];
        assert_eq!(mac_address(&bytes), IResult::Done(EMPTY_SLICE, MacAddress(bytes)));
    }

    macro_rules! mk_ethertype_test {
        ($func_name:ident, $bytes:expr, $correct_ethertype:expr) => (
            #[test]
            fn $func_name() {
                let bytes = $bytes;
                assert_eq!(ethertype(&bytes), IResult::Done(EMPTY_SLICE, $correct_ethertype));
            }
        )
    }

    mk_ethertype_test!(ethertype_gets_ipv4_correct, [0x08, 0x00], EtherType::IPv4);
    mk_ethertype_test!(ethertype_gets_arp_correct, [0x08, 0x06], EtherType::ARP);
    mk_ethertype_test!(ethertype_gets_ipv6_correct, [0x86, 0xDD], EtherType::IPv6);
    mk_ethertype_test!(ethertype_gets_vlan_correct, [0x81, 0x00], EtherType::VLAN);

    #[test]
    fn ethernet_frame_works() {
        let bytes =
            [0x00, 0x23, 0x54, 0x07, 0x93, 0x6c, // dest MAC
             0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b, // src MAC
             0x08, 0x00]; // Ethertype
        let expectation = EthernetFrame {
            source_mac: MacAddress([0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b]),
            dest_mac: MacAddress([0x00, 0x23, 0x54, 0x07, 0x93, 0x6c]),
            ethertype: EtherType::IPv4
        };
        assert_eq!(ethernet_frame(&bytes), IResult::Done(EMPTY_SLICE, expectation));
    }
}
