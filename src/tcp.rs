//! Handles parsing of TCP headers

use nom::{be_u8, IResult, Needed};
use nom::Endianness::Big;

// TCP Header Format
//
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          Source Port          |       Destination Port        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                        Sequence Number                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Acknowledgment Number                      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Data |           |U|A|P|R|S|F|                               |
//   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//   |       |           |G|K|H|T|N|N|                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |           Checksum            |         Urgent Pointer        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Options                    |    Padding    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                             data                              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// TCP Flags:
//    URG:  Urgent Pointer field significant
//    ACK:  Acknowledgment field significant
//    PSH:  Push Function
//    RST:  Reset the connection
//    SYN:  Synchronize sequence numbers
//    FIN:  No more data from sender


const END_OF_OPTIONS: u8 =  0;
const NO_OP: u8 = 1;
const MSS: u8 = 2;
const WINDOW_SCALE: u8 = 3;
const SACK_PERMITTED: u8 = 4;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TcpOption {
    EndOfOptions,
    NoOperation,
    MaximumSegmentSize(MaximumSegmentSize),
    WindowScale(WindowScale),
    SackPermitted,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MaximumSegmentSize {
    pub mss: u16,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct WindowScale {
    pub scaling: u8,
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct TcpHeader {
    pub source_port: u16,
    pub dest_port: u16,
    pub sequence_no: u32,
    pub ack_no: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flag_urg: bool,
    pub flag_ack: bool,
    pub flag_psh: bool,
    pub flag_rst: bool,
    pub flag_syn: bool,
    pub flag_fin: bool,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Option<Vec<TcpOption>>,
}
named!(dataof_res_flags<&[u8], (u8, u8, u8)>,
    bits!(tuple!(
        take_bits!(u8, 4),
        take_bits!(u8, 6),
        take_bits!(u8, 6))));

named!(tcp_parse<&[u8], TcpHeader>,
            chain!(src: u16!(Big) ~
              dst: u16!(Big) ~
              seq: u32!(Big) ~
              ack: u32!(Big) ~
              dataof_res_flags : dataof_res_flags ~
              window : u16!(Big) ~
              checksum : u16!(Big) ~
              urgent_ptr : u16!(Big),
              || {
                  TcpHeader {
                  source_port: src,
                  dest_port : dst,
                  sequence_no : seq,
                  ack_no : ack,
                  data_offset : dataof_res_flags.0,
                  reserved : dataof_res_flags.1,
                  flag_urg : dataof_res_flags.2 & 0b100000 == 0b100000,
                  flag_ack : dataof_res_flags.2 & 0b010000 == 0b010000,
                  flag_psh : dataof_res_flags.2 & 0b001000 == 0b001000,
                  flag_rst : dataof_res_flags.2 & 0b000100 == 0b000100,
                  flag_syn : dataof_res_flags.2 & 0b000010 == 0b000010,
                  flag_fin : dataof_res_flags.2 & 0b000001 == 0b000001,
                  window : window,
                  checksum : checksum,
                  urgent_pointer : urgent_ptr,
                  options : None
              }}));


named!(tcp_parse_option<&[u8], TcpOption>,
        switch!(be_u8,
            END_OF_OPTIONS => chain!(take!(0),
                || TcpOption::EndOfOptions)
            | NO_OP =>  chain!(take!(0),
                || TcpOption::NoOperation)
            | MSS => chain!(_len: be_u8 ~
                mss: u16!(Big),
                || TcpOption::MaximumSegmentSize(MaximumSegmentSize{mss: mss}))
            | WINDOW_SCALE => chain!(_len: be_u8 ~
                scaling: be_u8,
                || TcpOption::WindowScale(WindowScale{scaling: scaling}))
            | SACK_PERMITTED => chain!(_len: be_u8,
                  || TcpOption::SackPermitted)
            ));

fn tcp_parse_options(i: &[u8]) -> IResult<&[u8], Vec<TcpOption>> {
    let mut left = i;
    let mut options: Vec<TcpOption> = vec![];
    loop {
        match tcp_parse_option(left) {
            IResult::Done(l, opt) => {
                left = l;
                options.push(opt);

                if let TcpOption::EndOfOptions = opt {
                    break;
                }
            }

            IResult::Incomplete(e) => {
                return IResult::Incomplete(e);
            }
            IResult::Error(e) => {
                return IResult::Error(e);
            }
        }
    }

    IResult::Done(left, options)
}

pub fn parse_tcp_header(i: &[u8]) -> IResult<&[u8], TcpHeader> {
    match tcp_parse(i) {
        IResult::Done(left, mut tcp_header) => {
            // Offset in words (at least 5)
            if tcp_header.data_offset > 5 {
                let options_length = ((tcp_header.data_offset - 5) * 4) as usize;
                if options_length <= left.len() {
                    if let IResult::Done(_, options) = tcp_parse_options(&left[0..options_length]) {
                        tcp_header.options = Some(options);
                        return IResult::Done(&left[options_length..], tcp_header);
                    }
                    IResult::Done(&left[options_length..], tcp_header)
                } else {
                    IResult::Incomplete(Needed::Size(options_length - left.len()))
                }
            } else {
                IResult::Done(left, tcp_header)
            }
        }

        e => e,
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use nom::IResult;

    const EMPTY_SLICE: &'static [u8] = &[];

    #[test]
    fn test_tcp_parse() {
        let bytes = [0xc2, 0x1f, /* Source port */
                     0x00, 0x50, /* Dest port */
                     0x0f, 0xd8, 0x7f, 0x4c, /* Seq no */
                     0xeb, 0x2f, 0x05, 0xc8, /* Ack no */
                     0x50, 0x18, 0x01, 0x00, /* Window */
                     0x7c, 0x29, /* Checksum */
                     0x00, 0x00 /* Urgent pointer */];

        let expectation = TcpHeader {
            source_port: 49695,
            dest_port: 80,
            sequence_no: 0x0fd87f4c,
            ack_no: 0xeb2f05c8,
            data_offset: 5,
            reserved: 0,
            flag_urg: false,
            flag_ack: true,
            flag_psh: true,
            flag_rst: false,
            flag_syn: false,
            flag_fin: false,
            window: 256,
            checksum: 0x7c29,
            urgent_pointer: 0,
            options: None,
        };

        assert_eq!(parse_tcp_header(&bytes), IResult::Done(EMPTY_SLICE, expectation));
    }
}
