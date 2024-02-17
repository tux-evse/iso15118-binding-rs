use crate::prelude::*;
use std::net;

#[test]
fn sdp_decode() {
    // sdp record data bytes sample (TCP/No-TLS)
    let data_in: SdpRequestBuffer = [0x01, 0xfe, 0x90, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00];

    let request = SdpRequest::new(&data_in).expect("valid sdp request");
    request.check_header().expect("valid header");

    println!(
        "sdp request transport:{:?} security:{:?}",
        &request.get_transport(),
        request.get_security()
    )
}

#[test]
fn sdp_encode() {
    // sdp reponse data bytes sample for ip:[0xfe80::1:2:3:4:5:6:7] port:0xaabb
    let expected: SdpResponseBuffer = [
        1, 0xfe, 0x90, 1, 0, 0, 0, 0x14, 0xfe, 0x80, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0,
        0, 0xbb, 0xaa,
    ];

    let fake_ipv6 = IfaceAddr6 {
        addr: net::Ipv6Addr::new(0xfe80, 1, 2, 3, 4, 5, 6, 7),
        scope: 00,
    };

    let port = 0xaabb;

    let response = SdpResponse::new(&fake_ipv6, port);
    let buffer = response.encode().expect("valid ipv6");
    println!("encoded buffer= {:x?}", buffer);
    assert!(buffer == expected)
}
