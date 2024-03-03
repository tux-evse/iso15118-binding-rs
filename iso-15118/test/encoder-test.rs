use crate::prelude::*;
use std::net;

#[test]
fn sdp_decode() {
    // sdp record data bytes sample (TCP/No-TLS)
    let data_in: SdpRequestBuffer = [0x01, 0xfe, 0x90, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00];

    println!("decoding buffer= {:x?}", &data_in);
    let request = SdpRequest::new(&data_in).expect("valid sdp request");
    request.check_header().expect("valid header");

    println!(
        "sdp request transport:{:?} security:{:?}",
        &request.get_transport(),
        &request.get_security()
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

    let response = SdpResponse::new(
        &fake_ipv6,
        port,
        SdpTransportProtocol::TCP,
        SdpSecurityModel::TLS,
    );
    let buffer = response.encode().expect("valid ipv6");
    println!("encoded buffer= {:x?}", buffer);
    assert!(buffer == expected)
}

#[test]
fn app_hand_decode_everest() {
    // extract from Everest test suite
    let _result = "{AppHandProtocols
        { 'name_space': 'urn:iso:std:iso:15118:-20:AC',
            version_number_major: 1,
            version_number_minor: 0,
            schema_id: 1,
            priority: 1
        }
    }";
    let exi_data = [
        0x01, 0xfe, 0x80, 0x01, 0x00, 0x00, 0x00, 0x44, // vg2tp header
        0x80, 0x00, 0xf3, 0xab, 0x93, 0x71, 0xd3, 0x4b, 0x9b, 0x79, 0xd3, 0x9b, 0xa3, 0x21, 0xd3,
        0x4b, 0x9b, 0x79, 0xd1, 0x89, 0xa9, 0x89, 0x89, 0xc1, 0xd1, 0x69, 0x91, 0x81, 0xd2, 0x0a,
        0x18, 0x01, 0x00, 0x00, 0x04, 0x00, 0x40,
    ];

    // create a new stream with attached 8KB buffer
    let stream = ExiStream::new();

    // simulate network data read
    // preempt stream mutex
    // feed stream buffer (server should use zero copy)
    // free stream mutex
    {
        let mut handle = stream.get_handle();
        handle.buffer[0..exi_data.len()].copy_from_slice(&exi_data);
    }

    // check V2G header (should be donne before finalize to get doc len)
    let doc_size = stream.header_check().expect("expect valid V2G header");

    // validate buffer stream (exec data may come in multiple chucks)
    stream
        .finalize(doc_size)
        .expect("expect valid stream handle");

    // decode app-hand document
    let app_hand = AppHandExiDocument::decode(&stream).expect("valid AppHandExiDocument");

    // get app-hand protos
    let protos = app_hand.get_protocols().expect("valid document content");

    for idx in 0..protos.len() {
        let proto = &protos[idx];
        println!("  -- app-hand: proto[{}]={:?}", idx, proto);
    }
}

#[test]
fn app_hand_decode_trialog() {

    // Result
    // "proto[0]=AppHandProtocols { \
    //    name_space: 'urn:iso:15118:2:2013:MsgDef', version_number_major: 2, version_number_minor: 0, schema_id: 0, priority: 1
    //  }
    // "proto[1]=AppHandProtocols {
    //    name_space: 'urn:din:70121:2012:MsgDef', version_number_major: 2, version_number_minor: 0, schema_id: 1, priority: 2
    //  }"


    // extract from Trialog simulator handshake
    let exi_data = [
        0x01, 0xfe, 0x80, 0x01, 0x00, 0x00, 0x00, 0x44, 0x80, 0x00, 0xeb, 0xab, 0x93, 0x71, 0xd3,
        0x4b, 0x9b, 0x79, 0xd1, 0x89, 0xa9, 0x89, 0x89, 0xc1, 0xd1, 0x91, 0xd1, 0x91, 0x81, 0x89,
        0x99, 0xd2, 0x6b, 0x9b, 0x3a, 0x23, 0x2b, 0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0xb7,
        0x57, 0x26, 0xe3, 0xa6, 0x46, 0x96, 0xe3, 0xa3, 0x73, 0x03, 0x13, 0x23, 0x13, 0xa3, 0x23,
        0x03, 0x13, 0x23, 0xa4, 0xd7, 0x36, 0x74, 0x46, 0x56, 0x60, 0x04, 0x00, 0x00, 0x08, 0x08,
        0x80,
    ];

    // create a new stream with attached 8KB buffer
    let stream = ExiStream::new();

    // simulate network data read
    // preempt stream mutex
    // feed stream buffer (server should use zero copy)
    // free stream mutex
    {
        let mut handle = stream.get_handle();
        handle.buffer[0..exi_data.len()].copy_from_slice(&exi_data);
    }

    // check V2G header (should be donne before finalize to get doc len)
    let doc_size = stream.header_check().expect("expect valid V2G header");

    // validate buffer stream (exec data may come in multiple chucks)
    stream
        .finalize(doc_size)
        .expect("expect valid stream handle");

    // decode app-hand document
    let app_hand = AppHandExiDocument::decode(&stream).expect("valid AppHandExiDocument");

    // get app-hand protos
    let protos = app_hand.get_protocols().expect("valid document content");

    for idx in 0..protos.len() {
        let proto = &protos[idx];
        println!("  -- app-hand: proto[{}]={:?}", idx, proto);
    }
}
