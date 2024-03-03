/*
 * Copyright (C) 2015-2022 IoT.bzh Pionix, Chargebyte and Everest contributors
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Rust largely inspired from Everest C++ git@github.com:/EVerest/libiso15118.git
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 */

use crate::prelude::*;
use afbv4::prelude::*;
use std::sync::{Mutex, MutexGuard};
use std::mem;

#[derive(PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum SdpSecurityModel {
    TLS = cexi::SDP_V2G_SECURITY_TLS,
    NONE = cexi::SDP_V2G_SECURITY_NONE,
}

#[derive(PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum SdpTransportProtocol {
    TCP = cexi::SDP_V2G_TRANSPORT_TCP,
    UDP = cexi::SDP_V2G_TRANSPORT_UDP,
}

pub struct SdpState {
    pub remote_addr6: Option<SocketSourceV6>,
}

pub enum SdpMsgType {
    Request,
    Response,
}

// payload buffer data type
pub type SdpResponseBuffer =
    [u8; (cexi::SDP_V2G_RESPONSE_LEN + cexi::SDP_V2G_HEADER_LEN) as usize];
pub type SdpRequestBuffer = [u8; (cexi::SDP_V2G_REQUEST_LEN + cexi::SDP_V2G_HEADER_LEN) as usize];

pub struct SdpRequest {
    payload: cexi::sdp_request,
}
impl SdpRequest {
    pub fn new(buffer: &SdpRequestBuffer) -> Result<Self, AfbError> {
        let mut request = mem::MaybeUninit::<cexi::sdp_request>::uninit();
        let status = unsafe {
            cexi::sdp_v2g_decode_rqt(
                buffer.as_ptr() as *mut u8,
                buffer.len(),
                request.as_mut_ptr(),
            )
        };
        if status != 0 {
            return afb_error!("sdp-response-encode", "fail to decode response");
        }
        let response = SdpRequest {
            payload: unsafe { request.assume_init() },
        };
        Ok(response)
    }

    pub fn check_header(&self) -> Result<&Self, AfbError> {
        let header = self.payload.header;
        if header.version_std != cexi::SDP_V2G_VERSION
            || header.version_not != cexi::SDP_V2G_VERSION_NOT
        {
            return afb_error!(
                "sdp-request-header",
                "invalid Sdp/SDP version expected:[{:#02x},{:#02x}] received:[{:#02x},{:#02x}]",
                header.version_std,
                header.version_not,
                cexi::SDP_V2G_VERSION,
                cexi::SDP_V2G_VERSION_NOT
            );
        }

        if header.msg_type != cexi::SDP_V2G_REQUEST_TYPE {
            return afb_error!(
                "sdp-request-header",
                "invalid Sdp/SDP type expected:{:#04x} received:{:#04x}",
                cexi::SDP_V2G_REQUEST_TYPE,
                header.msg_type
            );
        }

        //let rqt_len = unsafe { cglue::ntohl(sdp_len) };
        if header.msg_len != cexi::SDP_V2G_REQUEST_LEN {
            return afb_error!(
                "sdp-request-header",
                "invalid Sdp/SDP lenght expected:{} received:{}",
                cexi::SDP_V2G_REQUEST_LEN,
                header.msg_type
            );
        }
        Ok(self)
    }

    pub fn get_transport(&self) -> SdpTransportProtocol {
        let transport = unsafe { mem::transmute(self.payload.transport) };
        transport
    }

    pub fn get_security(&self) -> SdpSecurityModel {
        let transport = unsafe { mem::transmute(self.payload.security) };
        transport
    }
}

pub struct SdpResponse {
    payload: cexi::sdp_response,
    sin6_scope: u32,
}

impl SdpResponse {
    pub fn new(
        saddr: &IfaceAddr6,
        port: u16,
        transport: SdpTransportProtocol,
        security: SdpSecurityModel,
    ) -> Self {
        let addr = cexi::sdp_in6_addr {
                u6_addr8: saddr.get_addr().octets(),
        };
        SdpResponse {
            payload: cexi::sdp_response {
                header: cexi::sdp_msg_header {
                    version_std: cexi::SDP_V2G_VERSION,
                    version_not: cexi::SDP_V2G_VERSION_NOT,
                    msg_len: cexi::SDP_V2G_RESPONSE_LEN,
                    msg_type: cexi::SDP_V2G_RESPONSE_TYPE,
                },
                addr,
                port,
                security: security as u8,
                transport: transport as u8,
            },
            sin6_scope: saddr.get_scope(),
        }
    }
    pub fn encode(&self) -> Result<SdpResponseBuffer, AfbError> {
        let mut buffer = mem::MaybeUninit::<SdpResponseBuffer>::uninit();
        let status = unsafe {
            cexi::sdp_v2g_encode_rsp(
                &self.payload,
                buffer.as_mut_ptr() as *mut u8,
                mem::size_of::<SdpResponseBuffer>(),
            )
        };
        if status != 0 {
            return afb_error!("sdp-response-encode", "fail to encode response");
        }
        let buffer = unsafe { buffer.assume_init() };
        Ok(buffer)
    }

    pub fn send_response(&self, sdp: &SdpServer) -> Result<(), AfbError> {
        let buffer = self.encode()?;
        sdp.send_buffer(&buffer, self.sin6_scope)?;

        Ok(())
    }
}

pub struct SdpServer {
    data_cell: Mutex<SdpState>,
    uid: &'static str,
    socket: SocketSdpV6,
}

impl SdpServer {
    pub fn new(api: &AfbApi, uid: &'static str, iface: &str, port: u16) -> Result<Self, AfbError> {
        let socket = SocketSdpV6::new()?;
        socket.bind(iface, port)?;
        socket.multicast_join(IP6_BROADCAST_ANY)?;
        afb_log_msg!(Notice, api, "{} accept anycast-ipv6 udp:{}@{}", uid, port, iface);

        let handle = SdpServer {
            data_cell: Mutex::new(SdpState { remote_addr6: None }),
            socket,
            uid,
        };
        Ok(handle)
    }

    pub fn get_sockfd(&self) -> i32 {
        self.socket.get_sockfd()
    }

    pub fn get_uid(&self) -> &'static str {
        self.uid
    }

    #[track_caller]
    fn get_handle(&self) -> Result<MutexGuard<'_, SdpState>, AfbError> {
        match self.data_cell.lock() {
            Err(_) => return afb_error!("sdp-state-get", "fail to access &mut data_cell"),
            Ok(value) => Ok(value),
        }
    }

    pub fn read_buffer(&self) -> Result<SdpRequestBuffer, AfbError> {
        // read sdp request directly from byte buffer
        let mut buffer = mem::MaybeUninit::<SdpRequestBuffer>::uninit();
        let remote_addr6 = self.socket.recvfrom(
            buffer.as_mut_ptr() as *mut u8,
            mem::size_of::<SdpRequestBuffer>(),
        )?;

        // request is valid, update remote source ipv6 addr
        afb_log_msg!(Debug, None, "Received sdp from addr6:{:0x?}", unsafe {
            &remote_addr6.addr.sin6_addr.__in6_u.__u6_addr16
        });
        let mut data_cell = self.get_handle()?;
        data_cell.remote_addr6 = Some(remote_addr6);
        Ok(unsafe { buffer.assume_init() })
    }

    pub fn send_buffer(&self, buffer: &SdpResponseBuffer, sin6_scope: u32) -> Result<(), AfbError> {
        let data_cell = self.get_handle()?;
        let remote_addr6 = match &data_cell.remote_addr6 {
            Some(value) => {
                // copy destination addr but should keep source ipv6 scope
                let destination = value.addr;
                SocketSourceV6 { addr: destination }
            }
            None => return afb_error!("sdp-respose-state", "No destination defined"),
        };

        afb_log_msg!(
            Debug,
            None,
            "Responding sdp to addr6:{} scope:{}",
            remote_addr6,
            sin6_scope
        );
        self.socket.sendto(buffer, &remote_addr6)?;
        Ok(())
    }
}
