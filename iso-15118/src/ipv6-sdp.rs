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
use std::cell::{RefCell, RefMut};
use std::mem;

#[derive(PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum SdpSecurityModel {
    TLS = 0x00,
    NONE = 0x10,
}

#[derive(PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum SdpTransportProtocol {
    TCP = 0x00,
    UDP = 0x10,
}

pub struct SdpState {
    pub remote_addr6: Option<SocketSourceV6>,
}

pub enum SdpMsgType {
    Request,
    Response,
}

pub struct SdpMsgHeader {
    version_std: u8,
    version_not: u8,
    msg_type: u16,
    msg_len: u32,
}

impl SdpMsgHeader {
    pub fn new(sdp_msg: SdpMsgType) -> Self {
        let (sdp_type, sdp_len) = match sdp_msg {
            SdpMsgType::Request => (V2G_SDP_REQUEST_TYPE, V2G_SDP_REQUEST_LEN),
            SdpMsgType::Response => (V2G_SDP_RESPONSE_TYPE, V2G_SDP_RESPONSE_LEN),
        };
        SdpMsgHeader {
            version_std: V2G_SDP_VERSION,
            version_not: V2G_SDP_VERSION_NOT,
            msg_type: unsafe { cglue::htons(sdp_type) },
            msg_len: unsafe { cglue::htonl(sdp_len) },
        }
    }

    pub fn check(&self, sdp_msg: SdpMsgType) -> Result<(), AfbError> {
        let (sdp_type, sdp_len) = match sdp_msg {
            SdpMsgType::Request => (V2G_SDP_REQUEST_TYPE, V2G_SDP_REQUEST_LEN),
            SdpMsgType::Response => (V2G_SDP_RESPONSE_TYPE, V2G_SDP_RESPONSE_LEN),
        };

        if self.version_std != V2G_SDP_VERSION || self.version_not != V2G_SDP_VERSION_NOT {
            return afb_error!(
                "Sdp-request-check",
                "invalid Sdp/SDP version expected:[{:#02x},{:#02x}] received:[{:#02x},{:#02x}]",
                self.version_std,
                self.version_not,
                V2G_SDP_VERSION,
                V2G_SDP_VERSION_NOT
            );
        }

        let rqt_type = unsafe { cglue::htons(sdp_type) };
        if self.msg_type != rqt_type {
            return afb_error!(
                "Sdp-request-check",
                "invalid Sdp/SDP type expected:{:#04x} received:{:#04x}",
                rqt_type,
                self.msg_type
            );
        }

        let rqt_len = unsafe { cglue::htonl(sdp_len) };
        if self.msg_len != rqt_len {
            return afb_error!(
                "Sdp-request-check",
                "invalid Sdp/SDP lenght expected:{} received:{}",
                rqt_type,
                self.msg_type
            );
        }
        Ok(())
    }
}

pub struct SdpRequest {
    pub security: SdpSecurityModel,
    pub transport: SdpTransportProtocol,
}
// make sure Rust does not hack memory mapping
#[repr(C, align(32))]
pub (self) struct SdpMsgRqt {
    header: SdpMsgHeader,
    payload: SdpRequest,
}

pub struct SdpResponse {
    pub addr: cglue::in6_addr,
    pub port: cglue::in_port_t,
}

impl SdpResponse {
    pub fn new(saddr: &IfaceAddr6, port: u16) -> Self {
        let port = unsafe { cglue::htons(port) };
        let addr = cglue::in6_addr {
            __in6_u: cglue::in6_addr__bindgen_ty_1 {
                __u6_addr8: saddr.get_addr().octets(),
            },
        };
        SdpResponse { port, addr }
    }
}

#[allow(dead_code)]
pub(self) struct SdpMsgRsp {
    header: SdpMsgHeader,
    payload: SdpResponse,
}

unsafe fn struct_as_u8<T: Sized>(p: &mut T) -> &mut [u8] {
    ::core::slice::from_raw_parts_mut((p as *mut T) as *mut u8, ::core::mem::size_of::<T>())
}

pub struct SdpServer {
    data_cell: RefCell<SdpState>,
    uid: &'static str,
    socket: SocketSdpV6,
}

impl SdpServer {
    pub fn new(uid: &'static str, iface: &str, port: u16) -> Result<Self, AfbError> {
        let socket = SocketSdpV6::new()?;
        socket.bind(iface, port)?;
        socket.multicast_join(IP6_BROADCAST_ANY)?;

        let handle = SdpServer {
            data_cell: RefCell::new(SdpState { remote_addr6: None }),
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
    fn get_cell(&self) -> Result<RefMut<'_, SdpState>, AfbError> {
        match self.data_cell.try_borrow_mut() {
            Err(_) => return afb_error!("sdp-state-get", "fail to access &mut data_cell"),
            Ok(value) => Ok(value),
        }
    }

    pub fn read_request(&self) -> Result<SdpRequest, AfbError> {
        // read sdp request directly from byte buffer
        let sdp_request = mem::MaybeUninit::<SdpMsgRqt>::uninit();
        let mut sdp_request= unsafe {sdp_request.assume_init()};
        let remote_addr6 = self
            .socket
            .recvfrom(unsafe { struct_as_u8(&mut sdp_request) })?;
        sdp_request.header.check(SdpMsgType::Request)?;

        // request is valid, update remote source ipv6 addr
        let mut data_cell = self.get_cell()?;
        data_cell.remote_addr6 = Some(remote_addr6);

        Ok(sdp_request.payload)
    }

    pub fn send_response(&self, payload: SdpResponse) -> Result<(), AfbError> {
        let data_cell = self.get_cell()?;
        let remote_addr6 = match &data_cell.remote_addr6 {
            Some(value) => value,
            None => return afb_error!("sdp-respose-state", "No destination defined"),
        };

        let mut sdp_respone = SdpMsgRsp {
            header: SdpMsgHeader::new(SdpMsgType::Response),
            payload: payload,
        };

        self.socket
            .sendto(unsafe { struct_as_u8(&mut sdp_respone) }, remote_addr6)?;

        Ok(())
    }
}
