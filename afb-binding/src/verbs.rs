/*
 * Copyright (C) 2015-2022 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
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
use iso15118::prelude::*;
//use typesv4::prelude::*;

pub struct AsyncSdpCtx {
    pub sdp: SdpServer,
    pub tcp_port: u16,
    pub tls_port: u16,
    pub sdp_addr6: IfaceAddr6,
}

fn buffer_to_str(buffer: &[u8]) -> Result<&str, AfbError> {
    let text = match std::str::from_utf8(buffer) {
        Ok(value) => value,
        Err(_) => return afb_error!("buffer-to_str", "fail UTF8 conversion"),
    };
    Ok(text)
}

AfbEvtFdRegister!(AsyncSdpCb, async_sdp_cb, AsyncSdpCtx);
fn async_sdp_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &mut AsyncSdpCtx) -> Result<(), AfbError> {
    if revent == AfbEvtFdPoll::IN.bits() {
        // get SDP/UDP packet
        let buffer = ctx.sdp.read_buffer()?;
        let request = SdpRequest::new(&buffer)?;
        request.check_header()?;

        let transport= request.get_transport();
        let security= request.get_security();

        let port = match &security {
            SdpSecurityModel::TLS => ctx.tls_port,
            SdpSecurityModel::NONE => ctx.tcp_port,
        };

        match &transport {
            SdpTransportProtocol::TCP => {}
            SdpTransportProtocol::UDP => {
                return afb_error!("sdp-request-udp", "currently not supported")
            }
        }

        afb_log_msg!(
            Debug,
            None,
            "Respond sdp {:?}:{:?}:[{:?}]:{}",
            &transport,
            &security,
            &ctx.sdp_addr6.addr,
            port
        );
        let response = SdpResponse::new(&ctx.sdp_addr6, port, transport, security);
        response.send_response(&ctx.sdp)?;
    }
    Ok(())
}

struct AsyncTcpClientCtx {
    client: TcpClient,
}

impl Drop for AsyncTcpClientCtx {
    fn drop(&mut self) {
        println!("**** TcpAsync drop");
    }
}

// New TCP client connecting
AfbEvtFdRegister!(AsyncTcpClientCb, async_tcp_client_cb, AsyncTcpClientCtx);
fn async_tcp_client_cb(
    _evtfd: &AfbEvtFd,
    revent: u32,
    ctx: &mut AsyncTcpClientCtx,
) -> Result<(), AfbError> {
    if revent == AfbEvtFdPoll::IN.bits() {
        // Fulup TBD should remove initialization
        let mut buffer: [u8; 255] = [0; 255];
        let count = ctx.client.get(&mut buffer)?;

        let data = buffer_to_str(&buffer[0..count])?;
        println!("**** tcp-client-read count:{} buffer:{}", count, data);
        let response = data.to_uppercase();
        let _count = ctx.client.send(&mut response.as_bytes())?;
    } else {
        println!("**** Tcp client Socket closed");
        let boxe = unsafe { Box::from_raw(ctx) };
        drop(boxe);
    }
    Ok(())
}

struct AsyncTlsClientCtx {
    connection: TlsConnection,
}

impl Drop for AsyncTlsClientCtx {
    fn drop(&mut self) {
        println!("**** TlsSession drop");
    }
}

// New TLS client connecting
AfbEvtFdRegister!(AsyncTlsClientCb, async_tls_client_cb, AsyncTlsClientCtx);
fn async_tls_client_cb(
    _evtfd: &AfbEvtFd,
    revent: u32,
    ctx: &mut AsyncTlsClientCtx,
) -> Result<(), AfbError> {
    if revent == AfbEvtFdPoll::IN.bits() {
        // Fulup TBD should remove initialization
        let mut buffer: [u8; 255] = [0; 255];
        let count = ctx.connection.recv(&mut buffer)?;
        if count > 0 {
            let data = buffer_to_str(&buffer[0..count])?;
            println!("**** tls-client-read count:{} buffer:{}", count, data);
            let response = data.to_uppercase();
            let _count = ctx.connection.send(&mut response.as_bytes())?;
        }
    } else {
        println!("**** Tls client Socket closed");
        let boxe = unsafe { Box::from_raw(ctx) };
        drop(boxe);
    }
    Ok(())
}

pub struct AsyncTcpCtx {
    pub tcp: TcpServer,
}
// New TCP client connecting
AfbEvtFdRegister!(AsyncTcpCb, async_tcp_cb, AsyncTcpCtx);
fn async_tcp_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &mut AsyncTcpCtx) -> Result<(), AfbError> {
    if revent == AfbEvtFdPoll::IN.bits() {
        let tcp_client = ctx.tcp.accept_client()?;

        AfbEvtFd::new("tcp-client")
            .set_fd(tcp_client.get_sockfd()?)
            .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
            .set_autounref(true)
            .set_callback(Box::new(AsyncTcpClientCtx { client: tcp_client }))
            .start()?;
    }
    Ok(())
}

pub struct AsyncTlsCtx {
    pub tls: TcpServer,
    pub config: &'static TlsConfig,
}
// New TLS connection
AfbEvtFdRegister!(AsyncTlsCb, async_tls_cb, AsyncTlsCtx);
fn async_tls_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &mut AsyncTlsCtx) -> Result<(), AfbError> {
    if revent == AfbEvtFdPoll::IN.bits() {
        let tls_client = ctx.tls.accept_client()?;
        let sockfd = tls_client.get_sockfd()?;
        let tls_connection = TlsConnection::new(ctx.config, tls_client)?;
        tls_connection.client_handshake()?;

        AfbEvtFd::new("tls-client")
            .set_fd(sockfd)
            .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
            .set_autounref(true)
            .set_callback(Box::new(AsyncTlsClientCtx {
                connection: tls_connection,
            }))
            .start()?;
    }
    Ok(())
}

AfbVerbRegister!(scanifv6Ctrl, scanifv6_callback);
fn scanifv6_callback(request: &AfbRequest, args: &AfbData) -> Result<(), AfbError> {
    let iface = args.get::<String>(0)?;
    let addr = get_iface_addrs(&iface, 0xfe80)?;

    println!(
        "iface:{} addr6:{} scope6:{}",
        iface,
        addr.get_addr().to_string(),
        addr.get_scope()
    );
    request.reply(AFB_NO_DATA, 0);
    Ok(())
}
pub(crate) fn register_verbs(api: &mut AfbApi, _config: &BindingConfig) -> Result<(), AfbError> {
    let scanifv6 = AfbVerb::new("scan-iface")
        .set_callback(Box::new(scanifv6Ctrl {}))
        .set_info("scan ipv6 interface return attached ipv6 addr")
        .finalize()?;

    api.add_verb(scanifv6);
    Ok(())
}
