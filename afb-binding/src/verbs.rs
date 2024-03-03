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

#[track_caller]
fn _buffer_to_str(buffer: &[u8]) -> Result<&str, AfbError> {
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

        let transport = request.get_transport();
        let security = request.get_security();

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
    connection: TcpClient,
    mgr: IsoManager,
    exi_in: ExiStream,
    exi_out: ExiStream,
    data_len: u32,
    payload_len: u32,
}

impl Drop for AsyncTcpClientCtx {
    fn drop(&mut self) {
        self.exi_in.drop();
        self.exi_out.drop();
    }
}

// New TCP client connecting
AfbEvtFdRegister!(AsyncTcpClientCb, async_tcp_client_cb, AsyncTcpClientCtx);
fn async_tcp_client_cb(
    _evtfd: &AfbEvtFd,
    revent: u32,
    ctx: &mut AsyncTcpClientCtx,
) -> Result<(), AfbError> {
    // read is the only accepted operation
    if revent != AfbEvtFdPoll::IN.bits() {
        let boxe = unsafe { Box::from_raw(ctx) };
        drop(boxe);
        return Ok(());
    }

    // move tcp socket data into exi stream buffer
    let (stream_idx, stream_avaliable) = ctx.exi_in.get_index();
    let read_count = if stream_avaliable == 0 {
        afb_log_msg!(
            Notice,
            None,
            "async_tcp_client {:?}, buffer full close session",
            ctx.connection.get_source()
        );
        ctx.connection.close()?;
        return Ok(());
    } else {
        let mut handle = ctx.exi_in.get_handle();
        let buffer = &mut handle.buffer[stream_idx..];
        ctx.connection.get_data(buffer)?
    };

    // when facing a new exi check how much data should be read
    if stream_idx == 0 {
        ctx.payload_len = ctx.exi_in.header_check()?;
    }

    // if data send in chunks let's complete exi buffer before processing it
    ctx.data_len = ctx.data_len + read_count;
    if ctx.data_len == ctx.payload_len {
        ctx.exi_in.finalize(ctx.payload_len)?;
        ctx.mgr.handle_exi_doc(&ctx.exi_in)?;
    }

    Ok(())
}

struct AsyncTlsClientCtx {
    connection: TlsConnection,
    mgr: IsoManager,
    exi_in: ExiStream,
    exi_out: ExiStream,
    data_len: u32,
    payload_len: u32,
}

impl Drop for AsyncTlsClientCtx {
    fn drop(&mut self) {
        println!("**** TlsSession drop");
        self.exi_in.drop();
        self.exi_out.drop();
    }
}

// New TLS client connecting
AfbEvtFdRegister!(AsyncTlsClientCb, async_tls_client_cb, AsyncTlsClientCtx);
fn async_tls_client_cb(
    _evtfd: &AfbEvtFd,
    revent: u32,
    ctx: &mut AsyncTlsClientCtx,
) -> Result<(), AfbError> {
    if revent != AfbEvtFdPoll::IN.bits() {
        println!("**** Tls client Socket closed");
        let boxe = unsafe { Box::from_raw(ctx) };
        drop(boxe);
        return Ok(());
    }

    // move tcp socket data into exi stream buffer
    let (stream_idx, stream_avaliable) = ctx.exi_in.get_index();
    let read_count = if stream_avaliable == 0 {
        afb_log_msg!(
            Notice,
            None,
            "async_tls_client {:?}, buffer full close session",
            ctx.connection.get_source()
        );
        ctx.connection.close();
        return Ok(());
    } else {
        let mut handle = ctx.exi_in.get_handle();
        let buffer = &mut handle.buffer[stream_idx..];
        ctx.connection.recv(buffer)?
    };

    // when facing a new exi check how much data should be read
    if stream_idx == 0 {
        ctx.payload_len = ctx.exi_in.header_check()?;
    }

    // if data send in chunks let's complete exi buffer before processing it
    ctx.data_len = ctx.data_len + read_count;
    if ctx.data_len == ctx.payload_len {
        ctx.exi_in.finalize(ctx.payload_len)?;
        ctx.mgr.handle_exi_doc(&ctx.exi_in)?;
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
            .set_callback(Box::new(AsyncTcpClientCtx {
                connection: tcp_client,
                data_len: 0,
                payload_len: 0,
                mgr: IsoManager::new()?,
                exi_in: ExiStream::new(),
                exi_out: ExiStream::new(),
            }))
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
        let source = tls_client.get_source();
        let sockfd = tls_client.get_sockfd()?;
        let tls_connection = TlsConnection::new(ctx.config, tls_client)?;
        tls_connection.client_handshake()?;

        afb_log_msg!(
            Notice,
            None,
            "New connection client:{} protocol:{}",
            source,
            tls_connection.get_version().to_string()
        );

        AfbEvtFd::new("tls-client")
            .set_fd(sockfd)
            .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
            .set_autounref(true)
            .set_callback(Box::new(AsyncTlsClientCtx {
                connection: tls_connection,
                data_len: 0,
                payload_len: 0,
                mgr: IsoManager::new()?,
                exi_in: ExiStream::new(),
                exi_out: ExiStream::new(),
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
