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
use iso15118::prelude::{v2g::*, *};
use nettls::prelude::*;
use std::str;
//use typesv4::prelude::*;

use std::mem;

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

pub fn async_sdp_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &AfbCtxData) -> Result<(), AfbError> {
    let ctx = ctx.get_ref::<AsyncSdpCtx>()?;
    if revent == AfbEvtFdPoll::IN.bits() {
        // get SDP/UDP packet
        let mut buffer = [0 as u8; mem::size_of::<SdpRequestBuffer>()];
        ctx.sdp.read_buffer(&mut buffer)?;

        let request = SdpRequest::decode(&buffer)?;
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
        let response =
            SdpResponse::new(ctx.sdp_addr6.get_addr().octets(), port, transport, security)
                .encode()?;
        ctx.sdp.send_buffer(&response)?;
    }
    Ok(())
}

struct AsyncTcpClientCtx {
    connection: TcpClient,
    ctrl: IsoController,
    stream: ExiStream,
    data_len: u32,
    payload_len: u32,
}

// New TCP client connecting
fn async_tcp_client_cb(
    _evtfd: &AfbEvtFd,
    revent: u32,
    context: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx = context.get_mut::<AsyncTcpClientCtx>()?;

    if revent != AfbEvtFdPoll::IN.bits() {
        afb_log_msg!(
            Debug,
            None,
            "async-tcp-client: closing tcp:{}",
            ctx.connection.get_source()
        );
        context.free::<AsyncTcpClientCtx>();
        return Ok(());
    }

    // move tcp socket data into exi stream buffer
    let mut lock = ctx.stream.lock_stream();
    let read_count = {
        let (stream_idx, stream_available) = ctx.stream.get_index(&lock);

        let read_count = if stream_available == 0 {
            afb_log_msg!(
                Notice,
                None,
                "async_tcp_client {:?}, buffer full close session",
                ctx.connection.get_source()
            );
            ctx.connection.close()?;
            return Ok(());
        } else {
            let buffer = &mut lock.buffer[stream_idx..];
            ctx.connection.get_data(buffer)?
        };

        // when facing a new exi check how much data should be read
        if stream_idx == 0 {
            let len = ctx.stream.get_payload_len(&lock);
            if len < 0 {
                afb_log_msg!(
                    Warning,
                    None,
                    "async_tcp_client: packet ignored (invalid v2g header) size:{}",
                    read_count
                );
            } else {
                ctx.payload_len = len as u32;
            }
            ctx.data_len = 0;
        }
        read_count
    };
    // if data send in chunks let's complete exi buffer before processing it
    ctx.data_len = ctx.data_len + read_count;
    if ctx.data_len >= ctx.payload_len + SDP_V2G_HEADER_LEN as u32 {
        // set data len and decode message and place response into stream-out (stream should not be lock_ined)
        ctx.stream.finalize(&lock, ctx.payload_len)?;
        println!(
            "**** tcp:v2g({})={}",
            ctx.stream.get_size(&lock),
            ctx.stream.dump_buffer(&lock, ExiDump::Everything)?
        );

        // decode request and encode response
        ctx.ctrl.iso_decode_payload(&ctx.stream, &mut lock)?;

        // send response and wipe stream for next request
        let response = ctx.stream.get_buffer(&lock);
        ctx.connection.put_data(response)?;
        ctx.stream.reset(&lock);
    }

    Ok(())
}

struct AsyncTlsClientCtx {
    connection: TlsConnection,
    ctrl: IsoController,
    stream: ExiStream,
    data_len: u32,
    payload_len: u32,
}

impl Drop for AsyncTlsClientCtx {
    fn drop(&mut self) {
        println!("**** TlsSession drop");
        self.stream.drop();
    }
}

// New TLS client connecting
fn async_tls_client_cb(
    _evtfd: &AfbEvtFd,
    revent: u32,
    context: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx = context.get_mut::<AsyncTlsClientCtx>()?;
    if revent != AfbEvtFdPoll::IN.bits() {
        afb_log_msg!(
            Debug,
            None,
            "async-tls-client: closing tls client:{}",
            ctx.connection.get_source()
        );
        context.free::<AsyncTlsClientCtx>();
        return Ok(());
    }

    // move tcp socket data into exi stream buffer
    let mut lock = ctx.stream.lock_stream();
    let read_count = {
        let (stream_idx, stream_available) = ctx.stream.get_index(&lock);
        let read_count = if stream_available == 0 {
            afb_log_msg!(
                Notice,
                None,
                "async_tls_client {:?}, buffer full close session",
                ctx.connection.get_source()
            );
            ctx.connection.close()?;
            return Ok(());
        } else {
            let buffer = &mut lock.buffer[stream_idx..];
            ctx.connection.get_data(buffer)?
        };

        let text= str::from_utf8(&lock.buffer[stream_idx..]).unwrap();
        println!("*** buffer={}", text);

        // when facing a new exi check how much data should be read
        if stream_idx == 0 {
            ctx.payload_len = ctx.stream.header_check(&lock, PayloadMsgId::SAP)?;
            ctx.data_len = 0;
        }

        // when facing a new exi check how much data should be read
        if stream_idx == 0 {
            let len = ctx.stream.get_payload_len(&lock);
            if len < 0 {
            afb_log_msg!(
                Warning,
                None,
                "async_tls_client: packet ignored (invalid v2g header) size:{}",
                read_count
            );
            } else {
               ctx.payload_len= len as u32;
            }
            ctx.data_len = 0;
        }
        read_count
    };

    // fix stream len for decoding
    ctx.data_len = ctx.data_len + read_count;
    if ctx.data_len == ctx.payload_len {
        // fix stream len for decoding
        ctx.stream.finalize(&lock, ctx.payload_len)?;
        println!(
            "**** tls:v2g({})={}",
            ctx.stream.get_size(&lock),
            ctx.stream.dump_buffer(&lock, ExiDump::Everything)?
        );

        // decode request and encode response
        ctx.ctrl.iso_decode_payload(&ctx.stream, &mut lock)?;

        // send response and wipe stream for next request
        let response = ctx.stream.get_buffer(&lock);
        ctx.connection.put_data(response)?;
        ctx.stream.reset(&lock);
    }

    Ok(())
}

pub struct AsyncTcpCtx {
    pub tcp: TcpServer,
}
// New TCP client connecting
pub fn async_tcp_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &AfbCtxData) -> Result<(), AfbError> {
    let ctx = ctx.get_ref::<AsyncTcpCtx>()?;
    if revent == AfbEvtFdPoll::IN.bits() {
        let tcp_client = ctx.tcp.accept_client()?;

        AfbEvtFd::new("tcp-client")
            .set_fd(tcp_client.get_sockfd()?)
            .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
            .set_autounref(true)
            .set_callback(async_tcp_client_cb)
            .set_context(AsyncTcpClientCtx {
                connection: tcp_client,
                data_len: 0,
                payload_len: 0,
                ctrl: IsoController::new()?,
                stream: ExiStream::new(),
            })
            .start()?;
    }
    Ok(())
}

pub struct AsyncTlsCtx {
    pub tls: TcpServer,
    pub config: &'static TlsConfig,
}
// New TLS connection
pub fn async_tls_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &AfbCtxData) -> Result<(), AfbError> {
    let ctx = ctx.get_ref::<AsyncTlsCtx>()?;
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
            .set_callback(async_tls_client_cb)
            .set_context(AsyncTlsClientCtx {
                connection: tls_connection,
                data_len: 0,
                payload_len: 0,
                ctrl: IsoController::new()?,
                stream: ExiStream::new(),
            })
            .start()?;
    }
    Ok(())
}

fn scanifv6_callback(
    request: &AfbRequest,
    args: &AfbRqtData,
    _ctx: &AfbCtxData,
) -> Result<(), AfbError> {
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
        .set_callback(scanifv6_callback)
        .set_info("scan ipv6 interface return attached ipv6 addr")
        .finalize()?;

    api.add_verb(scanifv6);
    Ok(())
}
