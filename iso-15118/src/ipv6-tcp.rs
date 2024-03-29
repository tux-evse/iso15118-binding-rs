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
 *   references:
 *    https://www.zupzup.org/epoll-with-rust/index.html
 *    https://github.com/rustls/rustls/blob/main/examples/src/bin/simpleserver.rs
 *
 */

use crate::prelude::*;
use afbv4::prelude::*;
use std::io::{Read, Write};
use std::net;
use std::os::unix::io::AsRawFd;
use std::sync::{Mutex, MutexGuard};

impl Drop for TcpClient {
    fn drop(&mut self) {
        println!("**** TcpClient drop");
        let _ = self.close();
    }
}

pub struct ClientState {
    pub connection: net::TcpStream,
}

pub struct TcpClient {
    source: net::SocketAddr,
    data_set: Mutex<ClientState>,
}

impl TcpClient {
    #[track_caller]
    pub fn get_handle(&self) -> Result<MutexGuard<'_, ClientState>, AfbError> {
        match self.data_set.lock() {
            Err(_) => return afb_error!("sock-client-state", "fail to access &mut data_set"),
            Ok(value) => Ok(value),
        }
    }

    pub fn get_sockfd(&self) -> Result<i32, AfbError> {
        let data_set = self.get_handle()?;
        let sockfd = data_set.connection.as_raw_fd();
        Ok(sockfd as i32)
    }

    pub fn close(&self) -> Result<(), AfbError> {
        let data_set = self.get_handle()?;
        match data_set.connection.shutdown(net::Shutdown::Both) {
            Ok(_) => {}
            Err(_) => {
                return afb_error!("sock-client-close", "fail to close client:{}", &self.source)
            }
        }
        Ok(())
    }

    pub fn get_data(&self, buffer: &mut [u8]) -> Result<u32, AfbError> {
        let mut data_set = self.get_handle()?;
        let count = match data_set.connection.read(buffer) {
            Ok(count) => count as u32,
            Err(_) => {
                return afb_error!("sock-client-read", "fail to read client:{}", &self.source)
            }
        };
        Ok(count)
    }

    pub fn get_source(&self) -> net::SocketAddr {
        self.source.clone()
    }

    pub fn send(&self, buffer: &[u8]) -> Result<usize, AfbError> {
        let mut data_set = self.get_handle()?;
        let count = match data_set.connection.write(buffer) {
            Ok(count) => count,
            Err(_) => {
                return afb_error!("sock-client-write", "fail to write client:{}", &self.source)
            }
        };
        Ok(count)
    }
}

pub struct TcpServer {
    uid: &'static str,
    listener: net::TcpListener,
}

impl TcpServer {
    pub fn new(
        api: &AfbApi,
        uid: &'static str,
        addr: &IfaceAddr6,
        port: u16,
    ) -> Result<Self, AfbError> {
        let addrv6 = addr.get_addr();
        let scopv6 = addr.get_scope();

        let socket = net::SocketAddrV6::new(addrv6, port, 0, scopv6);

        afb_log_msg!(Notice, api, "{} listen socket:{}", uid, socket);
        let listener = match net::TcpListener::bind(socket) {
            Ok(value) => value,
            Err(error) => {
                return afb_error!(
                    "sock-tcp-listen",
                    "fail to bind tcp port:{} error:{}",
                    port,
                    error
                )
            }
        };

        let handle = TcpServer { uid, listener };
        Ok(handle)
    }

    pub fn get_sockfd(&self) -> i32 {
        self.listener.as_raw_fd() as i32
    }

    pub fn get_uid(&self) -> &'static str {
        self.uid
    }

    pub fn accept_client(&self) -> Result<TcpClient, AfbError> {
        let client = match self.listener.accept() {
            Ok((connection, source)) => TcpClient {
                source,
                data_set: Mutex::new(ClientState{connection}),
            },
            Err(_) => {
                return afb_error!(
                    "sock-tcp-accept",
                    "uid:{} fail to accept client port",
                    self.uid
                )
            }
        };
        Ok(client)
    }
}
