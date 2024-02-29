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

pub struct TlsConnection {
    session: &'static GnuTlsSession,
    client: TcpClient,
}

impl Drop for TlsConnection {
    fn drop(&mut self) {
        println!("**** TlsConnection drop");
    }
}

impl TlsConnection {
    pub fn new(config: &TlsConfig, client: TcpClient) -> Result<Self, AfbError> {
        // create a new tls segit pullssion for server TlsConfig
        let sockfd = client.get_sockfd()?;
        let session = GnuTlsSession::new(&config.gtls, sockfd)?;
        // &session.set_client_sni(config);

        let connection = TlsConnection { session, client };
        Ok(connection)
    }

    pub fn get_sockfd(&self) -> Result<i32, AfbError> {
        let sockfd = self.client.get_sockfd()?;
        Ok(sockfd)
    }

    pub fn get_version(&self) -> GnuTlsVersion {
        self.session.get_version()
    }

    pub fn client_handshake(&self) -> Result<(), AfbError> {
        self.session.client_handshake()?;
        Ok(())
    }

    pub fn recv(&self, buffer: &mut [u8]) -> Result<usize, AfbError> {
        let count = self.session.recv(buffer)?;
        Ok(count)
    }

    pub fn send(&self, buffer: &[u8]) -> Result<usize, AfbError> {
        let count = self.session.send(buffer)?;
        Ok(count)
    }

    pub fn check_pending(&self) -> bool {
        self.session.check_pending()
    }

    pub fn close(&self) {
        let _ = self.client.close();
        let _ = self.session.close();
    }
}

pub struct TlsConfig {
    pub gtls: GnuTlsConfig,
}

// Parse certificate keys
impl TlsConfig {
    pub fn new(
        cert_file: &str,
        key_file: &str,
        key_pin:Option<&str>,
        ca_oem: Option<&str>,
        client_sni: Option<&'static str>,
        tls_psk: Option<&'static str>,
        psk_log: Option<&'static str>,
    ) -> Result<&'static Self, AfbError> {
        let config = GnuTlsConfig::new(
            cert_file,
            key_file,
            key_pin,
            ca_oem,
            client_sni,
            tls_psk,
            psk_log,
        )?;

        let handle = Box::new(TlsConfig { gtls: config });
        Ok(Box::leak(handle))
    }
}
