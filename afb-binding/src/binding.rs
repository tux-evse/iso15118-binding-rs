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
use typesv4::prelude::*;

pub struct BindingConfig {}

struct ApiUserData {
    iface: &'static str,
    sdp_port: u16,
    tls_port: u16,
    tcp_port: u16,
    prefix: u16,
    tls_conf: &'static TlsConfig,
}
impl AfbApiControls for ApiUserData {
    // the API is created and ready. At this level user may subcall api(s) declare as dependencies
    fn start(&mut self, api: &AfbApi) -> Result<(), AfbError> {
        afb_log_msg!(Notice, api, "iface:{} sdp:{}", self.iface, self.sdp_port);

        // get iface ipv6-addr matching prefix (local-link?)
        let sdp_addr6 = get_iface_addrs(&self.iface, self.prefix)?;

        // start TCP ws-server
        let tcp = TcpServer::new("tcp-wserver", &sdp_addr6, self.tcp_port)?;
        AfbEvtFd::new(tcp.get_uid())
            .set_fd(tcp.get_sockfd())
            .set_events(AfbEvtFdPoll::IN)
            .set_callback(Box::new(AsyncTcpCtx { tcp }))
            .start()?;

        // start TLS ws-server
        let tls = TcpServer::new("tls-wserver", &sdp_addr6, self.tls_port)?;
        AfbEvtFd::new(tls.get_uid())
            .set_fd(tls.get_sockfd())
            .set_events(AfbEvtFdPoll::IN)
            .set_callback(Box::new(AsyncTlsCtx {
                tls,
                config: self.tls_conf,
            }))
            .start()?;

        // start SDP discovery service
        let sdp = SdpServer::new("sdp-server", self.iface, self.sdp_port)?;
        AfbEvtFd::new(sdp.get_uid())
            .set_fd(sdp.get_sockfd())
            .set_events(AfbEvtFdPoll::IN)
            .set_callback(Box::new(AsyncSdpCtx {
                sdp,
                sdp_addr6,
                tcp_port: self.tcp_port,
                tls_port: self.tls_port,
            }))
            .start()?;

        Ok(())
    }

    // mandatory unsed declaration
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

// Binding init callback started at binding load time before any API exist
// -----------------------------------------
pub fn binding_init(rootv4: AfbApiV4, jconf: JsoncObj) -> Result<&'static AfbApi, AfbError> {
    afb_log_msg!(Info, rootv4, "config:{}", jconf);

    let uid = jconf.default::<&'static str>("uid", "iso15118-16")?;
    let api = jconf.default::<&'static str>("api", uid)?;
    let info = jconf.default::<&'static str>("info", "")?;
    let iface = jconf.default::<&'static str>("iface", "eth2")?;
    let prefix = jconf.default::<u32>("ip6_prefix", 0xFE80)? as u16;
    let sdp_port = jconf.default::<u32>("sdp_port", 15118)? as u16;
    let tcp_port = jconf.default::<u32>("tcp_port", 61341)? as u16;
    let tls_port = jconf.default::<u32>("tls_port", 64109)? as u16;
    let cert_file = jconf.get::<&str>("tls_cert")?;
    let priv_key = jconf.get::<&str>("tls_key")?;
    let pin_key = jconf.get::<&str>("tls_pin")?;
    let hostname = jconf.default::<&'static str>("hostname", "")?;

    // parse and load TLS certificates at binding init
    let tls_conf = TlsConfig::new(cert_file, priv_key, pin_key, hostname)?;

    // register data converter
    iso15118_registers()?;

    // create an register frontend api and register init session callback
    let api = AfbApi::new(api)
        .set_info(info)
        .set_callback(Box::new(ApiUserData {
            iface,
            prefix,
            sdp_port,
            tcp_port,
            tls_port,
            tls_conf,
        }));

    // create verbs
    let config = BindingConfig {};
    register_verbs(api, &config)?;

    // if acls set apply them
    if let Ok(value) = jconf.get::<&'static str>("permission") {
        api.set_permission(AfbPermission::new(value));
    };

    if let Ok(value) = jconf.get::<i32>("verbosity") {
        api.set_verbosity(value);
    };

    Ok(api.finalize()?)
}

// register binding within libafb
AfbBindingRegister!(binding_init);
