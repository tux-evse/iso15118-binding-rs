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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ref: https://gnutls.org/manual/html_node/Echo-server-with-X_002e509-authentication.html
 *      https://www.gnutls.org/reference/gnutls-gnutls.html
 *
 * Nota: did not implement revocation list CRLs
 */
use ::std::os::raw;
use std::ffi::CStr;
use std::ffi::CString;
use std::mem;
use std::net;
use std::fmt;

const MAX_ERROR_LEN: usize = 256;
pub mod cglue {
    #![allow(dead_code)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!("_capi-map.rs");
}

pub fn get_perror() -> String {
    let mut buffer = [0 as ::std::os::raw::c_char; MAX_ERROR_LEN];
    unsafe {
        cglue::strerror_r(
            *cglue::__errno_location(),
            &mut buffer as *mut raw::c_char,
            MAX_ERROR_LEN,
        )
    };
    let cstring = unsafe { CStr::from_ptr(&mut buffer as *const raw::c_char) };
    let slice: &str = cstring.to_str().unwrap();
    slice.to_owned()
}

pub fn gtls_perror(code: i32) -> String {
    let error = unsafe { cglue::gnutls_strerror(code) };
    let cstring = unsafe { CStr::from_ptr(error as *const raw::c_char) };
    let slice: &str = cstring.to_str().unwrap();
    slice.to_owned()
}

//use crate::prelude::*;
use afbv4::prelude::*;

pub const IP6_BROADCAST_ANY: [u8; cglue::C_INET6_ADDR_LEN] =
    [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];


pub struct IfaceAddr6 {
    pub addr: net::Ipv6Addr,
    pub scope: u32,
}

impl IfaceAddr6 {
    pub fn get_addr(&self) -> net::Ipv6Addr {
        self.addr
    }

    pub fn get_scope(&self) -> u32 {
        self.scope
    }
}

pub fn get_iface_addrs(iface: &str, filter: u16) -> Result<IfaceAddr6, AfbError> {
    // scan linux network interfaces
    let mut ifaddrs = mem::MaybeUninit::<*mut cglue::ifaddrs>::uninit();
    let status = unsafe { cglue::getifaddrs(ifaddrs.as_mut_ptr()) };
    let start = unsafe { ifaddrs.assume_init() };
    if status < 0 {
        return afb_error!(
            "ipv6-iface-scan",
            "fail to scan network interfaces {}",
            gtls_perror(status)
        );
    }

    // translate iface name to a valid C string
    let iface_name = match CString::new(iface) {
        Ok(value) => value,
        Err(_) => return afb_error!("ipv6-iface-import", "fail to import iface:{}", iface),
    };

    match unsafe { start.as_ref()} {
        None => return afb_error!("ipv6-iface-empty", "no network interface"),
        Some(_) => {}
    };

    let mut idx = 0;
    let mut next = start;
    let addr = loop {
        let ifa = match unsafe { next.as_ref() } {
            None => break None,
            Some(start) => {
                idx = idx + 1; // keep iface index for ipv6 bind
                start
            }
        };

        println!(
            "name:{} index:{}",
            unsafe { CStr::from_ptr(ifa.ifa_name).to_str().unwrap() },
            idx
        );

        // iface name match ?
        if iface_name.as_ref() != unsafe { CStr::from_ptr(ifa.ifa_name).as_ref() } {
            next = ifa.ifa_next;
            continue;
        }

        // extract sockaddr data
        let saddr = match unsafe { (ifa.ifa_addr as *mut cglue::sockaddr_in6).as_ref() } {
            Some(addr) => addr,
            None => {
                next = ifa.ifa_next;
                continue;
            }
        };

        // iface is IPV6 ?
        if saddr.sin6_family != cglue::C_AF_INET6 {
            next = ifa.ifa_next;
            continue;
        }

        // filter addrv6 (local-link=0xfe80)
        let addr_prefix = unsafe { cglue::htons(saddr.sin6_addr.__in6_u.__u6_addr16[0]) };
        if filter != 0 && addr_prefix != filter {
            next = ifa.ifa_next;
            continue;
        }

        // get a valid ip6-addr
        break Some(saddr);
    };

    let response = match addr {
        None => {
            return afb_error!(
                "ipv6-iface-match",
                "fail to find IPV6 iface:'{}' filter:'{}'",
                iface,
                filter
            )
        }
        Some(saddr) => IfaceAddr6 {
            addr: net::Ipv6Addr::from(unsafe { saddr.sin6_addr.__in6_u.__u6_addr8 }),
            scope: saddr.sin6_scope_id,
        },
    };
    unsafe { cglue::freeifaddrs(start) };
    Ok(response)
}

pub struct SocketSourceV6 {
    pub addr: cglue::sockaddr_in6,
}

impl fmt::Display for SocketSourceV6 {
   fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text="ipv6:[".to_string();
        for idx in 0 .. 8 {
            let slot= unsafe {self.addr.sin6_addr.__in6_u.__u6_addr16[idx]};
            let key= format!("{:#02x}:", unsafe{cglue::ntohs(slot)});
            text.push_str(&key.as_str());
        }
        text.push_str("]");
        write!(f, "{}",text)
   }
}

pub struct SocketSdpV6 {
    sockfd: i32,
}

impl SocketSdpV6 {
    pub fn new() -> Result<Self, AfbError> {
        const ENABLE: i32 = 1;

        let sockfd = unsafe {
            cglue::socket(
                cglue::C_AF_INET6 as i32,
                cglue::C_SOCK_DGRAM,
                cglue::C_IPPROTO_UDP,
            )
        };
        if sockfd < 0 {
            return afb_error!(
                "ipv6-socket-open",
                "fail to create IPv6 socket {}",
                get_perror()
            );
        }

        let status = unsafe {
            cglue::setsockopt(
                sockfd,
                cglue::C_SOL_SOCKET,
                cglue::C_SO_REUSEPORT,
                &ENABLE as *const _ as *mut raw::c_void,
                mem::size_of::<i32>() as u32,
            )
        };
        if status < 0 {
            unsafe { cglue::close(sockfd) };
            return afb_error!(
                "ipv6-socket-setopt",
                "fail to set reuseport option {}",
                get_perror()
            );
        }

        Ok(SocketSdpV6 { sockfd })
    }

    pub fn get_sockfd(&self) -> i32 {
        self.sockfd
    }

    pub fn attach_dev(&self, iface_name: &str) -> Result<(), AfbError> {
        let cstring = match CString::new(iface_name) {
            Ok(value) => value,
            Err(_) => {
                return afb_error!(
                    "ipv6-socket-attach",
                    "fail to translate iface-name:{}",
                    iface_name
                )
            }
        };

        let rc = unsafe {
            cglue::setsockopt(
                self.sockfd,
                cglue::C_SOL_SOCKET,
                cglue::C_BINDTODEVICE,
                cstring.as_ptr() as *const _ as *const raw::c_void,
                iface_name.len() as u32,
            )
        };
        if rc < 0 {
            return afb_error!(
                "ipv6-socket-attach",
                "fail device binding iface:{} err:{}",
                iface_name,
                get_perror()
            );
        }
        Ok(()) //ifr.ifr_if index
    }

    pub fn bind(&self, iface: &str, port: u16) -> Result<(), AfbError> {
        let mut socket_sdp = unsafe { mem::zeroed::<cglue::sockaddr_in6>() };
        socket_sdp.sin6_family = cglue::C_AF_INET6;
        socket_sdp.sin6_port = unsafe { cglue::htons(port) };
        // socket_sdp.sin6_addr = [0;] IPV6_ANY

        if iface != "" {
            self.attach_dev(iface)?;
        }
        let rc = unsafe {
            cglue::bind(
                self.sockfd,
                &socket_sdp as *const _ as *mut cglue::sockaddr,
                mem::size_of::<cglue::sockaddr_in6>() as u32,
            )
        };
        if rc < 0 {
            return afb_error!(
                "ipv6-socket-bind",
                "fail device bind port:{} err:{}",
                port,
                get_perror()
            );
        }
        Ok(())
    }

    pub fn multicast_join(
        &self,
        mcast_addr: [u8; cglue::C_INET6_ADDR_LEN],
    ) -> Result<(), AfbError> {
        let iface_num = 0;

        let in6_addr = cglue::in6_addr {
            __in6_u: cglue::in6_addr__bindgen_ty_1 {
                __u6_addr8: mcast_addr,
            },
        };

        let ipv6_mreq = cglue::ipv6_mreq {
            ipv6mr_multiaddr: in6_addr,
            ipv6mr_interface: iface_num,
        };

        let status = unsafe {
            cglue::setsockopt(
                self.sockfd,
                cglue::C_IPPROTO_IPV6,
                cglue::C_IPV6_JOIN_GROUP,
                &ipv6_mreq as *const _ as *mut raw::c_void,
                mem::size_of::<cglue::ipv6_mreq>() as u32,
            )
        };
        if status < 0 {
            unsafe { cglue::close(self.sockfd) };
            return afb_error!(
                "ipv6-socket-setopt",
                "fail to set ipv6_joint_group option {}",
                get_perror()
            );
        }

        Ok(())
    }

    pub fn recvfrom(&self, buffer: *mut u8, len: usize) -> Result<SocketSourceV6, AfbError> {
        let mut remote_addr6 = unsafe { mem::zeroed::<cglue::sockaddr_in6>() };
        let mut remote_len = mem::size_of::<cglue::sockaddr_in6>();

        let count = unsafe {
            cglue::recvfrom(
                self.sockfd,
                buffer as *mut raw::c_void,
                len,
                0,
                &mut remote_addr6 as *const _ as *mut cglue::sockaddr,
                &mut remote_len as *const _ as *mut cglue::socklen_t,
            )
        };
        if count < 0 || remote_len != mem::size_of::<cglue::sockaddr_in6>() {
            unsafe { cglue::close(self.sockfd) };
            return afb_error!(
                "ipv6-socket-recvfrom",
                "fail to read sdp socket len:{} err:{}",
                remote_len,
                get_perror()
            );
        }

        let source = SocketSourceV6 { addr: remote_addr6 };

        Ok(source)
    }

    pub fn sendto(&self, buffer: &[u8], destination: &SocketSourceV6) -> Result<(), AfbError> {
        let len = unsafe {
            cglue::sendto(
                self.sockfd,
                buffer.as_ptr() as *const _ as *mut raw::c_void,
                buffer.len(),
                0,
                &destination.addr as *const _ as *mut cglue::sockaddr,
                mem::size_of::<cglue::sockaddr_in6>() as cglue::socklen_t,
            )
        };
        if len != buffer.len() as isize {
            unsafe { cglue::close(self.sockfd) };
            return afb_error!(
                "ipv6-socket-recvfrom",
                "fail to send sdp socket len:{} err:{}",
                len,
                get_perror()
            );
        }

        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn client_certificate_cb(session: cglue::gnutls_session_t) -> raw::c_int {
    // retrieve tls session from gnutls_session_set_ptr()
    let tls_session = match unsafe {
        (cglue::gnutls_session_get_ptr(session) as *const GnuTlsSession).as_ref()
    } {
        Some(data) => data,
        None => {
            afb_log_msg!(
                Critical,
                None,
                "gtls-client-certificate: no session provided to callback"
            );
            return -1;
        }
    };

    let status: u32 = 0;
    let rc = unsafe {
        cglue::gnutls_certificate_verify_peers2(session, &status as *const _ as *mut u32)
    };
    if rc < 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: fail to verify certificate"
        );
        return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
    }
    if status & cglue::C_GNUTLS_CERT_INVALID != 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: the certificate is not trusted"
        );
    }
    if status & cglue::C_GNUTLS_CERT_SIGNER_NOT_FOUND != 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: the certificate hasn't got a known issuer"
        );
    }
    if status & cglue::C_GNUTLS_CERT_REVOKED != 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: the certificate has been revoked"
        );
    }
    if status & cglue::C_GNUTLS_CERT_EXPIRED != 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: the certificate has expired"
        );
    }
    if status & cglue::C_GNUTLS_CERT_NOT_ACTIVATED != 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: the certificate is not yet activated"
        );
    }
    if status != 0 {
        return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
    }

    if unsafe { cglue::gnutls_certificate_type_get(session) != cglue::C_GNUTLS_CRT_X509 } {
        afb_log_msg!(Error, None, "gtls-client-certificate: not X509 certificate");
        return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
    }

    let mut cert = mem::MaybeUninit::<cglue::gnutls_x509_crt_t>::uninit();
    let cert = if unsafe { cglue::gnutls_x509_crt_init(cert.as_mut_ptr()) } < 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: fail to init client x509 session"
        );
        return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
    } else {
        unsafe { cert.assume_init() }
    };

    let cert_list_size: u32 = 0;
    let cert_list = unsafe {
        cglue::gnutls_certificate_get_peers(session, &cert_list_size as *const _ as *mut u32)
    };
    if cert_list == 0 as *const cglue::gnutls_datum_t {
        afb_log_msg!(Error, None, "gtls-client-certificate: no certificate found");
        return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
    }

    // check only the first certificate - seems to be what curl does
    if unsafe { cglue::gnutls_x509_crt_import(cert, cert_list, cglue::C_GNUTLS_X509_FMT_DER) } < 0 {
        afb_log_msg!(
            Error,
            None,
            "gtls-client-certificate: fail parsing first certificate"
        );
        return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
    }

    if let Some(hostname) = &tls_session.hostname {
        if unsafe { cglue::gnutls_x509_crt_check_hostname(cert, hostname.as_ptr()) } != 0 {
            afb_log_msg!(
                Error,
                None,
                "gtls-client-certificate: certificate CN does not match hostname:{:?}",
                tls_session.hostname
            );
            return cglue::C_GNUTLS_E_CERTIFICATE_ERROR;
        }
    }
    // Fulup TBD for Jose probably useless in this context ?
    unsafe { cglue::gnutls_x509_crt_deinit(cert) };
    0
}

pub struct GnuTlsSession {
    hostname: Option<CString>,
    xsession: cglue::gnutls_session_t,
    xcred: cglue::gnutls_certificate_credentials_t,
}

impl Drop for GnuTlsSession {
    fn drop(&mut self) {
        unsafe { cglue::gnutls_deinit(self.xsession) };
        let boxe = unsafe { Box::from_raw(self) };
        drop(boxe);
    }
}

impl GnuTlsSession {
    pub fn new(
        config: &GnuTlsConfig,
        sockfd: i32,
        key_idx: u32,
        cert_idx: u32,
    ) -> Result<&'static Self, AfbError> {
        let private_key = config.get_key(key_idx)?;
        let (cert_list, cert_count) = config.get_cert(cert_idx)?;

        let xcred = unsafe {
            let mut cred = mem::MaybeUninit::<cglue::gnutls_certificate_credentials_t>::uninit();
            let status = cglue::gnutls_certificate_allocate_credentials(cred.as_mut_ptr());
            let cred = cred.assume_init();
            if status < 0 {
                return afb_error!(
                    "gtls-session-allocate",
                    "file to initialise session error:{}",
                    gtls_perror(status)
                );
            }
            cred
        };

        let status = unsafe {
            cglue::gnutls_certificate_set_x509_key(xcred, cert_list, cert_count as i32, private_key)
        };
        if status < 0 {
            return afb_error!(
                "gtls-session-certificate",
                "invalid glutls key/certification cert_idx:{} cert_key:{} error:{}",
                cert_idx,
                key_idx,
                gtls_perror(status)
            );
        }

        let xsession = unsafe {
            let mut session = mem::MaybeUninit::<cglue::gnutls_session_t>::uninit();
            let status = cglue::gnutls_init(
                session.as_mut_ptr(),
                cglue::gnutls_init_flags_t_GNUTLS_SERVER,
            );
            let session = session.assume_init();
            if status < 0 {
                return afb_error!(
                    "gtls-session-tlsinit",
                    "fail to initialise session error:{}",
                    gtls_perror(status)
                );
            }
            session
        };

        let status = unsafe { cglue::gnutls_set_default_priority(xsession) };
        if status < 0 {
            return afb_error!(
                "gtls-session-default",
                "fail to set default priority error:{}",
                gtls_perror(status)
            );
        }

        unsafe {
            let mut error = mem::MaybeUninit::<*mut raw::c_char>::uninit();
            let status = cglue::gnutls_priority_set_direct(
                xsession,
                config.priority.as_ptr(),
                error.as_mut_ptr() as *mut *const raw::c_char,
            );
            let error = error.assume_init();
            if status < 0 {
                return afb_error!(
                    "gtls-session-priority",
                    "fail to set priority:{:?} error:{}",
                    config.priority,
                    gtls_perror(status)
                );
            }
            error
        };

        let status = unsafe {
            cglue::gnutls_credentials_set(
                xsession,
                cglue::gnutls_credentials_type_t_GNUTLS_CRD_CERTIFICATE,
                xcred as *const _ as *mut raw::c_void,
            )
        };
        if status < 0 {
            return afb_error!(
                "gtls-session-credential",
                "fail to set priority error:{}",
                gtls_perror(status)
            );
        }

        unsafe {
            // request client cetificate, but do not enforce it
            cglue::gnutls_certificate_server_set_request(
                xsession,
                cglue::gnutls_certificate_request_t_GNUTLS_CERT_REQUEST,
            );
            cglue::gnutls_handshake_set_timeout(
                xsession,
                cglue::C_GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT as u32,
            );
        };

        unsafe {
            cglue::gnutls_transport_set_ptr(xsession, sockfd as cglue::gnutls_transport_ptr_t)
        };

        // when defined store hostname as a C string
        let hostname = if config.hostname == "" {
            None
        } else {
            match CString::new(config.hostname) {
                Ok(value) => Some(value),
                Err(_) => {
                    return afb_error!(
                        "gtls-session-hostname",
                        "fail hostname to UTF8 hostname:{}",
                        config.hostname
                    )
                }
            }
        };

        let this = Box::leak(Box::new(GnuTlsSession {
            xsession,
            xcred,
            hostname,
        }));
        Ok(this)
    }

    pub fn close(&self) {
        unsafe { cglue::gnutls_deinit(self.xsession) };
    }
    // client may have to known server certificate to authenticate server
    #[allow(dead_code)]
    pub fn set_cacert(&mut self, ca_path: &str) -> Result<&mut Self, AfbError> {
        let gnutls_ca = match CString::new(ca_path) {
            Ok(path) => path,
            Err(_) => return afb_error!("gtls-client-ca", "fail to import server ca:{}", ca_path),
        };
        let status = unsafe {
            cglue::gnutls_certificate_set_x509_trust_file(
                self.xcred,
                gnutls_ca.as_ptr(),
                cglue::C_GNUTLS_X509_FMT_PEM,
            )
        };
        if status < 0 {
            return afb_error!(
                "gtls-session-cacert",
                "fail to import server ca certificate:{} error:{}",
                ca_path,
                gtls_perror(status)
            );
        }
        Ok(self)
    }

    pub fn check_pending(&self) -> bool {
        let status = unsafe { cglue::gnutls_record_check_pending(self.xsession) };
        if status == 0 {
            false
        } else {
            true
        }
    }

    pub fn recv(&self, buffer: &mut [u8]) -> Result<usize, AfbError> {
        let ret = unsafe {
            cglue::gnutls_record_recv(
                self.xsession,
                buffer.as_mut_ptr() as *mut raw::c_void,
                buffer.len(),
            )
        };

        if unsafe { cglue::gnutls_error_is_fatal(ret as i32) } < 0 {
            // let try to rehandshake
            let response = if ret == cglue::C_GNUTLS_E_REHANDSHAKE as isize {
                self.client_handshake()?;
                Ok(0)
            } else {
                // move gnutls error to rust &str
                let cerror = unsafe { CStr::from_ptr(cglue::gnutls_strerror(ret as i32)) };
                let error = cerror.to_str().unwrap();
                afb_error!("gtls-session-recv", "error:{}", error)
            };
            return response;
        }

        Ok(ret as usize)
    }

    pub fn send(&self, buffer: &[u8]) -> Result<usize, AfbError> {
        let ret = unsafe {
            cglue::gnutls_record_send(
                self.xsession,
                buffer.as_ptr() as *mut raw::c_void,
                buffer.len(),
            )
        };

        if unsafe { cglue::gnutls_error_is_fatal(ret as i32) } < 0 {
            // let try to rehandshake
            let response = if ret == cglue::C_GNUTLS_E_REHANDSHAKE as isize {
                self.client_handshake()?;
                Ok(0)
            } else {
                // move gnutls error to rust &str
                let cerror = unsafe { CStr::from_ptr(cglue::gnutls_strerror(ret as i32)) };
                let error = cerror.to_str().unwrap();
                afb_error!("gtls-session-send", "error:{}", error)
            };
            return response;
        }

        Ok(ret as usize)
    }

    pub fn client_handshake(&self) -> Result<(), AfbError> {
        let status = unsafe { cglue::gnutls_handshake(self.xsession) };
        if status < 0 {
            return afb_error!(
                "gtls-session-handskake",
                "fail tls handshake error:{}",
                gtls_perror(status)
            );
        }
        Ok(())
    }
    #[allow(dead_code)]
    pub fn set_secure(&self) -> &Self {
        unsafe {
            cglue::gnutls_session_set_ptr(self.xsession, self as *const _ as *mut raw::c_void);
            cglue::gnutls_certificate_set_verify_function(self.xcred, Some(client_certificate_cb));
            cglue::gnutls_certificate_set_verify_flags(
                self.xcred,
                cglue::gnutls_certificate_verify_flags_GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT,
            );
        }
        self
    }
}

pub struct GnuTlsConfig {
    version: String,
    hostname: &'static str,
    priority: CString,
    xcred: cglue::gnutls_certificate_credentials_t,
}
impl GnuTlsConfig {
    pub fn new(cert_path: &str, key_path: &str, hostname: &'static str) -> Result<Self, AfbError> {
        const GNUTLS_PRIORITY: &str = "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2";
        const GNU_TLS_MIN_VER: &str = "3.4.6";

        let glutls_version = match CString::new(GNU_TLS_MIN_VER) {
            Ok(value) => value,
            Err(_) => {
                return afb_error!(
                    "gtls-init-string",
                    "fail to import iface:{}",
                    GNU_TLS_MIN_VER
                )
            }
        };
        let version = match unsafe { cglue::gnutls_check_version(glutls_version.as_ptr()).as_ref() }
        {
            Some(value) => unsafe { CStr::from_ptr(value).to_str().unwrap().to_string() },
            None => {
                return afb_error!(
                    "gtls-init-version",
                    "invalid glutls version expect minimum:{}",
                    GNU_TLS_MIN_VER
                )
            }
        };

        let glutls_key = match CString::new(key_path) {
            Ok(value) => value,
            Err(_) => return afb_error!("gtls-client-key", "fail to import key:{}", key_path),
        };

        let glutls_cert = match CString::new(cert_path) {
            Ok(value) => value,
            Err(_) => return afb_error!("gtls-client-cert", "fail to import cert:{}", cert_path),
        };

        let xcred = unsafe {
            let mut cred = mem::MaybeUninit::<cglue::gnutls_certificate_credentials_t>::uninit();
            let status = cglue::gnutls_certificate_allocate_credentials(cred.as_mut_ptr());
            let cred = cred.assume_init();
            if status < 0 {
                return afb_error!(
                    "gtls-config-credential",
                    "file to initialise session keyfile:{} error:{}",
                    key_path,
                    gtls_perror(status)
                );
            }
            cred
        };

        let status = unsafe {
            cglue::gnutls_certificate_set_x509_key_file(
                xcred,
                glutls_cert.as_ptr(),
                glutls_key.as_ptr(),
                cglue::C_GNUTLS_X509_FMT_PEM,
            )
        };

        if status < 0 {
            return afb_error!(
                "gtls-config-cert",
                "invalid glutls key/certification cert:{} key:{} error:{}",
                cert_path,
                key_path,
                gtls_perror(status)
            );
        }

        // prepare priority C string for session::new
        let priority = CString::new(GNUTLS_PRIORITY).unwrap();

        let config = GnuTlsConfig {
            version,
            hostname,
            xcred,
            priority,
        };
        Ok(config)
    }

    pub fn get_key(&self, index: u32) -> Result<cglue::gnutls_x509_privkey_t, AfbError> {
        let key = unsafe {
            let mut buffer = mem::MaybeUninit::<cglue::gnutls_x509_privkey_t>::uninit();
            let status =
                cglue::gnutls_certificate_get_x509_key(self.xcred, index, buffer.as_mut_ptr());
            if status < 0 {
                return afb_error!(
                    "gtls-session-credential",
                    "file to retreive private key from config index:{}, error:{}",
                    index,
                    gtls_perror(status)
                );
            }
            buffer.assume_init()
        };
        Ok(key)
    }
    pub fn get_cert(&self, index: u32) -> Result<(*mut cglue::gnutls_x509_crt_t, u32), AfbError> {
        let list = unsafe {
            let mut buffer = mem::MaybeUninit::<*mut cglue::gnutls_x509_crt_t>::uninit();
            let count = 0;
            let status = cglue::gnutls_certificate_get_x509_crt(
                self.xcred,
                index,
                buffer.as_mut_ptr(),
                &count as *const _ as *mut u32,
            );
            if status < 0 {
                return afb_error!(
                    "gtls-session-credential",
                    "file to retreive cert from config index:{}, error:{}",
                    index,
                    gtls_perror(status)
                );
            }
            (buffer.assume_init(), count)
        };
        Ok(list)
    }

    pub fn get_version(&self) -> String {
        self.version.clone()
    }
}
