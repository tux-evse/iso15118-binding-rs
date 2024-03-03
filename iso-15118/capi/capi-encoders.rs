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
// use ::std::os::raw;
// use std::ffi::CStr;
// use std::ffi::CString;
// use std::fmt;
use crate::prelude::*;
use afbv4::prelude::*;
use std::mem;
use std::pin::Pin;

pub mod cexi {
    #![allow(dead_code)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!("_capi-encoders.rs");
}

#[derive(Debug)]
#[allow(non_camel_case_types, dead_code)]
#[repr(i32)]
pub enum ExiErrorCode {
    NO_ERROR = cexi::EXI_ERROR__NO_ERROR as i32,
    BITSTREAM_OVERFLOW = cexi::EXI_ERROR__BITSTREAM_OVERFLOW,
    HEADER_COOKIE_NOT_SUPPORTED = cexi::EXI_ERROR__HEADER_COOKIE_NOT_SUPPORTED,
    HEADER_OPTIONS_NOT_SUPPORTED = cexi::EXI_ERROR__HEADER_OPTIONS_NOT_SUPPORTED,
    SUPPORTED_MAX_OCTETS_OVERRUN = cexi::EXI_ERROR__SUPPORTED_MAX_OCTETS_OVERRUN,
    OCTET_COUNT_LARGER_THAN_TYPE_SUPPORTS = cexi::EXI_ERROR__OCTET_COUNT_LARGER_THAN_TYPE_SUPPORTS,
    UNKNOWN_EVENT_FOR_DECODING = cexi::EXI_ERROR__UNKNOWN_EVENT_FOR_DECODING,
    DECODER_NOT_IMPLEMENTED = cexi::EXI_ERROR__DECODER_NOT_IMPLEMENTED,
    UNKNOWN_EVENT_FOR_ENCODING = cexi::EXI_ERROR__UNKNOWN_EVENT_FOR_ENCODING,
    ENCODER_NOT_IMPLEMENTED = cexi::EXI_ERROR__ENCODER_NOT_IMPLEMENTED,
    BIT_COUNT_LARGER_THAN_TYPE_SIZE = cexi::EXI_ERROR__BIT_COUNT_LARGER_THAN_TYPE_SIZE,
    BYTE_COUNT_LARGER_THAN_TYPE_SIZE = cexi::EXI_ERROR__BYTE_COUNT_LARGER_THAN_TYPE_SIZE,
    ARRAY_OUT_OF_BOUNDS = cexi::EXI_ERROR__ARRAY_OUT_OF_BOUNDS,
    CHARACTER_BUFFER_TOO_SMALL = cexi::EXI_ERROR__CHARACTER_BUFFER_TOO_SMALL,
    BYTE_BUFFER_TOO_SMALL = cexi::EXI_ERROR__BYTE_BUFFER_TOO_SMALL,
    UNKNOWN_GRAMMAR_ID = cexi::EXI_ERROR__UNKNOWN_GRAMMAR_ID,
    UNKNOWN_EVENT_CODE = cexi::EXI_ERROR__UNKNOWN_EVENT_CODE,
    UNSUPPORTED_SUB_EVENT = cexi::EXI_ERROR__UNSUPPORTED_SUB_EVENT,
    DEVIANTS_NOT_SUPPORTED = cexi::EXI_ERROR__DEVIANTS_NOT_SUPPORTED,
    STRINGVALUES_NOT_SUPPORTED = cexi::EXI_ERROR__STRINGVALUES_NOT_SUPPORTED,
    UNSUPPORTED_INTEGER_VALUE_TYPE = cexi::EXI_ERROR__UNSUPPORTED_INTEGER_VALUE_TYPE,
    UNSUPPORTED_DATETIME_TYPE = cexi::EXI_ERROR__UNSUPPORTED_DATETIME_TYPE,
    UNSUPPORTED_CHARACTER_VALUE = cexi::EXI_ERROR__UNSUPPORTED_CHARACTER_VALUE,
    INCORRECT_END_FRAGMENT_VALUE = cexi::EXI_ERROR__INCORRECT_END_FRAGMENT_VALUE,
    NOT_IMPLEMENTED_YET = cexi::EXI_ERROR__NOT_IMPLEMENTED_YET,
}

pub enum V2gExiDocType {
    AppHandReq,
    None,
}

// make following type public to crate
pub struct AppHandExiDocument {
    raw: cexi::appHand_exiDocument,
}

#[derive(Debug, Clone)]
pub struct AppHandProtocols {
    pub name_space: String,
    pub version_number_major: u32,
    pub version_number_minor: u32,
    pub schema_id: u8,
    pub priority: u8,
}
impl AppHandExiDocument {
    pub fn decode(stream: &ExiStream) -> Result<AppHandExiDocument, AfbError> {
        let handle = stream.get_handle();
        let exi_raw = unsafe {
            let mut exi_raw = mem::MaybeUninit::<cexi::appHand_exiDocument>::uninit();
            let status = cexi::decode_appHand_exiDocument(handle.stream, exi_raw.as_mut_ptr());
            let mut exi_raw = exi_raw.assume_init();
            match status {
                0 => {
                    exi_raw.set_supportedAppProtocolReq_isUsed(1);
                    exi_raw.set_supportedAppProtocolRes_isUsed(0);
                }
                1 => {
                    exi_raw.set_supportedAppProtocolReq_isUsed(0);
                    exi_raw.set_supportedAppProtocolRes_isUsed(1);
                }
                _ => return afb_error!("exi_decode_doc", "unsupported AppProtocolRes:{}", status),
            }
            exi_raw
        };
        Ok(AppHandExiDocument { raw: exi_raw })
    }

    pub fn get_protocols(&self) -> Result<Vec<AppHandProtocols>, AfbError> {
        let mut response: Vec<AppHandProtocols> = Vec::new();

        let (protocols, count) = unsafe {
            let request = if self.raw.supportedAppProtocolReq_isUsed() == 1 {
                self.raw.__bindgen_anon_1.supportedAppProtocolReq
            } else {
                return afb_error!("exi-app-proto", "fail, exi is not a request type");
            };

            let data = request.AppProtocol;
            (data.array, data.arrayLen as usize)
        };

        for idx in 0..count {
            let proto = protocols[idx];
            let slice = &proto.ProtocolNamespace.characters
                [0..proto.ProtocolNamespace.charactersLen as usize];
            let name_space = match std::str::from_utf8(unsafe {
                &*(slice as *const [i8] as *const [u8])
            }) {
                Ok(value) => value,
                Err(_) => return afb_error!("exi-app-proto", "fail to convert namespace to utf8"),
            };

            response.push(AppHandProtocols {
                name_space: name_space.to_string(),
                version_number_major: proto.VersionNumberMajor,
                version_number_minor: proto.VersionNumberMinor,
                schema_id: proto.SchemaID,
                priority: proto.Priority,
            })
        }
        Ok(response)
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum V2gTypeId {
    EXI_V2G_MSG = cexi::V2GTP20_SAP_PAYLOAD_ID as u16,
}

impl ExiErrorCode {
    pub fn from_i32(code: i32) -> Self {
        unsafe { mem::transmute(code) }
    }
}

// check header and return expected message size (payload+header_size)
pub fn v2gtp_header_check(type_id: V2gTypeId, buffer: Pin<&[u8]>) -> Result<u32, AfbError> {
    let mut payload_size: u32 = 0;
    let status = unsafe {
        cexi::V2GTP20_ReadHeader(
            buffer.as_ptr(),
            &mut payload_size as *mut u32,
            type_id as u16,
        )
    };
    if status != 0 {
        return afb_error!("v2g-header-check", "invalid payload");
    }

    Ok(payload_size+cexi::V2GTP_HEADER_LENGTH)
}
