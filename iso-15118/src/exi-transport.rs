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
 *
 */

use crate::prelude::*;
use afbv4::prelude::*;
use std::alloc;
use std::boxed::Box;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard};

pub struct ExiData {
    pub buffer: Pin<Box<[u8; cexi::EXI_MAX_DOCUMENT_SIZE]>>,
    pub stream: *mut cexi::exi_bitstream_t,
    layout: alloc::Layout,
}

pub struct ExiStream {
    data_set: Mutex<ExiData>,
}

#[no_mangle]
pub extern "C" fn exi_stream_cb(message_id: i32, status_code: i32, value_1: i32, value_2: i32) {
    afb_log_msg!(
        Debug,
        None,
        "message_id:{} status_code:{} val1:{} val2{}",
        message_id,
        status_code,
        value_1,
        value_2
    );
}

impl ExiStream {
    /// reserve stream memory space
    pub fn new() -> Self {
        // allocate exi_bitstream_t in heap and freeze it
        let layout = alloc::Layout::new::<cexi::exi_bitstream_t>();
        let handle = unsafe { alloc::alloc(layout) as *mut cexi::exi_bitstream_t };

        let mut stream = ExiData {
            layout,
            buffer: Box::pin([0; cexi::EXI_MAX_DOCUMENT_SIZE]),
            stream: handle,
        };

        // create an empty exi doc
        unsafe {
            cexi::exi_bitstream_init(
                handle,
                stream.buffer.as_mut_ptr(),
                cexi::EXI_MAX_DOCUMENT_SIZE,
                0,
                Some(exi_stream_cb),
            )
        }
        ExiStream {
            data_set: Mutex::new(stream),
        }
    }

    pub fn get_handle(&self) -> MutexGuard<ExiData> {
        self.data_set.lock().unwrap()
    }

    pub fn drop(&self) {
        // to drom object move back ExiStream handle into Rust allocate space
        let handle = self.get_handle();
        let _ = unsafe { alloc::dealloc(handle.stream as *mut u8, handle.layout) };
    }

    // remove header from data buffer stream to match exec decoder
    pub fn finalize(&self, doc_size: u32) -> Result<(), AfbError> {
        let handle = self.get_handle();

        match unsafe { handle.stream.as_mut() } {
            Some(data) => {
                data.data_size = doc_size as usize; // (cexi::SDP_V2G_HEADER_LEN+doc_size) as usize;
                data.byte_pos = cexi::SDP_V2G_HEADER_LEN as usize; // cexi::SDP_V2G_HEADER_LEN as usize
            }
            None => return afb_error!("exi-stream-shift", "fail to shift header (invalid stream)"),
        };

        Ok(())
    }

    pub fn get_index(&self) -> (usize, usize) {
        let handle = self.get_handle();
        let index = unsafe { cexi::exi_bitstream_get_length(handle.stream) };
        (index, cexi::EXI_MAX_DOCUMENT_SIZE - index)
    }

    pub fn reset(&self) {
        let handle = self.get_handle();
        unsafe { cexi::exi_bitstream_reset(handle.stream) };
    }
    pub fn get_length(&self) -> usize {
        let handle = self.get_handle();
        unsafe { cexi::exi_bitstream_get_length(handle.stream) }
    }
    pub fn write_bits(&self, value: u32, bit_count: usize) -> Result<(), AfbError> {
        let handle = self.get_handle();
        let status = unsafe { cexi::exi_bitstream_write_bits(handle.stream, bit_count, value) };
        if status != 0 {
            return afb_error!(
                "exi-stream-wbits",
                "fail to write bit error:{:?}",
                ExiErrorCode::from_i32(status)
            );
        }
        Ok(())
    }
    pub fn write_octet(&self, value: u8) -> Result<(), AfbError> {
        let handle = self.get_handle();
        let status = unsafe { cexi::exi_bitstream_write_octet(handle.stream, value) };
        if status != 0 {
            return afb_error!(
                "exi-stream-woctets",
                "fail to write byte error:{:?}",
                ExiErrorCode::from_i32(status)
            );
        }
        Ok(())
    }
    pub fn read_bits(&self, bit_count: usize) -> Result<u32, AfbError> {
        let handle = self.get_handle();
        let mut value: u32 = 0;
        let status = unsafe { cexi::exi_bitstream_read_bits(handle.stream, bit_count, &mut value) };
        if status != 0 {
            return afb_error!(
                "exi-stream-rbits",
                "fail to read bit error:{:?}",
                ExiErrorCode::from_i32(status)
            );
        }
        Ok(value)
    }
    pub fn read_octet(&self) -> Result<u8, AfbError> {
        let handle = self.get_handle();
        let mut value: u8 = 0;
        let status = unsafe { cexi::exi_bitstream_read_octet(handle.stream, &mut value) };
        if status != 0 {
            return afb_error!(
                "exi-stream-roctets",
                "fail to read byte error:{:?}",
                ExiErrorCode::from_i32(status)
            );
        }
        Ok(value)
    }

    pub fn header_check(&self) -> Result<u32, AfbError> {
        let handle = self.get_handle();

        // check vg2tp exi message header
        let count = v2gtp_header_check(V2gTypeId::EXI_V2G_MSG, handle.buffer.as_ref())?;
        if count > cexi::EXI_MAX_DOCUMENT_SIZE as u32 {
            return afb_error!(
                "exi_header_check",
                "doc size::{} to big max:{}",
                count,
                cexi::EXI_MAX_DOCUMENT_SIZE
            );
        }

        Ok(count)
    }
}
