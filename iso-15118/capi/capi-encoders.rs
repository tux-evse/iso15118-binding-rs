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
// use std::mem;


pub mod cencoder {
    #![allow(dead_code)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!("_capi-encoders.rs");
}
