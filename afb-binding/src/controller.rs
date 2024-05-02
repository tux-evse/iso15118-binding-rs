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
 */

use iso15118::prelude::*;
use std::sync::{Mutex, MutexGuard};

pub struct ControlerConfig {}

pub struct ControlerState {
    pub status: u32,
    pub protocol: v2g::ProtocolTagId,
    session_id: Vec<u8>,
    evccid: iso2::SessionSetupRequest,
}

pub struct IsoController {
    pub config: ControlerConfig,
    pub data_set: Mutex<ControlerState>,
}

impl IsoController {
    pub fn new() -> Result<Self, AfbError> {
        let state = Mutex::new(ControlerState {
            status: 0,
            protocol: v2g::ProtocolTagId::Unknown,
            session_id: Vec::new(),
            evccid: iso2::SessionSetupRequest::empty(),
        });
        let controler = IsoController {
            data_set: state,
            config: ControlerConfig {},
        };
        Ok(controler)
    }

    #[track_caller]
    pub fn lock_handle(&self) -> Result<MutexGuard<'_, ControlerState>, AfbError> {
        let guard = self.data_set.lock().unwrap();
        Ok(guard)
    }

    pub fn iso_decode_payload(
        &self,
        stream: &ExiStream,
        lock: &mut MutexGuard<RawStream>,
    ) -> Result<(), AfbError> {
        let mut state = self.lock_handle()?;
        match state.protocol {
            v2g::ProtocolTagId::Unknown => {
                // initial message should be v2g::AppHandSupportedAppProtocolReq
                let v2g_msg = v2g::SupportedAppProtocolExi::decode_from_stream(lock)?;
                let app_protocol_req = match v2g_msg {
                    v2g::V2gMsgBody::Response(_) => {
                        return afb_error!(
                            "iso2-controller-protocol",
                            "expect 'AppHandSupportedAppProtocolReq' as initial request"
                        )
                    }
                    v2g::V2gMsgBody::Request(value) => value,
                };

                // compare AppHandSupportedAppProtocolReq with evse supported protocols
                let (rcode, schema_id) = match app_protocol_req
                    .match_protocol(&v2g::V2G_PROTOCOLS_SUPPORTED_LIST)
                {
                    Ok((rcode, proto)) => {
                        state.protocol = proto.get_schema();
                        afb_log_msg!(
                            Debug,
                            None,
                            "iso-app-hand: selected protocol:{}",
                            proto.get_name()
                        );
                        (rcode, proto.get_schema() as u8)
                    }
                    Err(rcode) => {
                        afb_log_msg!(Error, None, "iso-app-hand: No common iso protocol founded");
                        (rcode, 255)
                    }
                };

                let v2g_response = v2g::SupportedAppProtocolRes::new(rcode, schema_id).encode();
                v2g::SupportedAppProtocolExi::encode_to_stream(lock, &v2g_response)?;
            }
            v2g::ProtocolTagId::Iso2 => {
                use iso2::*;
                let message = Iso2MessageDoc::decode_from_stream(lock)?;
                let header= message.get_header();
                match message.get_body()? {
                    Iso2MessageBody::SessionSetupReq(request) => {
                        state.evccid = request.clone();

                        afb_log_msg!(
                            Debug,
                            None,
                            "SessionSetupReq evccid:[{}]",
                            dump_buffer(request.get_id())
                        );

                        // check if we are facing a new session
                        let session_id = header.get_session_id();
                        let status = if &state.session_id != session_id {
                            state.session_id = session_id.to_vec();
                            ResponseCode::NewSession
                        } else {
                            ResponseCode::Ok
                        };

                        // Fulup TBD this should comme from config
                        let evse_id = "tux-evse-001";
                        let body = SessionSetupResponse::new(evse_id, status)?.encode();
                        Iso2MessageDoc::new(&header, &body).encode_to_stream(lock)?;
                    } //end SessionSetupReq

                    Iso2MessageBody::ServiceDiscoveryReq(request) => {
                        let scope = match request.get_scope() {
                            Some(value) => value.to_string(),
                            None => "no-scope-defined".to_string(),
                        };

                        afb_log_msg!(Debug, None, "DiscoverySvcReq optional scope:[{}]", scope);
                        let mut charging = ServiceCharging::new(29, false);
                        charging.set_name("Tux-Evse")?.set_scope("IoT-bzh")?;

                        let mut service = ServiceOther::new(56, ServiceCategory::Internet, true);
                        service.set_name("LTE")?.set_scope("Network")?;

                        let transfer = EngyTransfertMode::AcSinglePhase;

                        let body = ServiceDiscoveryResponse::new(ResponseCode::Ok)
                            .set_charging(&charging)
                            .add_service(&service)?
                            .add_transfer(transfer)?
                            .add_payment(PaymentOption::Contract)?
                            .encode();
                        Iso2MessageDoc::new(&header, &body).encode_to_stream(lock)?;
                    } // end DiscoverySvcReq

                    Iso2MessageBody::ServiceDetailReq(request) => {
                        afb_log_msg!(
                            Debug,
                            None,
                            "ServiceDetailReq service_id:{}",
                            request.get_id()
                        );

                        let mut param_set_1 = ParamSet::new(1);
                        param_set_1.add_param("prm_1", &ParamValue::Int16(123))?;
                        param_set_1
                            .add_param("prm_2", &ParamValue::Text("snoopy".to_string()))?;
                        param_set_1.add_param(
                            "prm_3",
                            &ParamValue::PhyValue(PhysicalValue::new(
                                240,
                                1,
                                PhysicalUnit::Volt,
                            )),
                        )?;

                        let body = ServiceDetailResponse::new(request.get_id(), ResponseCode::Ok)
                            .add_pset(&param_set_1)?
                            .encode();
                        Iso2MessageDoc::new(&header, &body).encode_to_stream(lock)?;
                    } // end ServiceDetailReq

                    _ => {
                        return afb_error!(
                            "mgr_handle-exi",
                            "unsupported iso2 message:[{}]",
                            stream.dump_buffer(lock, ExiDump::Everything)?
                        )
                    }
                };
            }

            // unexpected request coming from EV
            _ => return afb_error!("controller-handle-exi", "unsupported exi document type"),
        }
        Ok(())
    }
}
