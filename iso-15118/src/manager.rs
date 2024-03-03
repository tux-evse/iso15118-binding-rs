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
 * Reference:
 */

use std::sync::{Mutex, MutexGuard};

use crate::prelude::*;
use afbv4::prelude::*;
//use typesv4::prelude::*;

pub struct ManagerConfig {}

pub struct ManagerState {
    pub status: u32,
    pub pending: V2gExiDocType,
}

pub struct IsoManager {
    pub config: ManagerConfig,
    pub data_set: Mutex<ManagerState>,
}

impl IsoManager {
    pub fn new() -> Result<Self, AfbError> {
        let state = Mutex::new(ManagerState {
            status: 0,
            pending: V2gExiDocType::AppHandReq,
        });
        let manager = IsoManager {
            data_set: state,
            config: ManagerConfig{},
        };
        Ok(manager)
    }

    #[track_caller]
    pub fn get_handle(&self) -> Result<MutexGuard<'_, ManagerState>, AfbError> {
        let guard = self.data_set.lock().unwrap();
        Ok(guard)
    }

    pub fn handle_exi_doc(&self, stream: &ExiStream) -> Result<(), AfbError> {
        let data_set = self.get_handle()?;
        match data_set.pending {
            V2gExiDocType::AppHandReq => {
                println! ("**** AppHandReq");
                let app_hand = AppHandExiDocument::decode(stream)?;
                for proto in app_hand.get_protocols()? {
                    println! ("**** proto={:?}", proto);
                }
            }

            _ => return afb_error!("mgr_handle-exi", "unsupported exi document type"),
        }
        Ok(())
    }
}
