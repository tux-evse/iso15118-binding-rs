/*
 * Copyright (C) 2015-2022 IoT.bzh Company
 * iso15118or: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 */

use afbv4::prelude::*;
use serde::{Deserialize, Serialize};

AfbDataConverter!(iso15118_msg, _Iso15118Msg);
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum _Iso15118Msg {
    Initialized,
    Unknown,
}


pub fn iso15118_registers() -> Result<(), AfbError> {
    //iso15118_msg::register()?;
    Ok(())
}
