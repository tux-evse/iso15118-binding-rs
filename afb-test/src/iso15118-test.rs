/*
 * Copyright (C) 2015-2023 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Redpesk samples code/config use MIT License and can be freely copy/modified even within proprietary code
 * License: $RP_BEGIN_LICENSE$ SPDX:MIT https://opensource.org/licenses/MIT $RP_END_LICENSE$
 *
 * Debug: wireshark -i eth0 -k -S -f "host iso15118.biastaging.com and tcp port 80"
 */

use afbv4::prelude::*;
//use typesv4::prelude::*;

// This rootv4 demonstrate how to test an external rootv4 that you load within the same afb-binder process and security context
// It leverages test (Test Anything Protocol) that is compatible with redpesk testing report.
struct TapUserData {
    autostart: bool,
    autoexit: bool,
    output: AfbTapOutput,
    target: &'static str,
    iface: &'static str,
}

// AfbApi userdata implements AfbApiControls trait
impl AfbApiControls for TapUserData {
    fn start(&mut self, api: &AfbApi) -> Result<(), AfbError> {
        afb_log_msg!(Notice, api, "starting iso15118-16 testing");

        // check tad_id on server
        let scan_iface = AfbTapTest::new("scan-iface", self.target, "scan-iface")
            .set_info("scan for iface ipv6 addrs")
            .add_arg(self.iface)?
            .finalize()?;

        AfbTapSuite::new(api, "Tap Demo Test")
            .set_info("iso15118 frontend -> occp server test")
            .set_timeout(0)
            .add_test(scan_iface)

            .set_autorun(self.autostart)
            .set_autoexit(self.autoexit)
            .set_output(self.output)
            .finalize()?;
        Ok(())
    }

    fn config(&mut self, api: &AfbApi, jconf: JsoncObj) -> Result<(), AfbError> {
        afb_log_msg!(Debug, api, "api={} config={}", api.get_uid(), jconf);
        match jconf.get::<bool>("autostart") {
            Ok(value) => self.autostart = value,
            Err(_error) => {}
        };

        match jconf.get::<bool>("autoexit") {
            Ok(value) => self.autoexit = value,
            Err(_error) => {}
        };

        match jconf.get::<String>("output") {
            Err(_error) => {}
            Ok(value) => match value.to_uppercase().as_str() {
                "JSON" => self.output = AfbTapOutput::JSON,
                "TAP" => self.output = AfbTapOutput::TAP,
                "NONE" => self.output = AfbTapOutput::NONE,
                _ => {
                    afb_log_msg!(
                        Error,
                        api,
                        "Invalid output should be json|tap (default used)"
                    );
                }
            },
        };

        Ok(())
    }

    // mandatory for downcasting back to custom apidata object
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

struct DummyMockCtx {
    label: &'static str,
}
AfbVerbRegister!(DummyMockVerb, dummy_request_cb, DummyMockCtx);
fn dummy_request_cb(rqt: &AfbRequest, _args: &AfbData, ctx: &mut DummyMockCtx) -> Result<(), AfbError> {
    afb_log_msg!(Notice, rqt, "Api mocking:{}", ctx.label);
    rqt.reply(AFB_NO_DATA, 0);
    Ok(())
}

// rootv4 init callback started at rootv4 load time before any API exist
// -----------------------------------------
pub fn binding_test_init(rootv4: AfbApiV4, jconf: JsoncObj) -> Result<&'static AfbApi, AfbError> {
    let uid = jconf.get::<&'static str>("uid")?;
    let api = jconf.default::<&'static str>("api",uid)?;
    let target = jconf.get::<&'static str>("target")?;
    let iface = jconf.default::<&'static str>("iface","eth2")?;

    let tap_config = TapUserData {
        autostart: jconf.default::<bool>("autostart", true)?,
        autoexit: jconf.default::<bool>("autoexit", true)?,
        output: AfbTapOutput::TAP,
        target,
        iface,
    };

    let subscribe_verb = AfbVerb::new("subscribe")
        .set_info("Mock subscribe api")
        .set_callback(Box::new(DummyMockVerb {label: "subscribe"}))
        .finalize()?;

    afb_log_msg!(Notice, rootv4, "iso15118 test uid:{} target:{}", uid, target);
    let api = AfbApi::new(uid)
        .set_name(api)
        .set_info("Testing iso15118 tap reporting")
        .require_api(target)
        .add_verb(subscribe_verb)
        .set_callback(Box::new(tap_config))
        .seal(false)
        .finalize()?;
    Ok(api)
}

// register rootv4 within libafb
AfbBindingRegister!(binding_test_init);
