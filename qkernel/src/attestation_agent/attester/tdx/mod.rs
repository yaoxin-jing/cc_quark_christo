// Copyright (c) 2021 Quark Container Authors / 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::string::String;

use super::AttesterT;
use crate::drivers::tee::attestation::{Challenge, Response, ATTESTATION_DRIVER};
use crate::qlib::linux_def::SysErr;
use crate::{Error, Result};

#[derive(Default)]
pub struct TdxAttester;

#[derive(Default, Serialize)]
pub struct TdxEvidence {
    pub cc_eventlog: Option<String>,
    pub quote: String,
    pub aa_eventlog: Option<String>,
}

impl AttesterT for TdxAttester {
    fn get_tee_evidence(&self, challenge: &mut Challenge) -> Result<Response> {
        let mut atd_l = ATTESTATION_DRIVER.lock();
        let resp = atd_l.get_report(challenge);
        if resp.is_err() {
            error!("VM: challenge is not in valid format");
            return Err(Error::SystemErr(SysErr::EINVAL));
        }
        let report = resp.unwrap();
        let quote = base64::encode_config(report, base64::STANDARD);
        let tdx_ev = TdxEvidence{
            cc_eventlog: None,
            quote,
            aa_eventlog: None,
        };
        let res = serde_json::to_string(&tdx_ev)
            .expect("Serialize report to string");
        Ok(res)
    }
}
