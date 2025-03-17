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

use alloc::vec::Vec;

use self::util::{CertTableEntry, AttestationReport};

use super::AttesterT;
use crate::drivers::tee::attestation::{Challenge, Response, ATTESTATION_DRIVER};
use crate::qlib::common::Result;

pub mod util;

#[derive(Default)]
pub struct SevAttester;

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct SnpEvidence {
    pub attestation_report: AttestationReport,
    pub cert: Option<Vec<CertTableEntry>>
}

impl AttesterT for SevAttester {
    fn get_tee_evidence(&self, challenge: &mut Challenge) -> Result<Response> {
        let mut atd_l = ATTESTATION_DRIVER.lock();
        let res = atd_l.get_report(challenge);
        if res.is_err() {
            error!("VM: challenge was not in valid format.");
            return core::prelude::v1::Err(res.err().unwrap());
        }
        let rep = res.unwrap();
        let at_rep: AttestationReport = unsafe {
            *(rep.as_ptr() as *const AttestationReport)
        };
        let sev_att = SnpEvidence {
            attestation_report: at_rep,
            cert: None,
        };
        let ser_set = serde_json::to_string(&sev_att)
            .expect("serialize to string failed");
        Ok(ser_set)
    }
}
