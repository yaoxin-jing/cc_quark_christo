// Copyright (c) 2021 Quark Container Authors
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

use crate::drivers::tee::attestation::AttestationDriverT;
use crate::drivers::tee::attestation::{Challenge, Report};
use crate::Result;

use alloc::vec::Vec;
use tdx_tdcall;

#[derive(Default, Serialize)]
pub struct TdxAttestation;

impl TdxAttestation {
    const CHALLENGE_LENGTH: usize = 64;
}

impl AttestationDriverT for TdxAttestation {
    fn get_report(&mut self, _challenge: &Challenge) -> Result<Report> {
        let mut challenge: [u8; Self::CHALLENGE_LENGTH] = [0u8; Self::CHALLENGE_LENGTH];
        challenge.copy_from_slice(&_challenge);

        let _res: Vec<u8> = tdx_tdcall::tdreport::tdcall_report(&challenge)
            .expect("report from tdcall")
            .as_bytes()
            .to_vec();
        Ok(_res)
    }
}
