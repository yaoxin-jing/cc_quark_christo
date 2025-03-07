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

pub mod config;
pub mod attester;
pub mod util;

use alloc::string::String;
use alloc::vec::Vec;
use crate::qlib::common::Result;
use crate::{drivers::attestation::{Challenge, Response},
    qlib::{config::CCMode, kernel::arch::tee::{get_tee_type,
        is_hw_tee}}};

use self::util::{AttestationToken, InitDataStatus};
use self::{attester::Attester, config::AaConfig};

// Placeholder
struct DummyKbc;

pub trait AttestationAgentT {
    fn get_hw_tee_type(&self) -> Option<CCMode> {
        if is_hw_tee() {
            return Some(get_tee_type());
        }
        None
    }

    // Check if data matches host initial data provided during launch of TEE enviroment.
    // Possible Support: TDX, SEV/SNP
    fn check_init_data(&self, _init_data:Vec<u8>) -> Result<InitDataStatus> {
        Ok(InitDataStatus::Unsupported)
    }

    fn get_attestation_token(&mut self) -> Result<AttestationToken>;

    // Get measuremnt blob from TEE.
    fn get_tee_evidence(&self, challenge: Vec<u8>) -> Result<Response>;

    // Extend runtime measuremnt register of TEE when available.
    // Possible Support: TDX, SNV/SNP
    fn extend_runtime_measurement(&self) -> Result<bool> {
        Ok(false)
    }
}

pub struct AttestationAgent {
    attester: Attester,
    kbc: DummyKbc,
    config: AaConfig,
}

impl AttestationAgent {
    pub fn try_attest(config_path: Option<String>, envv: Option<Vec<String>>) {
        todo!("implement me");
    }

    pub fn new(config_path: Option<String>, env: Option<Vec<String>>) -> Result<Self> {
        todo!("implement me");
    }
}

impl AttestationAgentT for AttestationAgent {
    fn get_attestation_token(&mut self) -> Result<AttestationToken> {
        todo!("implement me");
    }

    fn get_tee_evidence(&self, challenge: Vec<u8>) -> Result<Response> {
        todo!("implement me");
    }
}
