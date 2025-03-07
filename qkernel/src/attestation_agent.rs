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
pub mod kbc;
pub mod util;

use core::convert::TryFrom;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::attestation_agent::util::ResourceUri;
use crate::qlib::common::Result;
use crate::{drivers::attestation::{Challenge, Response},
    qlib::{config::CCMode, kernel::arch::tee::{get_tee_type,
        is_hw_tee}}};

use self::attester::cca;
use self::kbc::{kbc_build, Kbc};
use self::util::{AttestationToken, InitDataStatus};
use self::{attester::Attester, config::AaConfig};

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
    kbc: Kbc,
    config: AaConfig,
}

impl AttestationAgent {
    pub fn try_attest(config_path: Option<String>, envv: Option<Vec<String>>) {
        let mut aa: AttestationAgent = Self::new(config_path, envv)
            .expect("AA - failed to create instance");
        let token = aa.get_attestation_token()
            .expect("AA - failed to get Token");
        debug!("AA: Token:{:?}", token);

        //TODO:
        // Test p-2
        // a) Default

       // let _repo = String::from("default");
       // let _type = String::from("test");
       // let _tag = String::from("dummy");
       // let uri = ResourceUri {
       //     kbs_address: aa.config.kbs_url(),
       //     repository: "".to_string(),
       //     r#type: "".to_string(),
       //     tag: "".to_string(),
       //     query: None};
       // let res = aa.kbc.get_resource(uri).map_err(|e| {
       //     error!("AA - get resources failed for: {:?}",e);
       // });
        // b) From from ENV
        //
        // c) From from file
        //let resureces = aa.config.kbs_resources().into_iter();
       // for r in resureces {
       //     todo!("get resources");
       // }
       // let res = aa.kbc.get_resource(uri).map_err(|e| {
       //     error!("AA - get resources failed for: {:?}",e);
       // });
       // debug!("AA - resource:{:?}", res);
    }

    pub fn new(config_path: Option<String>, env: Option<Vec<String>>) -> Result<Self> {
        let _attester = match get_tee_type() {
            CCMode::Cca => Box::<cca::CcaAttester>::default(),
            CCMode::SevSnp => todo!("implement me "),
            CCMode::Normal | CCMode::NormalEmu
            | CCMode::None => panic!("AA: No AA instance for CC mode ::None")
        };

        let _config = AaConfig::new(config_path, env);
        // Only Background check is supported at the moment.
        let _kbc = kbc_build(kbc::KbsClientType::BckgCheck,
            _config.kbs_url(), _config.kbs_cert());
        Ok(AttestationAgent {
            attester: _attester,
            kbc: _kbc,
            config: _config,
        })
    }
}

impl AttestationAgentT for AttestationAgent {
    fn get_attestation_token(&mut self) -> Result<AttestationToken> {
        let tee = self.get_hw_tee_type()
            .expect("VM: AA - expected HW TEE backup");
        let tee = String::try_from(tee).unwrap();
        let (token, tkp, httpc) = self.kbc.as_ref().get_token(tee, &self)
            .expect("AA - failed to get token");
        let _ = self.kbc.update_token(Some(token.clone()), Some(tkp.clone()));
        if httpc.is_some() {
            self.kbc.update_intern(httpc.unwrap());
        }
        Ok(token.inhalt.clone().as_bytes().to_vec())
    }

    fn get_tee_evidence(&self, challenge: Vec<u8>) -> Result<Response> {
        let mut nonce: Challenge = challenge;
        self.attester.get_tee_evidence(&mut nonce)
    }
}
