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
pub mod kbc;

use core::convert::TryFrom;

#[cfg(target_arch = "aarch64")]
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::attestation_agent::util::connection::{tls_connection,
    ConnectionClient, Connector};
use crate::attestation_agent::util::ResourceUri;
use crate::qlib::common::Result;
use crate::{drivers::attestation::{Challenge, Response},
    qlib::{config::CCMode, kernel::arch::tee::{get_tee_type,
        is_hw_tee}}};

#[cfg(target_arch = "aarch64")]
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

    fn get_attestation_token(&mut self, con_client: &mut ConnectionClient)
        -> Result<AttestationToken>;

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
        let resource_list = aa.get_resource_list();
        debug!("VM: Required resources: {:?}", resource_list);
        let mut read_rec = [0u8; util::connection::Connector::TLS_RECORD];
        let mut write_rec = [0u8; util::connection::Connector::TLS_RECORD];
        let httpc = Connector::create_connector(aa.kbc.kbs_address());
        let bind = httpc.clone();
        let tls = tls_connection(&bind, &mut read_rec, &mut write_rec)
            .map_err(|e| {
                panic!("VM: AttAgent - Failed to create TLS connection to KBS:{:?}",e);
            })
            .unwrap();
        let mut conn_client = ConnectionClient {
            http_client: httpc,
            tls_conn: tls,
            cookie: "".to_string()
        };
        let token = aa.get_attestation_token(&mut conn_client)
            .expect("AA - failed to get Token");
        debug!("AA: Token:{:?}", token);
        for item in resource_list {
            let resource = aa.kbc.get_resource(&mut conn_client, item);
            debug!("VM: Secret:{:?}", resource);
        }
       // let _repo = String::from("default");
       // let _type = String::from("test");
       // let _tag = String::from("dummy");
       // let uri = ResourceUri {
       //     kbs_address: aa.config.kbs_url(),
       //     repository: _repo,
       //     r#type: _type,
       //     tag: _tag,
       //     query: None};

       // let resource = aa.kbc.get_resource(&mut conn_client, uri)
       //     .expect("Expected secret resource");
       // debug!("VM: Secret:{:?}", resource);
        //TODO:
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
        //
        //TODO: close connection / socket
    }

    fn get_resource_list(&self) -> Vec<ResourceUri> {
        let mut resourse_list: Vec<ResourceUri> = vec![];
        self.config.kbs_resources()
            .inspect(|list| {
                for item in *list {
                    let i = item.1.clone();
                    let uri = ResourceUri {
                        kbs_address: self.config.kbs_url(),
                        repository: i.repo,
                        r#type: i.r#type,
                        tag: i.tag,
                        query: i.query,
                    };
                    resourse_list.push(uri);
                }
            });
        resourse_list
    }

    pub fn new(_config_path: Option<String>, _env: Option<Vec<String>>) -> Result<Self> {
        let _attester = match get_tee_type() {
            #[cfg(target_arch = "aarch64")]
            CCMode::Cca => Box::<cca::CcaAttester>::default(),
            CCMode::Normal | CCMode::NormalEmu
            | CCMode::None => panic!("AA: No AA instance for CC mode ::None"),
            _ => todo!("implement me "),
        };

        let _config = AaConfig::new(_config_path, _env);
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
    fn get_attestation_token(&mut self, con_client: &mut ConnectionClient)
        -> Result<AttestationToken> {
        let tee = self.get_hw_tee_type()
            .expect("VM: AA - expected HW TEE backup");
        let tee = String::try_from(tee).unwrap();
        let (token, tkp) = self.kbc.get_token(tee, con_client, &self)
            .expect("VM: AA - failed to get token");
        let _ = self.kbc.update_token(Some(token.clone()), Some(tkp.clone()));
        Ok(token.inhalt.clone().as_bytes().to_vec())
    }

    fn get_tee_evidence(&self, challenge: Vec<u8>) -> Result<Response> {
        let mut nonce: Challenge = challenge;
        self.attester.get_tee_evidence(&mut nonce)
    }
}
