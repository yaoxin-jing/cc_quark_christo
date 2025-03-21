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

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use crate::attestation_agent::util::connection::{tls_connection,
    ConnectionClient, Connector};
use crate::attestation_agent::util::ResourceUri;
use crate::qlib::common::{Result, Error};
use crate::qlib::linux_def::{ATType, Flags};
use crate::syscalls::sys_file::{close, createAt};
use crate::syscalls::sys_write::Write;
use crate::Task;
use crate::{drivers::tee::attestation::{Challenge, Response},
    qlib::{config::CCMode, kernel::arch::tee::{get_tee_type,
        is_hw_tee}}};

use self::attester::tdx::TdxAttester;
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
        let mut retrived_resource: Vec<(String, Vec<u8>)> = vec![];
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
            let resource = aa.kbc.get_resource(&mut conn_client, item.1)
                .expect("Exptect resource");
            debug!("VM: Secret:{:?}", resource);
            let dir_path = format!("/opt/{}", item.0);
            retrived_resource.push((dir_path, resource));
        }
        debug!("VM: AA - close connection to KBS");
        let _ = conn_client.close().map_err(|e| {
            panic!("VM: Failed to close connection with KBS: {:?}", e);
        });
        Self::install_resource(retrived_resource);
    }

    fn install_resource(list: Vec<(String, Vec<u8>)>) {
        use crate::qlib::linux_def::{ModeType, FileMode};
        use crate::qlib::cstring::CString;
        let task = Task::Current();
        let mode = ModeType::MODE_USER_READ | ModeType::MODE_GROUP_READ
            | ModeType::MODE_USER_WRITE | ModeType::MODE_GROUP_WRITE;
        let flag = Flags::O_CREAT | Flags::O_WRONLY;
        for (_name, _content) in list {
            let fname = CString::New(_name.as_str());
            let addr = fname.Ptr();
            let content = core::str::from_utf8(_content.as_slice())
                .expect("valid utf8 contnet");
            let content = CString::New(content);
            let fd = createAt(task, ATType::AT_FDCWD,
                addr, flag as u32, FileMode(mode)).expect("crate failed");
            if fd > 0i32 {
                let size: i64 = content.Len() as i64;
                let addr = content.Ptr();
                let res = Write(task, fd, addr, size).map_err(|e| {
                    panic!("VM: write content failed:{:?}", e);
                });
                debug!("VM: wrote in file:{:?} bytes", res);
                close(task, fd).expect("VM: failed to close fd");
            } else {
                panic!("VM: AA - failed to create :{:?} on guest", fname.Slice());
            }
        }
    }

    fn get_resource_list(&self) -> Vec<(String, ResourceUri)> {
        let mut resourse_list: Vec<(String, ResourceUri)> = vec![];
        self.config.kbs_resources()
            .inspect(|list| {
                for item in *list {
                    let i = item.clone();
                    let uri = ResourceUri {
                        kbs_address: self.config.kbs_url(),
                        repository: i.repo,
                        r#type: i.r#type,
                        tag: i.tag,
                        query: i.query,
                    };
                    resourse_list.push((i.local_name, uri));
                }
            });
        resourse_list
    }

    pub fn new(_config_path: Option<String>, _env: Option<Vec<String>>) -> Result<Self> {
        let _attester = Self::get_attester(get_tee_type());
        if _attester.is_none() {
            return Err(Error::Common(String::from("Attestation not supported")));
        }

        let _config = AaConfig::new(_config_path, _env);
        // Only Background check is supported at the moment.
        let _kbc = kbc_build(kbc::KbsClientType::BckgCheck,
            _config.kbs_url(), _config.kbs_cert());
        Ok(AttestationAgent {
            attester: _attester.unwrap(),
            kbc: _kbc,
            config: _config,
        })
    }

    fn get_attester(mode: CCMode) -> Option<Attester> {
        match mode {
            CCMode::Normal | CCMode::NormalEmu
            | CCMode::None => {
                error!("AA: No AA instance for CC mode:{:?}", mode);
                None
            },
            CCMode::TDX => Some(Box::new(TdxAttester::default())),
            _ => {
                error!("AA: Attestation currently not implmented for:{:?}", mode);
                None
            },
        }
    }
}

impl AttestationAgentT for AttestationAgent {
    fn get_attestation_token(&mut self, con_client: &mut ConnectionClient)
        -> Result<AttestationToken> {
        let tee = self.get_hw_tee_type()
            .expect("VM: AA - expected HW TEE backup");
        let tee = String::try_from(tee).unwrap();
        let token = self.kbc.get_token(tee, con_client, &self)
            .expect("VM: AA - failed to get token");
        let _ = self.kbc.update_token(Some(token.clone()));
        Ok(token.inhalt.clone().as_bytes().to_vec())
    }

    fn get_tee_evidence(&self, challenge: Vec<u8>) -> Result<Response> {
        let mut nonce: Challenge = challenge;
        self.attester.get_tee_evidence(&mut nonce)
    }
}
