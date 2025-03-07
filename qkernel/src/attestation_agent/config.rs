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

use alloc::{string::{String, ToString}, vec::Vec};

use crate::{qlib::linux_def::{ATType, Flags, MemoryDef},
    syscalls::{sys_file::{close, openAt}, sys_read::Read}, Task};
use crate::qlib::common::Result;

const DEFAULT_AA_CONFIG_PATH: &'static str = "/etc/attestation-agent.conf";

pub enum AaConfigReq {
    KbsConig
}

#[derive(Deserialize, Default)]
pub struct AaConfig {
    kbs_config: KbsConfig
}

impl AaConfig {
    fn new_from_envv(envv: Vec<String>) -> Self {
        let res = KbsConfig::new_from_envv(envv)
            .expect("VM: AA - Failed to create config from ENVV");

        Self { kbs_config: res }
    }

    fn new_from_config(config_path: Option<String>) -> Self {
        let res = match config_path {
            Some(path) => {
                let _kbs_conf = KbsConfig::new_from_config(&path);
                _kbs_conf
            },
            None => {
                let _kbs_conf = KbsConfig::new_from_config(&DEFAULT_AA_CONFIG_PATH);
                _kbs_conf
            }
        };
        let kbs_conf = res.expect("AA - Failed to construct KBS config");
        Self { kbs_config: kbs_conf }
    }

    pub fn new(config_path: Option<String>, envv: Option<Vec<String>>) -> Self {
        //
        // If configuratiin parameters are passed through ENV,
        // the config file is ignored.
        //
        let res = if envv.is_some() {
            Self::new_from_envv(envv.unwrap())
        } else {
            Self::new_from_config(config_path)
        };
        res
    }

    pub fn kbs_url(&self) -> String {
        self.kbs_config.url.clone()
    }

    pub fn kbs_cert(&self) -> Option<String> {
        self.kbs_config.cert.clone()
    }

    pub fn kbs_resources(&self) -> Option<&Vec<Resource>> {
        self.kbs_config.resources.as_ref()
    }
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct Resource {
    pub local_name: String,
    pub repo: String,
    pub r#type: String,
    pub tag: String,
    pub query: Option<String>,

}

#[derive(Deserialize, Default, Clone)]
pub(self) struct KbsConfig {
    pub(self) url: String,
    pub(self) cert: Option<String>,
    pub(self) resources: Option<Vec<Resource>>
}

impl KbsConfig {
    pub(self) fn new_from_config(config_path: &str) -> Result<Self> {
        let task = Task::Current();
        let flags = Flags::O_RDONLY as u32;
        let dirFd = ATType::AT_FDCWD;
        let path_addr = config_path.as_ptr() as u64;
        let open_res = openAt(task, dirFd, path_addr, flags);
        if open_res.is_err() {
            error!("AA - failed to open config - err:{:?}", open_res.unwrap());
            return Err(crate::qlib::common::Error::IOError("Failed to open file".to_string()));
        }

        let fd = open_res.unwrap();
        let mut buf_file = [0u8;MemoryDef::PAGE_SIZE_4K as usize];
        let buf_addr = buf_file.as_mut_ptr() as u64;
        let read_res = Read(task, fd, buf_addr, MemoryDef::PAGE_SIZE_4K as i64);
        let _ = close(task, fd);
        if read_res.is_err() {
            error!("AA - failed to read the config file - err:{:?}", read_res.unwrap());
            return Err(crate::qlib::common::Error::IOError("Failed to read file".to_string()));
        }

        let bytes = read_res.unwrap() as usize;
        let conf: AaConfig = serde_json::from_slice(&buf_file[0..bytes])
            .expect("AA - failed to parse config file - read failed");
        Ok(
            Self {
            url: conf.kbs_config.url,
            cert: conf.kbs_config.cert,
            resources: conf.kbs_config.resources,
        })
    }

    fn new_from_envv(envv: Vec<String>) -> Result<Self> {
        let mut kbs_conf: KbsConfig = Default::default();
        let mut requests: Vec<Resource> = Default::default();
        for e in envv {
            if e.contains("KBS_ADDRESS") {
                let address = e.strip_prefix("Q_AA_KBS_ADDRESS=")
                    .expect("VM: AA - Expected KBS \"IP:PORT\"").to_string();
                kbs_conf.url = address;
            } else if e.contains("KBS_CERT") {
                let cert = e.strip_prefix("Q_AA_KBS_CERT=");
                if cert.is_some() {
                    cert.map(|c| {
                        kbs_conf.cert = Some(c.to_string());
                    });
                }
            } else if e.contains("KBS_RESOURCE") {
                let resource = e.strip_prefix("Q_AA_KBS_RESOURCE_")
                    .expect("VM: AA - Expected resource_name=\"path/in/kbs\"");
                let mut iter = resource.split("=");
                let name = iter.next().expect("AA - expected name").to_string();
                let mut path = iter.next()
                    .expect("AA - expected path")
                    .split("/");
                let resource = Resource {
                    local_name: name,
                    repo: path.next().expect("Missing repo/... name").to_string(),
                    r#type: path.next().expect("Missing .../type/... name").to_string(),
                    tag: path.next().expect("Missing .../.../tag name").to_string(),
                    query: None,
                };

                requests.push(resource);
            }
        }
        if requests.is_empty() == false {
            kbs_conf.resources = Some(requests);
        }
        if kbs_conf.url.is_empty() {
            return Err(crate::qlib::common::Error::InvalidInput);
        }

        Ok(kbs_conf)
    }
}
