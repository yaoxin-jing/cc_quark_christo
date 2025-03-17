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

//
// The below declarations are predifined by the crate sev:[https://github.com/virtee/sev] and
// expected in this format by CoCo-trustee:[https://github.com/confidential-containers/trustee.git]

use alloc::vec::Vec;
use serde_big_array::BigArray;

#[repr(C)]
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct AttestationReport {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: GuestPolicy,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub sig_algo: u32,
    pub current_tcb: TcbVersion,
    pub plat_info: PlatformInfo,
    _author_key_en: u32,
    _reserved_0: u32,
    #[serde(with = "BigArray")]
    pub report_data: [u8; 64],
    #[serde(with = "BigArray")]
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    #[serde(with = "BigArray")]
    pub id_key_digest: [u8; 48],
    #[serde(with = "BigArray")]
    pub author_key_digest: [u8; 48],
    pub report_id: [u8; 32],
    pub report_id_ma: [u8; 32],
    pub reported_tcb: TcbVersion,
    _reserved_1: [u8; 24],
    #[serde(with = "BigArray")]
    pub chip_id: [u8; 64],
    pub committed_tcb: TcbVersion,
    pub current_build: u8,
    pub current_minor: u8,
    pub current_major: u8,
    _reserved_2: u8,
    pub committed_build: u8,
    pub committed_minor: u8,
    pub committed_major: u8,
    _reserved_3: u8,
    pub launch_tcb: TcbVersion,
    #[serde(with = "BigArray")]
    _reserved_4: [u8; 168],
    pub signature: Signature,
}

impl Default for AttestationReport {
    fn default() -> Self {
        Self {
            version: Default::default(),
            guest_svn: Default::default(),
            policy: Default::default(),
            family_id: Default::default(),
            image_id: Default::default(),
            vmpl: Default::default(),
            sig_algo: Default::default(),
            current_tcb: Default::default(),
            plat_info: Default::default(),
            _author_key_en: Default::default(),
            _reserved_0: Default::default(),
            report_data: [0; 64],
            measurement: [0; 48],
            host_data: Default::default(),
            id_key_digest: [0; 48],
            author_key_digest: [0; 48],
            report_id: Default::default(),
            report_id_ma: Default::default(),
            reported_tcb: Default::default(),
            _reserved_1: Default::default(),
            chip_id: [0; 64],
            committed_tcb: Default::default(),
            current_build: Default::default(),
            current_minor: Default::default(),
            current_major: Default::default(),
            _reserved_2: Default::default(),
            committed_build: Default::default(),
            committed_minor: Default::default(),
            committed_major: Default::default(),
            _reserved_3: Default::default(),
            launch_tcb: Default::default(),
            _reserved_4: [0; 168],
            signature: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize)]
pub struct GuestPolicy(u64);

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize)]
pub struct PlatformInfo(u64);

const RS_SIZE: usize = core::mem::size_of::<[u8; 72]>() * 2usize;
#[repr(C)]
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct Signature {
    #[serde(with = "BigArray")]
    r: [u8; 72],
    #[serde(with = "BigArray")]
    s: [u8; 72],
    #[serde(with = "BigArray")]
    _reserved: [u8; 512 - RS_SIZE],
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            r: [0u8; 72],
            s: [0u8; 72],
            _reserved: [0u8; (512 - (core::mem::size_of::<[u8; 72]>() * 2))],
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize)]
pub struct TcbVersion {
    pub bootloader: u8,
    pub tee: u8,
    _reserved: [u8; 4],
    pub snp: u8,
    pub microcode: u8,
}


#[repr(C)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CertType {
    Empty,
    ARK,
    ASK,
    VCEK,
    VLEK,
    CRL,
    OTHER(uuid::Uuid),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CertTableEntry {
    pub cert_type: CertType,
    pub data: Vec<u8>,
}

impl Default for CertTableEntry {
    fn default() -> Self {
        let _vec: Vec<u8> = vec![0];
        Self {
            cert_type: CertType::Empty,
            data: _vec,
        }
    }
}
