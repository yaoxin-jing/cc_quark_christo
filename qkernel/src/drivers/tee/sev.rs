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

use core::mem::size_of;

pub mod attestation;

pub const MSG_HDR_VER: u8 = 1;
pub const MSG_PAYLOAD_LEN: usize = 4000;
const MAX_AUTHTAG_LEN: usize = 32;
// Header of a SnpGuestMsg
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SnpGuestMsgHdr {
    authtag: [u8; MAX_AUTHTAG_LEN],
    msg_seqno: u64,
    rsvd1: [u8; 8],
    pub algo: u8,
    hdr_version: u8,
    hdr_sz: u16,
    msg_type: u8,
    msg_version: u8,
    msg_sz: u16,
    rsvd2: u32,
    msg_vmpck: u8,
    rsvd3: [u8; 35],
}

impl Default for SnpGuestMsgHdr {
    fn default() -> Self {
        SnpGuestMsgHdr {
            authtag: [0u8; MAX_AUTHTAG_LEN],
            msg_seqno: 0u64,
            rsvd1: [0u8; 8],
            algo: 0u8,
            hdr_version: 0u8,
            hdr_sz: 0u16,
            msg_type: 0u8,
            msg_version: 0u8,
            msg_sz: 0u16,
            rsvd2: 0u32,
            msg_vmpck: 0u8,
            rsvd3: [0u8; 35],
        }
    }
}

/// Header of the SnpReport Response
#[repr(C)]
pub struct SnpReportResponseHeader {
    /// 0 if valid
    pub status: u32,
    /// size of the report after this header
    pub size: u32,
    rsvd: [u8; 24],
}

// SAFETY: SnpReportResponseHeader is a C struct with no UD states and pointers.
unsafe impl ByteSized for SnpReportResponseHeader {}

#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
enum SnpMsgType {
    KeyReq = 3,
    KeyRsp = 4,
    ReportReq = 5,
    ReportRsp = 6,
}

#[derive(Copy, Clone)]
#[repr(u8)]
#[non_exhaustive]
pub enum AeadAlgo {
    // SnpAeadInvalid = 0,
    SnpAeadAes256Gcm = 1,
}

#[derive(Debug, Copy, Clone)]
#[repr(C, align(4096))]
pub struct SnpGuestMsg {
    pub hdr: SnpGuestMsgHdr,
    payload: [u8; MSG_PAYLOAD_LEN],
}

impl Default for SnpGuestMsg {
    fn default() -> Self {
        SnpGuestMsg {
            hdr: SnpGuestMsgHdr::default(),
            payload: [0u8; MSG_PAYLOAD_LEN],
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SnpReportRequest {
    /// Guest-provided data to be included into the attestation report
    pub report_data: [u8; 64],
    /// VMPL
    pub vmpl: u32,
    rsvd: [u8; 28],
}

impl Default for SnpReportRequest {
    fn default() -> Self {
        SnpReportRequest {
            report_data: [0u8; 64],
            vmpl: 0u32,
            rsvd: [0u8; 28],
        }
    }
}

unsafe impl ByteSized for SnpReportRequest {}

pub unsafe trait ByteSized: Sized {
    const SIZE: usize = size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }

        Some(unsafe { (bytes.as_ptr() as *const _ as *const Self).read_unaligned() })
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, Self::SIZE) }
    }
}

