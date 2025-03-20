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
use core::slice::from_raw_parts;

use aes_gcm::{aead::AeadMutInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
use alloc::string::String;
use x86_64::{PhysAddr, VirtAddr};

use crate::drivers::tee::attestation::{Challenge, Report};
use crate::qlib::linux_def::SysErr;
use crate::{drivers::tee::attestation::AttestationDriverT, Result, Error,
    GhcbHandle, GHCB};
use crate::qlib::kernel::arch::tee::sev_snp::secret_page::SECRETS;
use crate::qlib::kernel::Kernel::LOG_AVAILABLE;
use super::{AeadAlgo, ByteSized, SnpGuestMsg, SnpGuestMsgHdr, SnpMsgType, SnpReportRequest,
    SnpReportResponseHeader, MSG_HDR_VER};

#[derive(Default)]
pub struct SevAttestation {
    request: SnpGuestMsg,
    response: SnpGuestMsg,
}

impl SevAttestation {
    pub const REPORT_SIZE: usize = 1184;
    pub const ATTESTATION_BUFFER_LEN: usize = 4000;
}

impl AttestationDriverT for SevAttestation {
    fn init(&mut self) {
        let request_virt = VirtAddr::from_ptr(&self.request);
        let response_virt = VirtAddr::from_ptr(&self.response);

        let log_available =
            LOG_AVAILABLE.load(core::sync::atomic::Ordering::Acquire);
        let mut vcpuid = 0;
        if log_available {
            vcpuid = crate::qlib::kernel::asm::GetVcpuId();
        }

        {
            let ghcb_option: &mut Option<GhcbHandle<'_>> = &mut *GHCB[vcpuid].lock();
            let ghcb = ghcb_option.as_mut().unwrap();

            ghcb.set_memory_shared_4kb(request_virt, 1);

            ghcb.set_memory_shared_4kb(response_virt, 1);
        }
    }

    fn get_report(&mut self, _challenge: &Challenge) -> Result<Report> {
        let version = 1u8;
        let mut report_buf = [0u8; Self::ATTESTATION_BUFFER_LEN];

        let mut report_request = SnpReportRequest::default();
        report_request.report_data.copy_from_slice(_challenge.as_slice());

        let mut request = [0u8; SnpReportRequest::SIZE];
        request.copy_from_slice(report_request.as_bytes());

        let _ = self.enc_paylod(version, SnpMsgType::ReportReq, &mut request);
        let _ = self.guest_req().expect("AtD: request to FW failed");
        let _ = self.dec_payload(&mut report_buf, SnpMsgType::ReportRsp)
            .expect("Payload decrypt failed");

        if (self.response.hdr.msg_sz as usize) < size_of::<SnpReportResponseHeader>() {
            error!("invalid report response size  {}", self.response.hdr.msg_sz);
            return Err(Error::SysError(SysErr::EIO));
        }

        let report =
            SnpReportResponseHeader::from_bytes(
                &report_buf[..size_of::<SnpReportResponseHeader>()]
            ).ok_or_else(|| {
                error!("invalid report response size from bytes");
                SysErr::EIO
            }).unwrap();

        match report.status {
            0 => {
                let skip = size_of::<SnpReportResponseHeader>();
                let report_len = report.size as usize;
                let report = &report_buf[skip..][..report_len];
                let resp = report.to_vec();
                return Ok(resp);
            },
            0x16 => {
                error!("report request status 0x16");
                return Err(Error::SysError(SysErr::EIO));
            }
            _ => panic!("invalid MSG_REPORT_RSP error value {}", report.status),
        };
    }
}

impl SevAttestation {
    fn enc_paylod(&mut self, version: u8, msg_type: SnpMsgType,
        plaintext: &mut [u8]) -> Result<()> {
        let plaintext_size = plaintext.len();
        let request = &mut self.request;
        request.hdr.algo = AeadAlgo::SnpAeadAes256Gcm as _;
        request.hdr.hdr_version = MSG_HDR_VER;
        request.hdr.hdr_sz = size_of::<SnpGuestMsgHdr>() as _;
        request.hdr.msg_type = msg_type as _;
        request.hdr.msg_version = version;
        request.hdr.msg_seqno = SECRETS.lock().get_msg_seqno_0() as _;
        request.hdr.msg_vmpck = 0;
        request.hdr.msg_sz = plaintext_size as _;

        let vmpck0 = SECRETS.lock().get_vmpck0();

        let mut cipher = Aes256Gcm::new_from_slice(&vmpck0).unwrap();

        let mut seqno_nonce = [0u8; 12];
        seqno_nonce[0..8].copy_from_slice(unsafe {
           from_raw_parts(&request.hdr.msg_seqno as *const _ as *const u8, 8)
        });

        let nonce = Nonce::from_slice(&seqno_nonce); // 96-bits; unique per message

        let asssoc_data = unsafe {
            from_raw_parts(&request.hdr.algo as *const _ as *const u8, 48)
        };

        let tag = cipher
            .encrypt_in_place_detached(nonce, asssoc_data, plaintext)
            .map_err(|e| panic!("VM: Atd: encryption failed:{:?}", e)).unwrap();

        request.payload[0..plaintext_size].copy_from_slice(plaintext);

        request.hdr.authtag[0..16].copy_from_slice(&tag.as_slice()[0..16]);

        Ok(())
    }

    fn dec_payload(
        &mut self,
        plaintext: &mut [u8],
        expected_msg_type: SnpMsgType,
    ) -> Result<()> {
        let payload_size = plaintext.len();

        let request = &mut self.request;
        let response = &mut self.response;

        let next_seqno = request.hdr.msg_seqno
            .checked_add(1).ok_or(())
            .unwrap();
        if next_seqno != response.hdr.msg_seqno {
            return Err(Error::Common(String::from("Sequence number wrong")));
        }

        if expected_msg_type as u8 != response.hdr.msg_type {
            return Err(Error::Common(String::from("Response type wrong")));
        }

        if request.hdr.msg_version != response.hdr.msg_version {
            return Err(Error::Common(String::from("Version is wrong")));
        }

        if response.hdr.algo != AeadAlgo::SnpAeadAes256Gcm as u8 {
            return Err(Error::Common(String::from("Enc-algo is wrong")));
        }

        if response.hdr.hdr_sz != size_of::<SnpGuestMsgHdr>() as u16 {
            return Err(Error::Common(String::from("Header size is wrong")));
        }

        if response.hdr.msg_vmpck != 0 {
            return Err(Error::Common(String::from("VMPCK is not Zero")));
        }

        if response.hdr.msg_sz as usize > payload_size {
            return Err(Error::Common(String::from("Payload size too big")));
        }

        let vmpck0 = SECRETS.lock().get_vmpck0();
        let mut cipher = Aes256Gcm::new_from_slice(&vmpck0).unwrap();

        let mut seqno_nonce = [0u8; 12];
        seqno_nonce[0..8].copy_from_slice(unsafe {
            from_raw_parts(&response.hdr.msg_seqno as *const _ as *const u8, 8)
        });

        let nonce = Nonce::from_slice(&seqno_nonce); // 96-bits; unique per message

        let asssoc_data = unsafe {
            from_raw_parts(&response.hdr.algo as *const _ as *const u8, 48)
        };

        let tag = Tag::from_slice(&response.hdr.authtag[0..16]);

        plaintext[0..response.hdr.msg_sz as usize]
            .copy_from_slice(&response.payload[0..response.hdr.msg_sz as usize]);

        cipher
            .decrypt_in_place_detached(
                nonce,
                asssoc_data,
                &mut plaintext[0..response.hdr.msg_sz as usize],
                tag,
            )
            .expect("decrypt failed!");

        Ok(())
    }

    fn guest_req(&mut self) -> core::result::Result<(), u64> {
        let req_gpa = PhysAddr::new(VirtAddr::from_ptr(&self.request).as_u64());
        let resp_gpa = PhysAddr::new(VirtAddr::from_ptr(&self.response).as_u64());

        let log_available = LOG_AVAILABLE.load(core::sync::atomic::Ordering::Acquire);

        let mut vcpuid = 0;
        if log_available {
            vcpuid = crate::qlib::kernel::asm::GetVcpuId();
        }

        let ret = {
            let ghcb_option: &mut Option<GhcbHandle<'_>> = &mut *GHCB[vcpuid].lock();
            let ghcb = ghcb_option.as_mut().unwrap();

            // prevent earlier writes from being moved beyond this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

            // SAFETY: request and response are valid and mapped to shared memory

            let ret = unsafe { ghcb.guest_req(req_gpa, resp_gpa) };

            // prevent later reads from being moved before this point
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

            ret
        };

        if ret.is_err() {
            info!(
                "GhcbExtHandle guest_req 1 ret {:?}, error bym {:x}",
                ret,
                ret.err().unwrap()
            );
        }

        if ret.is_ok() {
            SECRETS.lock().inc_msg_seqno_0();
        }

        ret
    }
}

