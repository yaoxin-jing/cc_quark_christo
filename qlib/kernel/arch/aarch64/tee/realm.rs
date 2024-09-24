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

use lazy_static::lazy_static;
use core::ops::Sub;

use crate::qlib::kernel::asm::aarch64;

lazy_static! {
    ///
    ///On VMM: from the configuration
    ///On VM: The IPA size is read from TCR_EL1.IPS
    ///
    #[derive(Copy, Clone)]
    static ref IPA_SIZE: u64 = if cfg!(feature = "duck-qk") {
                                  get_ipa_size()
                               } else {
                                   debug!("VM: You are using IPA_SIZE=40 as default - needs fix");
                                    40
                               };
}

impl Sub<u64> for IPA_SIZE {
    type Output = u64;

    fn sub(self, other: u64) -> Self::Output {
        *self - other
    }
}

fn get_ipa_size() -> u64 {
    let tcr_el1: u64 = aarch64::read_tcr_el1();
    //IPS=TCR_EL1[34:32]
    let _ipa: u64 = tcr_el1 & (0x7 << 32);
    let ipa_size: u64 = match _ipa {
        0 => 32, //4GB
        1 => 36, //64GB
        2 => 40, //1TB
        3 => 42, //4TB
        4 => 44, //16TB
        5 => 48, //256TB
        6 => 52, //4PB
        7 => 56, //64PB
        _ => panic!("QKernel: Invalid IPA size."),
    };
    ipa_size
}

/// Memory address is marked as untrusted.
fn set_shared_bit(ipa: &mut u64) {
    *ipa = *ipa | (0x1 << (IPA_SIZE - 1u64));
}


/// Memory address is marked as trused.
///
///
/// NOTE: This is not always the case:
///     we discard the value of the shared bit
///     when we treat the address as the physical one.
pub fn unset_shared_bit(ipa: &mut u64) {
    *ipa = *ipa & !(0x1 << (IPA_SIZE - 1u64));

}

pub fn ipa_adjust(ipa: &mut u64, protect: bool) {
    if protect == false {
        set_shared_bit(ipa);
    } else {
        unset_shared_bit(ipa);
    }
}

// RSI //
#[repr(C)]
pub struct RsiHostCall {
    pub imm: u16,
    pub _pad0:[u8; 6],
    pub gprs: [u64; 31],
}

impl RsiHostCall {
    const FID: u32 = 0xC4000199;
    pub fn new (_imm: u16, _gprs: [u64; 31]) -> Self {
        Self {
            imm: _imm,
            _pad0: [0u8; 6],
            gprs: _gprs
        }
    }

    pub fn rsi_host_call() {
        use crate::qlib::kernel::asm::aarch64 as asm;
        let pc: u64;
        let sp: u64 = asm::GetCurrentUserSp();
        let ttbr0: u64 = asm::CurrentUserTable();



    }
}
