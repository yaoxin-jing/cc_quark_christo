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

use core::ops::Sub;
use lazy_static::lazy_static;
use crate::qlib::kernel::asm::aarch64;

lazy_static! {
    ///
    ///On VMM: Default - needs fix
    ///On VM: The Realm-IPA size is: TCR_EL1.IPS - 1
    ///
    #[derive(Copy, Clone)]
    static ref IPA_SIZE: u64 = if cfg!(feature = "duck-qk") {
                                  get_ipa_size() - 1
                               } else {
                                   debug!("VM: You are using IPA_SIZE=41 as default - needs fix");
                                   41
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
    let _ipa: u64 = (tcr_el1 >> 32) & 0b111;
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
/// NOTE: we discard the value of the shared bit
///    when we treat the address as the physical one.
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

pub mod psci {
    use core::arch::asm;

    pub fn cpu_on(boot_help_data: *const u64, vcpu_count: u64, pc: u64) {
        let data_items = 2 * vcpu_count; // => [item1:u64|pad:u32|item2:u32]
        let help_data_slice = unsafe {
            core::slice::from_raw_parts(boot_help_data, data_items as usize)
        };
        let FID_PSCI_CPU_ON:u32 = 0xC4000003;
        for i in (2..data_items).step_by(2) {
            let mpidr: u64 = help_data_slice[i as usize] & 0xFF00FFFFFF; //Mask RES0 bit
            let stack_base_offset: u32 = (help_data_slice[(i+1) as usize] >> 32) as u32;

            let cpu = i / 2;
            debug!("VM: CPU0 - help boot CPU{} - MPIDR:{:#0x} - Stack base offset:{:#0x}, BootPC:{:#0x}.",
            cpu, mpidr, stack_base_offset, pc);
            let mut _res: u64 = u64::MAX;
            unsafe {
                asm!("bl _smc_exit",
                    in("x0") FID_PSCI_CPU_ON as u64,
                    in("x1") mpidr,
                    in("x2") pc as u64,
                    in("w3") stack_base_offset,
                    lateout("x0") _res,);
            }
            debug!("VM: CPU{} - psci_cpu_on - ret:{}.", cpu, _res);
        }
    }
}
pub mod rsi {
    use core::arch::asm;

    pub const RSI_HOST_CALL_FID: u32 = 0xC4000199;
    #[repr(C, align(256))]
    pub struct RsiHostCall {
        pub imm: u16,
        pub _pad0: [u8; 6],
        pub gprs: [u64; 31],
    }

    impl RsiHostCall {
        pub fn new(_gprs: [u64; 31]) -> Self {
            Self {
                imm: 0u16,
                _pad0: [0u8; 6],
                gprs: _gprs,
            }
        }

        /// The RSI Host Call is (as for now) used to make hypercalls in user space: EXIT_HYPERCALL.
        /// The Linux kernel allows only the range X0..X7 to be retrieved from user-space, while 
        /// Quark's Hypercall API allows a total of 5 arguments to be passed.
        /// NOTE: We don't expect any answer back - X0 as return value is not considered.
        pub fn rsi_host_call(arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) {
            let mut gprs: [u64; 31] = [0u64; 31];
            gprs[0] = RSI_HOST_CALL_FID as u64;
            gprs[1] = arg0;
            gprs[2] = arg1;
            gprs[3] = arg2;
            gprs[4] = arg3;
            gprs[5] = arg4;

            let rhc: Self = Self::new(gprs);
            // NOTE: This is correct because the kernel:
            // - is *identically* mapped - PA <-> VA
            // - kernel IPA is protected
            let ipa_rhc: u64 = &rhc as *const _ as u64;
            unsafe {
                let mut _res: u64;
                asm!("bl _smc_exit",
                    in("x0") RSI_HOST_CALL_FID as u64,
                    in("x1") ipa_rhc,
                    lateout("x0") _res,);
            }
        }
    }
}
