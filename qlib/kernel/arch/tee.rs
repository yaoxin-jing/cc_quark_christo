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

#[cfg(target_arch = "aarch64")]
#[path = "./aarch64/tee/realm.rs"]
pub mod realm;

#[cfg(target_arch = "aarch64")]
use self::realm as _tee;

use core::sync::atomic::{AtomicBool, Ordering};
use lazy_static::lazy_static;
use crate::qlib::linux_def::MemoryDef;

lazy_static! {
    //TODO: It should be only set once
    pub static ref TEE_ACTIVE: AtomicBool = AtomicBool::new(false);
}

/// Depending on TEE architecture, the guest physical address should be
/// marked as shared("untrusted")/private("trusted"). The actual set/unset
/// bit(s) on the IPA is implementation defined by the particular TEE.
pub fn guest_physical_address_protect(address: &mut u64, protect: bool) {
    if TEE_ACTIVE.load(Ordering::Relaxed) {
        _tee::ipa_adjust(address, protect);
    }
}

/// Before the guest can reason on a GPA, the information on the IPA that
/// regard the TEE should be removed.
pub fn guest_physical_address(ipa_address: u64) -> u64 {
    let mut address_guest = ipa_address;
    if TEE_ACTIVE.load(Ordering::Relaxed) {
        _tee::unset_shared_bit(&mut address_guest);
    }
    address_guest
}

/// For Guest Physical Address
pub fn protected_address(gha: u64) -> bool {
    let mut res = false;
    let private_heap_top = MemoryDef::GUEST_PRIVATE_HEAP_OFFSET + MemoryDef::GUEST_PRIVATE_HEAP_SIZE;
    let kernel_top = MemoryDef::PHY_LOWER_ADDR + MemoryDef::QKERNEL_IMAGE_SIZE;
    if (gha >= MemoryDef::GUEST_PRIVATE_HEAP_OFFSET && gha < private_heap_top)
        || (gha >= MemoryDef::PHY_LOWER_ADDR && gha < kernel_top) {
        res = true;
    }
    res
}
