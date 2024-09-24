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

/*
* The KVM ARM_RME definitions are extracted from the 'arm- Run Arm CCA VMs with KVM'
* and 'arm64: Support for Arm CCA in KVM' patch series.
*/

use std::{convert::TryInto, mem::size_of};

use kvm_bindings::{
    kvm_device_attr, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3, kvm_enable_cap,
    KVM_DEV_ARM_VGIC_CTRL_INIT, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CTRL,
    KVM_DEV_ARM_VGIC_GRP_NR_IRQS, KVM_VGIC_ITS_ADDR_TYPE, KVM_VGIC_V3_ADDR_TYPE_DIST,
    KVM_VGIC_V3_ADDR_TYPE_REDIST,
};
use kvm_ioctls::{DeviceFd, VcpuFd, VmFd};
use vmm_sys_util::ioctl;

use crate::qlib::common::Error;

use crate::runc::runtime::vm_type::realm::realm::Realm;

const KVM_VM_TYPE_ARM_SHIFT: u64 = 8;
const KVM_VM_TYPE_ARM_MASK: u64 = (0xF as u64) << KVM_VM_TYPE_ARM_SHIFT;
const KVM_VM_TYPE_IPA_MASK: u64 = 0xFF;
const KVM_VM_TYPE_REALM: u64 = 1;
pub const KVM_VM_TYPE_ARM_IPA_SIZE_DEFAULT: u64 = 40;
pub const KVM_VM_TYPE_ARM_RPV_SIZE_BYTE: u64 = 64;
pub const KVM_VM_TYPE_ARM_REALM: u64 =
    (KVM_VM_TYPE_REALM << KVM_VM_TYPE_ARM_SHIFT) & KVM_VM_TYPE_ARM_MASK;
pub const KVM_ARM_RME_POPULATE_FLAGS_MEASURE: u32 = 1u32 << 0;

pub const KVM_ENABLE_CAP: u64 = ioctl::ioctl_expr(
    ioctl::_IOC_WRITE,
    0xAE as u32, //KVMIO
    0xA3,
    size_of::<kvm_bindings::kvm_enable_cap>() as u32,
) as u64;

const KVM_ARM_VCPU_FINALIZE: u64 = ioctl::ioctl_expr(
    ioctl::_IOC_WRITE,
    0xAE as u32, //KVMIO
    0xC2,
    size_of::<libc::c_int>() as u32,
) as u64;

#[repr(u32)]
pub enum KvmCapArmRmeVm {
    CfgRealm = 0u32,
    CreateRd = 1u32,
    InitIpaRealm = 2u32,
    PopulateRealm = 3u32,
    ActivateRealm = 4u32,
    CapRme = 300,
}

#[repr(u64)]
pub enum KvmArmVcpuFeature {
    HasEl2 = 7u64,  //Support nested virtualization
    VcpuRec = 8u64, // vCPU REC state
}

#[repr(u32)]
pub enum KvmCapArmRmeConfigRealm {
    CfgRpv = 0u32,
    CfgHashAlgo = 1u32,
    CfgSve = 2u32,
    CfgDbg = 3u32,
    CfgPmu = 4u32,
}

#[derive(Debug)]
#[repr(u32)]
pub enum KvmCapArmRmeMeasurementAlgo {
    Sha256 = 0u32,
    Sha512 = 1u32,
}

#[derive(Debug)]
#[repr(C, align(1))]
pub struct KvmCapArmRmeConfigHash {
    cfg: u32,
    hash_algo: u32,
    pad: [u8; 256 - 4], //Why
}

#[repr(C)]
pub struct KvmCapArmRmeInitIpaArgs {
    init_ipa_base: u64,
    init_ipa_size: u64,
    __pad: [u32; 4],
}

#[repr(C)]
pub struct KvmCapArmRmePopulateRealmArgs {
    init_ipa_base: u64,
    init_ipa_size: u64,
    flags: u32,
    __pad: [u32; 3],
}

impl Default for KvmCapArmRmeConfigHash {
    fn default() -> Self {
        Self {
            cfg: KvmCapArmRmeConfigRealm::CfgHashAlgo as u32,
            hash_algo: KvmCapArmRmeMeasurementAlgo::Sha256 as u32,
            pad: [0u8; 256 - 4],
        }
    }
}

//// Helpers ////
pub fn kvm_vm_arm_rme_enable_cap(vm_fd: &VmFd, cap: &mut kvm_enable_cap) -> Result<(), Error> {
    let error = unsafe { ioctl::ioctl_with_mut_ref(vm_fd, KVM_ENABLE_CAP, cap) };
    if error < 0i32 {
        let os_error = std::io::Error::last_os_error();
        error!("VM: Failed to enable cappability with error-{os_error:?}");
        return Err(Error::IOError(String::from("KVM ioctl - failed")));
    }

    Ok(())
}

pub fn kvm_vm_arm_create_irq_chip(realm: &Realm, vm_fd: &VmFd) -> Result<DeviceFd, Error> {
    let mut vgic_device = kvm_bindings::kvm_create_device {
        type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
        fd: 0,
        flags: 0,
    };

    let __vgic_fd = vm_fd.create_device(&mut vgic_device);
    if __vgic_fd.is_err() {
        let os_error = std::io::Error::last_os_error();
        error!("VM: Failed to create vGic device with error-{os_error:?}");
        return Err(Error::IOError(String::from("Kvm ioctl - failed")));
    }
    let _vgic_fd = __vgic_fd.unwrap();

    let _vgic_redist = kvm_bindings::kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: KVM_VGIC_V3_ADDR_TYPE_REDIST
            .try_into()
            .expect("KVM - failed to convert KVM_VGIC_V3_ADDR_TYPE_REDIST"),
        addr: &realm.vgic3.redistributor_base as *const _ as u64,
        flags: 0,
    };
    if _vgic_fd.set_device_attr(&_vgic_redist).is_err() {
        let os_error = std::io::Error::last_os_error();
        error!("VM: Failed to set device attribute vGicRedist-{os_error:?}");
        return Err(Error::IOError(String::from("Kvm ioctl - failed")));
    }

    let _vgic_dist = kvm_bindings::kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: KVM_VGIC_V3_ADDR_TYPE_DIST
            .try_into()
            .expect("KVM - failed to convert KVM_VGIC_V3_ADDR_TYPE_DIST"),
        addr: &realm.vgic3.distributor_base as *const _ as u64,
        flags: 0,
    };

    if _vgic_fd.set_device_attr(&_vgic_dist).is_err() {
        let os_error = std::io::Error::last_os_error();
        error!("VM: Failed to set device attribute vGicDist-{os_error:?}");
        return Err(Error::IOError(String::from("Kvm ioctl - failed")));
    };

    Ok(_vgic_fd)
}

pub fn kvm_vm_arm_create_its_device(realm: &Realm, vm_fd: &VmFd) -> Result<DeviceFd, Error> {
    let mut _its_device = kvm_bindings::kvm_create_device {
        type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_ITS,
        fd: 0,
        flags: 0,
    };

    let __its_fd = vm_fd.create_device(&mut _its_device);
    if __its_fd.is_err() {
        let os_error = std::io::Error::last_os_error();
        error!("VM: Failed to create vGic ITS device with error-{os_error:?}");
        return Err(Error::IOError(String::from("Kvm ioctl - failed")));
    };

    let _its_fd = __its_fd.unwrap();

    let _its_attrib = kvm_bindings::kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: KVM_VGIC_ITS_ADDR_TYPE
            .try_into()
            .expect("KVM - failed to convert KVM_VGIC_ITS_ADDR_TYPE"),
        addr: &realm.vgic3.its_base as *const _ as u64,
        flags: 0,
    };

    if _its_fd.set_device_attr(&_its_attrib).is_err() {
        let os_error = std::io::Error::last_os_error();
        error!("VM: Failed to set device attribute vGic ITS-{os_error:?}");
        return Err(Error::IOError(String::from("Kvm ioctl - failed")));
    }

    let _its_init_attrib = kvm_bindings::kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr: KVM_DEV_ARM_VGIC_CTRL_INIT
            .try_into()
            .expect("KVM - failed to convert KVM_DEV_ARM_VGIC_CTRL_INIT"),
        addr: 0,
        flags: 0,
    };

    if _its_fd.set_device_attr(&_its_init_attrib).is_err() {
        let os_error = std::io::Error::last_os_error();
        error!("VM: Failed to set device attribute vGic CTRL_INIT-{os_error:?}");
        return Err(Error::IOError(String::from("Kvm ioctl - failed")));
    };

    Ok(_its_fd)
}

pub fn kvm_vm_arm_ipa_size(ipa_width: u64) -> u64 {
    let _width = if ipa_width == KVM_VM_TYPE_ARM_IPA_SIZE_DEFAULT {
        0
    } else {
        ipa_width
    };
    _width & KVM_VM_TYPE_IPA_MASK
}

pub fn kvm_vm_arm_rme_init_ipa_range(
    vm_fd: &mut VmFd,
    base_adr: u64,
    size: u64,
) -> Result<(), Error> {
    let mut rme_init_ipa_realm = KvmCapArmRmeInitIpaArgs {
        init_ipa_base: base_adr,
        init_ipa_size: size,
        __pad: [0u32; 4],
    };

    let mut enable_cap_config: kvm_enable_cap = Default::default();
    enable_cap_config.cap = KvmCapArmRmeVm::CapRme as u32;
    enable_cap_config.args[0] = KvmCapArmRmeVm::InitIpaRealm as u64;
    enable_cap_config.args[1] =
        &mut rme_init_ipa_realm as *mut KvmCapArmRmeInitIpaArgs as *mut _ as u64;
    let err = unsafe { ioctl::ioctl_with_mut_ref(vm_fd, KVM_ENABLE_CAP, &mut enable_cap_config) };
    if err < 0i32 {
        let os_error = std::io::Error::last_os_error();
        error!("VM: Failed to enable cappability with error-{os_error:?}");
        return Err(Error::IOError(String::from("KVM ioctl - failed")));
    }
    Ok(())
}

pub fn kvm_vm_arm_rme_populate_range(
    vm_fd: &mut VmFd,
    base_adr: u64,
    size: u64,
) -> Result<(), Error> {
    let rme_init_ipa_realm: KvmCapArmRmePopulateRealmArgs = KvmCapArmRmePopulateRealmArgs {
        init_ipa_base: base_adr,
        init_ipa_size: size,
        flags: KVM_ARM_RME_POPULATE_FLAGS_MEASURE,
        __pad: [0u32; 3],
    };

    let mut enable_cap_config: kvm_enable_cap = Default::default();
    enable_cap_config.cap = KvmCapArmRmeVm::CapRme as u32;
    enable_cap_config.args[0] = KvmCapArmRmeVm::PopulateRealm as u64;
    enable_cap_config.args[1] =
        &rme_init_ipa_realm as *const KvmCapArmRmePopulateRealmArgs as *const _ as u64;
    let err = unsafe {
        info!(
            "KVM: Populate Realm memory - start:{:#x}, size:{:#x}.",
            base_adr, size
        );
        ioctl::ioctl_with_mut_ref(vm_fd, KVM_ENABLE_CAP, &mut enable_cap_config)
    };
    if err < 0i32 {
        let os_error = std::io::Error::last_os_error();
        error!("VM: Failed to enable cappability with error-{os_error:?}");
        return Err(Error::IOError(String::from("KVM ioctl - failed")));
    }
    Ok(())
}

pub fn kvm_arm_rme_vcpu_finalize(vcpu_fd: &VcpuFd) -> Result<(), Error> {
    let feature = KvmArmVcpuFeature::VcpuRec as u64;
    let err = unsafe { ioctl::ioctl_with_ref(vcpu_fd, KVM_ARM_VCPU_FINALIZE, &feature) };
    if err < 0i32 {
        let os_error = std::io::Error::last_os_error();
        error!("VM: Failed to enable cappability with error-{os_error:?}");
        return Err(Error::IOError(String::from("KVM ioctl - failed")));
    }

    Ok(())
}

pub fn kvm_arm_vgic_init_finalize(vgic_fd: Option<&DeviceFd>, irq_lines: u64) -> Result<(), Error> {
    if let Some(_vgic_fd) = vgic_fd {
        let vgic_init = kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            attr: 0,
            addr: &(irq_lines as i32) as *const i32 as u64,
            flags: 0,
        };
        _vgic_fd
            .set_device_attr(&vgic_init)
            .expect("KVM - vGIC failed to set IRQ lines.");
        let vgic_init = kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: KVM_DEV_ARM_VGIC_CTRL_INIT
                .try_into()
                .expect("KVM - Failed to convert KVM_DEV_ARM_VGIC_CTRL_INIT"),
            addr: 0,
            flags: 0,
        };
        _vgic_fd
            .set_device_attr(&vgic_init)
            .expect("KVM - vGIC failed to init.");
    } else {
        return Err(Error::IOError(String::from("KVM - No device-fd found.")));
    }
    Ok(())
}

pub fn kvm_arm_rme_activate_realm(vm_fd: &mut VmFd) -> Result<(), Error> {
    let mut realm_caps: kvm_enable_cap = Default::default();
    realm_caps.cap = KvmCapArmRmeVm::CapRme as u32;
    realm_caps.args[0] = KvmCapArmRmeVm::ActivateRealm as u64;

    let err = unsafe { ioctl::ioctl_with_mut_ref(vm_fd, KVM_ENABLE_CAP, &mut realm_caps) };
    if err < 0i32 {
        let os_error = std::io::Error::last_os_error();
        error!("VM: Failed to activate Realm with error-{os_error:?}");
        return Err(Error::IOError(String::from("KVM ioctl - failed")));
    }

    Ok(())
}
