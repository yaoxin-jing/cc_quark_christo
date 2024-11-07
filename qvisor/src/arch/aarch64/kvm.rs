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

pub mod kvm_ioctl {
    use std::convert::TryInto;
    use kvm_bindings::{kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3, KVM_DEV_ARM_VGIC_GRP_ADDR,
        KVM_VGIC_V3_ADDR_TYPE_REDIST, KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_ITS_ADDR_TYPE,
        KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_CTRL_INIT, kvm_device_attr,
        KVM_DEV_ARM_VGIC_GRP_NR_IRQS};
    use vmm_sys_util::ioctl::ioctl_with_ref;
    use kvm_ioctls::{VmFd, DeviceFd};
    use crate::qlib::common::Error;
    use crate::arch::kvm::KVM_SET_DEVICE_ATTR;
    use crate::runc::runtime::vm_type::realm::realm::vGic3;

    pub const KVM_ARM_VM_SMCCC_CTRL: u32 = 0;
    pub const KVM_ARM_VM_SMCCC_FILTER: u64 = 0;

    #[repr(u8)]
    pub enum KVM_SMCCC_FILTER_ACTION {
        Handle = 0,
        Deny = 1,
        FwdToUser = 2,
    }

    #[repr(C)]
    pub struct KvmSmcccFilter {
        pub base: u32,
        pub nr_functions: u32,
        pub action: u8,
        pub _pad: [u8; 15],
    }

    pub fn kvm_arm_vm_smccc_filter(vm_fd: &VmFd, filter_base: u32, length: u32, fwd_to_: u8)
        -> Result<(), Error> {
        let smccc_filter = KvmSmcccFilter {
            base: filter_base,
            nr_functions: length,
            action: fwd_to_,
            _pad: [0u8; 15],
        };
        let mut device_attr: kvm_bindings::kvm_device_attr = Default::default();
        device_attr.group = KVM_ARM_VM_SMCCC_CTRL;
        device_attr.attr = KVM_ARM_VM_SMCCC_FILTER;
        device_attr.flags = 0;
        device_attr.addr = &smccc_filter as *const _ as u64;
        let err = unsafe {
            ioctl_with_ref(vm_fd, KVM_SET_DEVICE_ATTR, &device_attr)
        };

        if err < 0 {
            panic!("VMM: Failed to set SMCCC filter - error:{:?}.",
                std::io::Error::last_os_error())
        } else {
            println!("VMM: SMCCC filter set - ret:{}", err);
        }

        Ok(())
    }

    pub fn kvm_vm_arm_create_irq_chip(vm_fd: &VmFd, vgic: &vGic3) -> Result<DeviceFd, Error> {
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
        let redist_base = vgic.redistributor_base.clone().unwrap();
        let _vgic_redist = kvm_bindings::kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: KVM_VGIC_V3_ADDR_TYPE_REDIST
                .try_into()
                .expect("KVM - failed to convert KVM_VGIC_V3_ADDR_TYPE_REDIST"),
            addr: &redist_base as *const u64 as u64,
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
            addr: &vgic.distributor_base as *const u64 as u64,
            flags: 0,
        };
        if _vgic_fd.set_device_attr(&_vgic_dist).is_err() {
            let os_error = std::io::Error::last_os_error();
            error!("VM: Failed to set device attribute vGicDist-{os_error:?}");
            return Err(Error::IOError(String::from("Kvm ioctl - failed")));
        };
        Ok(_vgic_fd)
    }

    pub fn kvm_vm_arm_create_its_device(vm_fd: &VmFd, vgic: &vGic3) -> Result<DeviceFd, Error> {
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
        let its_base = vgic.its_base.clone().unwrap();
        let _its_attrib = kvm_bindings::kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: KVM_VGIC_ITS_ADDR_TYPE
                .try_into()
                .expect("KVM - failed to convert KVM_VGIC_ITS_ADDR_TYPE"),
            addr: &its_base as *const u64 as u64,
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

    pub fn kvm_arm_vgic_init_finalize(vgic_fd: Option<&DeviceFd>, irq_lines: u64) -> Result<(), Error> {
        if let Some(_vgic_fd) = vgic_fd {
            let vgic_init = kvm_device_attr {
                group: KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
                attr: 0,
                addr: &(irq_lines as i32) as *const i32 as u64,
                flags: 0,
            };
            _vgic_fd.set_device_attr(&vgic_init)
                .expect("KVM - vGIC failed to set IRQ lines.");
            let vgic_init = kvm_device_attr {
                group: KVM_DEV_ARM_VGIC_GRP_CTRL,
                attr: KVM_DEV_ARM_VGIC_CTRL_INIT
                    .try_into()
                    .expect("KVM - Failed to convert KVM_DEV_ARM_VGIC_CTRL_INIT"),
                addr: 0,
                flags: 0,
            };
            _vgic_fd.set_device_attr(&vgic_init)
                .expect("KVM - vGIC failed to init.");
        } else {
            return Err(Error::IOError(String::from("KVM - No device-fd found.")));
        }
        Ok(())
    }
}
