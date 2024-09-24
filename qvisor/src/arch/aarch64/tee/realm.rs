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

use kvm_bindings::{KVM_ARM_VCPU_PTRAUTH_ADDRESS, KVM_ARM_VCPU_PTRAUTH_GENERIC};
use kvm_ioctls::{VcpuExit, VcpuFd};

use crate::{qlib::{config::CCMode, self, linux_def::MemoryDef, common::Error,
            qmsg::sharepara::ShareParaPage}, arch::{ConfCompExtension,
            vm::vcpu::kvm_vcpu::{Register, KvmAarch64Reg}, tee::util::adjust_addr_to_host}, QUARK_CONFIG, VMS, 
            runc::runtime::vm_type::{realm::VmCcRealm, VmType}, kvm_vcpu::KVMVcpu};
use super::super::vcpu::kvm_vcpu::KvmAarch64Reg::{X0, X1, SpEl1};

pub struct RealmCca<'a> {
    /// No special KVM Exits known at the momment
    kvm_exits_list: Option<[VcpuExit<'a>; 0]>,
    hypercalls_list: [u16; 1],
    pub cc_mode: CCMode,
    pub share_space_table_addr: Option<u64>,
    pub page_allocator_addr: u64,
    //TODO: extend per Realm vCPU fields
}

#[cfg(feature = "cc")]
impl ConfCompExtension for RealmCca<'_> {
    fn initialize_conf_extension(_share_space_table_addr: Option<u64>,
        _page_allocator_base_addr: Option<u64>) -> Result<Box<dyn ConfCompExtension>, crate::qlib::common::Error>
        where Self: Sized {
        let _cc_mode = QUARK_CONFIG.lock().CCMode;
        let _self: Box<dyn ConfCompExtension> = Box::new(RealmCca{
            kvm_exits_list: None,
            hypercalls_list:[qlib::HYPERCALL_SHARESPACE_INIT],
            share_space_table_addr: None,
            page_allocator_addr: _page_allocator_base_addr
                .expect("Exptected address of the page allocator - found None"),
            cc_mode: _cc_mode,
        });
        Ok(_self)
    }

    fn set_sys_registers(&self, _vcpu_fd: &VcpuFd, _regs: Option<Vec<Register>>)
            -> Result<(), Error> {
        let mut sys_regs = _regs.unwrap();
        let sp_el1 = sys_regs.pop().unwrap();
        let stack = self._set_sys_registers(sp_el1, &sys_regs)?;

        Ok(())
    }

    fn set_cpu_registers(&self, vcpu_fd: &VcpuFd, regs: Option<Vec<Register>>)
        -> Result<(), Error> {
        self._set_cpu_registers(vcpu_fd, regs)
    }

    fn get_hypercall_arguments(&self, vcpu_fd: &kvm_ioctls::VcpuFd, vcpu_id: usize)
        -> Result<(u64, u64, u64, u64), crate::qlib::common::Error> {
        self._get_hypercall_arguments(vcpu_fd, vcpu_id)
    }

    fn should_handle_kvm_exit(&self, kvm_exit: &kvm_ioctls::VcpuExit) -> bool {
        self.kvm_exits_list.is_some()
    }

    fn should_handle_hypercall(&self, hypercall: u16) -> bool {
        if hypercall == self.hypercalls_list[0] {
            true
        } else {
            false
        }
    }

    fn handle_kvm_exit(&self, kvm_exit: &kvm_ioctls::VcpuExit, vcpu_id: usize) -> Result<bool, crate::qlib::common::Error> {
        Ok(false)
    }

    fn handle_hypercall(&self, hypercall: u16, data: &[u8], arg0: u64, arg1: u64, arg2: u64,
        arg3: u64, vcpu_id: usize) -> Result<bool , crate::qlib::common::Error> {
        let mut _exit = false;
        _exit = match hypercall {
            qlib::HYPERCALL_SHARESPACE_INIT =>
                self._handle_hcall_shared_space_init(data, arg0, arg1, arg2, arg3, vcpu_id)?,
            _ => false,
        };

        Ok(_exit)
    }

    fn confidentiality_type(&self) -> CCMode {
        return self.cc_mode;
    }

    fn set_vcpu_features(&self, kvi: &mut kvm_bindings::kvm_vcpu_init) {
        //TODO: check extension support
        kvi.features[0] |= 0x01 << KVM_ARM_VCPU_PTRAUTH_ADDRESS;
        kvi.features[0] |= 0x01 << KVM_ARM_VCPU_PTRAUTH_GENERIC;
        if std::arch::is_aarch64_feature_detected!("sve") {
            info!("vCPU: support for SVE possible.");
        }
        if std::arch::is_aarch64_feature_detected!("sve2") {
            info!("vCPU: support for SVE2 possible.");
        }
    }
}

#[cfg(feature = "cc")]
impl RealmCca<'_> {
    fn _confidentiality_type(&self) -> CCMode {
        self.cc_mode
    }

    fn _get_hypercall_arguments(&self, _vcpu_fd: &kvm_ioctls::VcpuFd, vcpu_id: usize)
        -> Result<(u64, u64, u64, u64), Error> {
        let shared_param_buffer = unsafe {
            *(MemoryDef::HYPERCALL_PARA_PAGE_OFFSET as *const ShareParaPage)
        };
        let passed_params = shared_param_buffer.SharePara[vcpu_id];
        let _arg0 = passed_params.para1;
        let _arg1 = passed_params.para2;
        let _arg2 = passed_params.para3;
        let _arg3 = passed_params.para4;

        Ok((_arg0, _arg1, _arg2, _arg3))
    }

    pub(in self) fn _handle_hcall_shared_space_init(&self, _data: &[u8], arg0: u64, _arg1: u64,
        _arg2: u64, _arg3: u64, _vcpu_id: usize) -> Result<bool, Error> {
        let ctrl_sock: i32;
        let vcpu_count: usize;
        let rdma_svc_cli_sock: i32;
        let mut pod_id = [0u8; 64]; //TODO: Hardcoded length of ID set it as cost to check on
        {
            let mut vms = VMS.lock();
            ctrl_sock = vms.controlSock;
            vcpu_count = vms.vcpuCount;
            rdma_svc_cli_sock = vms.args.as_ref().unwrap().RDMASvcCliSock;
            pod_id.copy_from_slice(vms.args.as_ref().unwrap().ID.clone().as_bytes());
        }
        if let Err(e) = VmCcRealm::init_share_space(vcpu_count, ctrl_sock, rdma_svc_cli_sock,
            pod_id, Some(arg0), None) {
            error!("Vcpu: hypercall failed on shared-space initialization.");
            return Err(e);
        } else {
            info!("Vcpu: finished shared-space initialization.");
        }

        Ok(false)
    }

    pub(in crate::arch) fn _set_sys_registers(&self, stack: Register, sys_regs: &Vec<Register>)
        -> Result<u64, Error> {
        use std::slice;
        let (_, sp_el1) = stack.val().unwrap();
        let new_stack_base = sp_el1 - (sys_regs.len()
            .wrapping_mul(std::mem::size_of::<u64>()) as u64);
        info!("vCPU: Stack base-guest:{:#x}, new stack offset-guest:{:#x} - pushed elements:{}",
            sp_el1, new_stack_base, sys_regs.len());
        let stack = unsafe {
            slice::from_raw_parts_mut(
                adjust_addr_to_host(new_stack_base, self.cc_mode) as u64 as *mut u64,
                sys_regs.len())
        };
        let mut reg_id: KvmAarch64Reg;
        let mut reg_val: u64;
        for i in  0..sys_regs.len() {
            (reg_id, reg_val) = sys_regs[i].val().unwrap();
            stack[i] = reg_val;
            debug!("Push stack slot:{}, reg:{:?} - value:{:#x}", i, reg_id.to_string(), reg_val);
        }

        Ok(new_stack_base)
    }

    /// Host can specify only GPRs and PC. GPRs X0..5 are already used, we use X6 to pass
    /// the initialization value for SP_El1.
    /// NOTE: Linux cca-full/v3: Available registers for host: GPRs X0...7
    pub(in crate::arch) fn _set_cpu_registers(&self, vcpu_fd: &VcpuFd, regs: Option<Vec<Register>>)
        -> Result<(), Error> {
        let mut _regs: Vec<Register> = if regs.is_some() {
            regs.unwrap()
        } else {
            Vec::new()
        };
        _regs.push(Register::Reg(X0, self.page_allocator_addr));
        _regs.push(Register::Reg(X1, self.cc_mode as u64));
        KVMVcpu::set_regs(vcpu_fd, _regs)
    }
}
