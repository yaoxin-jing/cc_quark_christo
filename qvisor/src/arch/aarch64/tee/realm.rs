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

use kvm_bindings::{KVM_ARM_VCPU_PTRAUTH_ADDRESS, KVM_ARM_VCPU_PTRAUTH_GENERIC, KVM_ARM_VCPU_POWER_OFF};
use kvm_ioctls::{VcpuExit, VcpuFd};

use crate::{qlib::{config::CCMode, self, linux_def::MemoryDef, common::Error,
            qmsg::sharepara::ShareParaPage}, arch::{ConfCompExtension,
            vm::vcpu::kvm_vcpu::{Register, KvmAarch64Reg}, tee::util::adjust_addr_to_host, VirtCpu},
            QUARK_CONFIG, VMS, runc::runtime::vm_type::{realm::VmCcRealm, VmType},
            kvm_vcpu::KVMVcpu};
use super::super::vcpu::kvm_vcpu::KvmAarch64Reg::{X0, X1};

pub struct RealmCca<'a> {
    /// No special KVM Exits known at the momment
    kvm_exits_list: Option<[VcpuExit<'a>; 0]>,
    hypercalls_list: [u16; 1],
    pub cc_mode: CCMode,
    pub share_space_table_addr: Option<u64>,
    pub page_allocator_addr: u64,
}

#[cfg(feature = "cc")]
impl ConfCompExtension for RealmCca<'_> {
    fn initialize_conf_extension(_share_space_table_addr: Option<u64>,
        _page_allocator_base_addr: Option<u64>)
        -> Result<Box<dyn ConfCompExtension>, crate::qlib::common::Error>
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
        let _ = self._set_sys_registers(sp_el1, &sys_regs)?;

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

    fn should_handle_kvm_exit(&self, _kvm_exit: &kvm_ioctls::VcpuExit) -> bool {
        self.kvm_exits_list.is_some()
    }

    fn should_handle_hypercall(&self, hypercall: u16) -> bool {
        if hypercall == self.hypercalls_list[0] {
            true
        } else {
            false
        }
    }

    fn handle_hypercall(&self, hypercall: u16, arg0: u64, arg1: u64, arg2: u64,
        arg3: u64, vcpu_id: usize) -> Result<bool , crate::qlib::common::Error> {
        let mut _exit = false;
        _exit = match hypercall {
            qlib::HYPERCALL_SHARESPACE_INIT =>
                self._handle_hcall_shared_space_init(arg0, arg1, arg2, arg3, vcpu_id)?,
            _ => false,
        };

        Ok(_exit)
    }

    fn confidentiality_type(&self) -> CCMode {
        return self.cc_mode;
    }

    fn set_vcpu_features(&self, vcpu_id: usize, kvi: &mut kvm_bindings::kvm_vcpu_init) {
        //TODO: check extension support
        kvi.features[0] |= 0x01 << KVM_ARM_VCPU_PTRAUTH_ADDRESS;
        kvi.features[0] |= 0x01 << KVM_ARM_VCPU_PTRAUTH_GENERIC;
        if vcpu_id > 0 {
            kvi.features[0] |= 0x01 << KVM_ARM_VCPU_POWER_OFF;
        }
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

    pub(in self) fn _handle_hcall_shared_space_init(&self, arg0: u64, _arg1: u64,
        _arg2: u64, _arg3: u64, _vcpu_id: usize) -> Result<bool, Error> {
        debug!("VMM: handle ShSp-Init");
        let ctrl_sock: i32;
        let vcpu_count: usize;
        let rdma_svc_cli_sock: i32;
        let mut pod_id = [0u8; 64]; //TODO: Hardcoded length of ID set it as cost to check on
        {
            let vms = VMS.lock();
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

    /// System registers can only be set after the REC start to run. We reserve the
    /// first six frames of the stack to pass their values.
    pub(in crate::arch) fn _set_sys_registers(&self, stack: Register, sys_regs: &Vec<Register>)
        -> Result<(), Error> {
        let (_, sp_el1) = stack.val().unwrap();
        let sp_el1_host_addr = adjust_addr_to_host(sp_el1, self.cc_mode);
        let mut reg_id: KvmAarch64Reg;
        let mut reg_val: u64;
        let mut frames: Vec<(u64, u64)> = Vec::new();
        for i in 0..sys_regs.len() {
            (reg_id, reg_val) = sys_regs[i].val().unwrap();
            frames.push((reg_val, i as u64));
            debug!("Push stack slot:{}, reg:{:?} - value:{:#x}", i, reg_id.to_string(), reg_val);
        }
        crate::arch::ArchVirtCpu::vcpu_populate_stack(sp_el1_host_addr, frames)
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
        _regs.insert(0, Register::Reg(X0, self.page_allocator_addr));
        _regs.insert(1, Register::Reg(X1, self.cc_mode as u64));
        if _regs.len() == 2 {
            return KVMVcpu::set_regs(vcpu_fd, _regs);
        } else {
            let frame_offset = 6 * std::mem::size_of::<u64>(); // Reserved for system regs: 6
            let sp_el1 = _regs.pop().unwrap().val().unwrap().1;
            let sp_base_host = adjust_addr_to_host(sp_el1, self.cc_mode)
                - frame_offset as u64;
            debug!("VMM:(Guest) SP_EL1 base:{:#0x} - current push base:{:#0x}",
                sp_el1, sp_el1 - frame_offset as u64);
            let mut reg_id: KvmAarch64Reg;
            let mut reg_val: u64;
            let mut frames: Vec<(u64, u64)> = Vec::new();
            for i in 0.._regs.len() {
                (reg_id, reg_val) = _regs[i].val().unwrap();
                frames.push((reg_val, i as u64));
                debug!("Push stack slot:{}, reg:{:?} - value:{:#x}",
                    i, reg_id.to_string(), reg_val);
            }
            return crate::arch::ArchVirtCpu::vcpu_populate_stack(sp_base_host, frames);
        }
    }
}

/// For vCPUs other than vpcu0, the mpidr is needed to boot them.
/// The booted vcpu gets reset, so we have to provide the usual
/// boot information in their stack. The vCPU0 needes to know the
/// MPIDR_EL1 of the next to boot. The booted vcpu get the offset
/// of its stack base from the start of the initial private VM memory
/// as boot parameter in X0.
#[repr(C)]
pub struct RealmVcpuXBootHelpData {
    pub mpidr: u64,
    _pad: u32,
    pub stack_base_offset: u32,
}

impl RealmVcpuXBootHelpData {
    pub fn new(_mpidr: u64, _stack_base_offset: u32) -> Self {
        Self {
            mpidr: _mpidr,
            _pad: 0u32,
            stack_base_offset: _stack_base_offset,
        }
    }
}
