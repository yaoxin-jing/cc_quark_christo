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

use crate::arch::Register;
use crate::qlib::linux_def::MemoryDef;
use crate::runc::runtime::vm_type::emulcc::VmCcEmul;
use crate::runc::runtime::vm_type::VmType;
use crate::sharepara::ShareParaPage;
use crate::VMS;
use crate::{arch::ConfCompExtension, qlib};
use kvm_bindings::kvm_memory_attributes;
use kvm_ioctls::{VcpuExit, VmFd, Vmgexit};

use qlib::kernel::arch::tee::sev_snp::ghcb::*;
use qlib::common::Error;
use qlib::config::CCMode;

static mut DUMMY_U64: u64 = 0u64;

pub struct SevSnp<'a> {
    kvm_exits_list: [VcpuExit<'a>; 1],
    hypercalls_list: [u16; 1],
    pub cc_mode: CCMode,
    pub share_space_table_addr: Option<u64>,
    pub page_allocator_addr: u64,
}

impl ConfCompExtension for SevSnp<'_> {
    fn initialize_conf_extension(
        _share_space_table_addr: Option<u64>,
        _page_allocator_base_addr: Option<u64>,
    ) -> Result<Box<dyn ConfCompExtension>, crate::qlib::common::Error>
    where
        Self: Sized,
    {
        let _self: Box<dyn ConfCompExtension> = Box::new(SevSnp {
            kvm_exits_list: [VcpuExit::VMGExit(Vmgexit::Psc(0, unsafe {
                &mut DUMMY_U64
            }))],
            hypercalls_list: [qlib::HYPERCALL_SHARESPACE_INIT],
            share_space_table_addr: None,
            page_allocator_addr: _page_allocator_base_addr
                .expect("Exptected address of the page allocator - found None"),
            cc_mode: CCMode::SevSnp,
        });
        Ok(_self)
    }

    fn set_cpu_registers(
        &self,
        vcpu_fd: &kvm_ioctls::VcpuFd,
        _regs: Option<Vec<Register>>,
    ) -> Result<(), crate::qlib::common::Error> {
        self._set_cpu_registers(&vcpu_fd)
    }

    fn get_hypercall_arguments(
        &self,
        vcpu_fd: &kvm_ioctls::VcpuFd,
        vcpu_id: usize,
    ) -> Result<(u64, u64, u64, u64), crate::qlib::common::Error> {
        self._get_hypercall_arguments(vcpu_fd, vcpu_id)
    }

    fn should_handle_kvm_exit(&self, kvm_exit: &kvm_ioctls::VcpuExit) -> bool {
        self.kvm_exits_list.contains(kvm_exit)
    }

    fn should_handle_hypercall(&self, hypercall: u16) -> bool {
        self.hypercalls_list.contains(&hypercall)
    }

    fn handle_kvm_exit(
        &self,
        kvm_exit: &mut kvm_ioctls::VcpuExit,
        vcpu_id: usize,
        vm_fd: Option<&VmFd>,
    ) -> Result<bool, crate::qlib::common::Error> {
        let mut _exit = false;
        _exit = match kvm_exit {
            VcpuExit::VMGExit(exit) => self._handle_kvm_vmgexit(exit, vcpu_id, vm_fd.unwrap())?,
            _ => false,
        };

        Ok(_exit)
    }

    fn handle_hypercall(
        &self,
        hypercall: u16,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        vcpu_id: usize,
    ) -> Result<bool, crate::qlib::common::Error> {
        let mut _exit = false;
        _exit = match hypercall {
            qlib::HYPERCALL_SHARESPACE_INIT => {
                self._handle_hcall_shared_space_init(arg0, arg1, arg2, arg3, vcpu_id)?
            }
            _ => false,
        };

        Ok(_exit)
    }
}

impl SevSnp<'_> {
    fn _confidentiality_type(&self) -> CCMode {
        self.cc_mode
    }

    fn _get_hypercall_arguments(
        &self,
        _vcpu_fd: &kvm_ioctls::VcpuFd,
        vcpu_id: usize,
    ) -> Result<(u64, u64, u64, u64), Error> {
        let shared_param_buffer =
            unsafe { *(MemoryDef::HYPERCALL_PARA_PAGE_OFFSET as *const ShareParaPage) };
        let passed_params = shared_param_buffer.SharePara[vcpu_id];
        let _arg0 = passed_params.para1;
        let _arg1 = passed_params.para2;
        let _arg2 = passed_params.para3;
        let _arg3 = passed_params.para4;

        Ok((_arg0, _arg1, _arg2, _arg3))
    }

    pub(self) fn _handle_hcall_shared_space_init(
        &self,
        arg0: u64,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _vcpu_id: usize,
    ) -> Result<bool, Error> {
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
        if let Err(e) = VmCcEmul::init_share_space(
            vcpu_count,
            ctrl_sock,
            rdma_svc_cli_sock,
            pod_id,
            Some(arg0),
            None,
        ) {
            error!("Vcpu: hypercall failed on shared-space initialization.");
            return Err(e);
        } else {
            info!("Vcpu: finished shared-space initialization.");
        }

        Ok(false)
    }

    pub(self) fn _handle_kvm_vmgexit(
        &self,
        exit: &mut Vmgexit,
        vcpu_id: usize,
        vm_fd: &VmFd,
    ) -> Result<bool, Error> {
        debug!("Vmgexit");
        const KVM_MEMORY_ATTRIBUTE_PRIVATE: u64 = 1 << 3;
        match exit {
            Vmgexit::PscMsr(gpa, op, ret) => {
                debug!(
                    "Vmgexit PscMsr,gpa {:x},op {:x}, ret {:x}",
                    *gpa, *op, **ret as u64
                );
                let shared_to_private = *op == 1;
                let attr = if shared_to_private {
                    KVM_MEMORY_ATTRIBUTE_PRIVATE
                } else {
                    0
                };
                let memory_attributes = kvm_memory_attributes {
                    address: *gpa,
                    size: MemoryDef::PAGE_SIZE,
                    attributes: attr,
                    flags: 0,
                };
                vm_fd
                    .set_memory_attributes(&memory_attributes)
                    .expect("Unable to convert memory to private");
                    **ret = 0;
            }
            Vmgexit::Psc(_shared_gpa, ret) => {
                let mut entries_processed = 0u16;
                let mut gfn_base = 0u64;
                let mut gfn_count = 0i32;
                let mut range_to_private = false;
                let ghcb = unsafe {
                    &mut *((MemoryDef::GHCB_OFFSET + vcpu_id as u64 * MemoryDef::PAGE_SIZE)
                        as *mut Ghcb)
                };
                let mut shared_buffer = ghcb.get_shared_buffer_clone();
                let desc = unsafe { &mut *(shared_buffer.as_mut_ptr() as *mut SnpPscDesc) };
                debug!(
                    "Vmgexit Psc ghcb,desc.entries[0]:{:#x?},desc.entries[252]:{:#x?}",
                    desc.entries[0], desc.entries[252]
                );
                while next_contig_gpa_range(
                    desc,
                    &mut entries_processed,
                    &mut gfn_base,
                    &mut gfn_count,
                    &mut range_to_private,
                ) {
                    let attr = if range_to_private {
                        KVM_MEMORY_ATTRIBUTE_PRIVATE
                    } else {
                        0
                    };
                    let memory_attributes = kvm_memory_attributes {
                        address: gfn_base * MemoryDef::PAGE_SIZE,
                        size: gfn_count as u64 * MemoryDef::PAGE_SIZE,
                        attributes: attr,
                        flags: 0,
                    };
                    match vm_fd.set_memory_attributes(&memory_attributes) {
                        Ok(_) => desc.cur_entry += entries_processed,
                        Err(_) => {
                            **ret = 0x100u64 << 32;
                            error!("error doing memory conversion");
                            break;
                        },
                    }
                    desc.cur_entry += entries_processed;
                }
                ghcb.set_shared_buffer(shared_buffer);
            }
            Vmgexit::ExtGuestReq(_data_gpa, _data_npages, _ret) => {
                error!("Vmgexit::ExtGuestReq not supported yet!");
            }
        }
        Ok(false)
    }
}
