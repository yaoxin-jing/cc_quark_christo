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

pub mod kvm_vcpu;

use kvm_bindings::{kvm_vcpu_init, KVM_ARM_VCPU_PSCI_0_2};
use kvm_ioctls::{Kvm, VcpuExit, VmFd, Cap};
use kvm_vcpu::{Register, KvmAarch64Reg::*};
use libc::gettid;
use crate::{arch::{tee::{NonConf, emulcc::EmulCc}, ConfCompExtension, VirtCpu},
            kvm_vcpu::{KVMVcpuState, SetExitSignal}, qlib::{self, common::Error,
            linux::time::Timespec, linux_def::{MemoryDef, SysErr}, qmsg::qcall::{Print, QMsg},
            GetTimeCall, VcpuFeq, config::CCMode, task_mgr::TaskId}, runc::runtime::vm,
            syncmgr::SyncMgr, KVMVcpu, GLOCK, KERNEL_IO_THREAD, SHARE_SPACE, VMS};
use super::{vcpu::kvm_vcpu::*, tee::{realm::RealmCca, kvm::{self, SMC_RSI_HOST_CALL}}};
use std::{sync::atomic::Ordering, vec::Vec};

pub struct Aarch64VirtCpu {
    tcr_el1: u64,
    mair_el1: u64,
    ttbr0_el1: u64,
    cpacr_el1: u64,
    sctlr_el1: u64,
    cntkctl_el1: u64,
    pub kvi: kvm_vcpu_init,
    pub vcpu_base: KVMVcpu,
    pub conf_comp_extension: Box<dyn ConfCompExtension>,
}

pub type ArchVirtCpu = Aarch64VirtCpu;

impl VirtCpu for Aarch64VirtCpu {

    fn new_vcpu(vcpu_id: usize, total_vcpus: usize, vm_fd: &VmFd, entry_addr: u64,
        page_allocator_base_addr: Option<u64>, share_space_table_addr: Option<u64>,
        auto_start: bool, stack_size: usize, _kvm: Option<&Kvm>, conf_extension: CCMode)
        -> Result<Self, Error> {
        debug!("vCPU: create vcpu-{}", vcpu_id);
        let _vcpu_fd = vm_fd.create_vcpu(vcpu_id as u64)
            .expect("Failed to create KVM vcpu_fd.");
        let _ttbr0_el1 = VMS.lock().pageTables.GetRoot();
        let _vcpu_base = KVMVcpu::Init(vcpu_id, total_vcpus, entry_addr, stack_size,
            _vcpu_fd, auto_start)?;

        let mut _conf_comp_ext = match conf_extension {
            CCMode::None =>
                NonConf::initialize_conf_extension(share_space_table_addr,
                page_allocator_base_addr)?,
            CCMode::Normal | CCMode::NormalEmu => {
                EmulCc::initialize_conf_extension(share_space_table_addr,
                page_allocator_base_addr)?
            },
            CCMode::Cca => {
                RealmCca::initialize_conf_extension(share_space_table_addr,
                page_allocator_base_addr)?
            },
            _ => {
                return Err(
                    Error::InvalidArgument("Create vcpu failed - bad ConfCompType".to_string()));
            }
        };

        let mut _kvi = kvm_vcpu_init::default();
        vm_fd.get_preferred_target(&mut _kvi)
            .map_err(|e|
                Error::IOError(format!("Failed to find kvm target for vcpu - error:{:?}", e)))?;
        let _kvm_fd = _kvm.unwrap();
        if _kvm_fd.check_extension(Cap::ArmPsci02) == true {
            _kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        } else {
            info!("VMM: vCPU - KVM_CAP_ARM_PSCI_0_2 not supported.");
        }

        if _kvm_fd.check_extension(Cap::ArmPsci) == false && conf_extension == CCMode::Cca {
            panic!("VMM: vCPU - KVM_CAP_ARM_PSCI not supported, need to for co-cpus.");
        }
        _conf_comp_ext.set_vcpu_features(vcpu_id, &mut _kvi);

        let _self = Self {
            tcr_el1: TCR_EL1_DEFAULT,
            mair_el1: MT_EL1_DEFAULT,
            ttbr0_el1: _ttbr0_el1,
            cpacr_el1: CPACR_EL1_DEFAULT,
            sctlr_el1: SCTLR_EL1_DEFAULT,
            cntkctl_el1: CNTKCTL_EL1_DEFAULT,
            kvi: _kvi,
            vcpu_base: _vcpu_base,
            conf_comp_extension: _conf_comp_ext
        };

        Ok(_self)
    }

    fn vcpu_init(&self) -> Result<(), Error> {
        self.vcpu_base.vcpu_fd.vcpu_init(&self.kvi)
            .map_err(|e| Error::IOError(format!("Failed to initialize with kvi - error:{:?}",
                    e.errno())))?;
        Ok(())
    }

    fn initialize_sys_registers(&self) -> Result<(), Error> {
        let tcr_el1 = Register::Reg(TcrEl1, self.tcr_el1);
        let mair_el1 = Register::Reg(MairEl1, self.mair_el1);
        let ttbr0_el1 = Register::Reg(Ttbr0El1, self.ttbr0_el1);
        let cntkctl_el1 = Register::Reg(CntkctlEl1, self.cntkctl_el1);
        let cpacr_el1 = Register::Reg(CpacrEl1, self.cpacr_el1);
        let sctlr_el1 = Register::Reg(SctlrEl1, self.sctlr_el1);
        let mut reg_list: Vec<Register> = vec![mair_el1, ttbr0_el1, cntkctl_el1,
                                        cpacr_el1, sctlr_el1, tcr_el1];
        if self.conf_comp_extension.confidentiality_type() != CCMode::Cca {
            KVMVcpu::set_regs(&self.vcpu_base.vcpu_fd, reg_list)?;
            return self.conf_comp_extension.set_sys_registers(&self.vcpu_base.vcpu_fd, None)
        } else {
            reg_list.push(Register::Reg(X6, self.vcpu_base.topStackAddr));
            self.conf_comp_extension.set_sys_registers(&self.vcpu_base.vcpu_fd, Some(reg_list))
        }
    }

    /// QRealm ABI:
    /// vCPU0: X7 is used to pass the base address where additional
    ///     boot help information for the other vCPUs is placed.
    /// vCPUX: for X > 0, PC is passed by vCPU0 on boot, all other
    ///     X0..X5 are found in stack after Frame-5 (stack_base: Frame-0).
    fn initialize_cpu_registers(&self) -> Result<(), Error> {
        let pc = Register::Reg(PC, self.vcpu_base.entry);
        let x2 = Register::Reg(X2, self.vcpu_base.id as u64);
        let vdso_entry = VMS.lock().vdsoAddr;
        let x3 = Register::Reg(X3, vdso_entry);
        let x4 = Register::Reg(X4, self.vcpu_base.vcpuCnt as u64);
        let x5 = Register::Reg(X5, self.vcpu_base.autoStart as u64);
        let mut reg_list = vec![pc, x2, x3, x4, x5];
        if self.conf_comp_extension.confidentiality_type() != CCMode::Cca {
            reg_list.push(Register::Reg(SpEl1, self.vcpu_base.topStackAddr));
            KVMVcpu::set_regs(&self.vcpu_base.vcpu_fd, reg_list)?;
            return self.conf_comp_extension.set_cpu_registers(&self.vcpu_base.vcpu_fd, None);
        } else {
            reg_list.push(Register::Reg(X6, self.vcpu_base.topStackAddr));
            if self.vcpu_base.id == 0 {
                KVMVcpu::set_regs(&self.vcpu_base.vcpu_fd, reg_list)?;
                return self.conf_comp_extension.set_cpu_registers(&self.vcpu_base.vcpu_fd, None);
            } else {
                let _ = reg_list.remove(0);
                return self.conf_comp_extension.set_cpu_registers(&self.vcpu_base.vcpu_fd,
                    Some(reg_list));
            }
        }
    }

    /// Prepare stack for the Guest if needed. The stack base address should be passed
    /// as a Host address.
    fn vcpu_populate_stack(stack_base: u64, _frames: Vec<(u64, u64)>) -> Result<(), Error> {
        let new_base = stack_base - (_frames.len()
            .wrapping_mul(std::mem::size_of::<u64>()) as u64);
        info!("vCPU: Stack base(Host):{:#x}, new stack offset-guest:{:#x} - pushed elements:{}",
            stack_base, new_base, _frames.len());
        let stack = unsafe {
            std::slice::from_raw_parts_mut(new_base as *mut u64, _frames.len())
        };
        let mut val: u64;
        let mut pos: u64;
        for i in  0.._frames.len() {
            (val, pos) = _frames[i];
            stack[pos as usize] = val;
            debug!("Push stack - base:{:#0x}, slot:{}, - value:{:#x}",
                stack_base, (_frames.len() - 1) as u64 - pos, val);
        }
        Ok(())
    }

    fn vcpu_init_finalize(&self) -> Result<(), Error> {
        kvm::kvm_arm_rme_vcpu_finalize(&self.vcpu_base.vcpu_fd)
            .expect("vCpu: Failed to finalize initialization");
        Ok(())
    }

    fn vcpu_run(&self, tgid: i32) -> Result<(), Error> {
        SetExitSignal();
        self.vcpu_base.SignalMask();
        if self.vcpu_base.cordId > 0 {
            let core_id = core_affinity::CoreId {
                id: self.vcpu_base.cordId as usize,
            };
            core_affinity::set_for_current(core_id);
        }

        info!("vCPU-Run - id:[{}], entry:{:#x}, stack base:{:#x}",
            self.vcpu_base.id, self.vcpu_base.entry, self.vcpu_base.topStackAddr);
        let tid = unsafe { gettid() };
        self.vcpu_base.threadid.store(tid as u64, Ordering::SeqCst);
        self.vcpu_base.tgid.store(tgid as u64, Ordering::SeqCst);
        self._run()
    }

    fn default_hypercall_handler(&self, hypercall: u16, arg0: u64, arg1: u64,
        arg2: u64, arg3: u64) -> Result<bool, Error> {
        let id = self.vcpu_base.id;
        match hypercall {
            qlib::HYPERCALL_IOWAIT => {
                if !vm::IsRunning() {
                    return Ok(true);
                }
                match KERNEL_IO_THREAD.Wait(&SHARE_SPACE) {
                    Ok(()) => (),
                    Err(Error::Exit) => {
                        return Ok(true);
                    }
                    Err(e) => {
                        panic!("KERNEL_IO_THREAD get error {:?}", e);
                    }
                }
            },
            qlib::HYPERCALL_RELEASE_VCPU => {
                SyncMgr::WakeShareSpaceReady();
            },
            qlib::HYPERCALL_EXIT_VM => {
                let exit_code = arg0 as i32;
                info!("Exit-VM called - vcpu:{}", self.vcpu_base.id);
                crate::print::LOG.Clear();
                crate::qlib::perf_tunning::PerfPrint();
                vm::SetExitStatus(exit_code);
                //wake up Kernel io thread
                KERNEL_IO_THREAD.Wakeup(&SHARE_SPACE);
                //wake up workthread
                vm::VirtualMachine::WakeAll(&SHARE_SPACE);
            },
            qlib::HYPERCALL_PANIC => {
                let addr = arg0;
                let msg = unsafe { &*(addr as *const Print) };

                eprintln!("Application error: {}", msg.str);
                ::std::process::exit(1);
            },
            qlib::HYPERCALL_WAKEUP_VCPU => {
                let vcpuId = arg0 as usize;
                SyncMgr::WakeVcpu(vcpuId);
            },
            qlib::HYPERCALL_PRINT => {
                let addr = arg0;
                let msg = unsafe { &*(addr as *const Print) };
                log!("{}", msg.str);
            },
            qlib::HYPERCALL_MSG => {
                let data1 = arg0;
                let data2 = arg1;
                let data3 = arg2;
                let data4 = arg3;
                raw!(data1, data2, data3, data4);
            },
            qlib::HYPERCALL_OOM => {
                let data1 = arg0;
                let data2 = arg1;
                error!(
                    "OOM!!! cpu [{}], size is {:#x}, alignment is {:#x}",
                    id, data1, data2
                );
                eprintln!(
                    "OOM!!! cpu [{}], size is {:#x}, alignment is {:#x}",
                    id, data1, data2
                );
                ::std::process::exit(1);
            },
            qlib::HYPERCALL_EXIT => {
                info!("HYPERCALL_EXIT called");
                unsafe { libc::_exit(0) }
            },
            qlib::HYPERCALL_U64 => {
                info!("HYPERCALL_U64 is not handled");
            },
            qlib::HYPERCALL_GETTIME => {
                let data = arg0;
                unsafe {
                    let call = &mut *(data as *mut GetTimeCall);
                    let clockId = call.clockId;
                    let ts = Timespec::default();
                    let res = libc::clock_gettime(
                        clockId as libc::clockid_t,
                        &ts as *const _ as u64 as *mut libc::timespec,
                    ) as i64;

                    if res == -1 {
                        call.res = errno::errno().0 as i64;
                    } else {
                        call.res = ts.ToNs()?;
                    }
                }
            },
            qlib::HYPERCALL_VCPU_FREQ => {
                let data = arg0;
                // TODO: the cntfreq_el0 register may not be properly programmed
                // to represent the system counter frequency in many platforms
                // (careless firmware implementations). There should be a sanity
                // check here, if the cntfreq reads 0, work around it and get
                // the actual frequency.
                let freq = self.vcpu_base.get_frequency()?;
                if freq == 0 {
                    panic!("system counter frequency (cntfrq_el0) reads 0. It\
                           may not be properly programmed by the firmware");
                }
                unsafe {
                    let call = &mut *(data as *mut VcpuFeq);
                    call.res = freq as i64;
                }
            },
            qlib::HYPERCALL_VCPU_YIELD => {
                let _ret = crate::vmspace::host_uring::HostSubmit().unwrap();
            },
            qlib::HYPERCALL_VCPU_DEBUG => {
                error!("DEBUG not implemented");
            },
            qlib::HYPERCALL_VCPU_PRINT => {
                error!("[{}] HYPERCALL_VCPU_PRINT", id);
            },
            qlib::HYPERCALL_QCALL => {
                KVMVcpu::GuestMsgProcess(&SHARE_SPACE);
                // last processor in host
                if SHARE_SPACE.DecrHostProcessor() == 0 {
                    KVMVcpu::GuestMsgProcess(&SHARE_SPACE);
                }
            },
            qlib::HYPERCALL_HCALL => {
                let addr = arg0;

                let eventAddr = addr as *mut QMsg; // as &mut qlib::Event;
                let qmsg = unsafe { &mut (*eventAddr) };

                {
                    let _l = if qmsg.globalLock {
                        Some(GLOCK.lock())
                    } else {
                        None
                    };

                    qmsg.ret = KVMVcpu::qCall(qmsg.msg);
                }

                SHARE_SPACE.IncrHostProcessor();

                KVMVcpu::GuestMsgProcess(&SHARE_SPACE);
                // last processor in host
                if SHARE_SPACE.DecrHostProcessor() == 0 {
                    KVMVcpu::GuestMsgProcess(&SHARE_SPACE);
                }
            },
            qlib::HYPERCALL_VCPU_WAIT => {
                let retAddr = arg2;
                let ret = SHARE_SPACE.scheduler.WaitVcpu(&SHARE_SPACE, id, true);
                match ret {
                    #[cfg(not(feature = "cc"))]
                    Ok(taskId) => unsafe {
                        *(retAddr as *mut u64) = taskId as u64;
                    },
                    #[cfg(feature = "cc")]
                    Ok(taskId) => unsafe {
                        *(retAddr as *mut TaskId) = taskId;
                    },
                    Err(Error::Exit) => {
                        return Ok(true)
                    },
                    Err(e) => {
                        panic!("HYPERCALL_HLT wait fail with error {:?}", e);
                    }
                }
            }
            _ => error!("Unknown hypercall - number:{}", hypercall),
        }

        Ok(false)
    }

    fn default_kvm_exit_handler(&self, kvm_exit: VcpuExit) -> Result<bool, Error> {
        let id = self.vcpu_base.id;
        match kvm_exit {
            VcpuExit::MmioRead(addr, _data) => {
                self.vcpu_base.backtrace()?;
                panic!("CPU[{}] Received an MMIO Read Request for the address {:#x}.",
                    self.vcpu_base.id, addr,);
            },
            VcpuExit::Hlt => {
                error!("vCPU:{} - Halt-Exit", id);
            },
            VcpuExit::FailEntry => {
                error!("vCPU:{} - FailedEntry-Exit", id);
                return Ok(true);
            },
            VcpuExit::Exception => {
                info!("vCPU:{} - Exception-Exit", id);
            },
            VcpuExit::IrqWindowOpen => {
                self.vcpu_base.InterruptGuest();
                self.vcpu_base.vcpu_fd.set_kvm_request_interrupt_window(0);
                {
                    let mut interrupting = self.vcpu_base.interrupting.lock();
                    interrupting.0 = false;
                    interrupting.1.clear();
                }
            },
            VcpuExit::Intr => {
                self.vcpu_base.vcpu_fd.set_kvm_request_interrupt_window(1);
                {
                    let mut interrupting = self.vcpu_base.interrupting.lock();
                    interrupting.0 = false;
                    interrupting.1.clear();
                }
            },
            VcpuExit::Hypercall => {
                panic!("Received KVM_EXIT_HYPERCALL");
            },
            r => {
                error!("Panic: CPU[{}] Unexpected exit reason: {:?}", self.vcpu_base.id, r);
                unsafe {
                    libc::exit(0);
                }
            }
        }
        Ok(false)
    }
}

impl Aarch64VirtCpu {
    fn _run(&self) -> Result<(), Error> {
        let mut exit_loop: bool;
        loop {
            if !vm::IsRunning() {
                break;
            }
            self.vcpu_base.state.store(KVMVcpuState::GUEST as u64, Ordering::Release);
            let kvm_ret = match self.vcpu_base.vcpu_fd.run() {
                Ok(ret) => ret,
                Err(e) => {
                    error!("vCPU - Run exited with error.");
                    if e.errno() == SysErr::EINTR {
                        self.vcpu_base.vcpu_fd.set_kvm_immediate_exit(0);
                        self.vcpu_base.dump()?;
                        if self.vcpu_base.vcpu_fd.get_ready_for_interrupt_injection() > 0 {
                            VcpuExit::IrqWindowOpen
                        } else {
                            VcpuExit::Intr
                        }
                    } else {
                        self.vcpu_base.backtrace()?;
                        panic!("vCPU-Run failed - id:{}, error:{:?}", self.vcpu_base.id, e)
                    }
                }
            };
            self.vcpu_base.state.store(KVMVcpuState::HOST as u64, Ordering::Release);
            let mut  hypercall: u16 = 0;
            let mut arg0: u64 = 0;
            let mut arg1: u64 = 0;
            let mut arg2: u64 = 0;
            let mut arg3: u64 = 0;
            if self._hypercall_detected(&kvm_ret, &mut hypercall, &mut arg0, &mut arg1,
                &mut arg2, &mut arg3) {
                if self.conf_comp_extension.should_handle_hypercall(hypercall) {
                    exit_loop = self.conf_comp_extension.handle_hypercall(hypercall, arg0,
                        arg1, arg2, arg3, self.vcpu_base.id)
                        .expect("VM run failed - cannot handle hypercall correctly.");
                } else {
                    exit_loop = self.default_hypercall_handler(hypercall, arg0, arg1,
                        arg2, arg3)
                        .expect("VM run failed - cannot handle hypercall correctly.");
                }
            } else if self.conf_comp_extension.should_handle_kvm_exit(&kvm_ret) {
                exit_loop = self.conf_comp_extension.handle_kvm_exit(&kvm_ret, self.vcpu_base.id)?;
            } else {
                exit_loop = self.default_kvm_exit_handler(kvm_ret)?;
            }
            if exit_loop {
                return Ok(());
            }
        }
        info!("VM-Run stopped for id:{}", self.vcpu_base.id);
        Ok(())
    }

    fn _hypercall_detected(&self, vcpu_exit: &VcpuExit, hcall_id: &mut u16, arg0: &mut u64,
        arg1: &mut u64, arg2: &mut u64, arg3: &mut u64) -> bool {
        let ret: bool;
        match vcpu_exit {
            VcpuExit::MmioWrite(addr, _) => {
                {
                    let mut interrupting = self.vcpu_base.interrupting.lock();
                    interrupting.0 = false;
                    interrupting.1.clear();
                }
                *hcall_id = (addr - MemoryDef::HYPERCALL_MMIO_BASE) as u16;
                if *hcall_id > u16::MAX {
                    panic!("cpu[{}] Received hypercall id max than 255", self.vcpu_base.id);
                }
                (*arg0, *arg1, *arg2, *arg3) = self.conf_comp_extension
                    .get_hypercall_arguments(&self.vcpu_base.vcpu_fd, self.vcpu_base.id)
                    .expect("Failed to get hypercall arguments.");
                    debug!("VMM: HCALL Arguments from Shared-Space: arg0:{:#0x}, arg1:{:#0x},\
                        arg2:{:#0x}, arg3:{:#0x}", *arg0, *arg1, *arg2, *arg3);
                ret = true;
            },
            VcpuExit::Hypercall => {
                {
                    let mut interrupting = self.vcpu_base.interrupting.lock();
                    interrupting.0 = false;
                    interrupting.1.clear();
                }
                let fid = self.vcpu_base.vcpu_fd.get_one_reg(X0 as u64).expect("Failed to get X0");
                if fid as u32 == SMC_RSI_HOST_CALL {
                    let req = self.vcpu_base.vcpu_fd.get_one_reg(X1 as u64)
                        .expect("Failed to get X1");
                    *hcall_id = (req - MemoryDef::HYPERCALL_MMIO_BASE) as u16;
                    let x2 = self.vcpu_base.vcpu_fd.get_one_reg(X2 as u64).expect("GET x2 failed.");
                    let x3 = self.vcpu_base.vcpu_fd.get_one_reg(X3 as u64).expect("GET x3 failed.");
                    let x4 = self.vcpu_base.vcpu_fd.get_one_reg(X4 as u64).expect("GET x4 failed.");
                    let x5 = self.vcpu_base.vcpu_fd.get_one_reg(X5 as u64).expect("GET x5 failed.");
                    debug!("VMM: HCALL{} Arguments from RsiHostCall: arg0:{:#0x}, arg1:{:#0x},\
                        arg2:{:#0x}, arg3:{:#0x}", *hcall_id, x2, x3, x4, x5);
                    (*arg0, *arg1, *arg2, *arg3) = (x2, x3, x4, x5);
                    ret = true;
                } else {
                    panic!("VMM: EXIT-HYPERCALL for unexpected reason - X0:{:#0x}.", fid);
                }
            },
            _ => {
                ret = false;
            },
        };
        ret
    }
}
