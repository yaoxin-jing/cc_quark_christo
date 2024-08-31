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

#![no_std]
#![feature(proc_macro_hygiene)]
#![feature(alloc_error_handler)]
#![feature(abi_x86_interrupt)]
#![allow(dead_code)]
#![allow(deref_nullptr)]
#![allow(non_snake_case)]
#![allow(bare_trait_objects)]
#![feature(allocator_api)]
#![feature(associated_type_bounds)]
#![feature(maybe_uninit_uninit_array)]
#![feature(panic_info_message)]
#![allow(deprecated)]
#![recursion_limit = "256"]
#![allow(invalid_reference_casting)]
#![feature(btreemap_alloc)]
#![feature(sync_unsafe_cell)]

#[macro_use]
extern crate alloc;
extern crate bit_field;
#[macro_use]
extern crate bitflags;
extern crate cache_padded;
extern crate crossbeam_queue;
extern crate enum_dispatch;
extern crate hashbrown;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate scopeguard;
#[macro_use]
extern crate serde_derive;
extern crate log;
extern crate spin;
extern crate tdx_tdcall;
#[cfg(target_arch = "x86_64")]
extern crate x86_64;
extern crate xmas_elf;
//
// Conf-Comp deps. - AttAg.
//
extern crate rsa;
extern crate aes_gcm;
extern crate embedded_tls;
extern crate embedded_io;
extern crate httparse;
extern crate base64;
extern crate serde;
extern crate jwt_compact;
extern crate kbs_types;
extern crate getrandom;
extern crate zeroize;
extern crate sha2;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use core::{mem, ptr};
#[cfg(target_arch = "aarch64")]
use getrandom::register_custom_getrandom;
use spin::mutex::Mutex;

use qlib::mutex::*;
use taskMgr::{CreateTask, IOWait, WaitFn};
use vcpu::CPU_LOCAL;

use crate::qlib::kernel::GlobalIOMgr;
use crate::qlib::ShareSpace;

use self::asm::*;
use self::boot::controller::*;
use self::boot::loader::*;
use self::kernel::timer::*;
use self::kernel_def::*;
use self::loader::vdso::*;
use self::qlib::common::*;
use self::qlib::config::*;
use self::qlib::control_msg::*;
use self::qlib::cpuid::*;
use self::qlib::kernel::arch;
use self::qlib::kernel::asm;
use self::qlib::kernel::boot;
use self::qlib::kernel::fd;
use self::qlib::kernel::fs;
use self::qlib::kernel::kernel;
use self::qlib::kernel::loader;
use self::qlib::kernel::memmgr;
use self::qlib::kernel::perflog;
use self::qlib::kernel::quring;
use self::qlib::kernel::Kernel;
use self::qlib::kernel::arch::tee::is_cc_active;
use self::qlib::kernel::*;
use self::qlib::{ShareSpaceRef, SysCallID};
use self::qlib::kernel::socket;
use self::qlib::kernel::task;
use self::qlib::kernel::taskMgr;
use self::qlib::kernel::threadmgr;
use self::qlib::kernel::util;
use self::qlib::kernel::vcpu;
use self::qlib::kernel::vcpu::*;
use self::qlib::kernel::version;
use self::qlib::kernel::Scale;
use self::qlib::kernel::SignalDef;
use self::qlib::kernel::VcpuFreqInit;
use self::qlib::kernel::TSC;
use self::qlib::linux::time::*;
use self::qlib::linux_def::MemoryDef;
use self::qlib::loader::*;
use self::qlib::mem::list_allocator::*;
use self::qlib::pagetable::*;
use self::qlib::vcpu_mgr::*;
use self::quring::*;
use self::syscalls::syscalls::*;
use self::task::*;
use self::threadmgr::task_sched::*;

#[cfg(feature = "tdx")]
use self::qlib::cc::tdx::{set_memory_shared_2mb, set_sbit_mask};
#[cfg(feature = "tdx")]
use self::qlib::cc::*;
#[cfg(feature = "tdx")]
use self::qlib::kernel::Kernel::{IS_INITIALIZED, IS_INITIALIZED_COUNTER};
#[cfg(feature = "tdx")]
use x86_64::instructions::tables::load_tss;
#[cfg(feature = "tdx")]
use x86_64::registers::segmentation::*;
#[cfg(feature = "tdx")]
use x86_64::structures::gdt::*;
#[cfg(feature = "tdx")]
use x86_64::structures::tss::*;

use self::qlib::mem::cc_allocator::*;
use alloc::boxed::Box;
use memmgr::pma::PageMgr;

#[macro_use]
mod print;

#[macro_use]
mod qlib;
#[macro_use]
mod interrupt;
pub mod kernel_def;
pub mod rdma_def;
mod syscalls;
pub mod drivers;
pub mod attestation_agent;

#[global_allocator]
pub static VCPU_ALLOCATOR: GlobalVcpuAllocator = GlobalVcpuAllocator::New();

pub static GLOBAL_ALLOCATOR: HostAllocator = HostAllocator::New();

pub static  IS_GUEST: bool = true;
pub static SHARED_ALLOCATOR : GlobalVcpuSharedAllocator = GlobalVcpuSharedAllocator::New();
pub static GUEST_HOST_SHARED_ALLOCATOR: GuestHostSharedAllocator = GuestHostSharedAllocator::New();

lazy_static! {
    pub static ref GLOBAL_LOCK: Mutex<()> = Mutex::new(());
}

//used when cc is enabled
lazy_static! {
    pub static ref PRIVATE_VCPU_ALLOCATOR: Box<PrivateVcpuAllocators> = Box::new(PrivateVcpuAllocators::New());
    pub static ref PRIVATE_VCPU_SHARED_ALLOCATOR: Box<PrivateVcpuSharedAllocators> = Box::new(PrivateVcpuSharedAllocators::New());
    pub static ref PAGE_MGR_HOLDER: Box<PageMgr> = Box::new(PageMgr::default());
    pub static ref GUEST_KERNEL: Mutex<Option<kernel::kernel::Kernel>> = Mutex::new(None);
}

pub fn AllocIOBuf(size: usize) -> *mut u8 {
    unsafe {
        return GLOBAL_ALLOCATOR.AllocIOBuf(size);
    }
}

#[cfg(feature = "tdx")]
unsafe fn init_tss(gdt: &mut GlobalDescriptorTable, tssaddr: u64, tssIntStackStart: u64) {
    use bit_field::BitField;
    let stack_end = x86_64::VirtAddr::from_ptr(
        (tssIntStackStart + MemoryDef::INTERRUPT_STACK_PAGES * MemoryDef::PAGE_SIZE) as *const u64,
    );
    let tssSegment = tssaddr as *mut x86_64::structures::tss::TaskStateSegment;
    (*tssSegment).interrupt_stack_table[0] = stack_end;
    (*tssSegment).iomap_base = -1 as i16 as u16;
    let mut low = DescriptorFlags::PRESENT.bits();
    // base
    low.set_bits(16..40, tssaddr.get_bits(0..24));
    low.set_bits(56..64, tssaddr.get_bits(24..32));
    // limit
    low.set_bits(0..16, (core::mem::size_of::<TaskStateSegment>() - 1) as u64);
    // type
    low.set_bits(40..44, 0b1001);

    let mut high = 0;
    high.set_bits(0..32, tssaddr.get_bits(32..64));

    let tss_descriptor = Descriptor::SystemSegment(low, high);
    let tss_segment_selector = gdt.add_entry(tss_descriptor);

    gdt.load_unsafe();

    load_tss(tss_segment_selector);
}

#[cfg(feature = "tdx")]
pub unsafe fn init_gdt(vcpuid: u64) {
    let vmRegs = &(*(MemoryDef::VM_REGS_OFFSET as *const VMRegsArray)).vmRegsWrappers
        [vcpuid as usize]
        .vmRegs;
    let gdtAddr = vmRegs.gdtaddr;
    let tssAddr = vmRegs.tssaddr;
    let tssIntStackStart = vmRegs.tssIntStackStart;
    let gdt = &mut *(gdtAddr as *mut GlobalDescriptorTable);
    *gdt = GlobalDescriptorTable::new();
    let kcode64 = gdt.add_entry(Descriptor::kernel_code_segment());
    let kdata = gdt.add_entry(Descriptor::kernel_data_segment());
    let udata = gdt.add_entry(Descriptor::user_data_segment());
    let _ucode64 = gdt.add_entry(Descriptor::user_code_segment());
    gdt.load_unsafe();
    CS::set_reg(kcode64);
    DS::set_reg(udata);
    ES::set_reg(udata);
    SS::set_reg(kdata);
    FS::set_reg(udata);
    GS::set_reg(udata);
    init_tss(gdt, tssAddr, tssIntStackStart);
}

pub fn SingletonInit() {
    unsafe {
        vcpu::VCPU_COUNT.Init(AtomicUsize::new(0));
        vcpu::CPU_LOCAL.Init(&SHARESPACE.scheduler.VcpuArr);
        set_cpu_local(0);
        //init fp state with current fp state as it is brand new vcpu
        FP_STATE.Reset();

        // the error! can run after this point
        //error!("error message");

        if is_cc_active(){
            if crate::qlib::kernel::arch::tee::get_tee_type() != CCMode::TDX {
                KERNEL_PAGETABLE.Init(PageTables::Init(CurrentUserTable()));
                interrupt::InitSingleton();
                PAGE_MGR.SetValue(PAGE_MGR_HOLDER.Addr());
            }
        } else {
            KERNEL_PAGETABLE.Init(PageTables::Init(CurrentUserTable()));
            SHARESPACE.SetSignalHandlerAddr(SignalHandler as u64);
            PAGE_MGR.SetValue(SHARESPACE.GetPageMgrAddr());
            interrupt::InitSingleton();
        }
        IOURING.SetValue(SHARESPACE.GetIOUringAddr());
        LOADER.Init(Loader::default());
        KERNEL_STACK_ALLOCATOR.Init(AlignedAllocator::New(
            MemoryDef::DEFAULT_STACK_SIZE as usize,
            MemoryDef::DEFAULT_STACK_SIZE as usize,
        ));
        EXIT_CODE.Init(AtomicI32::new(0));

        let featureSet = HostFeatureSet();
        SUPPORT_XSAVE.store(
            featureSet.HasFeature(Feature(X86Feature::X86FeatureXSAVE as i32)),
            Ordering::Release,
        );
        SUPPORT_XSAVEOPT.store(
            featureSet.HasFeature(Feature(X86Feature::X86FeatureXSAVEOPT as i32)),
            Ordering::Release,
        );

        perflog::THREAD_COUNTS.Init(QMutex::new(perflog::ThreadPerfCounters::default()));

        fs::file::InitSingleton();
        fs::filesystems::InitSingleton();
        kernel::futex::InitSingleton();
        kernel::semaphore::InitSingleton();
        kernel::epoll::epoll::InitSingleton();
        kernel::timer::InitSingleton();
        loader::vdso::InitSingleton();
        socket::socket::InitSingleton();
        syscalls::sys_rlimit::InitSingleton();
        task::InitSingleton();

        qlib::InitSingleton();
    }
}

#[cfg(target_arch = "x86_64")]
extern "C" {
    pub fn syscall_entry();
}

#[cfg(target_arch = "aarch64")]
extern "C" {
    pub fn vector_table();
}

#[cfg(target_arch = "aarch64")]
register_custom_getrandom!(aarch64_getrandom);

#[cfg(target_arch = "aarch64")]
pub fn aarch64_getrandom(dest: &mut [u8]) -> core::result::Result<(), getrandom::Error> {
    let to_fill = dest.len();
    let rounds= to_fill / 8 as usize; // 64Bits can be read once from RNDR
    let remain = to_fill - (rounds * 8 as usize);
    let mut _dest: Vec<u8> = Vec::with_capacity(to_fill);
    for _ in 0..rounds {
        let val: u64 = crate::qlib::kernel::asm::aarch64::get_rand()
            .expect("VM: no rand generated - can not continue.");
       let mut byte: u8;
       for b in 0..8 {
           byte = ((val >> (b * 8)) & 0xFFFF) as u8;
           _dest.push(byte);
       }
    }
    if remain != 0 {
       let val = crate::qlib::kernel::asm::aarch64::get_rand()
            .expect("VM: no rand generated - can not continue.");
       let mut byte: u8;
        for b in 0..remain {
           byte = ((val >> (b * 8)) & 0xFFFF) as u8;
           _dest.push(byte);
        }
    }
    dest.copy_from_slice(&_dest[0..to_fill]);
    Ok(())
}

pub fn Init() {
    self::fs::Init();
    self::socket::Init();
    print::init().unwrap();
}

#[no_mangle]
#[cfg(target_arch = "x86_64")]
pub extern "C" fn syscall_handler(
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> ! {
    CPULocal::Myself().SetMode(VcpuMode::Kernel);

    let currTask = task::Task::Current();
    currTask.AccountTaskLeave(SchedState::RunningApp);
    let pt = currTask.GetPtRegs();

    let mut rflags = pt.eflags;
    rflags &= !USER_FLAGS_CLEAR;
    rflags |= USER_FLAGS_SET;
    pt.eflags = rflags;
    pt.r11 = rflags;
    pt.rip = pt.rcx;

    let mut nr = pt.orig_rax;

    let startTime = TSC.Rdtsc();
    let enterAppTimestamp = CPULocal::Myself().ResetEnterAppTimestamp() as i64;
    let worktime = Tsc::Scale(startTime - enterAppTimestamp) * 1000; // the thread has used up time slot

    let tick = if SHARESPACE.config.read().Realtime {
        REALTIME_CLOCK_TICK
    } else {
        CLOCK_TICK
    };

    if worktime > tick {
        taskMgr::Yield();
    }

    let res;
    let args = SyscallArguments {
        arg0: arg0,
        arg1: arg1,
        arg2: arg2,
        arg3: arg3,
        arg4: arg4,
        arg5: arg5,
    };

    let mut tid = 0;
    let mut pid = 0;
    let mut callId: SysCallID = SysCallID::UnknowSyscall;

    let debugLevel = SHARESPACE.config.read().DebugLevel;

    if debugLevel > DebugLevel::Error {
        let llevel = SHARESPACE.config.read().LogLevel;
        #[cfg(target_arch = "x86_64")]
        {
            callId = if nr < SysCallID::UnknowSyscall as u64 {
                unsafe { mem::transmute(nr as u64) }
            } else if SysCallID::sys_socket_produce as u64 <= nr
                && nr < SysCallID::EXTENSION_MAX as u64
            {
                unsafe { mem::transmute(nr as u64) }
            } else {
                nr = SysCallID::UnknowSyscall as _;
                SysCallID::UnknowSyscall
            };
        }

        if llevel == LogLevel::Complex {
            tid = currTask.Thread().lock().id;
            pid = currTask.Thread().ThreadGroup().ID();
            info!("({}/{})------get call id {:?} arg0:{:x}, 1:{:x}, 2:{:x}, 3:{:x}, 4:{:x}, 5:{:x}, userstack:{:x}, return address:{:x}, fs:{:x}",
                tid, pid, callId, arg0, arg1, arg2, arg3, arg4, arg5, currTask.GetPtRegs().get_stack_pointer(), currTask.GetPtRegs().rcx, GetFs());
        } else if llevel == LogLevel::Simple {
            tid = currTask.Thread().lock().id;
            pid = currTask.Thread().ThreadGroup().ID();
            info!(
                "({}/{})------get call id {:?} arg0:{:x}",
                tid, pid, callId, arg0
            );
        }
    }

    let currTask = task::Task::Current();

    let state = SysCall(currTask, nr, &args);
    MainRun(currTask, state);
    res = currTask.Return();
    currTask.DoStop();

    let pt = currTask.GetPtRegs();

    CPULocal::SetUserStack(pt.get_stack_pointer());
    CPULocal::SetKernelStack(currTask.GetKernelSp());

    currTask.AccountTaskEnter(SchedState::RunningApp);
    currTask.RestoreFp();

    if self::SHARESPACE.config.read().PerfDebug {
        let gap = TSC.Rdtsc() - startTime;
        if nr < crate::qlib::kernel::threadmgr::task_exit::SYS_CALL_TIME.len() as u64 {
            crate::qlib::kernel::threadmgr::task_exit::SYS_CALL_TIME[nr as usize]
                .fetch_add(gap as u64, Ordering::SeqCst);
        } else {
            crate::qlib::kernel::threadmgr::task_exit::QUARK_SYSCALL_TIME
                [nr as usize - EXTENSION_CALL_OFFSET]
                .fetch_add(gap as u64, Ordering::SeqCst);
        }
    }

    if debugLevel > DebugLevel::Error {
        let gap = if self::SHARESPACE.config.read().PerfDebug {
            TSC.Rdtsc() - startTime
        } else {
            0
        };

        info!(
            "({}/{})------Return[{}] res is {:x}: call id {:?} ",
            tid,
            pid,
            Scale(gap),
            res,
            callId
        );
    }

    let kernelRsp = pt as *const _ as u64;

    CPULocal::Myself().SetEnterAppTimestamp(TSC.Rdtsc());
    CPULocal::Myself().SetMode(VcpuMode::User);
    currTask.mm.HandleTlbShootdown();
    if !(pt.rip == pt.rcx && pt.r11 == pt.eflags) {
        IRet(kernelRsp)
    } else {
        SyscallRet(kernelRsp)
    }
}

// syscall_handler implementation for aarch64: Unlike x86, this function is NOT
// directly called from the asm code (vector). The C calling convention is not
// necessary. Also No AccountTaskLeave here because it's called already in the
// exception handler
// TODO move this function to a proper place.
#[no_mangle]
#[cfg(target_arch = "aarch64")]
pub fn syscall_dispatch_aarch64(
    call_no: u32,
    _arg0: u64,
    _arg1: u64,
    _arg2: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
) -> u64 {
    CPULocal::Myself().SetMode(VcpuMode::Kernel);

    let currTask = task::Task::Current();

    let mut nr = call_no as u64;

    let startTime = TSC.Rdtsc();
    let enterAppTimestamp = CPULocal::Myself().ResetEnterAppTimestamp() as i64;
    let worktime = Tsc::Scale(startTime - enterAppTimestamp) * 1000;
    // the thread has used up time slot
    if worktime > CLOCK_TICK {
        taskMgr::Yield();
    }

    let res;
    let args = SyscallArguments {
        arg0: _arg0,
        arg1: _arg1,
        arg2: _arg2,
        arg3: _arg3,
        arg4: _arg4,
        arg5: _arg5,
    };

    let mut tid = 0;
    let mut pid = 0;
    let mut callId: SysCallID = SysCallID::UnknowSyscall;

    let debugLevel = SHARESPACE.config.read().DebugLevel;

    if debugLevel > DebugLevel::Error {
        let llevel = SHARESPACE.config.read().LogLevel;
        callId = if nr < SysCallID::UnknowSyscall as u64 {
            unsafe { mem::transmute(nr as u64) }
        } else {
            nr = SysCallID::UnknowSyscall as _;
            SysCallID::UnknowSyscall
        };

        if llevel == LogLevel::Complex {
            tid = currTask.Thread().lock().id;
            pid = currTask.Thread().ThreadGroup().ID();
            info!("({}/{})------get call id {:?} arg0:{:x}, 1:{:x}, 2:{:x}, 3:{:x}, 4:{:x}, 5:{:x}, userstack:{:x}, return address:{:x}, fs:{:x}",
                tid, pid, callId, _arg0, _arg1, _arg2, _arg3, _arg4, _arg5, currTask.GetPtRegs().get_stack_pointer(),  currTask.context.pc, currTask.context.tls);
        } else if llevel == LogLevel::Simple {
            tid = currTask.Thread().lock().id;
            pid = currTask.Thread().ThreadGroup().ID();
            info!(
                "({}/{})------get call id {:?} arg0:{:x}",
                tid, pid, callId, _arg0
            );
        }
    }

    let currTask = task::Task::Current();

    let state = SysCall(currTask, nr, &args);
    MainRun(currTask, state);
    res = currTask.Return();
    currTask.DoStop();

    if debugLevel > DebugLevel::Error {
        let gap = if self::SHARESPACE.config.read().PerfDebug {
            TSC.Rdtsc() - startTime
        } else {
            0
        };
        info!(
            "({}/{})------Return[{}] res is {:x}: call id {:?} ",
            tid,
            pid,
            Scale(gap),
            res,
            callId
        );
    }

    CPULocal::Myself().SetEnterAppTimestamp(TSC.Rdtsc());
    CPULocal::Myself().SetMode(VcpuMode::User);
    currTask.mm.HandleTlbShootdown();
    return res;
}

#[inline]
pub fn MainRun(currTask: &mut Task, mut state: TaskRunState) {
    //PerfGoto(PerfType::KernelHandling);
    loop {
        state = match state {
            TaskRunState::RunApp => currTask.RunApp(),
            TaskRunState::RunInterrupt => {
                info!("RunInterrupt[{:x}] ...", currTask.taskId);
                currTask.RunInterrupt()
            }
            TaskRunState::RunExit => {
                info!("RunExit[{:x}] ...", currTask.taskId);
                currTask.RunExit()
            }
            TaskRunState::RunExitNotify => {
                info!("RunExitNotify ...");
                currTask.RunExitNotify();

                // !!! make sure there is no object hold on stack

                TaskRunState::RunExitDone
            }
            TaskRunState::RunThreadExit => {
                info!("RunThreadExit[{:x}] ...", currTask.taskId);
                currTask.RunThreadExit()
            }
            TaskRunState::RunThreadExitNotify => {
                info!("RunTreadExitNotify[{:x}] ...", currTask.taskId);
                currTask.RunThreadExitNotify()
            }
            TaskRunState::RunExitDone => {
                {
                    let thread = currTask.Thread();
                    //currTask.PerfStop();
                    currTask.SetDummy();

                    let fdtbl = thread.lock().fdTbl.clone();
                    thread.lock().fdTbl = currTask.fdTbl.clone();

                    // we have to clone fdtbl at first to avoid lock the thread when drop fdtbl
                    drop(fdtbl);

                    {
                        // the block has to been dropped after drop the fdtbl
                        // It is because we might to wait for QAsyncLockGuard in AsyncBufWrite
                        let dummyTask = DUMMY_TASK.read();
                        currTask.blocker = dummyTask.blocker.clone();
                    }

                    let mm = thread.lock().memoryMgr.clone();
                    thread.lock().memoryMgr = currTask.mm.clone();
                    CPULocal::SetPendingFreeStack(currTask.taskId);

                    /*if !SHARESPACE.config.read().KernelPagetable {
                        KERNEL_PAGETABLE.SwitchTo();
                    }*/
                    // mm needs to be clean as last function before SwitchToNewTask
                    // after this is called, another vcpu might drop the pagetable
                    core::mem::drop(mm);
                    unsafe {
                        (*CPULocal::Myself().pageAllocator.get()).Clean();
                    }
                }

                self::taskMgr::SwitchToNewTask();
                // !!!RunExitDone: should not reach here
            }
            TaskRunState::RunNoneReachAble => panic!("unreadhable TaskRunState::RunNoneReachAble"),
            TaskRunState::RunSyscallRet => TaskRunState::RunSyscallRet,
        };

        if state == TaskRunState::RunSyscallRet {
            break;
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn set_cpu_local(id: u64) {
    SetGs(&CPU_LOCAL[id as usize] as *const _ as u64);
    SwapGs();
}

#[cfg(target_arch = "aarch64")]
fn set_cpu_local(id: u64) {
    tpidr_el1_write(&CPU_LOCAL[id as usize] as *const _ as u64);
}

pub fn LogInit(pages: u64) {
    let bs = self::qlib::bytestream::ByteStream::Init(pages); // 4MB
    *SHARESPACE.logBuf.lock() = Some(bs);
}

pub fn InitTsc() {
    let _hosttsc1 = Kernel::HostSpace::Rdtsc();
    let tsc1 = TSC.Rdtsc();
    let hosttsc2 = Kernel::HostSpace::Rdtsc();
    let tsc2 = TSC.Rdtsc();
    let hosttsc3 = Kernel::HostSpace::Rdtsc();
    let tsc3 = TSC.Rdtsc();
    Kernel::HostSpace::SetTscOffset((hosttsc2 + hosttsc3) / 2 - (tsc1 + tsc2 + tsc3) / 3);
    VcpuFreqInit();
}

fn InitLoader() {
    let mut process = Process::default();
    Kernel::HostSpace::LoadProcessKernel(&mut process as *mut _ as u64) as usize;
    LOADER.InitKernel(process).unwrap();
}

#[cfg(feature = "tdx")]
//Need to initialize PAGEMGR(pagepool for page allocator) and kernel page table in advance
fn InitShareMemory() {
    set_memory_shared_2mb(
        VirtAddr::new(MemoryDef::FILE_MAP_OFFSET),
        MemoryDef::FILE_MAP_SIZE / MemoryDef::PAGE_SIZE_2M,
    );
    set_memory_shared_2mb(
        VirtAddr::new(MemoryDef::GUEST_HOST_SHARED_HEAP_OFFSET),
        MemoryDef::GUEST_HOST_SHARED_HEAP_SIZE / MemoryDef::PAGE_SIZE_2M,
    );
}

#[no_mangle]
pub extern "C" fn rust_main(
    heapStart: u64,
    shareSpaceAddr: u64,
    id: u64,
    vdsoParamAddr: u64,
    vcpuCnt: u64,
    autoStart: bool,
) {
    self::qlib::kernel::asm::fninit();
    if id == 0 {
        //if in any cc machine, shareSpaceAddr is reused as CCMode
        let mode = CCMode::from(shareSpaceAddr);
        #[cfg(feature = "tdx")]
        if mode == CCMode::TDX {
            //Memory is accpeted in firmware
            /*tdx_tdcall::tdx::td_accept_memory(
                MemoryDef::PHY_LOWER_ADDR,
                MemoryDef::IO_HEAP_END - MemoryDef::PHY_LOWER_ADDR,
            );*/
            GLOBAL_ALLOCATOR.SwitchToPrivateRunningHeap();
            unsafe {
                KERNEL_PAGETABLE.Init(PageTables::Init(CurrentKernelTable()));
                init_gdt(id);
                interrupt::InitSingleton();
            }
            interrupt::init();
            set_sbit_mask();
            PAGE_MGR.SetValue(PAGE_MGR_HOLDER.Addr());
            //Tdcall convert shared memory
            InitShareMemory();
        }
        GLOBAL_ALLOCATOR.InitPrivateAllocator(mode);
        if mode != CCMode::None {
            crate::qlib::kernel::arch::tee::set_tee_type(mode);
            GLOBAL_ALLOCATOR.InitSharedAllocator(mode);
            let size = core::mem::size_of::<ShareSpace>();
            let shared_space = unsafe {
                GLOBAL_ALLOCATOR.AllocSharedBuf(size, 2)
            };
            HyperCall64(qlib::HYPERCALL_SHARESPACE_INIT, shared_space as u64, 0, 0, 0);
            SHARESPACE.SetValue(shared_space as u64);
        } else {
            GLOBAL_ALLOCATOR.InitSharedAllocator(mode);
            SHARESPACE.SetValue(shareSpaceAddr);
        }

        SingletonInit();
        debug!("init singleton finished");
        SetVCPCount(vcpuCnt as usize);

        VCPU_ALLOCATOR.Print();
        VCPU_ALLOCATOR.Initializated();
        GUEST_HOST_SHARED_ALLOCATOR.Print();
        GUEST_HOST_SHARED_ALLOCATOR.Initializated();
        InitTsc();
        InitTimeKeeper(vdsoParamAddr);
        debug!("init time keeper finished");

        #[cfg(target_arch = "x86_64")]
        {
            let kpt = &KERNEL_PAGETABLE;

            let vsyscallPages: alloc::sync::Arc<alloc::vec::Vec<u64>> = PAGE_MGR.VsyscallPages();
            kpt.InitVsyscall(vsyscallPages);
        }
        debug!("init vsyscall finished");
        GlobalIOMgr().InitPollHostEpoll(SHARESPACE.HostHostEpollfd());
        debug!("init host epoll fd finished");
        VDSO.Initialization(vdsoParamAddr);
        debug!("init vdso finished");

        #[cfg(feature = "tdx")]
        if crate::qlib::kernel::arch::tee::get_tee_type() == CCMode::TDX {
            let additional_data = [0u8; 64];
            let report = tdx_tdcall::tdreport::tdcall_report(&additional_data).unwrap();
            info!("{:#x?}", report);
        }
        // release other vcpus
        HyperCall64(qlib::HYPERCALL_RELEASE_VCPU, 0, 0, 0, 0);
    } else {
        #[cfg(feature = "tdx")]
        if CCMode::from(shareSpaceAddr) == CCMode::TDX {
            unsafe {
                init_gdt(id);
            }
        }
        interrupt::init();
        set_cpu_local(id);
        //PerfGoto(PerfType::Kernel);
    }
    let initialized_num = IS_INITIALIZED_COUNTER.fetch_add(1, Ordering::Release);
    if initialized_num + 1 == vcpuCnt {
        IS_INITIALIZED.store(true, Ordering::Release);
    }
    if IS_INITIALIZED.load(Ordering::Acquire) {
        use crate::qlib::addr::Addr;
        KERNEL_PAGETABLE
            .UnmapWith1G(Addr(0), Addr(8 * MemoryDef::ONE_GB), &*PAGE_MGR)
            .expect("Failed to unmap firmware address!");
    }
    SHARESPACE.IncrVcpuSearching();
    taskMgr::AddNewCpu();

    #[cfg(target_arch = "x86_64")]
    {
        RegisterSysCall(syscall_entry as u64);
    }

    #[cfg(target_arch = "aarch64")]
    {
        RegisterExceptionTable(vector_table as u64);
    }

    /***************** can't run any qcall before this point ************************************/

    if id == 0 {
        IOWait();
    };

    if id == 1 {
        debug!("heap starts at:{:#x}", heapStart);
        self::Init();
        if autoStart {
            CreateTask(StartRootContainer as u64, ptr::null(), false);
        }

        if SHARESPACE.config.read().Sandboxed {
            self::InitLoader();
        }
    }

    WaitFn();
}

//Dummy: Only to avoid issues with qvisor
use alloc::string::String;
use alloc::vec::Vec;
pub fn try_attest(config_path: Option<String>, envv: Option<Vec<String>>) {
    crate::attestation_agent::AttestationAgent::try_attest(config_path, envv);
}

fn StartExecProcess(fd: i32, process: Process) -> ! {
    let (tid, entry, userStackAddr, kernelStackAddr) = { LOADER.ExecProcess(process).unwrap() };

    {
        WriteControlMsgResp(fd, &UCallResp::ExecProcessResp(tid), true);
    }

    let currTask = Task::Current();
    currTask.AccountTaskEnter(SchedState::RunningApp);

    EnterUser(entry, userStackAddr, kernelStackAddr);
}

fn StartSubContainerProcess(elfEntry: u64, userStackAddr: u64, kernelStackAddr: u64) -> ! {
    let currTask = Task::Current();
    currTask.AccountTaskEnter(SchedState::RunningApp);

    EnterUser(elfEntry, userStackAddr, kernelStackAddr);
}

pub fn StartRootProcess() {
    CreateTask(StartRootContainer as u64, ptr::null(), false);
}

fn StartRootContainer(_para: *const u8) -> ! {
    info!("StartRootContainer ....");
    let task = Task::Current();
    let mut process = Process::default();
    Kernel::HostSpace::LoadProcessKernel(&mut process as *mut _ as u64) as usize;

    let (_tid, entry, userStackAddr, kernelStackAddr) = {
        let mut processArgs = LOADER.Lock(task).unwrap().Init(process);
        match LOADER.LoadRootProcess(&mut processArgs) {
            Err(e) => {
                error!(
                    "load root process failed with error:{:?}, shutting down...",
                    e
                );
                SHARESPACE.StoreShutdown();
                Kernel::HostSpace::ExitVM(2);
                panic!("exiting ...");
            }
            Ok(r) => r,
        }
    };

    //CreateTask(StartExecProcess, ptr::null());
    let currTask = Task::Current();
    currTask.AccountTaskEnter(SchedState::RunningApp);
    debug!(
        "enter user, entry: {:#x}, userStackAddr: {:#x}, kernelStackAddr: {:#x}",
        entry, userStackAddr, kernelStackAddr
    );
    EnterUser(entry, userStackAddr, kernelStackAddr);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // bug https://github.com/QuarkContainer/Quark/issues/26.
    // todo: enable this after the issue is fixed
    //print!("get panic: {:?}", info);

    print!("get panic : {:?}", info.message());
    if let Some(location) = info.location() {
        print!(
            "panic occurred in file '{}' at line {}",
            location.file(),
            location.line(),
        );
    } else {
        print!("panic occurred but can't get location information...");
    }

    qlib::backtracer::trace(
        GetCurrentKernelIp(),
        GetCurrentKernelSp(),
        GetCurrentKernelBp(),
        &mut |frame| {
            print!("ExceptionHandler frame is {:#x?}", frame);
            true
        },
    );

    self::Kernel::HostSpace::Panic("get panic ...");
    loop {}
}

#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    self::Kernel::HostSpace::Panic(&format!("alloc_error_handler layout: {:?}", layout));
    loop {}
}
