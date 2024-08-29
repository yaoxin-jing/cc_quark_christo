use crate::qlib::kernel::{KERNEL_PAGETABLE, PAGE_MGR};
use crate::qlib::linux_def::*;
use core::sync::atomic::{AtomicU64, Ordering};
use tdx_tdcall::tdx::*;
use x86_64::VirtAddr;

/// The S_BIT_MASK indicating shared physical addresses
pub static S_BIT_MASK: AtomicU64 = AtomicU64::new(0);

pub static S_BIT_NUM: AtomicU64 = AtomicU64::new(0);

/// Get the shared bit from hardware by tdcall, can only be used on guest
#[inline(always)]
pub fn get_sbit() {
    let td_info = tdcall_get_td_info().expect("Fail to get TDINFO");
    let s_bit = td_info.gpaw - 1;
    assert!(s_bit == 47 || s_bit == 51, "invalid gpaw!");
    S_BIT_NUM.store(s_bit, Ordering::Release);
}

#[inline(always)]
pub fn set_sbit_mask() {
    get_sbit();
    S_BIT_MASK.store(1 << S_BIT_NUM.load(Ordering::Acquire), Ordering::Release);
}

#[inline(always)]
pub fn get_sbit_mask() -> u64 {
    return S_BIT_MASK.load(Ordering::Acquire);
}

///Test, if is intel cpu
pub fn check_intel() -> bool {
    let ebx;
    let edx;
    let ecx;
    unsafe {
        let ret = core::arch::x86_64::__cpuid(0x0);
        ebx = ret.ebx;
        edx = ret.edx;
        ecx = ret.ecx;
    }
    let ret = (ebx == 0x756E6547) && (ecx == 0x6C65746E) && (edx == 0x49656E69); //GenuineIntel
    return ret;
}

/// Test, if tdx is supported, can only used on guest
#[inline(always)]
pub fn check_tdx_support_on_guest() -> bool {
    let ebx;
    let ecx;
    let edx;
    unsafe {
        let ret = core::arch::x86_64::__cpuid(0x21);
        ebx = ret.ebx;
        ecx = ret.ecx;
        edx = ret.edx;
    }
    let ret = (ebx == 0x65746E49) && (ecx == 0x20202020) && (edx == 0x5844546C); //"IntelTDX "
    return ret;
}

pub const TEST_OUTPUT_PORT: u64 = 0x3f;

pub fn set_memory_shared_2mb(virt_addr: VirtAddr, npages: u64) {
    assert!(npages >= 1);
    let pt = &KERNEL_PAGETABLE;
    (virt_addr.as_u64()
        ..(virt_addr + MemoryDef::PAGE_SIZE_2M.checked_mul(npages as u64).unwrap()).as_u64())
        .step_by(MemoryDef::PAGE_SIZE_2M as usize)
        .for_each(|a| {
            let virt = VirtAddr::new(a);
            match pt.smash(virt, &*PAGE_MGR, true) {
                Ok(_) => (),
                Err(_) => tdvmcall_io_write_8(TEST_OUTPUT_PORT as u16, 0x1),
            };
        });

    match pt.set_s_bit_address_range(
        virt_addr,
        virt_addr + MemoryDef::PAGE_SIZE_2M.checked_mul(npages as u64).unwrap(),
        &*PAGE_MGR,
    ) {
        Ok(_) => (),
        Err(_) => {
            tdvmcall_io_write_16(TEST_OUTPUT_PORT as u16, (virt_addr.as_u64() >> 12) as u16);
            tdvmcall_halt();
        }
    }
    match tdx_tdcall::tdx::tdvmcall_mapgpa(
        true,
        virt_addr.as_u64(),
        (npages * MemoryDef::PAGE_SIZE_2M) as usize,
    ) {
        Ok(_) => (),
        Err(_) => {
            tdvmcall_io_write_8(TEST_OUTPUT_PORT as u16, 0x3);
            tdvmcall_halt();
        }
    }
}
