use core::sync::atomic::{AtomicU64, Ordering};

/// The S_BIT_MASK indicating shared physical addresses
pub static S_BIT_MASK: AtomicU64 = AtomicU64::new(0);

/// Get the shared bit from hardware by tdcall, can only be used on guest
#[inline(always)]
pub fn get_sbit() -> u64 {
    todo!();
}

#[inline(always)]
pub fn set_sbit_mask() {
    get_sbit();
    S_BIT_MASK.store(1 << get_sbit(), Ordering::Release);
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
    let ret = (ebx == 0x756E6547 ) && (ecx == 0x6C65746E) && (edx == 0x49656E69); //GenuineIntel
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
