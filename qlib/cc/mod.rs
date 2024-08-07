#[cfg(feature = "tdx")]
pub mod tdx;

pub const REGS_WRAPPER_SIZE: usize = 0x100;
pub const VMREGS_SIZE: usize = 0xc8;
//TDH.VP.INIT to pass the cpuid
#[derive(Default, Clone, Copy, Debug)]
#[repr(C,align(8))]
pub struct VMRegs {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub gdtaddr: u64,
    pub tssaddr: u64,
    pub tssIntStackStart: u64,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct VMRegsWrapper {
    pub vmRegs: VMRegs,
    reserved: [u8; REGS_WRAPPER_SIZE - VMREGS_SIZE],
}

pub struct VMRegsArray {
    pub vmRegsWrappers: [VMRegsWrapper; 0x2000],
}