.intel_syntax noprefix
.globl _start
_start:
/*
;
; #[repr(packed)]
; pub struct VMRegs {
;     pub cr0: u64,
;     pub cr3: u64,
;     pub cr4: u64,
;     pub efer: u64,
;     pub rax: u64,  0x11
;     pub rbx: u64,  0xdd
;     pub rcx: u64,
;     pub rdx: u64,
;     pub rsi: u64,
;     pub rdi: u64,
;     pub rsp: u64,
;     pub rbp: u64,
;     pub r8: u64,
;     pub r9: u64,
;     pub r10: u64,  not used from r10 to r15
;     pub r11: u64,
;     pub r12: u64,
;     pub r13: u64,
;     pub r14: u64,
;     pub r15: u64,
;     pub rip: u64,
;     pub rflags: u64,
;     pub gdtaddr: u64,
;     pub tssaddr: u64,
;     pub tssIntStackStart: u64,
; }



; This is a trampoline function, load the new pagetable, set all the
; registers and at last jump to the entry point of the kernel.
; 

; @param[in]      RDI    HOB_ADDRESS
; @param[in]      RSI    PAYLOAD_ADDRESS
; @param[in]      RDX    CPUID
*/

/* get the pointer of struct VMRegs*/
    mov rax, rdx
    mov r9, rdx
    mov rdx, 0x100
    mul rdx
    mov rdx, 0x4060200000
    add rax, rdx

/*rbx: VMRegs addr for current cpu */
    mov rbx, rax  

    cmp r9, 0x0
    je .is_bsp
/*hypercall here to wait the bsp finish initialization*/
    mov dx, 0x100
    out dx, al

.is_bsp:
/*continue*/
    mov rax, [rbx]
    mov cr0, rax
    mov rax, [rbx + 0x8]
    mov cr3, rax
    mov rax, [rbx + 0x10]
    mov cr4, rax
    

    /*load efer*/
    mov rax, [rbx + 0x18]
    xor rdx, rdx
    mov rdx, rax
    shr rdx, 32
    mov rcx, 0xC0000080
    wrmsr

    /*load general purpose registers*/
    mov rcx, [rbx + 0x30]
    mov rdx, [rbx + 0x38]
    mov rsi, [rbx + 0x40]
    mov rdi, [rbx + 0x48]
    
    mov r8, [rbx + 0x60]
    mov r9, [rbx + 0x68]
    mov r10, [rbx + 0x70]
    mov r11, [rbx + 0x78]
    mov r12, [rbx + 0x80]
    mov r13, [rbx + 0x88]
    mov r14, [rbx + 0x90]
    mov r15, [rbx + 0x98]    

    /*switch stack*/
    mov rsp, [rbx + 0x50]
    mov rbp, [rbx + 0x58]

    /* load rflags*/
    push [rbx + 0xA8]
    popfq

    
    mov rax, 0x11
    mov r10, rbx
    mov rbx, 0xdd

    jmp [r10 + 0xA0]

/*
    mov dx, 0x03F8
    mov al, 38
    out dx, al
    hlt
*/
