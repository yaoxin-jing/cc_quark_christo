.globl _start, hlt, _set_regs, _start_main, _smc_exit, _boot_cpux
.extern rust_main

#ABI: CPU0
# X0: HeapStart
# X2: CPU id
# X3: VDSO address
# X4: Count of CPUs
# X5: Auto start
# -----Confidential Computing Feature-----
# *NOT* Enabled:
# X1: ShareSpace address
# Same for all other CPUs
# ------------------------
# Enabled:
# Only CPU0
# X1: CCMode type:
#     * Normal
#     * NormalEmu
#     * Realm
# X6: SP_EL1
# X7: BootHelpData address
# ------------------------
# Same for all CPUs
# SP_EL1[0]: TCR_EL1
# SP_EL1[1]: SCTLR_EL1
# SP_EL1[2]: CPACR_EL1
# SP_EL1[3]: CNTKCTL_EL1
# SP_EL1[4]: TTBR0_EL1
# SP_EL1[5]: MAIR_EL1
# ------------------------
# Same for all CPUs id > 0
# SP_EL1[6]: Auto start      ---->                X5
# SP_EL1[7]: Count of CPUs                        X4
# SP_EL1[8]: VDSO address    ----> rust_main ===> X3
# SP_EL1[9]: CPU id                               X2
# SP_EL1[10]: CCMode type                         X1
# SP_EL1[11]: HeapStart      ---->                X0


# Note: It is always the boot cpu that start first
_start:
# CCA Realm
 cmp x1, #4
 b.eq _start_main_cpu
_start_main:
  b rust_main
hlt:
  mov x0, 0x10000000
  mov x1, #0
  str w1, [x0]

.globl BOOT_HELP_DATA, BOOT_VCPU_PC
BOOT_HELP_DATA:
        .quad 0
BOOT_VCPU_PC:
        .quad 0

_start_main_cpu:
 mov sp, x6
 # We read inhalt value in rust-land
 adr x8, BOOT_HELP_DATA
 str x7, [x8]
 adr x7, _boot_cpux
 adr x8, BOOT_VCPU_PC
 str x7, [x8]
 b _set_sregs

_boot_cpux:
  # resolve stack base
  # GuestPrivateMemoryStartLower32B
  mov w3, 0x40000000
  add w0, w0, w3
  # GuestPrivateMemoryStartUpper32B
  mov x1, 0x43
  lsl x1, x1, #32
  # CPUX Stack base
  add x0, x0, x1
  mov sp, x0
  # set call arguments for rust_main
  ldp x4, x5, [sp, #16 * (-4)]
  ldp x2, x3, [sp, #16 * (-5)]
  ldp x0, x1, [sp, #16 * (-6)]
_set_sregs:
  ldp x8, x7, [sp, #16 * (-1)]
  ldp x10, x9, [sp, #16 * (-2)]
  ldp x12, x11, [sp, #16 * (-3)]
  msr tcr_el1, x7
  msr cpacr_el1, x9
  msr cntkctl_el1, x10
  msr ttbr0_el1, x11
  msr mair_el1, x12
  msr sctlr_el1, x8
  # Flush table
  isb
  dsb ish
  # Reset used GPRs
  mov x7, xzr
  mov x8, xzr
  mov x9, xzr
  mov x10, xzr
  mov x11, xzr
  mov x12, xzr
  b _start_main

_smc_exit:
 smc #0
 ret
