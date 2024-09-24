.globl _start, hlt, _set_regs, _start_main, _bad_exit
.extern rust_main

#ABI:
# X0: HeapStart
# X2: CPU id
# X3: VDSO address
# X4: Count of CPUs
# X5: Auto start
# -----Confidential Computing Feature-----
# *NOT* Enabled:
# X1: ShareSpace address
# Enabled:
# X1: CCMode type:
#     * Normal
#     * NormalEmu
#     * Realm
# X6: SP_EL1
# SP_EL1[0]: TCR_EL1
# SP_EL1[1]: SCTLR_EL1
# SP_EL1[2]: CPACR_EL1
# SP_EL1[3]: CNTKCTL_EL1
# SP_EL1[4]: TTBR0_EL1
# SP_EL1[5]: MAIR_EL1

# CCA Realm
_start:
 cmp x1, #4
 b.eq _set_regs
_start_main:
  b rust_main
hlt:
  mov x0, 0x10000000
  mov x1, #0
  str w1, [x0]
_set_regs:
  mov sp, x6
  ldp x7, x8, [sp, #16 * 0]
  ldp x9, x10, [sp, #16 * (-1)]
  ldp x11, x12, [sp, #16 * (-2)]
  msr tcr_el1, x7
  msr cpacr_el1, x9
  msr cntkctl_el1, x10
  msr ttbr0_el1, x11
  msr mair_el1, x12
  msr sctlr_el1, x8
  # Reset used GPRs
  mov x6, xzr
  mov x7, xzr
  mov x8, xzr
  mov x9, xzr
  mov x10, xzr
  mov x11, xzr
  mov x12, xzr
  b _start_main

# Realm RAM - heap
_test_heap:
  # Test01: read data from start of the gp_heap
  ldr x13, [x0]
  smc #0xDEAD
  #b _exit_hcall
  # Test02: read data 2 pages from start of the gp_heap
  mov x14, x0
  add x14, x14, 0x200000
  ldr x13, [x14]
  b _exit_hcall
  # Write to gp_heap
  mov x13, 0x0
  str x13, [x0]
  b _start_main
  # Test03: read data 2 pages from start of the hs_heap
  ldr x14, =0x4380000000
  ldr x13, [x14]
  # Test04: test hypercall
#  b _exit_hcall
#  b _start_main

_bad_exit:
#mov x14, 0xcfff
#lsl x14, x14, #0x18
#add x14, x14, 0xfff000
#ldr x13, [x14]
smc #0

# Use it to cause an exit.
_exit_hcall:
  mov x13, 0x3ffffff000
  #add x13, x13, 0x9
  mov w14, #9
  str w14, [x13]
