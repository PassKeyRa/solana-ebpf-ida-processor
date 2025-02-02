# BPF ALU defines from uapi/linux/bpf_common.h
# Mainly using these for disassembling atomic instructions
BPF_ADD = 0x00
BPF_SUB = 0x10
BPF_MUL = 0x20
BPF_DIV = 0x30
BPF_OR  = 0x40
BPF_AND = 0x50
BPF_LSH = 0x60
BPF_RSH = 0x70
BPF_NEG = 0x80
BPF_MOD = 0x90
BPF_XOR = 0xa0

# and these atomic-specific constants from include/uapi/linux/bpf.h
# /* atomic op type fields (stored in immediate) */
BPF_FETCH = 0x01 # /* not an opcode on its own, used to build others */
BPF_XCHG = (0xe0 | BPF_FETCH) # /* atomic exchange */
BPF_CMPXCHG = (0xf0 | BPF_FETCH) # /* atomic compare-and-write */

# being lazy, we only use this for atomic ops so far
bpf_alu_string = {BPF_ADD: 'add', BPF_AND: 'and', BPF_OR: 'or', BPF_XOR: 'xor'}

# Three least significant bits are operation class:
## BPF operation class: load from immediate. [DEPRECATED]
BPF_LD = 0x00
## BPF operation class: load from register.
BPF_LDX = 0x01
## BPF operation class: store immediate.
BPF_ST = 0x02
## BPF operation class: store value from register.
BPF_STX = 0x03
## BPF operation class: 32 bits arithmetic operation.
BPF_ALU = 0x04
## BPF operation class: jump.
BPF_JMP = 0x05
## BPF operation class: product / quotient / remainder.
BPF_PQR = 0x06
## BPF operation class: 64 bits arithmetic operation.
BPF_ALU64 = 0x07

# Size modifiers:
## BPF size modifier: word (4 bytes).
BPF_W = 0x00
## BPF size modifier: half-word (2 bytes).
BPF_H = 0x08
## BPF size modifier: byte (1 byte).
BPF_B = 0x10
## BPF size modifier: double word (8 bytes).
BPF_DW = 0x18

# Mode modifiers:
## BPF mode modifier: immediate value.
BPF_IMM = 0x00
## BPF mode modifier: absolute load.
BPF_ABS = 0x20
## BPF mode modifier: indirect load.
BPF_IND = 0x40
## BPF mode modifier: load from / store to memory.
BPF_MEM = 0x60
# [ 0x80 reserved ]
# [ 0xa0 reserved ]
# [ 0xc0 reserved ]

# For arithmetic (BPF_ALU/BPF_ALU64) and jump (BPF_JMP) instructions:
# +----------------+--------+--------+
# |     4 bits     |1 b.|   3 bits   |
# | operation code | src| insn class |
# +----------------+----+------------+
# (MSB)                          (LSB)

# Source modifiers:
## BPF source operand modifier: 32-bit immediate value.
BPF_K = 0x00
## BPF source operand modifier: `src` register.
BPF_X = 0x08

# Operation codes -- BPF_ALU or BPF_ALU64 classes:
## BPF ALU/ALU64 operation code: addition.
BPF_ADD = 0x00
## BPF ALU/ALU64 operation code: subtraction.
BPF_SUB = 0x10
## BPF ALU/ALU64 operation code: multiplication. [DEPRECATED]
BPF_MUL = 0x20
## BPF ALU/ALU64 operation code: division. [DEPRECATED]
BPF_DIV = 0x30
## BPF ALU/ALU64 operation code: or.
BPF_OR = 0x40
## BPF ALU/ALU64 operation code: and.
BPF_AND = 0x50
## BPF ALU/ALU64 operation code: left shift.
BPF_LSH = 0x60
## BPF ALU/ALU64 operation code: right shift.
BPF_RSH = 0x70
## BPF ALU/ALU64 operation code: negation. [DEPRECATED]
BPF_NEG = 0x80
## BPF ALU/ALU64 operation code: modulus. [DEPRECATED]
BPF_MOD = 0x90
## BPF ALU/ALU64 operation code: exclusive or.
BPF_XOR = 0xa0
## BPF ALU/ALU64 operation code: move.
BPF_MOV = 0xb0
## BPF ALU/ALU64 operation code: sign extending right shift.
BPF_ARSH = 0xc0
## BPF ALU/ALU64 operation code: endianness conversion.
BPF_END = 0xd0
## BPF ALU/ALU64 operation code: high or.
BPF_HOR = 0xf0

# Operation codes -- BPF_PQR class:
#    7         6               5                               4       3          2-0
# 0  Unsigned  Multiplication  Product Lower Half / Quotient   32 Bit  Immediate  PQR
# 1  Signed    Division        Product Upper Half / Remainder  64 Bit  Register   PQR
## BPF PQR operation code: unsigned high multiplication.
BPF_UHMUL = 0x20
## BPF PQR operation code: unsigned division quotient.
BPF_UDIV = 0x40
## BPF PQR operation code: unsigned division remainder.
BPF_UREM = 0x60
## BPF PQR operation code: low multiplication.
BPF_LMUL = 0x80
## BPF PQR operation code: signed high multiplication.
BPF_SHMUL = 0xA0
## BPF PQR operation code: signed division quotient.
BPF_SDIV = 0xC0
## BPF PQR operation code: signed division remainder.
BPF_SREM = 0xE0

# Operation codes -- BPF_JMP class:
## BPF JMP operation code: jump.
BPF_JA = 0x00
## BPF JMP operation code: jump if equal.
BPF_JEQ = 0x10
## BPF JMP operation code: jump if greater than.
BPF_JGT = 0x20
## BPF JMP operation code: jump if greater or equal.
BPF_JGE = 0x30
## BPF JMP operation code: jump if `src` & `reg`.
BPF_JSET = 0x40
## BPF JMP operation code: jump if not equal.
BPF_JNE = 0x50
## BPF JMP operation code: jump if greater than (signed).
BPF_JSGT = 0x60
## BPF JMP operation code: jump if greater or equal (signed).
BPF_JSGE = 0x70
## BPF JMP operation code: syscall function call.
BPF_CALL = 0x80
## BPF JMP operation code: return from program.
BPF_EXIT = 0x90
## BPF JMP operation code: jump if lower than.
BPF_JLT = 0xa0
## BPF JMP operation code: jump if lower or equal.
BPF_JLE = 0xb0
## BPF JMP operation code: jump if lower than (signed).
BPF_JSLT = 0xc0
## BPF JMP operation code: jump if lower or equal (signed).
BPF_JSLE = 0xd0


# RELOCATIONS

REL_TYPE = {
    0: 'R_BPF_NONE',
    1: 'R_BPF_64_64',
    2: 'R_BPF_64_ABS64',
    3: 'R_BPF_64_ABS32',
    4: 'R_BPF_64_NODYLD32',
    8: 'R_BPF_64_RELATIVE', # SOLANA SPEC (https://github.com/solana-labs/llvm-project/blob/038d472bcd0b82ff768b515cc77dfb1e3a396ca8/llvm/include/llvm/BinaryFormat/ELFRelocs/BPF.def#L11)
    10: 'R_BPF_64_32'
}

REL_PATCH_SIZE = {
    0: None,
    1: 32,
    2: 64,
    3: 32,
    4: 32,
    8: 32,
    10: 32
}