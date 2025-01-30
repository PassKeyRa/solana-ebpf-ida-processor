# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <clement (dot) berthaux (at) synacktiv (dot) com> wrote this file.  As long as you
# retain this notice you can do whatever you want with this stuff. If we meet
# some day, and you think this stuff is worth it, you can buy me a beer in
# return.    Clement Berthaux
# ----------------------------------------------------------------------------

from idaapi import *
from idc import *
from idautils import *
from ida_segment import *
from ida_frame import *

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from rust_demangler.rust import TypeNotFoundError

import rust_demangler
import string
#import cxxfilt

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

class DecodingError(Exception):
    pass

class INST_TYPES(object):
    pass

extern_segment = 0x00

STRINGS_PREVIEW_LIMIT = 30

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

class EBPFProc(processor_t):
    id = 0x8000 + 247 # 0x8000+ are reserved for third party plugins
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE
    cnbits = 8
    dnbits = 8
    psnames = ['EBPF']
    plnames = ['Solana VM']
    segreg_size = 0
    instruc_start = 0
    assembler = {
        'flag':  ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,
        "uflag": 0,
        "name": "eBPF",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": "db",
        "a_byte": "db",
        "a_word": "dw",
        'a_dword': "dd",
        'a_qword': "dq",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",

    }

    def ev_loader_elf_machine(self, li, machine_type, p_procname, p_pd, loader, reader): # doesn't work from ida python for some reason
        print(f'ev_loader_elf_machine: {machine_type}')
        if machine_type == 247:
            p_procname = 'Solana VM'
        return machine_type

    def __init__(self):
        processor_t.__init__(self)
        
        self.init_instructions()
        self.init_registers()

        self.relocations = {}
        self.functions = {}
        self.sorted_strings = []
    
    def _parse_relocation(self, rel_type, loc, val):
        type_ = REL_TYPE[rel_type]
        changes = []
        if type_ == 'R_BPF_64_64':
            changes.append({'loc': loc + 4, 'val': val & 0xFFFFFFFF})
            changes.append({'loc': loc + 8 + 4, 'val': val >> 32})
        elif type_ == 'R_BPF_64_ABS64':
            changes.append({'loc': loc, 'val': val})
        elif type_ == 'R_BPF_64_ABS32':
            pass
        elif type_ == 'R_BPF_64_NODYLD32':
            changes.append({'loc': loc, 'val': val & 0xFFFFFFFF})
        elif type_ == 'R_BPF_64_32':
            #changes.append[{'loc': loc + 4, 'val': ((val - 8) / 8) & 0xFFFFFFFF}] strange, but that doesn't work
            changes.append({'loc': loc + 4, 'val': val & 0xFFFFFFFF})
        elif type_ == 'R_BPF_64_RELATIVE':
            pass
        else:
            print(f'[WARN] unknown relocation type: {type_}')
        
        return changes

    def _decode_name(self, name):
        name = name.replace('.rel.text.','')
        name = name.replace('.rel.data.rel.ro.','')
        return name
    
    def _extract_rels_funcs_rodata(self, filename):
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)

            sections = []
            for section in elffile.iter_sections():
                sections.append(section)

            relocations = {}
            functions = {}
            rodata = {}

            symtab_s = elffile.get_section_by_name('.symtab')
            symtab = []

            if symtab_s:
                for sym in symtab_s.iter_symbols():
                    symtab.append({'name': sym.name, 'val': sym.entry['st_value'], 'size': sym.entry['st_size']})
                        
            for s in sections:
                # dynamic
                if s.header['sh_type'] == 'SHT_REL' and s.name == '.rel.dyn':
                    dynsym = elffile.get_section_by_name(".dynsym")
                    if not dynsym or not isinstance(dynsym, SymbolTableSection):
                        print("dynsym not found. what?")
                        continue
                    
                    symbols = []
                    for symbol in dynsym.iter_symbols():
                        symbols.append({'name': symbol.name, 'val': symbol.entry['st_value']})
                    
                    for reloc in s.iter_relocations():
                        relsym = symbols[reloc['r_info_sym']]

                        name = self._decode_name(relsym['name'])

                        reloc_parsed = self._parse_relocation(reloc['r_info_type'], reloc['r_offset'], relsym['val'])
                        mods = []

                        for r in reloc_parsed:
                            mods.append({'loc': get_fileregion_ea(r['loc']), 'val': r['val']})
                        
                        relocation = {
                            'type': reloc['r_info_type'],
                            'name': name,
                            'mods': mods
                        }

                        relocations[get_fileregion_ea(reloc['r_offset'])] = relocation
                        
                    continue

                if s.header['sh_type'] == 'SHT_REL':
                    if not symtab_s:
                        print("symtab section not found. what?")
                        continue

                    code_s = sections[s.header['sh_info']]
                    base_offset = code_s.header['sh_offset']

                    section_name = self._decode_name(s.name)
                    ea_addr = get_fileregion_ea(base_offset)
                    if s.name.startswith('.rel.text.'):
                        functions[section_name] = ea_addr
                    elif s.name.startswith('.rel.data.rel.ro.'):
                        rodata[section_name] = ea_addr

                    for reloc in s.iter_relocations():
                        relsym = symtab[reloc['r_info_sym']]

                        name = self._decode_name(relsym['name'])

                        reloc_parsed = self._parse_relocation(reloc['r_info_type'], reloc['r_offset'], relsym['val'])
                        mods = []

                        for r in reloc_parsed:
                            mods.append({'loc': get_fileregion_ea(base_offset + r['loc']), 'val': r['val']})
                        
                        relocation = {
                            'type': reloc['r_info_type'],
                            'name': name,
                            'mods': mods
                        }

                        relocations[get_fileregion_ea(base_offset + reloc['r_offset'])] = relocation

            return relocations, functions, rodata, symtab
    

    """ ------ Strings ------ """
    
    def _recover_known_strings(self):
        _rodata = get_segm_by_name(".rodata")
        
        strings_to_create = {}

        for s in self.symtab:
            if s['val'] >= _rodata.start_ea and s['val'] <= _rodata.end_ea:
                l = s['size']
                if l > 0:
                    strings_to_create[s['val']] = l
        
        _data_rel_ro = get_segm_by_name(".data.rel.ro")
        start_ea = _data_rel_ro.start_ea
        loopcount = _data_rel_ro.end_ea - start_ea

        for addr in range(0, loopcount - 4, 4):
            Addr = get_dword(start_ea+addr)
            l = get_dword(start_ea+addr+4)
            if l < 1024 and Addr + l < 2**32:
                if Addr >= _rodata.start_ea and Addr <= _rodata.end_ea:
                    if Addr not in strings_to_create:
                        strings_to_create[Addr] = l
        
        for k in strings_to_create.keys():
            #status = create_strlit(k, k + strings_to_create[k])
            #set_name(k, "str_%08X" % k, SN_FORCE)
            #self.sorted_strings.append([k, strings_to_create[k]])
            if strings_to_create[k] > 0:
                self._add_string(k, strings_to_create[k])
        
        #self.sorted_strings.sort(key=lambda x: x[0])
    
    def _binary_search(self, addr):
        left = 0
        right = len(self.sorted_strings) - 1
        
        while left <= right:
            mid = (left + right) // 2
            curr_addr = self.sorted_strings[mid][0]
            curr_len = self.sorted_strings[mid][1]
            
            if curr_addr <= addr < curr_addr + curr_len:
                return mid
                
            if curr_addr < addr:
                left = mid + 1
            else:
                right = mid - 1
                
        return left - 1  # Return insertion point - 1

    def _find_previous_string_idx(self, addr):
        if not self.sorted_strings:
            return None
            
        if addr < self.sorted_strings[0][0]:
            return None
            
        idx = self._binary_search(addr)
        if idx >= 0 and idx < len(self.sorted_strings):
            return idx
            
        return None

    def _find_next_string_idx(self, addr):
        if not self.sorted_strings:
            return None
            
        if addr >= self.sorted_strings[-1][0]:
            return None
            
        idx = self._binary_search(addr)
        next_idx = idx + 1
        
        if next_idx < len(self.sorted_strings):
            return next_idx
            
        return None
    
    def getstr(self, addr, max_len=512):
        data = get_bytes(addr, max_len)
        for i in range(len(data)):
            if data[i] == 0:
                return data[:i]
        return data

    def _add_string(self, addr, size=None):
        previous_idx = self._find_previous_string_idx(addr)
        if previous_idx is None:
            if size is None:
                s = self.getstr(addr, 512)
                size = len(s)
            
            if self.sorted_strings and self.sorted_strings[0][0] < addr + size:
                size = self.sorted_strings[0][0] - addr

            self.sorted_strings.insert(0, [addr, size])
            success = create_strlit(addr, addr + size)
            set_name(addr, "str_%08X" % addr, SN_FORCE)
            return

        previous_string = self.sorted_strings[previous_idx]
        if previous_string[0] == addr:
            if size is None:
                size = 512

            if previous_string[1] > size:
                success = create_strlit(addr, addr + size)
                if success:
                    self.sorted_strings[previous_idx] = [addr, size]
            return

        if previous_string[0] + previous_string[1] >= addr:
            # Patch previous string
            new_len = addr - previous_string[0]
            success = create_strlit(previous_string[0], previous_string[0] + new_len)
            if success:
                self.sorted_strings[previous_idx] = [previous_string[0], new_len]
        
        next_string = None
        if previous_idx + 1 < len(self.sorted_strings):
            next_string = self.sorted_strings[previous_idx + 1]
            if next_string[0] == addr:
                if size is not None and next_string[1] != size:
                    # Patch already existing string
                    success = create_strlit(addr, addr + size)
                    if success:
                        self.sorted_strings[previous_idx + 1] = [addr, size]
                return
        
        if size is None:
            if next_string is not None:
                size = next_string[0] - addr
            else:
                s = self.getstr(addr, 512)
                size = len(s)
        
        if size == 0:
            return

        success = create_strlit(addr, addr + size)
        if success:
            self.sorted_strings.insert(previous_idx + 1, [addr, size])
            set_name(addr, "str_%08X" % addr, SN_FORCE)
        return

    
    #def _beautify_references(self):


    # callback from demangle_name
    # since the default demangler in IDA takes C++ names,
    # here we replace it with rust_demangler
    # returns: [res_from_ev_demangle_name, outbuffer, res_from_demangle_name]
    def ev_demangle_name(self, name, disable_mask, demreq):
        try:
            return [1, rust_demangler.demangle(name), 1] # use rust demangler
        except Exception as e:
            #print(e)
            return [1, name, 1]

    def ev_newfile(self, fname):
        for ea, name in Names():
            name = self._decode_name(name)
            self.functions[name] = ea
            set_name(ea, name, SN_NOCHECK | SN_FORCE) # demangle function names
        
        self.relocations, self.funcs, self.rodata, self.symtab = self._extract_rels_funcs_rodata(fname)
        print(f'[INFO] {len(self.relocations)} relocations found')

        self._recover_known_strings()

        for ea, name in Names():
            print(f'{hex(ea)}: {name}')
        
        return True

    def init_instructions(self):
        # https://github.com/solana-labs/rbpf/blob/179a0f94b68ae0bef892b214750a54448d61b1be/src/ebpf.rs#L205

        self.OPCODES = {
            # MEM
            BPF_LD | BPF_IMM | BPF_DW: ('lddw', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_LDX | BPF_MEM | BPF_W: ('ldxw', self._ana_reg_regdisp, CF_USE1|CF_USE2|CF_CHG1),
            BPF_LDX | BPF_MEM | BPF_H: ('ldxh', self._ana_reg_regdisp, CF_USE1|CF_USE2|CF_CHG1),
            BPF_LDX | BPF_MEM | BPF_B: ('ldxb', self._ana_reg_regdisp, CF_USE1|CF_USE2|CF_CHG1),
            BPF_LDX | BPF_MEM | BPF_DW: ('ldxdw', self._ana_reg_regdisp, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ST | BPF_MEM | BPF_W: ('stw', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ST | BPF_MEM | BPF_H: ('sth', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ST | BPF_MEM | BPF_B: ('stb', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ST | BPF_MEM | BPF_DW: ('stdw', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_STX | BPF_MEM | BPF_W: ('stxw', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),    
            BPF_STX | BPF_MEM | BPF_H: ('stxh', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_STX | BPF_MEM | BPF_B: ('stxb', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_STX | BPF_MEM | BPF_DW: ('stxdw', self._ana_regdisp_reg, CF_USE1|CF_USE2|CF_CHG1),

            # ALU 32
            BPF_ALU | BPF_K | BPF_ADD: ('add32', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_ADD: ('add32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_SUB: ('sub32', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_SUB: ('sub32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_MUL: ('mul32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_MUL: ('mul32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_DIV: ('div32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_DIV: ('div32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_OR: ('or32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_OR: ('or32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_AND: ('and32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_AND: ('and32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_LSH: ('lsh32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_LSH: ('lsh32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_RSH: ('rsh32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_RSH: ('rsh32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_NEG: ('neg32', self._ana_1reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_MOD: ('mod32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_MOD: ('mod32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_XOR: ('xor32', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_XOR: ('xor32', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_MOV: ('mov32', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_MOV: ('mov32', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU | BPF_K | BPF_ARSH: ('arsh32', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU | BPF_X | BPF_ARSH: ('arsh32', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),

            BPF_PQR | BPF_K | BPF_LMUL: ('lmul32', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_X | BPF_LMUL: ('lmul32', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            # BPF_PQR | BPF_K | BPF_UHMUL: ('uhmul32', self._ana_reg_imm, CF_USE1 | CF_USE2),
            # BPF_PQR | BPF_X | BPF_UHMUL: ('uhmul32', self._ana_2regs, CF_USE1 | CF_USE2),
            BPF_PQR | BPF_K | BPF_UDIV: ('udiv32', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_X | BPF_UDIV: ('udiv32', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_K | BPF_UREM: ('urem32', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_X | BPF_UREM: ('urem32', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            # BPF_PQR | BPF_K | BPF_SHMUL: ('shmul32', self._ana_reg_imm, CF_USE1 | CF_USE2),
            # BPF_PQR | BPF_X | BPF_SHMUL: ('shmul32', self._ana_2regs, CF_USE1 | CF_USE2),
            BPF_PQR | BPF_K | BPF_SDIV: ('sdiv32', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_X | BPF_SDIV: ('sdiv32', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_K | BPF_SREM: ('srem32', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_X | BPF_SREM: ('srem32', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),


            BPF_ALU | BPF_K | BPF_END: ('le', self._ana_reg_imm, CF_USE1|CF_CHG1),
            BPF_ALU | BPF_X | BPF_END: ('be', self._ana_reg_imm, CF_USE1|CF_CHG1),

            # ALU 64
            BPF_ALU64 | BPF_K | BPF_ADD: ('add64', self._ana_reg_imm, CF_USE1 | CF_USE2 | CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_ADD: ('add64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_SUB: ('sub64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_SUB: ('sub64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_MUL: ('mul64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_MUL: ('mul64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_DIV: ('div64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_DIV: ('div64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_OR: ('or64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_OR: ('or64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_AND: ('and64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_AND: ('and64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_LSH: ('lsh64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_LSH: ('lsh64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_RSH: ('rsh64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_RSH: ('rsh64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_NEG: ('neg64', self._ana_1reg, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_MOD: ('mod64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_MOD: ('mod64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_XOR: ('xor64', self._ana_reg_imm, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_XOR: ('xor64', self._ana_2regs, CF_USE1|CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_MOV: ('mov64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_MOV: ('mov64', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_ARSH: ('arsh64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_X | BPF_ARSH: ('arsh64', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_ALU64 | BPF_K | BPF_HOR: ('hor64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1), # new, SOLANA SPEC?

            BPF_PQR | BPF_B | BPF_K | BPF_LMUL: ('lmul64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_X | BPF_LMUL: ('lmul64', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_K | BPF_UHMUL: ('uhmul64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_X | BPF_UHMUL: ('uhmul64', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_K | BPF_UDIV: ('udiv64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_X | BPF_UDIV: ('udiv64', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_K | BPF_UREM: ('urem64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_X | BPF_UREM: ('urem64', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_K | BPF_SHMUL: ('shmul64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_X | BPF_SHMUL: ('shmul64', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_K | BPF_SDIV: ('sdiv64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_X | BPF_SDIV: ('sdiv64', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_K | BPF_SREM: ('srem64', self._ana_reg_imm, CF_USE1 | CF_USE2|CF_CHG1),
            BPF_PQR | BPF_B | BPF_X | BPF_SREM: ('srem64', self._ana_2regs, CF_USE1 | CF_USE2|CF_CHG1),


            # BRANCHES
            BPF_JMP | BPF_JA: ('ja', self._ana_jmp, CF_USE1|CF_JUMP),
            BPF_JMP | BPF_K | BPF_JEQ: ('jeq', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JEQ: ('jeq', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_K | BPF_JGT: ('jgt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JGT: ('jgt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_K | BPF_JGE: ('jge', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JGE: ('jge', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_K | BPF_JLT: ('jlt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JLT: ('jlt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_K | BPF_JLE: ('jle', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP), # new
            BPF_JMP | BPF_X | BPF_JLE: ('jle', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP), # new
            BPF_JMP | BPF_K | BPF_JSET: ('jset', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JSET: ('jset', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_K | BPF_JNE: ('jne', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JNE: ('jne', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),

            BPF_JMP | BPF_K | BPF_JSGT: ('jsgt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JSGT: ('jsgt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_K | BPF_JSGE: ('jsge', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JSGE: ('jsge', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),            
            BPF_JMP | BPF_K | BPF_JSLT: ('jslt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            BPF_JMP | BPF_X | BPF_JSLT: ('jslt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP), # new
            BPF_JMP | BPF_K | BPF_JSLE: ('jsle', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP), # new
            BPF_JMP | BPF_X | BPF_JSLE: ('jsle', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP), # new

            BPF_JMP | BPF_CALL: ('call', self._ana_call, CF_USE1|CF_CALL), # call imm
            BPF_JMP | BPF_X | BPF_CALL: ('callx', self._ana_callx, CF_USE1|CF_CALL), # tail call
            BPF_JMP | BPF_EXIT: ('exit', self._ana_nop, CF_STOP) # return r0
        }
        
        Instructions = [{'name':x[0], 'feature':x[2]} for x in self.OPCODES.values()]
        self.inames = {v[0]:k for k,v in self.OPCODES.items()}
        self.instruc_end = 0xff
        self.instruc = [({'name':self.OPCODES[i][0], 'feature':self.OPCODES[i][2]} if i in self.OPCODES else {'name':'unknown_opcode', 'feature':0}) for i in range(0xff)]
        
    def init_registers(self):
        self.reg_names = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'CS', 'DS']

        self.reg_cs = 0
        self.reg_ds = 1

        self.reg_first_sreg = self.reg_cs
        self.reg_last_sreg = self.reg_ds

        self.reg_code_sreg = self.reg_cs
        self.reg_data_sreg = self.reg_ds

    def ev_ana_insn(self, insn):
        try:
            return self._ana(insn)
        except DecodingError:
            return 0

    def _ana(self, insn):
        self.opcode = insn.get_next_byte()
        registers = insn.get_next_byte()

        self.src = (registers >> 4) & 15
        self.dst = registers & 15
        
        self.off = insn.get_next_word()
            
        self.imm = insn.get_next_dword()
        
        if self.opcode == BPF_LD | BPF_IMM | BPF_DW:
            insn.get_next_dword()
            imm2 = insn.get_next_dword()
            self.imm += imm2 << 32

        insn.itype = self.opcode

        if self.opcode not in self.OPCODES:
            raise DecodingError("wuut")

        self.OPCODES[self.opcode][1](insn)
        
        return insn.size

    def _ana_nop(self, insn):
        pass
    
    def _ana_reg_imm(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.dst

        insn[1].type = o_imm
        # special quad-word load
        if self.opcode == BPF_LD | BPF_IMM | BPF_DW:
            insn[1].dtype = dt_qword
        else:
            insn[1].dtype = dt_dword
            
        insn[1].value = self.imm

        insn[0].addr = insn.ea
        insn[1].addr = insn.ea
        
    def _ana_1reg(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.dst

    def _ana_2regs(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.dst
        
        insn[1].type = o_reg
        insn[1].dtype = dt_dword
        insn[1].reg = self.src

    def _ana_call(self, insn):
        insn[0].type = o_near
        insn[0].value = self.imm
        insn[0].dtype = dt_dword

        if insn.ea in self.relocations:
            insn[0].addr = BADADDR
            return

        offset = ctypes.c_int32(self.imm).value
        if self.src == 0:
            # call imm
            insn[0].addr = 8 * offset
        elif self.src == 1:
            # tail call
            insn[0].addr = 8 * offset + insn.ea + 8
        else:
            print("UNKNOWN CALL TYPE")

    def _ana_callx(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.imm

    def _ana_jmp(self, insn):
        insn[0].type = o_near
        offset = ctypes.c_int16(self.off).value
        if offset < 0:
            pass
        insn[0].addr = 8*offset + insn.ea + 8
        insn[0].dtype = dt_word

    def _ana_cond_jmp_reg_imm(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.dst

        insn[1].type = o_imm
        insn[1].value = self.imm
        insn[1].dtype = dt_dword
        
        offset = ctypes.c_int16(self.off).value
        if offset < 0:
            pass
        insn[2].type = o_near
        insn[2].addr = 8 * offset + insn.ea + 8
        insn[2].dtype = dt_dword

    def _ana_cond_jmp_reg_reg(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.dst

        insn[1].type = o_reg
        insn[1].dtype = dt_dword
        insn[1].reg = self.src

        offset = ctypes.c_int16(self.off).value
        if offset < 0:
            pass
        insn[2].type = o_near
        insn[2].addr = 8 * offset + insn.ea + 8
        insn[2].dtype = dt_dword

    def _ana_regdisp_reg(self, insn):
        insn[0].type = o_displ
        insn[0].dtype = dt_word
        insn[0].value = self.off
        insn[0].phrase = self.dst

        insn[1].type = o_reg
        insn[1].dtype = dt_dword
        insn[1].reg = self.src

    def _ana_regdisp_reg_atomic(self, insn):
        insn[0].type = o_displ
        insn[0].dtype = dt_word
        insn[0].value = self.off
        insn[0].phrase = self.dst

        insn[1].type = o_reg
        insn[1].dtype = dt_dword
        insn[1].reg = self.src

        insn[2].type = o_imm
        insn[2].dtype = dt_dword
        insn[2].value = self.imm

    def _ana_reg_regdisp(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = self.dst

        insn[1].type = o_displ
        insn[1].dtype = dt_word
        insn[1].value = self.off
        insn[1].phrase = self.src

        if self.opcode in [0x40, 0x48, 0x50, 0x58]:
            insn[0].reg = 0 # hardcoded r0 destination
            insn[1].value = self.imm # use imm not offset for displacement
            insn[1].dtype = dt_dword # imm are 32-bit, off are 16-bit.


    def _ana_phrase_imm(self, insn):
        insn[0].type = o_reg
        insn[0].dtype = dt_dword
        insn[0].reg = 0 # hardcode destination to r0
        
        insn[1].type = o_phrase
        insn[1].dtype = dt_dword
        insn[1].value = self.imm
    
    def _apply_rel_mods(self, mods, patch_size):
        for mod in mods:
            if mod['val'] != 0:
                if patch_size == 32:
                    patch_dword(mod['loc'], mod['val'])
                elif patch_size == 64:
                    patch_qword(mod['loc'], mod['val'])
                else:
                    print('[ERROR] apply relocation: none type')
                #print(f'[INFO] patched by offset {hex(mod["loc"])} -> {hex(mod["val"])}')
    
    def _apply_relocation(self, insn, relocation):
        #return #1F0A8
        if relocation['type'] == 8: # lddw usually
            print('R_BPF_RELATIVE', hex(insn.ea), relocation)
            source_addr = insn[0].addr
            target_addr = insn[1].value
            print(f'target_addr: {hex(target_addr)}')
            print(f'sclass: {getseg(target_addr).sclass}')
            seg = getseg(target_addr)
            if seg.sclass == 3: # CONST .data.rel.ro
                pass
            elif seg.sclass == 4: # CONST .text
                if not get_func(target_addr):
                    add_func(target_addr)
                insn.add_cref(target_addr, insn[1].offb, fl_CF)
            elif seg.sclass == 6: # CONST .rodata
                self._add_string(target_addr)
                insn.add_dref(target_addr, insn[1].offb, dr_R)
            else:
                print(f'unhandled sclass: {seg.sclass}')
        

        patch_size = REL_PATCH_SIZE[relocation['type']]
        self._apply_rel_mods(relocation['mods'], patch_size)
        
        if REL_TYPE[relocation['type']] == 'R_BPF_64_32': # call
            if relocation['mods'][0]['val'] != 0: # internal function call
                insn.add_cref(relocation['mods'][0]['val'], insn[0].offb, fl_CN)
            else:
                insn.add_dref(self.functions[relocation['name']], insn[0].offb, fl_CN)
        
        if REL_TYPE[relocation['type']] == 'R_BPF_64_64': # lddw
            if relocation['name'] in self.rodata:
                data_addr = self.rodata[relocation['name']]
                mods = self._parse_relocation(relocation['type'], insn.ea, data_addr)
                self._apply_rel_mods(mods, patch_size)
                insn.add_dref(data_addr, insn[1].offb, dr_R)
                print('R_BPF_64_64', hex(insn.ea), data_addr, relocation['name'])


    def ev_emu_insn(self, insn):
        Feature = insn.get_canon_feature()

        if Feature & CF_JUMP:
            dst_op_index = 0 if insn.itype == 0x5 else 2
            insn.add_cref(insn[dst_op_index].addr, insn[dst_op_index].offb, fl_JN)
            remember_problem(cvar.PR_JUMP, insn.ea) # PR_JUMP ignored?

        if insn[0].type == o_displ or insn[1].type == o_displ:
            op_ind = 0 if insn[0].type == o_displ else 1
            # TODO: trace sp when it changes and call add_auto_stkpnt
            if may_create_stkvars():
                val = ctypes.c_int16(insn[op_ind].value).value # create_stkvar takes signed value
                if insn.create_stkvar(insn[op_ind], val, STKVAR_VALID_SIZE):
                    op_stkvar(insn.ea, op_ind)
        
        if insn[1].type == o_imm and insn[1].dtype == dt_qword:
            if insn.ea in self.relocations:
                self._apply_relocation(insn, self.relocations[insn.ea])
        
        abort = False
        if Feature & CF_CALL:
            if insn.ea in self.relocations:
                self._apply_relocation(insn, self.relocations[insn.ea])
                if self.relocations[insn.ea]['name'] == 'abort':
                    abort = True
            else:
                insn.add_cref(insn[0].addr, insn[0].offb, fl_CF)

        # continue execution flow if not stop instruction (exit), not abort, and not unconditional jump
        flow = (Feature & CF_STOP == 0) and not abort and not insn.itype == 0x5
        
        if flow:
            insn.add_cref(insn.ea + insn.size, 0, fl_F)
        
        for op in insn:
            if op.type == o_imm and op.dtype == dt_qword:
                addr = op.value
                seg = getseg(addr)
                if seg:
                    if seg.sclass == 6: # CONST .rodata
                        try:
                            s = get_strlit_contents(addr, -1, STRTYPE_TERMCHR).decode()
                            add_dref(op.addr, addr, dr_R)
                        except Exception as e:
                            pass

        return True

    def ev_out_insn(self, ctx):
        cmd = ctx.insn
        ft = cmd.get_canon_feature()
        buf = ctx.outbuf

        # handle byteswap instruction suffix encoded in immediate, don't print immediate
        if cmd.itype == 0xd4 or cmd.itype == 0xdc:
            # directly use immediate as suffix in decimal
            # analysis function sets second operand as immediate
            if cmd.ops[1].type == o_imm:
                ctx.out_mnem(15, f"{cmd.ops[1].value}")
            else:
                print("[ev_out_insn] analysis error: invalid 2nd operand type for byteswap instruction")
        # special handling for atomic instruction, mnemonic is determined by immediate, not opcode
        elif cmd.itype == 0xdb or cmd.itype == 0xc3:
            atomic_alu_ops = [BPF_ADD, BPF_AND, BPF_OR, BPF_XOR]
            atomic_alu_fetch_ops = [op | BPF_FETCH for op in atomic_alu_ops]
            if cmd.ops[2].type == o_imm:
                # TODO: add size/width to disassembly?
                if cmd.ops[2].value in atomic_alu_ops:
                    # first case; 'lock' instruction we first came across
                    ctx.out_mnem(15, f" {bpf_alu_string[cmd.ops[2].value]}")
                elif cmd.ops[2].value in atomic_alu_fetch_ops:
                    print("[ev_out_insn] untested case for atomic instruction: ALU fetch op")
                    ctx.out_mnem(15, f" fetch {bpf_alu_string[cmd.ops[2].value]}")
                elif cmd.ops[2].value == BPF_CMPXCHG:
                    print("[ev_out_insn] untested case for atomic instruction: CMPXCHG")
                    ctx.out_mnem(15, " cmpxchg")
                elif cmd.ops[2].value == BPF_XCHG:
                    print("[ev_out_insn] untested case for atomic instruction: XCHG")
                    ctx.out_mnem(15, " xchg")
                else:
                    print("[ev_out_insn] invalid operation type in immediate for atomic instruction")
            else:
                print("[ev_out_insn] analysis error: 3rd parameter for atomic instruction must be o_imm. debug me!")
        elif ft & CF_CALL and cmd.ea in self.relocations and self.relocations[cmd.ea]['name'].startswith('sol_'):
            ctx.out_custom_mnem("syscall", 15)
        else:
            ctx.out_mnem(15)
        
        if ft & CF_USE1:
            if ft & CF_CALL:
                pass
            ctx.out_one_operand(0)
        if ft & CF_USE2:
            ctx.out_char(',')
            ctx.out_char(' ')
            ctx.out_one_operand(1)
        if ft & CF_USE3:
            ctx.out_char(',')
            ctx.out_char(' ')
            ctx.out_one_operand(2)
        cvar.gl_comm = 1
        ctx.flush_outbuf()

    def ev_out_operand(self, ctx, op):
        if op.type == o_reg:
            ctx.out_register(self.reg_names[op.reg])

        elif op.type == o_imm:
            if op.dtype == dt_qword:
                addr = op.value
                seg = getseg(addr)
                isString = False
                if seg and seg.sclass == 6: # CONST .rodata
                    try:
                        s = get_strlit_contents(addr, -1, -1).decode() # check if that's a string
                        isString = True
                    except Exception as e:
                        pass

                name = get_name(addr)
                if name:
                    ctx.out_name_expr(op, addr, BADADDR)
                else:
                    ctx.out_value(op, OOF_SIGNED|OOFW_IMM|OOFW_64)
            elif op.dtype == dt_dword:
                ctx.out_value(op, OOF_SIGNED|OOFW_IMM|OOFW_32)
            else:
                print(f"[ev_out_operand] immediate operand, unhandled dtype: {op.dtype:#8x}")
                ctx.out_value(op, OOF_SIGNED|OOFW_IMM|OOFW_32)

        elif op.type in [o_near, o_mem]:
            if op.type == o_near and ctx.insn_ea in self.relocations:
                ok = ctx.out_name_expr(op, self.functions[self.relocations[ctx.insn_ea]['name']], BADADDR)
                if not ok:
                    ctx.out_tagon(COLOR_ERROR)
                    ctx.out_long(self.functions[self.relocations[ctx.insn_ea]['name']], 16)
                    ctx.out_tagoff(COLOR_ERROR)
            else:
                ok = ctx.out_name_expr(op, op.addr, BADADDR)
                if not ok:
                    ctx.out_tagon(COLOR_ERROR)
                    ctx.out_long(op.addr, 16)
                    ctx.out_tagoff(COLOR_ERROR)
                
        elif op.type == o_phrase:
            ctx.out_printf('skb') # text color is a bit off. fix later.
            ctx.out_symbol('[')
            ctx.out_value(op, OOF_SIGNED|OOFW_IMM|OOFW_32) # "OpDecimal" fails on this, figure out why & fix it.
            ctx.out_symbol(']')
            
        elif op.type == o_displ:
            if op.dtype == dt_dword:
                ctx.out_printf('skb')
            ctx.out_symbol('[')
            ctx.out_register(self.reg_names[op.phrase])
            if op.value:
                if op.dtype == dt_word:
                    ctx.out_value(op, OOFS_NEEDSIGN|OOF_SIGNED|OOFW_IMM|OOFW_16)
                elif op.dtype == dt_dword:
                    ctx.out_value(op, OOFS_NEEDSIGN|OOF_SIGNED|OOFW_IMM|OOFW_32)
                else:
                    print("[ev_out_operand] unexpected displacement dtype: {op.dtype:#8x}")
                    ctx.out_value(op, OOFS_NEEDSIGN|OOF_SIGNED|OOFW_IMM)
            ctx.out_symbol(']')
        else:
            return False
        return True
    
    def ev_endbinary(self, *args):
        print(f'[INFO] ev_endbinary: {args}')

def PROCESSOR_ENTRY():
    return EBPFProc()
