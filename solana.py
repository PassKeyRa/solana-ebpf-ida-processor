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

class EBPFProc(processor_t):
    id = 247
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

    def __init__(self):
        processor_t.__init__(self)
        
        self.init_instructions()
        self.init_registers()

        self.relocations = {}
        self.functions = {}
    
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
            # ???
            pass
        
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
                    symtab.append({'name': sym.name, 'val': sym.entry['st_value']})
            
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

            return relocations, functions, rodata
    
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
        
        self.relocations, self.funcs, self.rodata = self._extract_rels_funcs_rodata(fname)

        #print('\n')
        #for r in self.relocations:
        #    print('[INFO]', f'{hex(r)}:', self.relocations[r])
        #print('\n')
        
        return True

    def init_instructions(self):
        # there is a logic behind the opcode values but I chose to ignore it
        self.OPCODES = {
            # ALU
            0x07:('add', self._ana_reg_imm, CF_USE1 | CF_USE2),
            0x0f:('add', self._ana_2regs, CF_USE1|CF_USE2),
            0x17:('sub', self._ana_reg_imm, CF_USE1 | CF_USE2),
            0x1f:('sub', self._ana_2regs, CF_USE1|CF_USE2),
            0x27:('mul', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x2f:('mul', self._ana_2regs, CF_USE1|CF_USE2),
            0x37:('div', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x3f:('div', self._ana_2regs, CF_USE1|CF_USE2),
            0x47:('or', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x4f:('or', self._ana_2regs, CF_USE1|CF_USE2),
            0x57:('and', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x5f:('and', self._ana_2regs, CF_USE1|CF_USE2),
            0x67:('lsh', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x6f:('lsh', self._ana_2regs, CF_USE1|CF_USE2),
            0x77:('rsh', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x7f:('rsh', self._ana_2regs, CF_USE1|CF_USE2),
            0x87:('neg', self._ana_1reg, CF_USE1|CF_USE2),
            0x97:('mod', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x9f:('mod', self._ana_2regs, CF_USE1|CF_USE2),
            0xa7:('xor', self._ana_reg_imm, CF_USE1|CF_USE2),
            0xaf:('xor', self._ana_2regs, CF_USE1|CF_USE2),
            0xb7:('mov', self._ana_reg_imm, CF_USE1 | CF_USE2),
            0xbf:('mov', self._ana_2regs, CF_USE1 | CF_USE2),
            0xc7:('arsh', self._ana_reg_imm, CF_USE1 | CF_USE2),
            0xcf:('arsh', self._ana_2regs, CF_USE1 | CF_USE2),

            # TODO: ALU 32 bit opcodes

            # Byteswap Instructions
            # 1 register operand (destination), 1 immediate.
            # imm == 16 | 32 | 64, indicating width
            # TODO: output the proper mnemonic w/ optional suffix based on the immediate operand.
            #     what should happen is that the immediate operand is used as the decimal
            #     width modifier to produce 'be16', 'be32', etc.
            0xd4:('le', self._ana_reg_imm, CF_USE1),
            0xdc:('be', self._ana_reg_imm, CF_USE1),

            # MEM
            # special-case quad-word load
            0x18:('lddw', self._ana_reg_imm, CF_USE1|CF_USE2),

            0x61:('ldxw', self._ana_reg_regdisp, CF_USE1|CF_USE2),
            0x69:('ldxh', self._ana_reg_regdisp, CF_USE1|CF_USE2),
            0x71:('ldxb', self._ana_reg_regdisp, CF_USE1|CF_USE2),
            0x79:('ldxdw', self._ana_reg_regdisp, CF_USE1|CF_USE2),
            0x62:('stw', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x6a:('sth', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x72:('stb', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x7a:('stdw', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x63:('stxw', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x6b:('stxh', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x73:('stxb', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x7b:('stxdw', self._ana_regdisp_reg, CF_USE1|CF_USE2),

            # LOCK instructions
            0xc3:('lock', self._ana_regdisp_reg_atomic, CF_USE1|CF_USE2),
            0xdb:('lock', self._ana_regdisp_reg_atomic, CF_USE1|CF_USE2),

            # BRANCHES
            0x05:('ja', self._ana_jmp, CF_USE1|CF_JUMP),
            0x15:('jeq', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x1d:('jeq', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x25:('jgt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x2d:('jgt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x35:('jge', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x3d:('jge', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x45:('jset', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x4d:('jset', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x55:('jne', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x5d:('jne', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x65:('jsgt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x6d:('jsgt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x75:('jsge', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x7d:('jsge', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),

            0xa5:('jlt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0xad:('jlt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            # TODO: do we have to add any extra info here to handle differences with signed/unsigned conditional jumps?
            0xc5:('jslt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),

            0x85:('call', self._ana_call, CF_USE1|CF_CALL),            
            0x8d:('callx', self._ana_callx, CF_USE1|CF_CALL),

            0x95:('ret', self._ana_nop, CF_STOP)
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
        
        if self.opcode == 0x18:
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
        if self.opcode == 0x18:
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
        if relocation['type'] == 8:
            print('R_BPF_RELATIVE', hex(insn.ea), relocation['name'])
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

        # TODO: see what stack emulation we need to do when operating on/with r10
        if insn[0].type == o_displ or insn[1].type == o_displ:
            op_ind = 0 if insn[0].type == o_displ else 1
            if may_create_stkvars():
                # annoying problem: we can properly display 16-bit offsets in the out stage,
                # but this step gets them highlighted in red as if they were invalid
                # Disable until we can do this correctly
                #insn.create_stkvar(insn[op_ind], insn[op_ind].value, STKVAR_VALID_SIZE)
                #op_stkvar(insn.ea, op_ind)
                pass
        
        if insn[1].type == o_imm and insn[1].dtype == dt_qword:
            if insn.ea in self.relocations:
                self._apply_relocation(insn, self.relocations[insn.ea])
            
        # TODO: use FLIRT/whatever to make nice annotations for helper calls, like we get for typical PEs
        if Feature & CF_CALL:
            if insn.ea in self.relocations:
                self._apply_relocation(insn, self.relocations[insn.ea])
            else:
                insn.add_cref(insn[0].addr, insn[0].offb, fl_CN)

        # continue execution flow if not stop instruction (call), and not unconditional jump
        flow = (Feature & CF_STOP == 0) and not insn.itype == 0x5
        
        if flow:
            insn.add_cref(insn.ea + insn.size, 0, fl_F)

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
                if seg:
                    if seg.sclass == 6: # CONST .rodata
                        try:
                            s = get_strlit_contents(addr, -1, -1).decode()
                            if len(s) > STRINGS_PREVIEW_LIMIT:
                                s = s[:STRINGS_PREVIEW_LIMIT] + "..."
                            s = "\"" + s + "\""
                            ida_bytes.set_cmt(op.addr, s, True)
                            sName = s[1:-1]
                            if len(s) > 15:
                                sName = s[:15]
                            sName_ = ''
                            for i in sName:
                                if i in string.ascii_letters:
                                    sName_ += i
                            set_name(addr, sName_, SN_FORCE)
                            add_dref(ctx.insn_ea, addr, dr_R)
                            isString = True
                        except Exception as e:
                            print(e)
                            pass

                if isString:
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

def PROCESSOR_ENTRY():
    return EBPFProc()
