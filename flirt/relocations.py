#!/usr/bin/env python3

# Sources: 
# https://docs.kernel.org/bpf/llvm_reloc.html
# https://github.com/solana-labs/llvm-project/blob/038d472bcd0b82ff768b515cc77dfb1e3a396ca8/lld/ELF/Arch/BPF.cpp

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

import cxxfilt

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
    10: 32
}

def parse_relocation(rel_type, loc, val):
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

def decode_func_name(name):
    name_ = name
    name = name.replace('.rel.text.','')
    name = cxxfilt.demangle(name)
    
    # drop hash away
    name = '::'.join(name.split('::')[:-1])
    if name == '':
        return name_
    return name



def extract_rels_funcs(filename):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        sections = []
        for section in elffile.iter_sections():
            sections.append(section)
        
        relocations = {}
        functions = {}

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

                    name = decode_func_name(relsym['name'])

                    reloc_parsed = parse_relocation(reloc['r_info_type'], reloc['r_offset'], relsym['val'])
                    mods = []

                    for r in reloc_parsed:
                        mods.append({'offset': r['loc'], 'value': r['val']})
                    
                    relocation = {
                        'type': reloc['r_info_type'],
                        'name': name,
                        'mods': mods
                    }

                    relocations[reloc['r_offset']] = relocation
                    
                continue

            if s.header['sh_type'] == 'SHT_REL':
                if not symtab_s:
                    print("symtab section not found. what?")
                    continue

                code_s = sections[s.header['sh_info']]
                base_offset = code_s.header['sh_offset']

                func_name = ''

                if s.name.startswith('.rel.text.'):
                    func_name = decode_func_name(s.name)
                    functions[func_name] = base_offset

                for reloc in s.iter_relocations():
                    relsym = symtab[reloc['r_info_sym']]

                    name = decode_func_name(relsym['name'])

                    reloc_parsed = parse_relocation(reloc['r_info_type'], reloc['r_offset'], relsym['val'])
                    mods = []

                    for r in reloc_parsed:
                        mods.append({'offset': base_offset + r['loc'], 'value': r['val']})
                    
                    relocation = {
                        'type': reloc['r_info_type'],
                        'name': name,
                        'mods': mods
                    }

                    relocations[base_offset + reloc['r_offset']] = relocation

        return relocations, functions

if __name__ == '__main__':
    relocations, functions = extract_rels_funcs('flirt/libs/blake3.so')
    
    for r in relocations:
        print(f'{hex(r)}:', relocations[r])
    
    print('\n')
    
    for f in functions:
        print(f'{f}:', hex(functions[f]))