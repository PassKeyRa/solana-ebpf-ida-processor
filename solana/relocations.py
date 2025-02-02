import idaapi

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from solana.constants import REL_TYPE
from solana.helpers import decode_name

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
        pass
    else:
        print(f'[WARN] unknown relocation type: {type_}')
    
    return changes

def process_relocations(filename):
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

                    name = decode_name(relsym['name'])

                    reloc_parsed = parse_relocation(reloc['r_info_type'], reloc['r_offset'], relsym['val'])
                    mods = []

                    for r in reloc_parsed:
                        mods.append({'loc': idaapi.get_fileregion_ea(r['loc']), 'val': r['val']})
                    
                    relocation = {
                        'type': reloc['r_info_type'],
                        'name': name,
                        'mods': mods
                    }

                    relocations[idaapi.get_fileregion_ea(reloc['r_offset'])] = relocation
                    
                continue

            if s.header['sh_type'] == 'SHT_REL':
                if not symtab_s:
                    print("symtab section not found. what?")
                    continue

                code_s = sections[s.header['sh_info']]
                base_offset = code_s.header['sh_offset']

                section_name = decode_name(s.name)
                ea_addr = idaapi.get_fileregion_ea(base_offset)
                if s.name.startswith('.rel.text.'):
                    functions[section_name] = ea_addr
                elif s.name.startswith('.rel.data.rel.ro.'):
                    rodata[section_name] = ea_addr

                for reloc in s.iter_relocations():
                    relsym = symtab[reloc['r_info_sym']]

                    name = decode_name(relsym['name'])

                    reloc_parsed = parse_relocation(reloc['r_info_type'], reloc['r_offset'], relsym['val'])
                    mods = []

                    for r in reloc_parsed:
                        mods.append({'loc': idaapi.get_fileregion_ea(base_offset + r['loc']), 'val': r['val']})
                    
                    relocation = {
                        'type': reloc['r_info_type'],
                        'name': name,
                        'mods': mods
                    }

                    relocations[idaapi.get_fileregion_ea(base_offset + reloc['r_offset'])] = relocation

        return relocations, functions, rodata, symtab
