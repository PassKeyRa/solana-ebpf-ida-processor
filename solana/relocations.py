import idaapi

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from solana.constants import REL_TYPE, REL_PATCH_SIZE
from solana.config import STRINGS_PREVIEW_LIMIT
from solana.strings import add_string
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

def apply_rel_mods(mods, patch_size):
    for mod in mods:
        if mod['val'] != 0:
            if patch_size == 32:
                idaapi.patch_dword(mod['loc'], mod['val'])
            elif patch_size == 64:
                idaapi.patch_qword(mod['loc'], mod['val'])
            else:
                print('[ERROR] apply relocation: none type')

def apply_relocation(functions, rodata, sorted_strings, insn, relocation):
    if relocation['type'] == 8: # lddw usually
        source_addr = insn[0].addr
        target_addr = insn[1].value
        seg = idaapi.getseg(target_addr)
        if seg.sclass == 3: # CONST .data.rel.ro
            # Resolve reference
            try:
                ref_addr = idaapi.get_dword(target_addr + 4)
                ref_len = idaapi.get_dword(target_addr + 8)
                seg_ = idaapi.getseg(ref_addr)
                if seg_.sclass == 6: # CONST .rodata
                    sorted_strings, len_ = add_string(sorted_strings, ref_addr, ref_len)
                    name = idaapi.get_name(ref_addr)
                    if name:
                        idaapi.create_dword(target_addr, 4)
                        idaapi.create_dword(target_addr + 4, 4)
                        idaapi.create_dword(target_addr + 8, 4)

                        idaapi.op_offset(target_addr + 4, 0, idaapi.REF_OFF32)

                        idaapi.set_name(target_addr, f"{name}_ref", idaapi.SN_FORCE)
                        idaapi.set_name(target_addr + 4, f"{name}_ref_addr", idaapi.SN_FORCE)
                        idaapi.set_name(target_addr + 8, f"{name}_ref_len", idaapi.SN_FORCE)

                        idaapi.add_dref(insn.ea, target_addr, idaapi.dr_O)

                        s = idaapi.get_strlit_contents(ref_addr, len_, idaapi.STRTYPE_TERMCHR).decode("utf-8", errors="ignore")
                        s_preview = 'Ref to "' + s[:STRINGS_PREVIEW_LIMIT] + '"'
                        if len(s) > STRINGS_PREVIEW_LIMIT:
                            s_preview += "..."

                        idaapi.set_cmt(source_addr, "", 0)
                        idaapi.set_cmt(source_addr, s_preview, 0)
                        
                        
            except Exception as e:
                print(f'error during reference resolution: {e}')
        elif seg.sclass == 4: # CONST .text
            if not idaapi.get_func(target_addr):
                idaapi.add_func(target_addr)
            insn.add_cref(target_addr, insn[1].offb, idaapi.fl_CF)
        elif seg.sclass == 6: # CONST .rodata
            sorted_strings, len_ = add_string(sorted_strings, target_addr)
            insn.add_dref(target_addr, insn[1].offb, idaapi.dr_R)
        else:
            print(f'unhandled sclass: {seg.sclass}')

    patch_size = REL_PATCH_SIZE[relocation['type']]
    apply_rel_mods(relocation['mods'], patch_size)
    
    if REL_TYPE[relocation['type']] == 'R_BPF_64_32': # call
        if relocation['mods'][0]['val'] != 0: # internal function call
            insn.add_cref(relocation['mods'][0]['val'], insn[0].offb, idaapi.fl_CF)
            mods = parse_relocation(relocation['type'], insn.ea, relocation['mods'][0]['val'])
            apply_rel_mods(mods, patch_size)
        else:
            insn.add_cref(functions[relocation['name']], insn[0].offb, idaapi.fl_CF)
    
    if REL_TYPE[relocation['type']] == 'R_BPF_64_64': # lddw
        if relocation['name'] in rodata:
            data_addr = rodata[relocation['name']]
            mods = parse_relocation(relocation['type'], insn.ea, data_addr)
            apply_rel_mods(mods, patch_size)
            insn.add_dref(data_addr, insn[1].offb, idaapi.dr_R)
    
    return sorted_strings