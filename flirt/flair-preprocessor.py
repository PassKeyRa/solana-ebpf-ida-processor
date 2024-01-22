#!/usr/bin/env python3

# This is the Solana eBPF preprocessor for FLAIR tools that
# are used to generate FLIRT signatures. The result of 
# the tool is a .pat file for a corresponding library, 
# which can be passed to the sigmake tool to generate 
# the final .sig file

from elftools.elf.elffile import ELFFile

import argparse
import cxxfilt

REL_PATCH_SIZE = {
    0: None,
    1: 32,
    2: 64,
    3: 32,
    4: 32,
    10: 32
}

REL_TYPE = {
    0: 'R_BPF_NONE',
    1: 'R_BPF_64_64',
    2: 'R_BPF_64_ABS64',
    3: 'R_BPF_64_ABS32',
    4: 'R_BPF_64_NODYLD32',
    8: 'R_BPF_64_RELATIVE', # SOLANA SPEC (https://github.com/solana-labs/llvm-project/blob/038d472bcd0b82ff768b515cc77dfb1e3a396ca8/llvm/include/llvm/BinaryFormat/ELFRelocs/BPF.def#L11)
    10: 'R_BPF_64_32'
}

def map_rels_to_funcs(elffile):
    sections = []
    for section in elffile.iter_sections():
        sections.append(section)

    relocations = {}

    symtab_s = elffile.get_section_by_name('.symtab')
    symtab = []

    if symtab_s:
        for sym in symtab_s.iter_symbols():
            symtab.append({'name': sym.name, 'val': sym.entry['st_value']})
    
    for s in sections:
        if s.header['sh_type'] == 'SHT_REL':
            if not symtab_s:
                print("symtab section not found")
                exit(0)

            code_s = sections[s.header['sh_info']]
            base_offset = code_s.header['sh_offset']

            if s.name.startswith('.rel.text.'):
                func_name = s.name.replace('.rel.text.','')

                # try to demangle, but put the mangled name in the result
                func_name_ = cxxfilt.demangle(func_name)

                if func_name_:
                    if func_name in relocations:
                        print('same function again?')
                        continue

                    relocations[func_name] = {'offset': base_offset, 'func_size': code_s.header['sh_size'], 'internal': []}

                    for reloc in s.iter_relocations():
                        relsym = symtab[reloc['r_info_sym']]
                        
                        relocation = {
                            'type': reloc['r_info_type'],
                            'name': relsym['name'],
                            'offset': reloc['r_offset']
                        }

                        relocations[func_name]['internal'].append(relocation)

    return relocations

def parse_relocation(rel_type, loc):
        type_ = REL_TYPE[rel_type]
        changes = []
        if type_ == 'R_BPF_64_64':
            changes.append({'size': REL_PATCH_SIZE[rel_type], 'loc': loc + 4})
            changes.append({'size': REL_PATCH_SIZE[rel_type], 'loc': loc + 8 + 4})
        elif type_ == 'R_BPF_64_ABS64':
            changes.append({'size': REL_PATCH_SIZE[rel_type], 'loc': loc})
        elif type_ == 'R_BPF_64_ABS32':
            pass
        elif type_ == 'R_BPF_64_NODYLD32':
            changes.append({'size': REL_PATCH_SIZE[rel_type], 'loc': loc})
        elif type_ == 'R_BPF_64_32':
            #changes.append[{'loc': loc + 4, 'val': ((val - 8) / 8) & 0xFFFFFFFF}] strange, but that doesn't work
            changes.append({'size': REL_PATCH_SIZE[rel_type], 'loc': loc + 4})
        elif type_ == 'R_BPF_64_RELATIVE':
            # ???
            pass
        
        return changes

def process_function(libdata, fname, fdata):
    print('[FUNCTION]', fname, 'size', fdata['func_size'])
    fbytes = libdata[fdata['offset'] : fdata['offset'] + fdata['func_size']]
    fhex = fbytes.hex().upper()

    # Drop all variable bytes based on relocations
    for reloc in fdata['internal']:
        mods = parse_relocation(reloc['type'], reloc['offset'])
        for mod in mods:
            size = int(mod['size'] / 8)
            fhex = fhex[:mod['loc']*2] + '..' * size + fhex[(mod['loc']+size)*2:]

    print(fhex)
    print()
    

def process_library(libfile):
    libelf = ELFFile(libfile)

    # The first approach will be function detection by the
    # section type and name. For each function we need its offset
    # and size. After that, it will be possible to process each 
    # function data
    functions = map_rels_to_funcs(libelf)

    pat_funcs = []
    libfile.seek(0)
    libdata = libfile.read()

    for f in functions:
        pat_funcs.append(process_function(libdata, f, functions[f]))

    return ''


def main():
    parser = argparse.ArgumentParser(description="Solana eBPF libraries PAT files generator")
    parser.add_argument('-f', '--folder', required=False, help='Folder with libraries')
    parser.add_argument('file', help='Library file')
    args = parser.parse_args()

    with open(args.file, 'rb') as f:
        patdata = process_library(f)
    
    print(patdata)

if  __name__ == '__main__':
    main()