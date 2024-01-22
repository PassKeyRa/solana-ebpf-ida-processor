#!/usr/bin/env python3

# This is the Solana eBPF preprocessor for FLAIR tools that
# are used to generate FLIRT signatures. The result of 
# the tool is a .pat file for a corresponding library, 
# which can be passed to the sigmake tool to generate 
# the final .sig file

from elftools.elf.elffile import ELFFile

import argparse
import cxxfilt


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

                    relocations[func_name] = {'offset': base_offset, 'func_size': s.header['sh_size'], 'internal': []}

                    for reloc in s.iter_relocations():
                        relsym = symtab[reloc['r_info_sym']]
                        
                        relocation = {
                            'type': reloc['r_info_type'],
                            'name': relsym['name'],
                            'offset': reloc['r_offset']
                        }

                        relocations[func_name]['internal'].append(relocation)

    return relocations

def process_function(libdata, fname, fdata):
    func_data = libdata[fdata['offset'] : fdata['offset'] + fdata['func_size']]
    print(func_data)

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