#!/usr/bin/env python3

# This is the Solana eBPF preprocessor for FLAIR tools that
# are used to generate FLIRT signatures. The result of 
# the tool is a .pat file for a corresponding library, 
# which can be passed to the sigmake tool to generate 
# the final .sig file

from elftools.elf.elffile import ELFFile

import argparse
import cxxfilt
import crcmod.predefined

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

# CRC16 from https://github.com/mandiant/flare-ida/blob/master/python/flare/idb2pat.py

CRC16_TABLE = [
  0x0, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1,
  0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x108, 0x3393, 0x221a,
  0x56a5, 0x472c, 0x75b7, 0x643e, 0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64,
  0xf9ff, 0xe876, 0x2102, 0x308b, 0x210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
  0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5, 0x3183, 0x200a,
  0x1291, 0x318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50,
  0xfbef, 0xea66, 0xd8fd, 0xc974, 0x4204, 0x538d, 0x6116, 0x709f, 0x420, 0x15a9,
  0x2732, 0x36bb, 0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
  0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x528, 0x37b3, 0x263a, 0xdecd, 0xcf44,
  0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72, 0x6306, 0x728f, 0x4014, 0x519d,
  0x2522, 0x34ab, 0x630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3,
  0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x738,
  0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70, 0x8408, 0x9581,
  0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x840, 0x19c9, 0x2b52, 0x3adb,
  0x4e64, 0x5fed, 0x6d76, 0x7cff, 0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324,
  0xf1bf, 0xe036, 0x18c1, 0x948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
  0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5, 0x2942, 0x38cb,
  0xa50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699, 0x8710,
  0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0xb58, 0x7fe7, 0x6e6e,
  0x5cf5, 0x4d7c, 0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
  0x4a44, 0x5bcd, 0x6956, 0x78df, 0xc60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704,
  0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232, 0x5ac5, 0x4b4c, 0x79d7, 0x685e,
  0x1ce1, 0xd68, 0x3ff3, 0x2e7a, 0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3,
  0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0xe70, 0x1ff9,
  0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e,
  0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0xf78]


def crc16(data, crc):
    for byte in data:
        crc = (crc >> 8) ^ CRC16_TABLE[(crc ^ byte) & 0xFF]
    crc = (~crc) & 0xFFFF
    crc = (crc << 8) | ((crc >> 8) & 0xFF)
    return crc & 0xffff

def process_function(libdata, fname, fdata):
    print('[FUNCTION]', fname, 'size', fdata['func_size'])
    fbytes = libdata[fdata['offset'] : fdata['offset'] + fdata['func_size']]

    if len(fbytes) >= 0x8000:
        return None # too long function 
    
    if len(fbytes) < 35:
        return None # too short function

    fhex = fbytes.hex().upper()

    internal_names = {}

    # Drop all variable bytes based on relocations and generate
    # internal function names list
    for reloc in fdata['internal']:
        mods = parse_relocation(reloc['type'], reloc['offset'])
        for mod in mods:
            size = int(mod['size'] / 8)
            fhex = fhex[:mod['loc']*2] + '..' * size + fhex[(mod['loc']+size)*2:]
        
        if REL_TYPE[reloc['type']] == 'R_BPF_64_32':
            internal_names[hex(mods[0]['loc'])[2:].upper().zfill(4)] = reloc['name']

    # Replace remaining unrelocated calls if any (shouldn't be)
    fhex = fhex.replace('85100000FFFFFFFF', '..' * 8)
    
    pat_data = fhex[:64]

    alen = 255 if len(fhex) - 64 > 255 * 2 else (len(fhex) - 64 - 2) // 2
    if '..' in fhex[64:64+alen*2]:
        alen = (fhex.index('..', 64) - 64)//2
    
    crc = hex(crc16(int(fhex[64:64+alen*2], 16).to_bytes(alen), crc=0xFFFF))[2:].upper().zfill(4)

    func_len = hex(fdata['func_size'])[2:].upper().zfill(4)

    pat_data += f" {hex(alen)[2:].upper().zfill(2)} {crc} {func_len} :0000 {fname}"

    for ioff in internal_names:
        pat_data += f" ^{ioff} {internal_names[ioff]}"
    
    pat_data += f" {fhex[64+alen*2:]}"

    return pat_data


def process_library(libfile):
    libelf = ELFFile(libfile)

    # The first approach will be a function detection by the
    # section type and name. For each function we need its offset
    # and size. After that, it will be possible to process each 
    # function data
    functions = map_rels_to_funcs(libelf)

    pat_funcs = []
    libfile.seek(0)
    libdata = libfile.read()

    for f in functions:
        pat_data_ = process_function(libdata, f, functions[f])
        if pat_data_ != None:
            pat_funcs.append(pat_data_)

    return '\n'.join(pat_funcs) + '\n---\n'


def main():
    parser = argparse.ArgumentParser(description="Solana eBPF libraries PAT files generator")
    #parser.add_argument('-f', '--folder', required=False, help='Folder with libraries')
    parser.add_argument('input_file', help='Library file')
    parser.add_argument('output_file', help='Resulted PAT file')
    args = parser.parse_args()

    with open(args.input_file, 'rb') as f:
        patdata = process_library(f)
    
    with open(args.output_file, 'w') as f:
        f.write(patdata)
    
    print('The PAT file generated successfully')

if  __name__ == '__main__':
    main()