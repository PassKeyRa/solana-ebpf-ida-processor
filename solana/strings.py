import idaapi
import idc

def binary_search(addr, sorted_strings):
    left = 0
    right = len(sorted_strings) - 1
    
    while left <= right:
        mid = (left + right) // 2
        curr_addr = sorted_strings[mid][0]
        curr_len = sorted_strings[mid][1]
        
        if curr_addr <= addr < curr_addr + curr_len:
            return mid
            
        if curr_addr < addr:
            left = mid + 1
        else:
            right = mid - 1
            
    return left - 1  # Return insertion point - 1

def find_previous_string_idx(addr, sorted_strings):
    if not sorted_strings:
        return None
        
    if addr < sorted_strings[0][0]:
        return None
        
    idx = binary_search(addr, sorted_strings)
    if idx >= 0 and idx < len(sorted_strings):
        return idx
        
    return None

def find_next_string_idx(addr, sorted_strings):
    if not sorted_strings:
        return None
        
    if addr >= sorted_strings[-1][0]:
        return None
        
    idx = binary_search(addr, sorted_strings)
    next_idx = idx + 1
    
    if next_idx < len(sorted_strings):
        return next_idx
        
    return None

def getstr(addr, max_len=512):
    data = idaapi.get_bytes(addr, max_len)
    for i in range(len(data)):
        if data[i] == 0:
            return data[:i]
    return data

def add_string(sorted_strings, addr, size=None) -> tuple[list, int]:
    previous_idx = find_previous_string_idx(addr, sorted_strings)
    if previous_idx is None:
        if size is None or size == 0:
            s = getstr(addr, 512)
            size = len(s)
        
        if sorted_strings and sorted_strings[0][0] < addr + size:
            size = sorted_strings[0][0] - addr

        sorted_strings.insert(0, [addr, size])
        success = idc.create_strlit(addr, addr + size)
        idaapi.set_name(addr, "str_%08X" % addr, idaapi.SN_FORCE)
        return sorted_strings, size

    previous_string = sorted_strings[previous_idx]
    if previous_string[0] == addr:
        if size is None or size == 0:
            size = 512

        if previous_string[1] > size:
            success = idc.create_strlit(addr, addr + size)
            if success:
                sorted_strings[previous_idx] = [addr, size]
        else:
            size = previous_string[1]
        return sorted_strings, size

    if previous_string[0] + previous_string[1] >= addr:
        # Patch previous string
        new_len = addr - previous_string[0]
        success = idc.create_strlit(previous_string[0], previous_string[0] + new_len)
        if success:
            sorted_strings[previous_idx] = [previous_string[0], new_len]
    
    next_string = None
    if previous_idx + 1 < len(sorted_strings):
        next_string = sorted_strings[previous_idx + 1]
        if next_string[0] == addr:
            if size not in [None, 0]:
                if next_string[1] != size:
                    # Patch already existing string
                    success = idc.create_strlit(addr, addr + size)
                    if success:
                        sorted_strings[previous_idx + 1] = [addr, size]
            else:
                return sorted_strings, sorted_strings[previous_idx + 1][1]
            return sorted_strings, size
    
    if size is None or size == 0: # 285c0
        if next_string is not None:
            size = next_string[0] - addr
        else:
            s = getstr(addr, 512)
            size = len(s)
    
    if size == 0:
        return sorted_strings, size

    success = idc.create_strlit(addr, addr + size)
    if success:
        sorted_strings.insert(previous_idx + 1, [addr, size])
        idaapi.set_name(addr, "str_%08X" % addr, idaapi.SN_FORCE)
    return sorted_strings, size

def recover_known_strings(sorted_strings, symtab):
    _rodata = idaapi.get_segm_by_name(".rodata")
        
    strings_to_create = {}

    for s in symtab:
        if s['val'] >= _rodata.start_ea and s['val'] <= _rodata.end_ea:
            l = s['size']
            if l > 0:
                strings_to_create[s['val']] = l
    
    _data_rel_ro = idaapi.get_segm_by_name(".data.rel.ro")
    start_ea = _data_rel_ro.start_ea
    loopcount = _data_rel_ro.end_ea - start_ea

    for addr in range(0, loopcount - 4, 4):
        Addr = idaapi.get_dword(start_ea+addr)
        l = idaapi.get_dword(start_ea+addr+4)
        if l < 1024 and Addr + l < 2**32:
            if Addr >= _rodata.start_ea and Addr <= _rodata.end_ea:
                if Addr not in strings_to_create:
                    strings_to_create[Addr] = l
    
    for k in strings_to_create.keys():
        if strings_to_create[k] > 0:
            sorted_strings, size = add_string(sorted_strings, k, strings_to_create[k])

    return sorted_strings
