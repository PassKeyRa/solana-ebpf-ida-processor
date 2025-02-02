import idaapi

class AnchorBeautifier():
    def __init__(self):
        self.is_anchor = self._is_anchor()

    def _is_anchor(self):
        rodata = idaapi.get_segm_by_name(".rodata")
        if not rodata:
            return False
        
        data = idaapi.get_bytes(rodata.start_ea, rodata.size())
        
        search_strings = [b"anchor:idl", b"AnchorError"]
        for search_string in search_strings:
            if search_string in data:
                return True
        return False
