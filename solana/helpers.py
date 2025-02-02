def decode_name(name):
    name = name.replace('.rel.text.','')
    name = name.replace('.rel.data.rel.ro.','')
    return name