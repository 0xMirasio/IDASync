import idaapi
import ida_struct
import json

def get_basic_type_from_size(size):
    if size == 1:
        return "byte"
    elif size == 2:
        return "word"
    elif size == 4:
        return "dword"
    elif size == 8:
        return "qword"
    else:
        return "unknown"
        
def scripts_get_structures():
    struct_list = []
    nb_struct = idaapi.get_struc_qty()
    struct_id = idaapi.get_first_struc_idx()
    for i in range(nb_struct):
        struct_t = ida_struct.get_struc(ida_struct.get_struc_by_idx(struct_id))        
        struct_id = ida_struct.get_next_struc_idx(struct_id)
        
        if struct_t:
            members = []
            offset = 0
            struct_size = idaapi.get_struc_size(struct_t)
            while offset < struct_size:
                member = idaapi.get_member(struct_t, offset)
                if member:
                    member_name = idaapi.get_member_name(member.id)
                    member_tinfo = idaapi.tinfo_t()
                    if idaapi.get_member_tinfo(member_tinfo, member):
                        member_type = member_tinfo.dstr()
                    else:
                        member_type = get_basic_type_from_size(member.eoff - member.soff)
                    
                    members.append({
                        'name': member_name,
                        'type': member_type
                    })
                    offset += member.eoff + 1
                else:
                    offset += 1
            struct_list.append({
                'struct_name': idaapi.get_struc_name(struct_t.id),
                'size': struct_size,
                'members': members
            })
        
    return struct_list

