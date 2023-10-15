import idaapi
import ida_enum
import ida_typeinf
import idautils

from idasync.util import pprint

def scripts_get_enums():
    all_enums = {}

    idx=0
    enum_id = ida_enum.getn_enum(idx)
    while enum_id != idaapi.BADADDR:
        enum_name = ida_enum.get_enum_name(enum_id)
        size = ida_enum.get_enum_size(enum_id)
        
        enum_data = {
            'data': {},
            'size': size
        }
        
        member_value = ida_enum.get_first_enum_member(enum_id)
        while member_value != idaapi.BADADDR:
            member_id = ida_enum.get_enum_member(enum_id, member_value, -1, 0)
            if member_id:
                member_name = ida_enum.get_enum_member_name(member_id)                
                enum_data['data'][member_name] = member_value
            member_value = ida_enum.get_next_enum_member(enum_id, member_value)

        all_enums[enum_name] = enum_data
        idx += 1
        enum_id = ida_enum.getn_enum(idx)
        
    return all_enums

def scripts_import_enum(enum_name, enum_data):

    enum_id = ida_enum.get_enum(enum_name)
        
    if enum_id != idaapi.BADADDR:
        ida_enum.del_enum(enum_id)
        
    new_enum_id = ida_enum.add_enum(idaapi.BADADDR, enum_name, 0)
    
    if new_enum_id == idaapi.BADADDR:
        pprint("Failed to create enum:", enum_name)
        return
    
    for member_name, member_value in enum_data.items():
        ida_enum.add_enum_member(new_enum_id, member_name, member_value)
    
    pprint(f"Enum {enum_name} has been imported successfully.")
