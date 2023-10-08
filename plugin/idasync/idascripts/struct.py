import idaapi
import ida_struct
import ida_typeinf
import idautils

def scripts_get_structures():
    til = ida_typeinf.get_idati()
    struct_ordinal = [ida_struct.get_struc(id).ordinal for _, id, _ in idautils.Structs()]
    global_struct = {}

    for ordinal in struct_ordinal:
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        tuple = ida_typeinf.get_named_type(til, name, 1)   
        tinfo = idaapi.tinfo_t()
        tinfo.deserialize(til, tuple[1], tuple[2])

        s_data = str(tinfo)

        #IDA export is not very efficient, it remove ";" at the end of C  header and remove struct name
        s_data += ";"
        s_data= s_data.replace("{", f"{name} " + '{')

        #we should have the C header : 
        """
            struct [s_name] [flags] {
                [preformated members]
            };
        
        """
    
        global_struct[name] = { 
            "data" : s_data,
            "size" : tinfo.get_size()
        }

    return global_struct


def script_import_structure(s_name, s_data):
    til = ida_typeinf.get_idati()
        
    import_ret = ida_typeinf.idc_set_local_type(-1, s_data, ida_typeinf.PT_TYP) #add new struct to the end of the local type list
    if import_ret == idaapi.BADNODE:
        print(f"[IDASync::struct.py] Failed to set local type for {s_name}")
        return
    
    ord = ida_typeinf.import_type(til, -1, s_name) #import it
    if ord == ida_typeinf.BADORD:
        print(f"[IDASync::struct.py] Failed to import {s_name}")
        return
        
    print(f"[IDASync::struct.py] Importing {s_name} sucessfull")
    

