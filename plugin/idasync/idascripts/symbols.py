import idaapi
import idautils
import json
import ida_segment
import ida_typeinf
import idc 
import ida_nalt
import ida_hexrays

from idasync.util import pprint

# basic functions, useless to export
blacklist = [
    "deregister_tm_clones",
    "register_tm_clones",
    "__do_global_dtors_aux",
    "frame_dummy"
]

def get_function_signature(func_ea):
    """
    Get the signature of a function.

    Parameters:
        func_ea (int): The effective address of the function.

    Returns:
        dict: A dictionary containing function signature information.
    """
    func_type = ida_typeinf.print_type(func_ea, 0)
    
    signature = {
        "address": "0x{:X}".format(func_ea),
        "signature" : func_type,
        "instance" : ida_nalt.get_root_filename()
    }

    return signature

def scripts_get_symbols():
    """
    List symbolized functions in the current IDB.

    Returns:
        list: A list of dictionaries containing function information.
    """
    text_start = ida_segment.get_segm_by_name(".text").start_ea
    text_end = ida_segment.get_segm_by_name(".text").end_ea

    functions = {}

    for func_ea in idautils.Functions(text_start,text_end):
        fname = idc.get_func_name(func_ea)
        if not fname:
            continue
        if fname.startswith("sub"):
            continue
        if fname in blacklist:
            continue 
            
        functions[fname] = get_function_signature(func_ea)

    return functions


def scripts_import_symbol(symbol_data, sym_name):
    
    functions = {}
    
    # for externals functions, we set the import to the wrapper in .plt
    extern_start = ida_segment.get_segm_by_name("extern").start_ea
    extern_end = ida_segment.get_segm_by_name("extern").end_ea

    ea = 0
    for func_ea in idautils.Functions():
        fname = idc.get_func_name(func_ea)
        if sym_name == fname:
            ea = func_ea
            break
            
    if ea == 0:
        pprint(f"Symbol not found : {sym_name}")
        return 1
        
    if ea >= extern_start and ea <= extern_end:
        for func_ea in idautils.Functions():
            fname = idc.get_func_name(func_ea)
            if "." + sym_name == fname:
                ea = func_ea
                break
            
        if ea == 0:
            pprint(f"Extern PLT Symbol not found : {sym_name}")
            return 1
            
    signature = symbol_data["signature"]
    instance = symbol_data["instance"]
        
    comment = "@IDASync SymbolsImport\n{}:{}".format(instance, signature)
    r = idc.set_cmt(ea, comment, 1)
    
    r = idc.SetType(ea, signature)
    if r is None:
        pprint(f"Failed to setType for {signature} at {hex(ea)}")
        return 3
        
    idc.set_func_cmt(ea, comment, 0)
    
    return 0

def main():
    
    symbols = {
            "adress" : 0x333, 
            "signature" : "unsigned __int64 custom_lib_func(CustomStruct *struct_ptr, int *ptr, unsigned __int64 num)",  
            "instance" : "libcustom.so"
    }    
    
    scripts_import_symbol(symbols, "custom_lib_func")


if __name__ == "__main__":
    main()