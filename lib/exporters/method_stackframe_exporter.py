import idaapi
import idautils
import ida_typeinf
import ida_funcs
import ida_name
import ida_struct
import ida_bytes
import ida_kernwin
import importlib
import math

import lib.idahelpers as idahelpers
importlib.reload(idahelpers)
import lib.idahelpers as idahelpers

def dump_method_stackframes(cursor):
    """
    Export stack frame information for each named method in the current IDA database.
    This includes frame size, return address offset, argument base, local base, and member information.
    """
    print("  [+] Extracting method stack frames")
    
    frame_count = 0
    member_count = 0
    
    # Get total function count for progress
    total_funcs = len(list(idautils.Functions()))
    processed_funcs = 0
    
    # Iterate through all functions in the database
    for func_ea in idautils.Functions():
        processed_funcs += 1
        if processed_funcs % (max(math.floor(total_funcs / 100), 100)) == 0:
            percentage = (processed_funcs / total_funcs) * 100
            ida_kernwin.replace_wait_box(f"Exporting function stack frames... ({processed_funcs}/{total_funcs}) - {percentage:.1f}%")
        
        # Get the function object
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
            
        # Get the function name
        func_name = ida_name.get_name(func_ea)
        if not func_name or func_name.startswith("sub_") or func_name.startswith("nullsub"):
            # Skip unnamed functions (typically labeled as sub_XXXX)
            continue
            
        # Get the function type information
        tinfo = ida_typeinf.tinfo_t()
        if not ida_typeinf.guess_tinfo(tinfo, func_ea):
            continue
            
        # Try to get more detailed information about parameters
        funcdata = idaapi.func_type_data_t()
        if not tinfo.get_func_details(funcdata) or len(funcdata) == 0:
            continue
            
        frame = idaapi.get_frame(func_ea)
        if not frame:
            continue
            
        frame_size = idaapi.get_struc_size(frame)
        info = idahelpers.get_frame_info(func_ea)
        return_offset = info["return_address_offset"]
        arg_base = info["arg_base"]
        loc_base = info["local_base"]
        
        # Insert stack frame info into database
        cursor.execute('''
        INSERT INTO method_stackframes (
            function_name, function_address, frame_size, 
            return_offset, arg_base, local_base
        ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (func_name, func_ea, frame_size, return_offset, arg_base, loc_base))
        
        frame_id = cursor.lastrowid
        frame_count += 1
        
        # Get parameter information
        params = {}
        for i, arg in enumerate(funcdata):
            arg_name = arg.name if arg.name else f"arg_{i}"
            params[arg_name] = arg
        
        # Get stack frame member information
        member_offset = ida_struct.get_struc_first_offset(frame)
        while member_offset != -1:
            member = idaapi.get_member(frame, member_offset)
            if not member:
                break
                
            member_name = idaapi.get_member_name(member.id)
            next_offset = ida_struct.get_struc_next_offset(frame, member_offset)
            member_size = next_offset - member_offset if next_offset != -1 else frame_size - member_offset
            
            # Determine member type
            member_type = member_name in params and params[member_name].type or idahelpers.get_member_simple_type(member)
            if member_name in params and member_size != params[member_name].type.get_size():
                member_type = idahelpers.get_member_simple_type(member)
            
            # Insert frame member info into database
            cursor.execute('''
            INSERT INTO stackframe_members (
                frame_id, member_name, member_offset, 
                member_size, member_flags, member_type
            ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (frame_id, member_name, member_offset, member_size, member.flag, str(member_type)))
            
            member_count += 1
            member_offset = ida_struct.get_struc_next_offset(frame, member_offset)
    
    print(f"    [+] Stack frames extracted: {frame_count:,}")
    print(f"    [+] Stack frame members extracted: {member_count:,}")
    return True, frame_count, member_count