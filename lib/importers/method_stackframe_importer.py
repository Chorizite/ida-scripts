import re
import sqlite3
import math

import idautils
import idc
import idaapi
import ida_typeinf
import ida_funcs
import ida_name
import ida_frame
import ida_struct
import ida_bytes
import ida_kernwin
import importlib 

import lib.idahelpers as idahelpers
importlib.reload(idahelpers) 

import lib.idahelpers as idahelpers

debug = False
count_args_failed = 0
count_args = 0
count_funcs = 0
def should_skip_stack_member_name(name):
    return name == " s" or name == " r"

def find_arg_with_name_r(data, name):
    for k, arg in data.items():
        if arg["name"] == name:
            return arg
    return None

def wipe_function_frame_stack(func_addr):
    global debug
    """Delete all existing function arguments and create a single argument in the frame."""
    func = idaapi.get_func(func_addr)
    if not func:
        if debug: print(f"Could not find func at 0x{func_addr:x}")
        return False
    
    frame = ida_frame.get_frame(func)
    if not frame:
        if debug: print(f"Could not find frame for func at 0x{func_addr:x}")
        return False
    
    member_offset = ida_struct.get_struc_first_offset(frame)
    offsets_to_delete = []
    while member_offset != -1 and member_offset < 0xFFFF:
        member = idaapi.get_member(frame, member_offset)
        if not member:
            member_offset = ida_struct.get_struc_next_offset(frame, member_offset)
            continue
        member_name = idaapi.get_member_name(member.id)
        if member_offset >= 0 and not should_skip_stack_member_name(member_name):
            offsets_to_delete.append(member_offset)
        member_offset = ida_struct.get_struc_next_offset(frame, member_offset)
    
    for offset in offsets_to_delete:
        ida_struct.del_struc_member(frame, offset)

    return True

def clean_type_name(type_name):
    global debug
    return type_name.replace("struct ", "").replace("unsigned int", "int")

def compare_types(t1, t2):
    global debug
    if t1.endswith('*') and clean_type_name(t2) == "int": return True
    return (clean_type_name(t1) == clean_type_name(t2))

def create_func_args_from_type(func_ea, frame_info, members):
    """Create function arguments based on the function's type information with proper types."""
    global count_args, count_funcs, count_args_failed
    
    func = ida_funcs.get_func(func_ea)
    if not func:
        if debug: print(f"Could not find func for {func_ea:x}")
        return False
    
    func_name = idc.get_func_name(func_ea)
    frame = ida_frame.get_frame(func)
    if not frame:
        if debug: print(f"Could not find frame for {func_ea:x} {func_name}")
        return False
    
    # Get the function type information
    tinfo = ida_typeinf.tinfo_t()
    if not ida_typeinf.guess_tinfo(tinfo, func_ea):
        if debug: print(f"Could not guess_tinfo for {func_ea:x} {func_name}")
        return False
    
    funcdata = idaapi.func_type_data_t()
    if not tinfo.get_func_details(funcdata):
        if debug: print(f"Could not get_func_details for {func_ea:x} {func_name}")
        return False
    
    # Delete existing stack frame struct first
    if not wipe_function_frame_stack(func_ea):
        print(f"Failed to wipe function stack {func_ea:x} {func_name}")
        return False
    
    if not func_name.startswith("?"):
        if debug: print(f"Skipping: 0x{func_ea:x} {func_name}")
        return False

    new_return_offset = idahelpers.get_function_stack_return_offset(func_ea)
    old_return_offset = frame_info["return_offset"]
    
    adj_offset = 0
    if old_return_offset != new_return_offset:
        if debug: print(f"Adjusting offset because r changed: Old offset: {old_return_offset:x} New: {new_return_offset:x} diff: {old_return_offset - new_return_offset:x} on 0x{func_ea:x} {func_name}")
        adj_offset = new_return_offset - old_return_offset

    start_count_args = count_args
    
    for member in members:
        name = member["member_name"]
        offset = member["member_offset"] + adj_offset
        size = member["member_size"]
        flags = member["member_flags"]
        type_str = str(member["member_type"])

        if size > 0xFFFF:
            if debug: print(f"  Skipping {name} because size is weird? {size}")
            continue

        if not should_skip_stack_member_name(name):
            tinfo = idahelpers.create_tinfo_from_string(type_str, size)
            flags = idahelpers.get_flags_from_arg_tinfo(tinfo, size)
            mt = None
            mt = idaapi.opinfo_t()
            mt.tid = ida_struct.get_struc_id(tinfo.get_type_name())
            
            # Create the new member
            if ida_struct.add_struc_member(frame, name, offset, flags, mt, size) == 0:
                member = ida_struct.get_member_by_name(frame, name)
                if member:
                    ida_struct.set_member_tinfo(frame, member, 0, tinfo, 0)
                    if debug: print(f"    Created argument: {name} ({tinfo}:{tinfo.get_ordinal()}) at offset 0x{offset:x} with size {size} and flags 0x{flags:x}")
                    count_args += 1
                else:
                    print(f"    FAILED to find created member {name} ({tinfo}:{tinfo.get_ordinal()}) at offset 0x{offset:x} with size {size} and flags 0x{flags:x} on {func_name}")
                    count_args_failed += 1
            else:
                print(f"    FAILED to create member {name} ({tinfo}:{tinfo.get_ordinal()}) at offset 0x{offset:x} with size {size} and flags 0x{flags:x} on {func_name}")
                count_args_failed += 1
    
    if start_count_args != count_args:
        count_funcs += 1

def import_method_stackframes(cursor):
    """Update function arguments using data from the SQLite database."""
    global count_args, count_funcs, count_args_failed
    
    ida_kernwin.replace_wait_box("Importing method stack frames...")

    # Get count of total functions first
    cursor.execute("SELECT COUNT(DISTINCT function_address) FROM method_stackframes")
    total_funcs = cursor.fetchone()[0]
    
    # Get all stack frames and their members
    cursor.execute("""
        SELECT 
            f.function_name, f.function_address, f.frame_size,
            f.return_offset, f.arg_base, f.local_base,
            m.member_name, m.member_offset, m.member_size,
            m.member_flags, m.member_type
        FROM method_stackframes f
        LEFT JOIN stackframe_members m ON f.id = m.frame_id
        ORDER BY f.function_address, m.member_offset
    """)
    
    current_func = None
    current_frame_info = None
    current_members = []
    processed = 0
    
    for row in cursor.fetchall():
        (func_name, func_addr, frame_size, ret_offset, arg_base, local_base,
         member_name, member_offset, member_size, member_flags, member_type) = row
        
        # If we've moved to a new function, process the previous one
        if current_func != func_addr and current_func is not None:
            create_func_args_from_type(current_func, current_frame_info, current_members)
            current_members = []
            processed += 1
            if processed % (max(math.floor(total_funcs / 100), 100)) == 0:
                percentage = (processed / total_funcs) * 100
                ida_kernwin.replace_wait_box(f"Importing method stack frames... {processed}/{total_funcs} ({percentage:.1f}%)")
        
        # Update current function info
        if current_func != func_addr:
            current_func = func_addr
            current_frame_info = {
                "function_name": func_name,
                "frame_size": frame_size,
                "return_offset": ret_offset,
                "arg_base": arg_base,
                "local_base": local_base
            }
        
        # Add member info if it exists
        if member_name:
            current_members.append({
                "member_name": member_name,
                "member_offset": member_offset,
                "member_size": member_size,
                "member_flags": member_flags,
                "member_type": member_type
            })
    
    # Process the last function
    if current_func is not None:
        create_func_args_from_type(current_func, current_frame_info, current_members)
        processed += 1
    
    print(f"Updated {count_args:,} (failed {count_args_failed:,}) variable names in {count_funcs:,} functions")
