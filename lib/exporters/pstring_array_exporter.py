import idaapi
import idautils
import idc
import ida_kernwin
import ida_bytes
import ida_name
import math
import re
import lib.idahelpers as idahelpers

def _find_pstring_array_init_functions():
    """Find PStringBase arrays in .data section and their initialization functions through xrefs."""
    init_funcs = []
    
    # Find .data segment
    data_seg = idaapi.get_segm_by_name(".data")
    if not data_seg:
        print("    [-] Could not find .data segment")
        return init_funcs
    
    print("    [+] Scanning .data segment for PStringBase arrays...")
    
    # Calculate total addresses to scan for progress reporting
    total_addrs = data_seg.end_ea - data_seg.start_ea
    processed = 0
    last_progress = 0
    
    # Iterate through .data segment looking for PStringBase arrays
    ea = data_seg.start_ea
    while ea < data_seg.end_ea:
        # Update progress every 1%
        processed = ea - data_seg.start_ea
        progress = (processed / total_addrs) * 100
        if progress - last_progress >= 1:
            ida_kernwin.replace_wait_box(f"Scanning .data for string arrays... {progress:.1f}%")
            last_progress = progress
            
        # Check if we have a name at this address that looks like a PStringBase array
        name = ida_name.get_name(ea)
        type_info = idc.get_type(ea)
        if name and type_info and "PStringBase" in type_info and type_info.endswith("]"):
            # Get all xrefs to this array
            for xref in idautils.XrefsTo(ea):
                func = idaapi.get_func(xref.frm)
                if not func:
                    continue
                
                success, array_name, cleanup_func, members = idahelpers.get_string_array_initializer_members(func.start_ea)
                
                if success:
                    init_funcs.append((func.start_ea, array_name, cleanup_func, members))
                    break  # Found the initializer, no need to check other xrefs
                    
        # Move to next item in .data section
        ea = idc.next_head(ea)
    
    print(f"    [+] Found {len(init_funcs)} PStringBase array initializers")
    return init_funcs

def dump_pstring_arrays(cursor):
    """Export PStringBase arrays and their members to the database."""
    print("  [+] Extracting PStringBase arrays")
    
    # Find all PStringBase array initialization functions
    init_funcs = _find_pstring_array_init_functions()
    total_funcs = len(init_funcs)
    
    array_count = 0
    member_count = 0
    
    for i, (func_ea, array_name, cleanup_func, members) in enumerate(init_funcs):
        if i % (max(math.floor(total_funcs / 100), 100)) == 0:
            progress = (i / total_funcs) * 100
            ida_kernwin.replace_wait_box(f"Processing PStringBase arrays... {i}/{total_funcs} ({progress:.1f}%)")
            
        # Get array information
        if not array_name:
            continue
            
        array_ea = idc.get_name_ea_simple(array_name)
        if array_ea == idaapi.BADADDR:
            print(f"    [-] Could not find array {array_name} at {hex(func_ea)}")
            continue
            
        # Get the size of the data segment
        data_size = idc.get_item_size(array_ea)
            
        # Insert array info into database
        cursor.execute('''
        INSERT INTO pstring_arrays (array_name, array_address, array_size, cleanup_func, data_size)
        VALUES (?, ?, ?, ?, ?)
        ''', (array_name, array_ea, len(members), cleanup_func, data_size))
        
        array_id = cursor.lastrowid
        array_count += 1
        
        # Process each member
        for j in range(len(members)):
            member_name = members[j]
            if not member_name:
                continue

            # get the value of the member
            member_ea = idc.get_name_ea_simple(member_name)
            member_value = idc.get_strlit_contents(member_ea, -1, idc.STRTYPE_C)
            print(f"    [+] Member {member_name} at {member_ea:08X} has value {member_value}")
                
            # Insert member info into database
            cursor.execute('''
            INSERT INTO pstring_array_members (array_id, member_index, member_name, member_value)
            VALUES (?, ?, ?, ?)
            ''', (array_id, j, member_name, member_value))
            
            member_count += 1
    
    print(f"    [+] PStringBase arrays extracted: {array_count}")
    print(f"    [+] Array members extracted: {member_count}")
    return True, array_count, member_count 