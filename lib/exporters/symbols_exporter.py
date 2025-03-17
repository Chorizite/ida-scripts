import idaapi
import idautils
import idc
import sqlite3
import importlib
import os
import ida_funcs
import ida_typeinf
import ida_kernwin
import ida_nalt
import math
import lib.idahelpers as idahelpers
importlib.reload(idahelpers) 

def dump_subroutines(cursor):
    """Export all subroutines and their cross-references using IDA's Functions API."""
    print("  [+] Extracting subroutines")
    
    symbol_count = 0
    xref_count = 0
    
    # Get total function count first for progress
    total_funcs = len(list(idautils.Functions()))
    
    # Iterate through all functions in the database
    for i, func_ea in enumerate(idautils.Functions(), 1):
        # Show progress every 100 functions
        percentage = (i / total_funcs) * 100
        idahelpers.update_wait_box(f"Exporting functions... ({i:,}/{total_funcs:,} ({percentage:.1f}%)")
            
        # Get function name
        name = idc.get_func_name(func_ea)
        if not name:
            continue
            
        # Get function object and size
        func = idaapi.get_func(func_ea)
        if not func:
            continue
            
        size = func.end_ea - func.start_ea
        type_name = get_function_type_declaration(func_ea)

        print(f"    [+] Exporting function: {name} @ 0x{func_ea:X}")
        print(f"        [+] Type: {type_name}")
        print(f"        [+] Size: {size}")
        
        # Insert function into database
        cursor.execute('''
        INSERT INTO symbols (name, address, size, type, section)
        VALUES (?, ?, ?, ?, ?)
        ''', (name, func_ea, size, type_name, ".text"))
        
        symbol_id = cursor.lastrowid
        symbol_count += 1
        
        # Get all cross-references to this function
        for xref in idautils.XrefsTo(func_ea):
            xref_addr = xref.frm
            xref_type = idahelpers.get_xref_type(xref)
            
            # Get function information for the xref
            xref_func = idaapi.get_func(xref_addr)
            xref_func_name = ""
            xref_func_addr = 0
            xref_offset = 0
            
            if xref_func:
                xref_func_addr = xref_func.start_ea
                xref_func_name = idc.get_func_name(xref_func_addr)
                xref_offset = xref_addr - xref_func_addr
            else:
                # If not in a function, try to get the name of the containing item
                xref_func_addr = idc.get_item_head(xref_addr)
                xref_func_name = idc.get_name(xref_func_addr)
                xref_offset = xref_addr - xref_func_addr
            
            # Insert xref into database
            cursor.execute('''
            INSERT INTO data_xrefs (symbol_id, xref_address, xref_type, xref_function, xref_function_address, xref_offset)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (symbol_id, xref_addr, xref_type, xref_func_name, xref_func_addr, xref_offset))
            
            xref_count += 1
    
    print(f"    [+] Subroutines extracted: {symbol_count:,}")
    print(f"    [+] Cross-references extracted: {xref_count:,}")
    return True, symbol_count, xref_count

def get_function_type_declaration(address):
    """
    Retrieves the type declaration of a function at the given address in IDA.
    Args:
        address (int): The address of the function.
    Returns:
        str: The type declaration string of the function, or None if an error occurs.
    """
    func = ida_funcs.get_func(address)
    if func is None:
        print(f"Error: No function found at address {hex(address)}.")
        return None
    
    # Create a tinfo_t object to store the type info
    tinfo = ida_typeinf.tinfo_t()
    
    # Use the correct API function: guess_tinfo instead of get_func_tinfo
    if not ida_nalt.get_tinfo(tinfo, func.start_ea):
        # Try using guess_tinfo if get_tinfo fails
        if not ida_typeinf.guess_tinfo(tinfo, func.start_ea):
            return None
    
    # Convert the type info to a string
    type_str = ""
    # Use a simple string instead of qstring which doesn't exist in IDA 8.2
    prototype_buffer = ""
    if ida_typeinf.print_type(func.start_ea, 0):
        prototype_buffer = ida_typeinf.print_type(func.start_ea, 0)
    else:
        # Fallback to print_tinfo with a string buffer
        prototype_buffer = ida_typeinf.print_tinfo('', 0, 0, 0, tinfo, None, None)
    
    return prototype_buffer

def dump_segment_symbols(segment_name, cursor):
    seg = idahelpers.find_named_segment(segment_name)
    
    if not seg:
        print(f"  [-] Error: {segment_name} section not found!")
        return False, 0, 0
    
    seg_start = idc.get_segm_start(seg)
    seg_end = idc.get_segm_end(seg)

    print(f"  [+] Extracting symbols from {segment_name}: {hex(seg_start)} - {hex(seg_end)}")
    
    symbol_count = 0
    xref_count = 0
    
    # Calculate total addresses to process
    total_addrs = seg_end - seg_start
    
    for i, addr in enumerate(range(seg_start, seg_end), 1):
        # Show progress every 10000 addresses
        percentage = (i / total_addrs) * 100
        idahelpers.update_wait_box(f"Exporting {segment_name} symbols... ({i:,}/{total_addrs:,} ({percentage:.1f}%)")
            
        # Check if there's a named item at this address
        name = idc.get_name(addr)
        if name and idahelpers.is_named_data_symbol(name):
            if segment_name == ".text" and not idahelpers.is_subroutine(addr):
                continue
            
            # Get symbol information
            size = idc.get_item_size(addr)
            type_name = idahelpers.get_symbol_type_from_addr(addr)

            value = None
            if segment_name == ".rdata":
                value = idahelpers.get_data_value(addr)
            
            # Insert symbol into database
            cursor.execute('''
            INSERT INTO symbols (name, address, size, type, section, value)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, addr, size, type_name, segment_name, value))
            
            symbol_id = cursor.lastrowid
            symbol_count += 1
            local_xref_count = 0
            # Get all cross-references to this symbol
            for xref in idautils.XrefsTo(addr):
                xref_addr = xref.frm
                xref_type = idahelpers.get_xref_type(xref)
                
                # Get function information for the xref
                xref_func_addr = idaapi.get_func(xref_addr)
                xref_func_name = ""
                xref_offset = 0
                
                if xref_func_addr:
                    xref_func_addr = xref_func_addr.start_ea
                    xref_func_name = idc.get_func_name(xref_func_addr)
                    xref_offset = xref_addr - xref_func_addr
                else:
                    # If not in a function, try to get the name of the containing item
                    xref_func_addr = idc.get_item_head(xref_addr)
                    xref_func_name = idc.get_name(xref_func_addr)
                    xref_offset = xref_addr - xref_func_addr
                
                # Insert xref into database with additional information
                cursor.execute('''
                INSERT INTO data_xrefs (symbol_id, xref_address, xref_type, xref_function, xref_function_address, xref_offset)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (symbol_id, xref_addr, xref_type, xref_func_name, xref_func_addr, xref_offset))
                
                xref_count += 1
                local_xref_count += 1
            
            # Delete symbols that didnt have any xrefs
            if local_xref_count == 0 and segment_name != ".text":
                cursor.execute('DELETE FROM symbols WHERE id = ?', (symbol_id,))
                symbol_count -= 1

    print(f"    [+] {segment_name} Symbols extracted: {symbol_count:,}")
    print(f"    [+] {segment_name} Cross-references extracted: {xref_count:,}")
    return True, symbol_count, xref_count