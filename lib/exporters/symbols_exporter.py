import idaapi
import idautils
import idc
import sqlite3
import importlib
import os
import ida_typeinf

import lib.idahelpers as idahelpers
importlib.reload(idahelpers) 

def dump_subroutines(cursor):
    """Export all subroutines and their cross-references using IDA's Functions API."""
    print("  [+] Extracting subroutines")
    
    symbol_count = 0
    xref_count = 0
    
    # Iterate through all functions in the database
    for func_ea in idautils.Functions():
        # Get function name
        name = idc.get_func_name(func_ea)
        if not name:
            continue
            
        # Get function object and size
        func = idaapi.get_func(func_ea)
        if not func:
            continue
            
        size = func.end_ea - func.start_ea
        type_name = idahelpers.get_symbol_type_from_addr(func_ea)
        
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

def dump_segment_symbols(segment_name, cursor):
    # For .text segment, use the new dump_subroutines function
    if segment_name == ".text":
        return dump_subroutines(cursor)
        
    seg = idahelpers.find_named_segment(segment_name)
    
    if not seg:
        print(f"  [-] Error: {segment_name} section not found!")
        return False, 0, 0
    
    seg_start = idc.get_segm_start(seg)
    seg_end = idc.get_segm_end(seg)

    print(f"  [+] Extracting symbols from {segment_name}: {hex(seg_start)} - {hex(seg_end)}")
    
    symbol_count = 0
    xref_count = 0
    
    for addr in range(seg_start, seg_end):
        # Check if there's a named item at this address
        name = idc.get_name(addr)
        if name and idahelpers.is_named_data_symbol(name):
            if segment_name == ".text" and not idahelpers.is_subroutine(addr):
                continue
            
            # Get symbol information
            size = idc.get_item_size(addr)
            type_name = idahelpers.get_symbol_type_from_addr(addr)
            
            # Insert symbol into database
            cursor.execute('''
            INSERT INTO symbols (name, address, size, type, section)
            VALUES (?, ?, ?, ?, ?)
            ''', (name, addr, size, type_name, segment_name))
            
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