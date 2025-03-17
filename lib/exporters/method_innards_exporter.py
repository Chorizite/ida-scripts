import idaapi
import idautils
import idc
import ida_kernwin
import math
import importlib

import lib.idahelpers as idahelpers
importlib.reload(idahelpers)

def dump_method_disasm(cursor):
    """Export disassembly lines for all functions in the database."""
    print("  [+] Extracting method disassembly")
    
    disasm_count = 0
    batch_size = 1000  # Number of records to insert at once
    
    # Get total function count first for progress
    total_funcs = len(list(idautils.Functions()))
    
    # Cache all symbols in memory for quick lookup
    print("    [+] Caching symbols...")
    symbol_cache = {}
    cursor.execute('SELECT id, address FROM symbols')
    for symbol_id, address in cursor.fetchall():
        symbol_cache[address] = symbol_id
    
    # Collect disassembly lines for batch insert
    disasm_batch = []
    
    # Iterate through all functions in the database
    for i, func_ea in enumerate(idautils.Functions(), 1):
        # Show progress every 100 functions
        percentage = (i / total_funcs) * 100
        idahelpers.update_wait_box(f"Exporting function disassembly... {i:,}/{total_funcs:,} ({percentage:.1f}%)")
            
        # Get function name
        name = idc.get_func_name(func_ea)
        if not name:
            continue
            
        # Get function object
        func = idaapi.get_func(func_ea)
        if not func:
            continue
            
        # Get disassembly lines
        disasm_lines = idahelpers.get_function_disasm_lines(func_ea)
        
        # Get the symbol ID from cache
        symbol_id = symbol_cache.get(func_ea)
        if not symbol_id:
            continue
            
        # Collect disassembly lines for batch insert
        for line_idx, line in enumerate(disasm_lines):
            line_addr = idc.get_item_head(func.start_ea + line_idx)
            disasm_batch.append((symbol_id, line_idx, line_addr, line))
            disasm_count += 1
            
            # Perform batch insert when batch size is reached
            if len(disasm_batch) >= batch_size:
                cursor.executemany('''
                    INSERT INTO disasm (symbol_id, line_number, address, line_text)
                    VALUES (?, ?, ?, ?)
                ''', disasm_batch)
                disasm_batch = []
    
    # Insert any remaining records
    if disasm_batch:
        cursor.executemany('''
            INSERT INTO disasm (symbol_id, line_number, address, line_text)
            VALUES (?, ?, ?, ?)
        ''', disasm_batch)
    
    print(f"    [+] Disassembly lines extracted: {disasm_count:,}")
    return True, disasm_count
