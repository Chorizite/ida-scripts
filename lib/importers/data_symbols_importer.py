import idaapi
import idautils
import idc
import sqlite3
import os
import math
import ida_kernwin
from collections import defaultdict
import importlib

import lib.idahelpers as idahelpers
importlib.reload(idahelpers)

def get_section_segment(section_name):
    """Get the segment for a given section name."""
    for seg in idautils.Segments():
        if idc.get_segm_name(seg).lower() == section_name.lower():
            return seg
    return None

def build_current_symbols_map(section_start, section_end, section_name):
    """Build a dictionary of current symbols in section and their xrefs."""
    current_symbols = {}
    xref_cache = defaultdict(list)
    
    # Pre-cache all xrefs in the section range for faster lookup
    total_heads = len(list(idautils.Heads(section_start, section_end)))
    processed_heads = 0
    for head in idautils.Heads(section_start, section_end):
        processed_heads += 1
        percentage = (processed_heads / total_heads) * 100
        idahelpers.update_wait_box(f"Building {section_name} symbol map: ({processed_heads}/{total_heads}) - {percentage:.1f}%")
        for xref in idautils.XrefsTo(head):
            xref_cache[head].append(xref)
    
    # Count total heads for progress calculation
    total_heads = sum(1 for _ in idautils.Heads(section_start, section_end))
    
    # Process heads in batches
    BATCH_SIZE = 1000
    heads = list(idautils.Heads(section_start, section_end))
    
    for batch_start in range(0, len(heads), BATCH_SIZE):
        batch_end = min(batch_start + BATCH_SIZE, len(heads))
        batch = heads[batch_start:batch_end]
        
        progress = (batch_start / total_heads) * 100
        idahelpers.update_wait_box(f"Building {section_name} symbol map: ({batch_start}/{total_heads}) - {progress:.1f}%")
        
        for head in batch:
            name = idc.get_name(head)
            if name and not idahelpers.is_named_data_symbol(name):
                xref_signatures = []
                
                for xref in xref_cache[head]:
                    xref_addr = xref.frm
                    func = idaapi.get_func(xref_addr)
                    
                    if func:
                        func_addr = func.start_ea
                        func_name = idc.get_func_name(func_addr)
                        offset = xref_addr - func_addr
                        xref_type = idahelpers.get_xref_type(xref)
                        xref_signatures.append((func_name, offset, xref_type))
                
                if xref_signatures:  # Only store symbols with xrefs
                    # Sort xref signatures for faster comparison later
                    xref_signatures.sort()
                    current_symbols[head] = {
                        "name": name,
                        "xrefs": tuple(xref_signatures)  # Convert to tuple for hashability
                    }
    
    return current_symbols

def fetch_db_symbols(cursor, section_name):
    """Fetch and group symbols from database for a given section."""
    # Fetch symbols and xrefs separately for better performance
    cursor.execute('SELECT id, name FROM symbols WHERE section = ?', (section_name,))
    symbols = {row[0]: {"name": row[1], "xrefs": []} for row in cursor.fetchall()}
    
    # Fetch xrefs in batches
    BATCH_SIZE = 5000
    cursor.execute('SELECT symbol_id, xref_function, xref_offset, xref_type FROM data_xrefs WHERE symbol_id IN (SELECT id FROM symbols WHERE section = ?)', (section_name,))
    
    while True:
        rows = cursor.fetchmany(BATCH_SIZE)
        if not rows:
            break
            
        for symbol_id, func, offset, xref_type in rows:
            if symbol_id in symbols:
                symbols[symbol_id]["xrefs"].append((func, offset, xref_type))
    
    # Sort xrefs and convert to tuples for faster comparison
    for symbol_data in symbols.values():
        symbol_data["xrefs"].sort()
        symbol_data["xrefs"] = tuple(symbol_data["xrefs"])
    
    return symbols

def process_section(section_name, cursor):
    """Process a single section and rename matching symbols."""
    print(f"  [+] Processing {section_name} section...")
    
    section_seg = get_section_segment(section_name)
    if not section_seg:
        print(f"[-] Error: {section_name} section not found in current database!")
        return 0, 0
    
    section_start = idc.get_segm_start(section_seg)
    section_end = idc.get_segm_end(section_seg)
    
    print(f"    [+] Building current symbol map for {section_name}...")
    current_symbols = build_current_symbols_map(section_start, section_end, section_name)
    
    # Create lookup dictionary by xref signature for O(1) matching
    current_symbols_by_xrefs = {}
    for addr, symbol_data in current_symbols.items():
        current_symbols_by_xrefs[symbol_data["xrefs"]] = (addr, symbol_data["name"])
    
    db_symbols = fetch_db_symbols(cursor, section_name)
    print(f"    [+] Processing {len(db_symbols)} symbols from database...")
    
    renamed_count = 0
    total_processed = 0
    
    # Process database symbols in batches
    BATCH_SIZE = 1000
    db_items = list(db_symbols.items())
    
    for batch_start in range(0, len(db_items), BATCH_SIZE):
        batch_end = min(batch_start + BATCH_SIZE, len(db_items))
        batch = db_items[batch_start:batch_end]
        
        progress = (batch_start / len(db_items)) * 100
        idahelpers.update_wait_box(f"Processing {section_name} symbols: ({batch_start}/{len(db_items)}) - {progress:.1f}%")
        
        for symbol_id, symbol_data in batch:
            xrefs = symbol_data["xrefs"]
            if not xrefs:
                continue
            
            # O(1) lookup instead of O(n) comparison
            if xrefs in current_symbols_by_xrefs:
                curr_addr, curr_name = current_symbols_by_xrefs[xrefs]
                if not idahelpers.is_named_data_symbol(curr_name):
                    symbol_name = symbol_data["name"]
                    idahelpers.name_until_free_index(curr_addr, symbol_name)
                    idc.set_name(curr_addr, symbol_name, idc.SN_NOWARN)
                    renamed_count += 1
                    
            total_processed += 1
    
    print(f"    [+] {section_name} section complete!")
    print(f"      [+] Renamed {renamed_count} symbols")
    return renamed_count, total_processed

def load_and_compare_symbols(cursor):
    """Main function to load and compare symbols from database with IDA database.
    
    Args:
        cursor (sqlite3.Cursor): Database cursor for executing queries
    """
    
    total_renamed = 0
    total_processed = 0
    
    sections = [".data", ".rdata"]
    for section_name in sections:
        section_renamed, section_processed = process_section(section_name, cursor)
        total_renamed += section_renamed
        total_processed += section_processed
    
    print(f"    [+] Data symbols comparison complete!")
    print(f"      [+] Total symbols renamed: {total_renamed}")
    print(f"      [+] Total symbols processed: {total_processed}")
    
    return total_renamed, total_processed
