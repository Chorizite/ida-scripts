import idaapi
import idautils
import idc
import sqlite3
import os

from lib import idahelpers

def load_and_compare_symbols(db_path):
    print("[+] Starting symbol comparison...")
    
    # Ensure database exists
    if not os.path.exists(db_path):
        print(f"[-] Error: Database {db_path} not found!")
        return
    
    # Connect to SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Dictionary to store current IDA database symbols and their xrefs
    current_symbols = {}
    renamed_count = 0
    
    # Process both .data and .rdata sections
    sections = [".data", ".rdata"]
    for section_name in sections:
        print(f"\n[+] Processing {section_name} section...")
        
        # Get section in current database
        section_seg = None
        for seg in idautils.Segments():
            if idc.get_segm_name(seg).lower() == section_name.lower():
                section_seg = seg
                break
        
        if not section_seg:
            print(f"[-] Error: {section_name} section not found in current database!")
            continue
        
        section_start = idc.get_segm_start(section_seg)
        section_end = idc.get_segm_end(section_seg)
        
        # Build a dictionary of current symbols in section and their xrefs
        print(f"[+] Building current symbol map for {section_name}...")
        for addr in range(section_start, section_end):
            name = idc.get_name(addr)
            
            if name and not idahelpers.is_named_data_symbol(name):
                xref_signatures = []
                
                for xref in idautils.XrefsTo(addr):
                    xref_addr = xref.frm
                    func = idaapi.get_func(xref_addr)
                    
                    if func:
                        func_addr = func.start_ea
                        func_name = idc.get_func_name(func_addr)
                        offset = xref_addr - func_addr
                        
                        # Create a signature for this xref
                        xref_signature = (func_name, offset)
                        xref_signatures.append(xref_signature)
                
                current_symbols[addr] = {
                    "name": name,
                    "xrefs": xref_signatures,
                    "section": section_name
                }
        
        # Get all symbols from the database for this section
        cursor.execute('''
        SELECT s.id, s.name, s.address
        FROM data_symbols s
        WHERE s.section = ?
        ''', (section_name,))
        
        db_symbols = cursor.fetchall()
        section_renamed = 0
        
        # For each database symbol, get its xrefs
        for symbol_id, symbol_name, old_addr in db_symbols:
            cursor.execute('''
            SELECT xref_function, xref_offset
            FROM xrefs
            WHERE symbol_id = ?
            ''', (symbol_id,))
            
            db_xrefs = cursor.fetchall()
            xref_signatures = [(func_name, offset) for func_name, offset in db_xrefs if func_name]
            
            # If no meaningful xrefs, skip this symbol
            if not xref_signatures:
                continue
            
            # Look for matching symbols in current database
            for curr_addr, curr_symbol in current_symbols.items():
                # Skip if not in the same section
                if curr_symbol["section"] != section_name:
                    continue
                    
                curr_xrefs = curr_symbol["xrefs"]
                
                # Skip if no xrefs to compare
                if not curr_xrefs:
                    continue
                
                # Check for signature match
                # We need at least one matching xref signature
                matching_xrefs = set(xref_signatures).intersection(set(curr_xrefs))
                
                if matching_xrefs:
                    # We have a match - should we rename?
                    curr_name = curr_symbol["name"]
                    
                    # only rename if it's not a named data symbol
                    if not idahelpers.is_named_data_symbol(curr_name):
                        # Rename this symbol
                        if idc.set_name(curr_addr, symbol_name):
                            print(f"[+] Renamed {curr_name} to {symbol_name} at 0x{hex(curr_addr)} (old: 0x{hex(old_addr)})")
                            renamed_count += 1
                            section_renamed += 1
                        else:
                            print(f"[-] Failed to rename {curr_name} to {symbol_name} at 0x{hex(curr_addr)} (old: 0x{hex(old_addr)})")
        
        print(f"[+] {section_name} section complete! Renamed {section_renamed} symbols.")
    
    conn.close()
    print(f"\n[+] Comparison complete! Total symbols renamed: {renamed_count}")
