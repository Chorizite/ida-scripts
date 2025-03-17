import idaapi
import idautils
import idc
import ida_kernwin
import ida_bytes
import ida_name
import ida_typeinf
import ida_struct
import math
import re
import importlib

import lib.idahelpers as idahelpers
importlib.reload(idahelpers)

def import_vtables(cursor):
    """Import vtables and their members from the database."""
    print("  [+] Importing vtables")
    
    # Find .rdata segment
    rdata_seg = idaapi.get_segm_by_name(".rdata")
    if not rdata_seg:
        print("    [-] Could not find .rdata segment")
        return 0, 0
    
    # Get all vtables from database
    cursor.execute('''
    SELECT v.id, v.name, v.address, v.size, v.class_name,
           m.member_index, m.member_name, m.member_address, m.member_type
    FROM vtables v
    LEFT JOIN vtable_members m ON v.id = m.vtable_id
    ORDER BY v.id, m.member_index
    ''')
    
    rows = cursor.fetchall()
    if not rows:
        print("    [-] No vtables found in database")
        return 0, 0
    
    # Group rows by vtable
    vtables = {}
    for row in rows:
        vtable_id = row[0]
        if vtable_id not in vtables:
            vtables[vtable_id] = {
                'name': row[1],
                'address': row[2],
                'size': row[3],
                'class_name': row[4],
                'members': []
            }
        if row[5] is not None:  # If there are members
            vtables[vtable_id]['members'].append({
                'index': row[5],
                'name': row[6],
                'address': row[7],
                'type': row[8]
            })
    
    total_vtables = len(vtables)
    processed = 0
    imported_vtables = 0
    imported_members = 0
    
    # Process each vtable
    for vtable_id, vtable in vtables.items():
        processed += 1
        percentage = (processed / total_vtables) * 100
        idahelpers.update_wait_box(f"Importing vtables... ({processed}/{total_vtables}) - {percentage:.1f}%")
        
        # Check if we can find this vtable in the current database
        curr_ea = idc.get_name_ea_simple(vtable['name'])
        curr_name = ida_name.get_name(curr_ea)

        if curr_name:
            imported_vtables += 1
                
            # Process members
            for member in vtable['members']:
                # Get the function pointer
                ptr = ida_bytes.get_dword(curr_ea)
                
                # Set the member name if it's not already named
                member_name = ida_name.get_name(ptr)
                if not member_name or member_name.startswith("sub_") or member_name.startswith("xxgen_"):
                    if member['name'] and ida_name.set_name(ptr, member['name'], ida_name.SN_NOWARN):
                        imported_members += 1
                        
                        # Try to set the function type if available
                        if member['type']:
                            tinfo = ida_typeinf.tinfo_t()
                            if tinfo.get_named_type(idaapi.get_idati(), member['type']):
                                ida_typeinf.apply_tinfo(ptr, tinfo, ida_typeinf.TINFO_DEFINITE)
                
                curr_ea += 4
    
    print(f"    [+] Imported {imported_vtables:,} vtables")
    print(f"    [+] Imported {imported_members:,} vtable members")
    return imported_vtables, imported_members
