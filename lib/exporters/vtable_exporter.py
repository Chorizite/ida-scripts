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
import lib.idahelpers as idahelpers

def _find_vtables():
    """Find vtables in .rdata section by looking for arrays of function pointers."""
    vtables = []
    
    # Find .rdata segment
    rdata_seg = idaapi.get_segm_by_name(".rdata")
    if not rdata_seg:
        print("    [-] Could not find .rdata segment")
        return vtables
    
    print("    [+] Scanning .rdata segment for vtables...")
    
    # Calculate total addresses to scan for progress reporting
    total_addrs = rdata_seg.end_ea - rdata_seg.start_ea
    processed = 0
    
    # Iterate through .rdata segment looking for vtables
    ea = rdata_seg.start_ea
    while ea < rdata_seg.end_ea:
        processed += 1
        percentage = (processed / total_addrs) * 100
        idahelpers.update_wait_box(f"Scanning for vtables... ({processed}/{total_addrs}) - {percentage:.1f}%")
        
        # Check if this is a named location that could be a vtable
        name = ida_name.get_name(ea)
        if name and "??_7" in name:
            print(f"    [+] Found vtable: {name} at 0x{ea:X}")
            # Get the class name from the vtable name - extract between ??_7 and @@
            class_name = name.split("??_7")[-1].split("@@")[0] if "@@" in name else name
            
            # Find the size by counting consecutive function pointers
            size = 0
            curr_ea = ea
            while curr_ea < rdata_seg.end_ea:
                # Get the value at this address
                ptr = ida_bytes.get_dword(curr_ea)
                
                # Check if it points to code segment
                if idaapi.getseg(ptr) and idaapi.getseg(ptr).perm & idaapi.SEGPERM_EXEC:
                    size += 1
                    curr_ea +=  4
                else:
                    break
            
            if size > 0:
                # Get all member functions
                members = []
                curr_ea = ea
                for i in range(size):
                    ptr = ida_bytes.get_dword(curr_ea)
                    member_name = ida_name.get_name(ptr)
                    member_type = None
                    
                    # Try to get function type
                    tinfo = ida_typeinf.tinfo_t()
                    if ida_typeinf.guess_tinfo(tinfo, ptr):
                        member_type = str(tinfo)
                    
                    members.append((i, member_name, ptr, member_type))
                    curr_ea += 4
                
                vtables.append((name, ea, size, class_name, members))
        
        ea += 4
    
    return vtables

def dump_vtables(cursor):
    """Export vtables and their members to the database."""
    print("  [+] Extracting vtables")
    
    # Find all vtables
    vtables = _find_vtables()
    total_vtables = len(vtables)
    
    vtable_count = 0
    member_count = 0
    
    for i, (name, address, size, class_name, members) in enumerate(vtables):
        progress = (i / total_vtables) * 100
        idahelpers.update_wait_box(f"Processing vtables... ({i}/{total_vtables}) - {progress:.1f}%")
        
        # Insert vtable info into database
        cursor.execute('''
        INSERT INTO vtables (name, address, size, class_name)
        VALUES (?, ?, ?, ?)
        ''', (name, address, size, class_name))
        
        vtable_id = cursor.lastrowid
        vtable_count += 1
        
        # Process each member
        for member_index, member_name, member_address, member_type in members:
            if not member_name:
                continue
            
            # Insert member info into database
            cursor.execute('''
            INSERT INTO vtable_members (vtable_id, member_index, member_name, member_address, member_type)
            VALUES (?, ?, ?, ?, ?)
            ''', (vtable_id, member_index, member_name, member_address, member_type))
            
            member_count += 1
    
    print(f"    [+] Vtables extracted: {vtable_count}")
    print(f"    [+] Vtable members extracted: {member_count}")
    return True, vtable_count, member_count
