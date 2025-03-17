import idaapi
import idautils
import ida_typeinf
import ida_lines
import ida_bytes
import idc
import ida_kernwin
import math
import importlib
import re
import time
import os
import lib.idahelpers as idahelpers
importlib.reload(idahelpers)

_registers = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
_filled = {}

def import_method_innards(cursor):
    """Import method innards from database."""

    print("  [+] Importing method innards...")
    
    # Get total function count for progress
    total_funcs = len(list(idautils.Functions()))
    processed = 0
    matches = 0
    name_matches = 0
    
    # Cache all symbols in memory for quick lookup
    print("    [+] Caching symbols...")
    symbol_cache = {}
    cursor.execute('SELECT id, name FROM symbols')
    for symbol_id, name in cursor.fetchall():
        symbol_cache[name] = symbol_id
    
    # Iterate through all functions
    for i, func_ea in enumerate(idautils.Functions(), 1):
        idahelpers.update_wait_box(f"Comparing function disassembly... {i:,}/{total_funcs:,} ({(i/total_funcs)*100:.1f}%)")

        if func_ea != 0x00412E50:
            #continue
            pass

        
        # Get function name and object
        name = idc.get_func_name(func_ea)
        if not name:
            continue
            
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        
        # Get symbol ID from cache
        symbol_id = symbol_cache.get(name)
        if not symbol_id:
            continue
            
        # Get IDA's disassembly
        ida_disasm = idahelpers.get_function_disasm_lines(func_ea)
        
        # Get database disassembly
        cursor.execute('''
            SELECT line_text 
            FROM disasm 
            WHERE symbol_id = ?
            ORDER BY line_number
        ''', (symbol_id,))
        db_disasm = [row[0] for row in cursor.fetchall()]
        
        # Compare disassembly
        if len(ida_disasm) == len(db_disasm):
            all_match = True
            for ida_line, db_line in zip(ida_disasm, db_disasm):
                # Extract just the opcode part for comparison
                ida_opcode = ida_line.split()[0] if ida_line.split() else ""
                db_opcode = db_line.split()[0] if db_line.split() else ""
                
                if ida_opcode != db_opcode:
                    all_match = False
                    break
            
            if all_match:
                name_matches += _try_fill_method_innards(func_ea, ida_disasm, db_disasm, cursor, symbol_cache)
                matches += 1
        
        processed += 1
    
    print(f"    [+] Processed {processed:,} functions, found {matches:,} exact matches") 
    print(f"      [+] Name matches: {name_matches:,}")

def _try_fill_method_innards(func_ea, ida_disasm, db_disasm, cursor, symbol_cache):
    """Try to fill method innards from database."""

    func = idaapi.get_func(func_ea)
    if not func:
        return 0

    # Pre-calculate all line offsets once
    line_offsets = []
    curr_ea = func.start_ea
    while curr_ea < func.end_ea:
        line_offsets.append(curr_ea)
        curr_ea = idc.next_head(curr_ea)

    total_matches = 0
    for i, (ida_line, db_line) in enumerate(zip(ida_disasm, db_disasm)):
        if i >= len(line_offsets):
            break
            
        ida_line_offset = line_offsets[i]

        ida_operands = ida_line[8:].split(';')[0].split(",")
        db_operands = db_line[8:].split(';')[0].split(",")

        # compare all operands between ida and db
        for ida_operand, db_operand in zip(ida_operands, db_operands):
            if ida_operand == db_operand:
                continue

            did_type = False

            res, name, offset, reason = _is_in_data_segment(ida_operand)
            #print(f"        [+] {ida_operand} -> {res}, {name}, {offset}, {reason}")
            if res:
                _, db_name, _, _ = _is_in_data_segment(db_operand)

                if idahelpers.is_invalid_db_name(db_name):
                    return 0

                if db_name in _filled:
                    continue

                db_query_name = db_name
                if "." in db_name:
                    db_query_name = db_name.split(".")[0]

                # find existing symbol in database
                cursor.execute('''
                    SELECT s.name, s.size, s.type
                    FROM symbols s 
                    WHERE s.name = ?
                ''', (db_query_name,))
                symbol_info = cursor.fetchone()
                if not symbol_info:
                    print(f"        [-] Failed to find symbol info for {db_name} @ func 0x{func_ea:X} + {ida_line_offset:X}")
                    continue

                db_name_orig = db_name
                db_name, type_size, type = symbol_info

                if "." in db_name_orig:
                    db_name_1 = db_name_orig.split(".")[0]
                    struct_member_name = db_name_orig.split(".")[1]
                    db_type = idahelpers.create_tinfo_from_string(type, type_size)
                    struct_member_offset = idahelpers.get_struct_member_offset(db_type, struct_member_name)
                    if struct_member_offset:
                        offset = struct_member_offset

                my_ea = idc.get_name_ea_simple(name)
                if my_ea != idc.BADADDR:
                    if idahelpers.is_invalid_db_name(db_name):
                        return 0

                    # Set new name and types
                    reason = f"method_innards: found unmapped operand {name} -> {db_name} @ 0x{my_ea:X} in func 0x{func_ea:X}"
                    set_name_res, error = idahelpers.set_name_and_type(my_ea - offset, db_name, type, type_size, reason, True)
                    if set_name_res == -1:
                        print(f"        [-] Failed to rename {name} to {db_name} @ 0x{my_ea - offset:X} func 0x{func_ea:X} because {error}")
                        continue
                    
                    _filled[db_name] = True

                    if set_name_res == 1:
                        total_matches += 1
                    continue
                else:
                    print(f"        [-] Failed2 to find symbol info for {db_name}")
                    continue

            # try to transfer comment
            if not did_type and ";" in db_line:
                _try_transfer_comment(ida_line_offset, db_line, ida_line)
    
    return total_matches

def _try_transfer_comment(address, db_line, ida_line):
    has_comment = idaapi.get_cmt(address, 0)
    db_comment = db_line.split(";")[1].strip()

    if has_comment:
        idc.set_cmt(address, db_comment, 0)
        return
    
    line_with_tags = idaapi.tag_remove(ida_line)
    if ";" not in line_with_tags:
        idc.set_cmt(address, db_comment, 0)


def _is_in_data_segment(name):
    name = _clean_name(name)
    if name in _registers:
        return False, name, 0, "register"
    if "[" in name:
        return False, name, 0, "array"
    
    offset = 0
    if "+" in name:
        oname = name
        parts = name.split("+")
        name = parts[0]
        try:
            if parts[1].endswith("h"):
                offset = int(parts[1][:-1], 16)
            else:
                offset = int(parts[1])
        except Exception as e:
            print(f"        [-] Failed to parse offset {parts}       --({oname})")
            print(f"        [-] Error: {e}")

    name = name.strip()

    ea = idc.get_name_ea_simple(name) - offset
    if ea == idc.BADADDR:
        return False, name, 0, "badaddr"

    if idc.get_segm_name(ea).endswith("data"):
        return True, name, offset, "data"

    return False, name, 0, "notdata"


_bad_word_starts = ["dword", "word", "qword", "ptr", "offset"]
def _clean_name(name):
    name = name.strip()
    name = name.strip("()")
    for bad_word in _bad_word_starts:
        if name.startswith(bad_word + " "):
            name = name[len(bad_word + " "):].strip()
    return name
