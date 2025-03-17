import lib.idahelpers as idahelpers
import re
import math
import idautils
import ida_kernwin
import ida_name
import ida_funcs
import ida_bytes
import idc
import sqlite3

def export_wide_string_init_funcs(cursor):
    """Export the wide string initializer functions and symbols"""

    print("  [+] Exporting wide string initializer functions and symbols")

    # Get total count first for progress
    total_funcs = len(list(idautils.Functions()))
    matched = 0
    processed = 0
    for func_ea in idautils.Functions():
        processed += 1
        percentage = (processed / total_funcs) * 100
        idahelpers.update_wait_box(f"Checking for wide string initializer functions... ({processed}/{total_funcs}) - {percentage:.1f}%")

        # Get the function object and name
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        
        func_name = ida_name.get_name(func_ea)
        if not func_name:
            continue

        if not func_name.startswith("$"):
            continue

        if _try_match_wide_string_init_func(func_ea, cursor, func_name):
            matched += 1

    print(f"    [+] Exported {matched} wide string initializer functions and symbols")

def _try_match_wide_string_init_func(ea, cursor, func_name):
    """Check if the function is a wide string initializer by analyzing its characteristics"""

    """
.text:00709F10 sub_709F10      proc near               ; DATA XREF: .data:008141F0↓o
.text:00709F10                 push    offset aYouCanTUseChat_0 ; "You can't use chat emotes in combat mod"...
.text:00709F15                 call    ds:wcslen
.text:00709F1B                 add     esp, 4
.text:00709F1E                 push    eax
.text:00709F1F                 mov     ecx, offset dword_871704
.text:00709F24                 call    ?allocate_ref_buffer@?$PStringBase@G@@IAE_NI@Z ; PStringBase<ushort>::allocate_ref_buffer(uint)
.text:00709F29                 mov     eax, dword_871704
.text:00709F2E                 push    offset aYouCanTUseChat_0 ; "You can't use chat emotes in combat mod"...
.text:00709F33                 push    eax             ; Destination
.text:00709F34                 call    ds:wcscpy
.text:00709F3A                 push    offset sub_7749B0 ; void (__cdecl *)()
.text:00709F3F                 call    _atexit
.text:00709F44                 add     esp, 0Ch
.text:00709F47                 retn
.text:00709F47 sub_709F10      endp

.text:00709000 $E136_30        proc near               ; DATA XREF: .data:$S138_33↓o
.text:00709000                 push    offset aYouCanTUseChat_0 ; "You can't use chat emotes in combat mod"...
.text:00709005                 call    ds:__imp__wcslen
.text:0070900B                 add     esp, 4
.text:0070900E                 push    eax             ; len
.text:0070900F                 mov     ecx, offset cant_emote_combat ; this
.text:00709014                 call    ?allocate_ref_buffer@?$PStringBase@G@@IAE_NI@Z ; PStringBase<ushort>::allocate_ref_buffer(uint)
.text:00709019                 mov     eax, cant_emote_combat.m_charbuffer
.text:0070901E                 push    offset aYouCanTUseChat_0 ; "You can't use chat emotes in combat mod"...
.text:00709023                 push    eax             ; Destination
.text:00709024                 call    ds:__imp__wcscpy
.text:0070902A                 push    offset $E137_37 ; func
.text:0070902F                 call    _atexit
.text:00709034                 add     esp, 0Ch
.text:00709037                 retn
.text:00709037 $E136_30        endp
    """

    disasm_lines = idahelpers.get_function_disasm_lines(ea)

    success, matches = idahelpers.is_function_disasm_match(ea, [
        r"push    offset (?P<string_rdata_name>\S+);?",
        r"call    ds.*wcslen",
        r"add     esp, 4",
        r"push    eax",
        r"mov     ecx, offset (?P<string_data_name>\S+);?",
        r"call    .*allocate_ref_buffer.*PStringBase",
        r"call    ds.*wcscpy",
        r"push    offset",
        r"call    _atexit",
        r"add     esp, 0Ch",
        r"retn",
    ], strict=False, disasm_lines=disasm_lines)

    if not success:
        if ea == 0x00709000: print(f"did not match: {disasm_lines}")
        return False
    
    data_name = matches['string_data_name'].strip(";")
    rdata_name = matches['string_rdata_name'].strip(";")

    #get the actual text of the rdata string
    rdata_ea = idc.get_name_ea_simple(rdata_name)
    # decode as utf-16
    rdata_value = idahelpers.get_data_value(rdata_ea)

    # Insert the data into SQLite
    cursor.execute("""
        INSERT INTO wstrings (func_name, func_offset, data_name, rdata_name, text_value)
        VALUES (?, ?, ?, ?, ?)
    """, (func_name, ea, data_name, rdata_name, rdata_value))

    return True