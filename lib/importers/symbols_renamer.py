import re
import idc
import idaapi
import idautils
import ida_kernwin
import ida_name
import ida_funcs
import ida_typeinf
import math
from lib import idahelpers

def rename_patterned_subroutines(cursor):
  """rename subroutines that match a pattern"""

  print("  [+] Renaming patterned subroutines")

  # Get total count first for progress
  total_funcs = len(list(idautils.Functions()))
  renamed_counts = {
    "init_string": 0,
    "logging_category_init": 0,
    "pstring_array_init": 0,
    "compute_str_hash": 0,
    "null_exit": 0,
    "wide_string_init": 0,
    "static_math_init": 0
  }

  # Helper function to process functions with a specific pattern matcher
  def process_functions_with_pattern(pattern_name, matcher_func, extra_args=None):
    processed = 0
    for func_ea in idautils.Functions():
      processed += 1
      percentage = (processed / total_funcs) * 100
      idahelpers.update_wait_box(f"Checking for {pattern_name} functions... ({processed}/{total_funcs}) - {percentage:.1f}%")

      # Get the function object and name
      func = ida_funcs.get_func(func_ea)
      if not func:
        continue
        
      func_name = ida_name.get_name(func_ea)
      if not func_name:
        continue
      
      if not func_name.startswith("nullsub_") and not func_name.startswith("sub_") and not func_name.startswith("$"):
        continue

      # Call the matcher function with any extra arguments
      if extra_args:
        if matcher_func(func_ea, *extra_args):
          renamed_counts[pattern_name] += 1
      else:
        if matcher_func(func_ea):
          renamed_counts[pattern_name] += 1

  # Process each pattern type separately
  process_functions_with_pattern("null_exit", _try_match_null_exit_func)
  process_functions_with_pattern("init_string", _try_match_init_string_func)
  process_functions_with_pattern("logging_category_init", _try_match_logging_category_init_func)
  process_functions_with_pattern("compute_str_hash", _try_match_compute_str_hash_func)
  process_functions_with_pattern("pstring_array_init", _try_match_pstring_array_init_func, [cursor])
  process_functions_with_pattern("wide_string_init", _try_match_wide_string_init_func, [cursor])
  process_functions_with_pattern("static_math_init", _try_match_static_math_init_func, [cursor])

  # Print results
  print(f"    [+] Renamed {renamed_counts['init_string']:,} string initializer subroutines")
  print(f"    [+] Renamed {renamed_counts['logging_category_init']:,} logging category initializer subroutines")
  print(f"    [+] Renamed {renamed_counts['pstring_array_init']:,} PStringBase array initializer subroutines")
  print(f"    [+] Renamed {renamed_counts['compute_str_hash']:,} compute string hash subroutines")
  print(f"    [+] Renamed {renamed_counts['null_exit']:,} null exit subroutines")
  print(f"    [+] Renamed {renamed_counts['wide_string_init']:,} wide string initializer subroutines")
  print(f"    [+] Renamed {renamed_counts['static_math_init']:,} static math initializer subroutines")

def _try_match_static_math_init_func(ea, cursor):
    """Check if the function is a static math initializer by analyzing its characteristics"""

    """
.text:00722930 sub_722930      proc near               ; DATA XREF: .data:0081751C↓o
.text:00722930                 fld     ds:flt_802C70
.text:00722936                 fmul    ds:flt_7938B4
.text:0072293C                 fstp    flt_8FADEC
.text:00722942                 retn
.text:00722942 sub_722930      endp
    """

    disasm_lines = idahelpers.get_function_disasm_lines(ea)
    if len(disasm_lines) < 3 or not "retn" in disasm_lines[-1]:
        return False
    
    valid_opcodes = ["fld", "fmul", "fstp", "retn", "fadd", "fsub", "fdiv", "fsubr", "fdivr"]

    for line in disasm_lines:
        if not any(opcode in line for opcode in valid_opcodes):
            return False
    
    idahelpers.name_until_free_index(ea, f"xxgen__InitStaticMath")

    return True


def _try_match_wide_string_init_func(ea, cursor):
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
    """

    # quick check to see if the function is a wide string initializer
    disasm_lines = idahelpers.get_function_disasm_lines(ea)
    if len(disasm_lines) != 14 or not "call    ds:wcslen" in disasm_lines[1]:
        return False

    success, matches = idahelpers.is_function_disasm_match(ea, [
      r"push    offset (?P<string_rdata_name>\S+);?",
      r"call    ds.*wcslen",
      r"add     esp, 4",
      r"push    eax",
      r"mov     ecx, offset (?P<string_data_name>\S+)",
      r"call    .*allocate_ref_buffer.*PStringBase",
      r"call    ds.*wcscpy",
      r"push    offset (?P<deref_sub_name>\S+)",
      r"call    _atexit",
      r"add     esp, 0Ch",
      r"retn",
    ], strict=False, disasm_lines=disasm_lines)

    if not success:
        return False
    
    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', matches['string_rdata_name']).strip("_")
    dname = matches['string_data_name'].strip(";")
    rname = matches['string_rdata_name'].strip(";")
    deref_name = matches['deref_sub_name'].strip(";")

    # Look up the rdata name in the wstrings table
    cursor.execute("""
        SELECT data_name
        FROM wstrings
        WHERE rdata_name = ?
    """, (rname,))
    
    db_match = cursor.fetchone()
    
    if db_match and not idahelpers.is_named_data_symbol(dname):
        dword_ea = _get_address_from_name(dname)
        if dword_ea:
            # Use the data_name from the database
            db_data_name = db_match[0]
            idx = idahelpers.name_until_free_index(dword_ea, db_data_name)
            
            # Set the type to PStringBase<ushort>
            type_str = "PStringBase<ushort>"
            str_tif = idahelpers.create_tinfo_from_string(type_str, 2)
            str_ptr_tif = ida_typeinf.tinfo_t()
            str_ptr_tif.create_ptr(str_tif)
            ida_typeinf.apply_tinfo(dword_ea, str_ptr_tif, ida_typeinf.TINFO_DEFINITE)
            
            # Rename the function with the same index if one was used
            if idx:
                clean_name = f"{clean_name}_{idx}"
    
    deref_ea = idc.get_name_ea_simple(deref_name)
    if deref_ea:
        idahelpers.name_until_free_index(deref_ea, f"xxgen__Exit_DerefWideString__{clean_name}")

    idahelpers.name_until_free_index(ea, f"xxgen__InitWideString__{clean_name}")

    return True




def _try_match_null_exit_func(ea):
    """Check if the function is a null exit function by analyzing its characteristics"""

    """
.text:00715E80 sub_715E80      proc near               ; DATA XREF: .data:00815B84↓o
.text:00715E80                 push    offset xxgen__nullsub_0077FFE0 ; void (__cdecl *)()
.text:00715E85                 call    _atexit
.text:00715E8A                 pop     ecx
.text:00715E8B                 retn
.text:00715E8B sub_715E80      endp

.text:00715E90 sub_715E90      proc near               ; DATA XREF: .data:00815B88↓o
.text:00715E90                 push    offset xxgen__nullsub_0077FFF0 ; void (__cdecl *)()
.text:00715E95                 call    _atexit
.text:00715E9A                 pop     ecx
.text:00715E9B                 retn
.text:00715E9B sub_715E90      endp

.text:006F3340 xxgen__exit_nullsub_392 proc near       ; DATA XREF: .data:0081107C↓o
.text:006F3340                 push    offset xxgen__nullsub_00762200 ; void (__cdecl *)()
.text:006F3345                 call    _atexit
.text:006F334A                 pop     ecx
.text:006F334B                 retn
.text:006F334B xxgen__exit_nullsub_392 endp

    """
    disasm_lines = idahelpers.get_function_disasm_lines(ea)

    if len(disasm_lines) != 4:
        return False

    success, matches = idahelpers.is_function_disasm_match(ea, [
        r"push    offset .*null",
        r"call    _atexit",
        r"pop     ecx",
        r"retn",
    ], strict=True, disasm_lines=disasm_lines)

    if not success:
        return False

    idahelpers.name_until_free_index(ea, f"xxgen__Exit_nullsub")

    return True


def _try_match_compute_str_hash_func(ea):
    """Check if the function is a compute string hash function by analyzing its characteristics"""

    """
.text:006F85C0 $E124_49        proc near               ; DATA XREF: .data:00811D88↓o
.text:006F85C0                 push    offset aProgress ; "PROGRESS"
.text:006F85C5                 call    ?compute_str_hash@@YAKPBD@Z ; compute_str_hash(char const *)
.text:006F85CA                 add     esp, 4
.text:006F85CD                 mov     dword_841C74, eax
.text:006F85D2                 retn
.text:006F85D2 $E124_49        endp
    """

    # quick check to see if the function is a compute string hash function
    disasm_lines = idahelpers.get_function_disasm_lines(ea)
    if len(disasm_lines) != 5 or not "retn" in disasm_lines[4] or not "compute_str_hash" in disasm_lines[1]:
        return False

    success, matches = idahelpers.is_function_disasm_match(ea, [
        r"push    offset (?P<string_rdata_name>\S+)",
        r"call    .*compute_str_hash",
        r"add     esp, 4",
        r"mov     (?P<hash_data_name>[^,]+), eax",
        r"retn",
    ], strict=True, disasm_lines=disasm_lines)

    if not success:
        return False

    dname = matches['hash_data_name']
    rname = matches['string_rdata_name']
    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', rname).strip("_")

    if dname.startswith("dword ptr Buffer"):
        buffer_offset = dname.split("+")[1][:-1]
        if not idc.create_dword(int(buffer_offset, 16)):
            print(f"    [+] Failed to create dword at {buffer_offset}")
            return False
        _rename_data_entry(int(buffer_offset, 16), rname, "ID")

    elif not idahelpers.is_named_data_symbol(dname):
        dword_ea = _get_address_from_name(dname)
        _rename_data_entry(dword_ea, rname, "ID")

    idahelpers.name_until_free_index(ea, f"xxgen__ComputeIdHash__{clean_name}")

    return True

def _try_match_init_string_func(ea):
    """Check if the function is an init function by analyzing its characteristics
    if it is, rename it and the dword it references if undefined name"""

    """
    .text:0070F2E0 sub_70F2E0      proc near               ; DATA XREF: .data:00814C8C↓o
    .text:0070F2E0                 push    offset aBounce  ; "Bounce"
    .text:0070F2E5                 mov     ecx, offset dword_8EF160
    .text:0070F2EA                 call    sub_401340
    .text:0070F2EF                 push    offset sub_7787F0
    .text:0070F2F4                 call    _atexit
    .text:0070F2F9                 pop     ecx
    .text:0070F2FA                 retn
    .text:0070F2FA sub_70F2E0      endp

    .text:006C8580 $E255           proc near               ; DATA XREF: .data:0080B97C↓o
    .text:006C8580                 push    offset aFrameloop ; "FrameLoop"
    .text:006C8585                 mov     ecx, (offset byte_8388D0+534h)
    .text:006C858A                 call    ??0?$PStringBase@D@@QAE@PBD@Z ; PStringBase<char>::PStringBase<char>(char const *)
    .text:006C858F                 push    offset $E256_15 ; void (__cdecl *)()
    .text:006C8594                 call    _atexit
    .text:006C8599                 pop     ecx
    .text:006C859A                 retn
    .text:006C859A $E255           endp
    """

    # quick check to see if the function is an init string function
    disasm_lines = idahelpers.get_function_disasm_lines(ea)
    if len(disasm_lines) != 7 or not "call    _atexit" in disasm_lines[4]:
        if ea == 0x006C8580: print(f"failed early: {ea:08X} {disasm_lines}")
        return False

    success, matches = idahelpers.is_function_disasm_match(ea, [
        r"push    offset (?P<string_rdata_name>\S+)",
        r"mov     ecx, (offset (?P<string_data_name>\S+)|.*_(?P<string_data_offset>[0-9A-Z]+\+[0-9A-Z]+h))",
        r"call",
        r"push    offset (?P<deref_sub_name>\S+)",
        r"call    _atexit",
        r"pop     ecx",
        r"retn",
    ], strict=True, disasm_lines=disasm_lines)
    
    if not success:
        if ea == 0x006C8580: print(f"failed is_function_disasm_match: {ea:08X} {disasm_lines}")
        return False

    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', matches['string_rdata_name']).strip("_")
    dname = matches['string_data_name']
    doffset = matches['string_data_offset']
    rname = matches['string_rdata_name']
    deref_name = matches['deref_sub_name']

    if doffset:
        data_offset = int(doffset.split("+")[0], 16)
        data_offset_offset = int(doffset.split("+")[1].strip("h"), 16)
        data_offset += data_offset_offset
        dname = f"byte_8388D0+{data_offset:02X}"
        print(f"doffset: {doffset}")

        tmp_name = "__" + hex(data_offset) + "__" + clean_name
        if not ida_name.set_name(data_offset, tmp_name, ida_name.SN_NOWARN):
            print(f"    [+] Failed to set name for {data_offset}: {tmp_name}")
        dname = tmp_name

    # Handle case where data symbol needs to be renamed
    if not idahelpers.is_named_data_symbol(dname) or dname.startswith("__"):
        dword_ea = _get_address_from_name(dname)
        idx = _rename_data_entry(dword_ea, rname, "KW")
        # change the type of the array to PStringBase<char> of size db_data_size / 4
        type_str = f"PStringBase<char>"
        str_tif = idahelpers.create_tinfo_from_string(type_str, 4)

        #make sure str_ptr_tif is a pointer
        str_ptr_tif = ida_typeinf.tinfo_t()
        str_ptr_tif.create_ptr(str_tif)
        ida_typeinf.apply_tinfo(dword_ea, str_ptr_tif, ida_typeinf.TINFO_DEFINITE)

        _rename_string_functions(ea, deref_name, clean_name, idx)
    else:
        idahelpers.name_until_free_index(ea, f"xxgen__InitString__{clean_name}")
        dword_ea = _get_address_from_name(dname)
        idx = _rename_data_entry(dword_ea, rname, "KW")
        _rename_string_functions(ea, deref_name, clean_name, idx)
    
    return True

def _try_match_logging_category_init_func(ea):
    """Check if the function is an init function by analyzing its characteristics
    if it is, rename it and the dword it references if undefined name"""

    """
.text:00715A60 sub_715A60      proc near               ; DATA XREF: .data:00815AC4↓o
.text:00715A60                 push    offset aIerrorGenerale ; "IError::GeneralError"
.text:00715A65                 call    sub_40EB20
.text:00715A6A                 add     esp, 4
.text:00715A6D                 mov     dword_8F8604, eax
.text:00715A72                 retn
.text:00715A72 sub_715A60      endp
    """
    # quick check to see if the function is a logging category initializer
    disasm_lines = idahelpers.get_function_disasm_lines(ea)
    if len(disasm_lines) != 5 or not "retn" in disasm_lines[4]:
        return False

    success, matches = idahelpers.is_function_disasm_match(ea, [
        r"push    offset (?P<string_rdata_name>\S+)",
        r"call    .*CreateLoggingCategory.*",
        r"add     esp, 4",
        r"mov     (?P<string_data_name>\S+), eax",
        r"retn",
    ], strict=True, disasm_lines=disasm_lines)

    if not success:
        return False

    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', matches['string_rdata_name']).strip("_")
    dname = matches['string_data_name']
    rname = matches['string_rdata_name']

    # Handle case where data symbol needs to be renamed
    if not idahelpers.is_named_data_symbol(dname):
        dword_ea = _get_address_from_name(dname)
        _rename_data_entry(dword_ea, rname, "LC")
    idahelpers.name_until_free_index(ea, f"xxgen__InitLogCategory__{clean_name}")

    return True

def _try_match_pstring_array_init_func(ea, cursor):
    """Check if the function is a PStringBase array initialization function by analyzing its characteristics.
    If it is, rename it and the array it references if undefined name.
    
    Example disassembly pattern:
      .text:00724670 $E186_42        proc near               ; DATA XREF: .data:$S188_41↓o
      .text:00724670                 push    offset aAuto    ; "Auto"
      .text:00724675                 mov     ecx, offset Render_AspectRatio_Choices_50 ; this
      .text:0072467A                 call    ??0?$PStringBase@D@@QAE@PBD@Z ; PStringBase<char>::PStringBase<char>(char const *)
      .text:0072467F                 push    offset aNormal  ; "Normal"
      .text:00724684                 mov     ecx, (offset Render_AspectRatio_Choices_50.m_charbuffer+4) ; this
      .text:00724689                 call    ??0?$PStringBase@D@@QAE@PBD@Z ; PStringBase<char>::PStringBase<char>(char const *)
      .text:0072468E                 push    offset aWide    ; "Wide"
      .text:00724693                 mov     ecx, (offset Render_AspectRatio_Choices_50.m_charbuffer+8) ; this
      .text:00724698                 call    ??0?$PStringBase@D@@QAE@PBD@Z ; PStringBase<char>::PStringBase<char>(char const *)
      .text:0072469D                 push    offset $E187_74 ; func
      .text:007246A2                 call    _atexit
      .text:007246A7                 pop     ecx
      .text:007246A8                 retn
      .text:007246A8 $E186_42        endp

    .text:007254D0 sub_7254D0      proc near               ; DATA XREF: .data:00817BA0↓o
    .text:007254D0                 push    offset aLow     ; "Low"
    .text:007254D5                 mov     ecx, offset unk_8FC734
    .text:007254DA                 call    ??0?$PStringBase@D@@QAE@PBD@Z ; PStringBase<char>::PStringBase<char>(char const *)
    .text:007254DF                 push    offset aMedium  ; "Medium"
    .text:007254E4                 mov     ecx, offset unk_8FC738
    .text:007254E9                 call    ??0?$PStringBase@D@@QAE@PBD@Z ; PStringBase<char>::PStringBase<char>(char const *)
    .text:007254EE                 push    offset aHigh    ; "High"
    .text:007254F3                 mov     ecx, offset unk_8FC73C
    .text:007254F8                 call    ??0?$PStringBase@D@@QAE@PBD@Z ; PStringBase<char>::PStringBase<char>(char const *)
    .text:007254FD                 push    offset sub_792520 ; void (__cdecl *)()
    .text:00725502                 call    _atexit
    .text:00725507                 pop     ecx
    .text:00725508                 retn
    .text:00725508 sub_7254D0      endp
    """
    # quick check to see if the function is a PStringBase array initializer
    disasm_lines = idahelpers.get_function_disasm_lines(ea)
    if not len(disasm_lines) > 6 or not "retn" in disasm_lines[-1] or not "call    _atexit" in disasm_lines[-3]:
        return False

    success, array_name, cleanup_func, members = idahelpers.get_string_array_initializer_members(ea)
    
    if not success or not array_name:
        return False

    # Clean up the array name to create a valid identifier
    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', array_name).strip("_")
    
    # Get array address
    array_ea = idc.get_name_ea_simple(array_name)
    if array_ea == idaapi.BADADDR:
        return False

    # Get string values for each member
    member_values = []
    for member_name in members:
        member_ea = idc.get_name_ea_simple(member_name)
        if member_ea == idaapi.BADADDR:
            continue
        member_value = idahelpers.get_data_value(member_ea)
        if member_value:
            member_values.append(member_value)

    if not member_values:
        return False

    # Look up array in database by matching member values
    cursor.execute('''
        SELECT DISTINCT a.id, a.array_name, a.data_size
        FROM pstring_arrays a
        JOIN pstring_array_members m ON m.array_id = a.id
        WHERE a.array_size = ?
        GROUP BY a.id
        HAVING COUNT(*) = ?
    ''', (len(member_values), len(member_values)))
    
    potential_arrays = cursor.fetchall()
    db_array = None

    # For each potential array, verify all member values match
    for array_id, array_name, data_size in potential_arrays:
        cursor.execute('''
            SELECT member_value 
            FROM pstring_array_members 
            WHERE array_id = ?
            ORDER BY member_index
        ''', (array_id,))
        db_values = [row[0] for row in cursor.fetchall()]
        
        if member_values == db_values:
            db_array = (array_id, array_name, data_size)
            break
    
    if db_array:
        db_array_id, db_array_name, db_data_size = db_array
        db_data_size = int(db_data_size)

        # remove any existing data symbols
        current_ea = array_ea
        while current_ea < array_ea + db_data_size:
            idc.del_items(current_ea, idc.DELIT_SIMPLE | idc.SN_NOWARN, 1)
            current_ea += 1

        # Rename the array to follow the naming convention
        idx = idahelpers.name_until_free_index(array_ea, db_array_name)
        if idx:
          clean_name = f"{db_array_name}_{idx}"
        else:
          clean_name = db_array_name

        # change the type of the array to PStringBase<char> of size db_data_size / 4
        type_str = f"PStringBase<char>"
        str_tif = idahelpers.create_tinfo_from_string(type_str, db_data_size)

        #make sure str_ptr_tif is a pointer
        str_ptr_tif = ida_typeinf.tinfo_t()
        str_ptr_tif.create_ptr(str_tif)

        # Create array of void pointers
        array_tif = ida_typeinf.tinfo_t()
        array_tif.create_array(str_ptr_tif, int(db_data_size / 4))
        ida_typeinf.apply_tinfo(array_ea, array_tif, ida_typeinf.TINFO_DEFINITE)

        # Rename the function to follow the naming convention
        idahelpers.name_until_free_index(ea, f"xxgen__InitPStringArray__{clean_name}")

        # Rename the cleanup function if needed
        if cleanup_func and not idahelpers.is_named_data_symbol(cleanup_func):
            cleanup_ea = _get_address_from_name(cleanup_func)
            if cleanup_ea:
                idahelpers.name_until_free_index(cleanup_ea, f"xxgen__Exit_DerefPStringArray__{clean_name}")
    else:
        return False
    return True

def _get_address_from_name(name):
    """Gets an address from a named symbol"""
    ea = idc.get_name_ea_simple(name)
    if ea:
        return ea
    print(f"    [+] Failed to get address from name: {name}")
    return None

def _rename_string_functions(init_func_ea, deref_name, clean_name, idx=None):
    """Rename both the init string function and its corresponding dereference function"""
    name_suffix = f"_{idx}" if idx and idx.isdigit() else ""
    init_name = f"xxgen__Init_String__{clean_name}{name_suffix}"
    deref_name_new = f"xxgen__Exit_DerefString__{clean_name}{name_suffix}"

    idahelpers.name_until_free_index(init_func_ea, init_name)

    # Rename dereference function if needed
    if not idahelpers.is_named_data_symbol(deref_name):
        deref_ea = _get_address_from_name(deref_name)
        idahelpers.name_until_free_index(deref_ea, deref_name_new)

def _rename_data_entry(dword_ea, name, prefix="KW"):
    """Rename a data entry to follow the PREFIX_NAME_1 pattern"""
    if not dword_ea:
        return
    
    name = name.startswith("a") and name[1:] or name
        
    current_name = ida_name.get_name(dword_ea)
    if not current_name or not current_name.startswith("dword_"):
        return
        
    # Clean and uppercase the name
    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', name).upper().strip("_")

    # if the name is already prefixed, don't add another prefix
    if current_name.startswith(prefix):
      clean_name = current_name.split("_")[1:]

    return idahelpers.name_until_free_index(dword_ea, f"{prefix}_{clean_name}")
