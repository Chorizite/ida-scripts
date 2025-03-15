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
  processed = 0
  renamed_init_string_funcs = 0
  renamed_logging_category_init_funcs = 0
  renamed_pstring_array_init_funcs = 0
  renamed_compute_str_hash_funcs = 0
  renamed_null_exit_funcs = 0

  for func_ea in idautils.Functions():
    processed += 1
    if processed % (max(math.floor(total_funcs / 100), 100)) == 0:
      percentage = (processed / total_funcs) * 100
      ida_kernwin.replace_wait_box(f"Renaming patterned subroutines... {processed}/{total_funcs} ({percentage:.1f}%)")

    # Get the function object
    func = ida_funcs.get_func(func_ea)
    if not func:
        continue
        
    # Get the function name
    func_name = ida_name.get_name(func_ea)
    if not func_name:
        continue
    
    if not func_name.startswith("sub_") and not func_name.startswith("$") and not func_name.startswith("xxgen_"):
        continue

    if _try_match_init_string_func(func_ea):
        renamed_init_string_funcs += 1
    elif _try_match_logging_category_init_func(func_ea):
        renamed_logging_category_init_funcs += 1
    elif _try_match_compute_str_hash_func(func_ea):
        renamed_compute_str_hash_funcs += 1
    elif _try_match_null_exit_func(func_ea):
        renamed_null_exit_funcs += 1
    elif _try_match_pstring_array_init_func(func_ea, cursor):
        renamed_pstring_array_init_funcs += 1

  print(f"    [+] Renamed {renamed_init_string_funcs:,} string initializer subroutines")
  print(f"    [+] Renamed {renamed_logging_category_init_funcs:,} logging category initializer subroutines")
  print(f"    [+] Renamed {renamed_pstring_array_init_funcs:,} PStringBase array initializer subroutines")
  print(f"    [+] Renamed {renamed_compute_str_hash_funcs:,} compute string hash subroutines")
  print(f"    [+] Renamed {renamed_null_exit_funcs:,} null exit subroutines")

def _try_match_null_exit_func(ea):
    """Check if the function is a null exit function by analyzing its characteristics"""

    """
.text:006C3A80 $E10            proc near               ; DATA XREF: .data:0080B058↓o
.text:006C3A80                 mov     eax, dword_83742C
.text:006C3A85                 inc     eax
.text:006C3A86                 push    offset xxgen__nullsub_00725CC0 ; void (__cdecl *)()
.text:006C3A8B                 mov     word ptr dword_837420, ax
.text:006C3A91                 call    _atexit
.text:006C3A96                 pop     ecx
.text:006C3A97                 retn
.text:006C3A97 $E10            endp
    """
    return False


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
    ], strict=True)

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
        return False
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
    """

    # quick check to see if the function is an init string function
    disasm_lines = idahelpers.get_function_disasm_lines(ea)
    if len(disasm_lines) != 7 or not "call    _atexit" in disasm_lines[4]:
        return False

    success, matches = idahelpers.is_function_disasm_match(ea, [
        r"push    offset (?P<string_rdata_name>\S+)",
        r"mov     ecx, offset (?P<string_data_name>\S+)",
        r"call",
        r"push    offset (?P<deref_sub_name>\S+)",
        r"call    _atexit",
        r"pop     ecx",
        r"retn",
    ], strict=True)
    
    if not success:
        return False

    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', matches['string_rdata_name']).strip("_")
    dname = matches['string_data_name']
    rname = matches['string_rdata_name']
    deref_name = matches['deref_sub_name']

    # Handle case where data symbol needs to be renamed
    if not idahelpers.is_named_data_symbol(dname):
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
    ], strict=True)

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
        member_value = idc.get_strlit_contents(member_ea, -1, idc.STRTYPE_C)
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

    # Rename init function
    if not idc.set_name(init_func_ea, init_name, idc.SN_NOWARN):
        print(f"    [+] Failed to rename {init_func_ea:08X} to {init_name}")

    # Rename dereference function if needed
    if not idahelpers.is_named_data_symbol(deref_name):
        deref_ea = _get_address_from_name(deref_name)
        if not idc.set_name(deref_ea, deref_name_new, idc.SN_NOWARN):
            print(f"    [+] Failed to rename {deref_ea:08X} to {deref_name_new}")

def _rename_data_entry(dword_ea, name, prefix="KW"):
    """Rename a data entry to follow the PREFIX_NAME_1 pattern"""
    if not dword_ea:
        return
        
    current_name = ida_name.get_name(dword_ea)
    if not current_name or not current_name.startswith("dword_"):
        return
        
    # Clean and uppercase the name
    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', name).upper().strip("_")

    # if the name is already prefixed, don't add another prefix
    if current_name.startswith(prefix):
      clean_name = current_name.split("_")[1:]

    return idahelpers.name_until_free_index(dword_ea, f"{prefix}_{clean_name}")
