import os
import re
import idc
import idaapi
import idautils
import ida_typeinf
import ida_funcs
import ida_name
import ida_struct
import ida_bytes
import ida_frame
import time
import ida_kernwin
import ida_idaapi

# Cache for storing disassembly lines
_disasm_cache = {}

# Cache for storing last used index for each base name
_name_index_cache = {}


_invalid_db_name_prefixes = ["word_", "dword_", "qword_", "xmmword_", "off_", "asc_", "unk_", "stru_", "$", "sub_"]

def is_invalid_db_name(name):
    for prefix in _invalid_db_name_prefixes:
        if name.startswith(prefix):
            return True
    return False

def set_name_and_type(ea, name, type, type_size, reason, force=False):
    if ea == idc.BADADDR:
        return -1, f"BADADDR: {reason}"
    
    existing_name = idc.get_name(ea)

    if not force:
        if is_named_data_symbol(existing_name):
            return 0, f"Already named: {reason}"
    
    # Create data symbol if one doesn't exist
    if not idc.is_data(idc.get_full_flags(ea)):
        # if the previous item is a data item, and it overlaps, resize it
        prev_item = idc.prev_head(ea)
        if prev_item and idc.is_data(idc.get_full_flags(prev_item)):
            prev_size = idc.get_item_size(prev_item)
            if ea - prev_item <= prev_size:
                ida_bytes.del_items(prev_item, 0, ea - prev_item)


        # Create data item with appropriate flags
        if type:
            tif = create_tinfo_from_string(type, type_size)
            flags = get_flags_from_arg_tinfo(tif, type_size)
            idc.create_data(ea, flags, type_size, idaapi.BADNODE)

    existing_is_indexed = existing_name.split("_")[-1].isdigit()
    name_is_indexed = name.split("_")[-1].isdigit()

    existing_is_indexed = existing_is_indexed and not is_invalid_db_name(existing_name.split("_")[0])
    name_is_indexed = name_is_indexed and not is_invalid_db_name(name.split("_")[0])

    if existing_is_indexed and name_is_indexed and existing_name.split("_")[0] == name.split("_")[0]:
        return 0, f"Already named: {reason}"
    
    if existing_is_indexed and not name_is_indexed and existing_name.split("_")[0] == name:
        return 0, f"Already named: {reason}"
    
    if not existing_is_indexed and name_is_indexed and existing_name == name.split("_")[0]:
        return 0, f"Already named: {reason}"
        
    name_res = idc.set_name(ea, name, idc.SN_NOWARN | ida_name.SN_FORCE | ida_name.SN_NOCHECK) and 1 or -1

    if name_res == 1 and type != None:
        try:
            type = type.replace("_DWORD (__stdcall *[", "int (__stdcall void *[")
            tif = create_tinfo_from_string(type, type_size)
            ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
        except Exception as e:
            print(f"        [-] Failed to apply type {type} for {name} @ 0x{ea:X}")
            print(f"        [-] Error: {e}")

    if name_res == 1:
        with open("name_res.txt", "a") as f:
            f.write(f"{name} @ 0x{ea:X} got renamed because {reason}\n")
        return 1, "OK"
    else:
        return -1, f"Failed to set name {existing_is_indexed} {name_is_indexed}"

def get_xref_type(xref):
    """Get the type of a cross-reference."""
    if xref.type == idaapi.fl_CF or xref.type == idaapi.fl_CN:
        xref_type = "call"
    elif xref.type == idaapi.fl_JF or xref.type == idaapi.fl_JN:
        xref_type = "jump"
    else:
        # Try to determine data reference type
        try:
            op_type = idc.get_operand_type(xref.frm, xref.iscode)
            if op_type == idc.o_mem or op_type == idc.o_displ:
                xref_type = "read"  # Reasonable default for most data references
            else:
                xref_type = "data"  # Generic data reference
        except:
            xref_type = "data"
    return xref_type

def get_symbol_type_from_addr(addr):
    """Get the actual type information for a symbol at the given address."""
    tinfo = ida_typeinf.tinfo_t()
    if ida_typeinf.guess_tinfo(tinfo, addr):
        # Get the type name
        type_name = tinfo.get_type_name()
        if type_name:
            return type_name
        
        # If no type name, try to get a string representation
        type_str = str(tinfo)
        if type_str:
            return type_str
    
    # If we couldn't get type info, try to get the type from the name
    name = idc.get_name(addr)
    if name and "<?>" in name:
        # Extract the type from the name (e.g., "Legacy_Vector3_ZeroVector___250 AC1Legacy::Vector3 <?>")
        parts = name.split("<?>")
        if len(parts) > 1:
            type_part = parts[0].strip().split()[-1]  # Get the last part before <?>
            return type_part
    
    return "Unknown"

def is_subroutine(address):
    # Check if an address is within a function
    is_func_member = ida_funcs.get_func(address) is not None

    # Get function details
    func = ida_funcs.get_func(address)
    if func:
        # Is it a function chunk rather than a main function?
        is_func_chunk = func.flags & ida_funcs.FUNC_THUNK or func.start_ea != address
        is_local_func = func.flags & ida_funcs.FUNC_LIB  # Library/local function

    return is_func_member and not is_func_chunk and not is_local_func

def find_named_segment(name):
    for seg in idautils.Segments():
        seg_name = idc.get_segm_name(seg)
        if seg_name.lower() == name.lower():
            return seg
    return None

def is_named_data_symbol(name):
    badstarts = ["$", "jpt_", "locret_", "def_", "byte_" "unk_", "sub_", "nullsub_", "loc_", "stru_", "off_", "asc_", "word_", "dword_", "xmmword_", "flt_", "dbl_"]
    for badstart in badstarts:
        if name.startswith(badstart):
            return False
    return True

def get_member_simple_type(member):
    # Get the member's type information
    tinfo = ida_typeinf.tinfo_t()
    if ida_typeinf.guess_tinfo(tinfo, member.id):
        # Convert tinfo to string representation
        type_str = str(tinfo)
        return type_str
    else:
        # If we couldn't get detailed type info, try to get basic type
        flags = member.flag
        if flags & ida_bytes.off_flag():
            return "offset"
        elif flags & ida_bytes.byte_flag():
            return "byte"
        elif flags & ida_bytes.word_flag():
            return "word"
        elif flags & ida_bytes.dword_flag():
            return "dword"
        elif flags & ida_bytes.qword_flag():
            return "qword"
        else:
            return "unknown"

def get_frame_info(func_ea):
    """
    Gets information about the stack frame for a function.
    
    Args:
        func_ea: The address of the function
        
    Returns:
        A dictionary containing frame information
    """
    # Get the function object
    func = idaapi.get_func(func_ea)
    if not func:
        print(f"No function at address 0x{func_ea:X}")
        return None
    
    # Get the stack frame
    frame = idaapi.get_frame(func)
    if not frame:
        print(f"Function at 0x{func_ea:X} has no frame")
        return None
    
    # Get frame information
    frame_size = idaapi.get_struc_size(frame)
    
    # Get the return address offset (often stored in " r")
    r_id = idaapi.get_member_by_name(frame, " r")
    r_offset = r_id.soff if r_id else None
    
    # Get the saved registers offset (often stored in " s")
    s_id = idaapi.get_member_by_name(frame, " s")
    s_offset = s_id.soff if s_id else None
    
    # Determine the frame pointer (FP) value relative to stack pointer (SP)
    pfn = idaapi.get_func(func_ea)
    frame_reg = pfn.frame
    
    # Calculate key offsets
    arg_base = 0  # Arguments typically start at offset 0 or higher
    local_base = pfn.frsize
    
    return {
        "function_name": idaapi.get_func_name(func_ea),
        "function_address": func_ea,
        "frame_size": frame_size,
        "return_address_offset": r_offset,
        "saved_regs_offset": s_offset,
        "frame_reg": frame_reg,
        "arg_base": arg_base,
        "local_base": local_base
    }

def get_stack_member_info(func_ea, offset):
    """
    Analyzes a stack member to determine if it's a local variable or parameter.
    
    Args:
        func_ea: The address of the function
        offset: The offset within the stack frame
        
    Returns:
        A string indicating the type: "local", "parameter", or "special"
    """
    frame_info = get_frame_info(func_ea)
    if not frame_info:
        return "unknown"
    
    # Check if it's a special member
    if frame_info["return_address_offset"] == offset:
        return "special (return address)"
    if frame_info["saved_regs_offset"] == offset:
        return "special (saved registers)"
    
    # In many architectures:
    # - Negative offsets from FP are local variables
    # - Positive offsets from FP are parameters
    if offset < 0:
        return "local variable"
    else:
        return "parameter"

def get_flags_from_arg_tinfo(tinfo, size):
    """
    Get the appropriate flags for a variable based on its tinfo_t type.
    
    Args:
        tinfo: tinfo_t object representing the variable type
        size: size of the data type
    Returns:
        flags for the variable
    """
    # Default to data flag
    flags = idaapi.FF_DATA
    
    # Add type-specific flags
    if tinfo.is_ptr():
        flags |= idaapi.FF_QWORD if size == 8 else idaapi.FF_DWORD  # Most pointers are DWORD (32-bit) or QWORD (64-bit)
    elif tinfo.is_array():
        element_size = tinfo.get_array_element().get_size()
        if element_size == 1:
            flags |= idaapi.FF_BYTE
        elif element_size == 2:
            flags |= idaapi.FF_WORD
        elif element_size == 4:
            flags |= idaapi.FF_DWORD
        elif element_size == 8:
            flags |= idaapi.FF_QWORD
        else:
            flags |= idaapi.FF_STRUCT  # Treat complex arrays as structs
    elif tinfo.is_struct():
        flags |= idaapi.FF_STRUCT
    elif tinfo.is_enum():
        flags |= idaapi.FF_0NUMH  # Enum flag
    elif tinfo.is_bitfield():
        flags |= idaapi.FF_0NUMD  # Bitfield flag
    else:
        # Handle primitive types based on size
        if size == 1:
            flags |= idaapi.FF_BYTE
        elif size == 2:
            flags |= idaapi.FF_WORD
        elif size == 4:
            flags |= idaapi.FF_DWORD
        elif size == 8:
            flags |= idaapi.FF_QWORD
        else:
            flags |= idaapi.FF_STRUCT  # Default to struct for complex types
    
    return flags

def create_tinfo_from_string(type_str, size):
    """
    Create a tinfo_t object from a type string.
    Args:
        type_str: C-style type declaration (e.g., "int", "char *", "struct point")
        size: size of the data type
    Returns:
        tinfo_t object if successful, None otherwise
    """
    type_str = str(type_str).strip()
    original_type_str = type_str  # Keep original for IDA parsing attempts

    
    
    # Basic types dictionary
    basic_types = {
        "int": ida_typeinf.BTF_INT,
        "unsigned int": ida_typeinf.BTF_UINT,
        "char": ida_typeinf.BTF_CHAR,
        "unsigned char": ida_typeinf.BTF_UCHAR,
        "short": ida_typeinf.BTF_INT16,
        "unsigned short": ida_typeinf.BTF_UINT16,
        "long": ida_typeinf.BTF_INT32,
        "unsigned long": ida_typeinf.BTF_UINT32,
        "long long": ida_typeinf.BTF_INT64,
        "unsigned long long": ida_typeinf.BTF_UINT64,
        "float": ida_typeinf.BTF_FLOAT,
        "double": ida_typeinf.BTF_DOUBLE,
        "bool": ida_typeinf.BTF_BOOL,
        "void": ida_typeinf.BTF_VOID,
        "__int16": ida_typeinf.BTF_INT16,
        "__int32": ida_typeinf.BTF_INT32
    }

    if type_str.lower() in basic_types:
        tif = ida_typeinf.tinfo_t()
        tif.create_simple_type(basic_types[type_str.lower()])
        return tif
    
    # Check if this is already an array pattern like "type[size]"
    array_match = re.match(r'^(.*?)(\[\d+\])$', type_str)
    if array_match:
        base_type = array_match.group(1).strip()
        array_size = int(array_match.group(2).strip('[]'))
        # Try to create base type first
        base_tif = create_tinfo_from_string(base_type, 4)  # Default element size

        # Create the array type if we have a valid base type
        if base_tif:
            array_tif = ida_typeinf.tinfo_t()
            if array_tif.create_array(base_tif, array_size):
                return array_tif
    
    # Rest of original function
    # Remove keywords but remember if it was an enum
    is_enum = False
    if type_str.startswith("enum "):
        is_enum = True
        type_str = type_str.replace("enum ", "")
    
    # Handle other keywords
    bad_keywords = ["const", "struct", "class"]
    for k in bad_keywords:
        if type_str.startswith(k + " "):
            type_str = type_str.replace(k + " ", "")
    
    # Detect array types (e.g., "char[260]" or "enum CharCase[50]")
    if "[" in type_str and "]" in type_str:
        base_type, array_size = type_str.split("[")
        base_type = base_type.strip()
        array_size = int(array_size.rstrip("]"))
        
        # Create the base type
        base_tif = None
        
        # Try to create the base type
        if is_enum:
            # For enums, try to use IDA's built-in parsing
            enum_tif = ida_typeinf.tinfo_t()
            enum_type_str = "enum " + base_type
            
            if enum_tif.get_named_type(ida_typeinf.get_idati(), enum_type_str):
                base_tif = enum_tif
            elif ida_typeinf.parse_decl(enum_tif, None, enum_type_str, ida_typeinf.PT_SIL) == 0:
                base_tif = enum_tif
        elif base_type in basic_types:
            # For basic types, create directly
            base_tif = ida_typeinf.tinfo_t()
            base_tif.create_simple_type(basic_types[base_type])
        else:
            # Try IDA's built-in parsing for other types
            base_tif = ida_typeinf.tinfo_t()
            if base_tif.get_named_type(ida_typeinf.get_idati(), base_type):
                pass  # base_tif is now set
            elif ida_typeinf.parse_decl(base_tif, None, base_type, ida_typeinf.PT_SIL) == 0:
                pass  # base_tif is now set
        
        # If we successfully created a base type, create the array
        if base_tif:
            array_tif = ida_typeinf.tinfo_t()
            array_tif.create_array(base_tif, array_size)
            return array_tif
    
    # Create tinfo object
    tif = ida_typeinf.tinfo_t()
    
    # First check if it's a basic type
    if type_str.lower() in basic_types:
        tif.create_simple_type(basic_types[type_str.lower()])
        return tif
    
    # Then check for pointers
    is_ptr = "*" in type_str
    ptr_level = type_str.count("*")
    if is_ptr:
        base_type = type_str.replace("*", "").strip()
        if base_type in basic_types:
            # Create the base type
            base_tif = ida_typeinf.tinfo_t()
            base_tif.create_simple_type(basic_types[base_type])
            # Add pointer levels
            for _ in range(ptr_level):
                ptr_tif = ida_typeinf.tinfo_t()
                ptr_tif.create_ptr(base_tif)
                base_tif = ptr_tif
            return base_tif
    
    # Try IDA's built-in parsing with the original type string
    if tif.get_named_type(ida_typeinf.get_idati(), original_type_str):
        return tif
    
    # Try parsing as a declaration with the original type string
    if ida_typeinf.parse_decl(tif, None, original_type_str, ida_typeinf.PT_SIL) == 0:
        return tif
    
    # Handle void pointer arrays explicitly (common case in the failures)
    if "void *[" in original_type_str:
        parts = original_type_str.split("[")
        array_size = int(parts[1].rstrip("]"))
        
        # Create void pointer
        void_ptr = ida_typeinf.tinfo_t()
        void_ptr.create_ptr(ida_typeinf.tinfo_t().get_stock(ida_typeinf.STI_PVOID))
        
        # Create array of void pointers
        array_tif = ida_typeinf.tinfo_t()
        array_tif.create_array(void_ptr, array_size)
        return array_tif
    
    # Last resort - use size information to create a type
    if size == 1:
        tif.create_simple_type(ida_typeinf.BTE_CHAR)
    elif size == 2:
        tif.create_simple_type(ida_typeinf.BT_INT16)
    elif size == 4:
        tif.create_simple_type(ida_typeinf.BT_INT32)
    elif size == 8:
        tif.create_simple_type(ida_typeinf.BT_INT64)
    else:
        # If we can't determine the type, create a byte array
        byte_tif = ida_typeinf.tinfo_t()
        byte_tif.create_simple_type(ida_typeinf.BTF_UCHAR)
        tif.create_array(byte_tif, size)
    
    return tif


def get_function_stack_return_offset(func_addr):
    func = idaapi.get_func(func_addr)
    if not func:
        return -1
    
    frame = ida_frame.get_frame(func)
    if not frame:
        return -1
    
    member_offset = ida_struct.get_struc_first_offset(frame)
    while member_offset != -1 and member_offset < 0xFFFF:
        member = idaapi.get_member(frame, member_offset)
        if not member:
            member_offset = ida_struct.get_struc_next_offset(frame, member_offset)
            continue
        member_name = idaapi.get_member_name(member.id)
        if member_name == " r":
            return member_offset
        member_offset = ida_struct.get_struc_next_offset(frame, member_offset)
    
    return -1

def get_function_disasm_lines(ea):
    """
    Get disassembly lines for a function with caching.
    
    Args:
        ea: Function address
        
    Returns:
        List of disassembly lines for the function
    """
    # Check if result is in cache
    if ea in _disasm_cache:
        return _disasm_cache[ea]
        
    disasm_lines = []
    func = idaapi.get_func(ea)
    if not func:
        return []
        
    curr_ea = func.start_ea
    while curr_ea < func.end_ea:
        line = idc.GetDisasm(curr_ea)
        if line:
            disasm_lines.append(line)
        curr_ea = idc.next_head(curr_ea)
    
    # Cache the result
    _disasm_cache[ea] = disasm_lines
    return disasm_lines

def is_function_disasm_match(ea, patterns, strict=True, disasm_lines=None):
    """
    Check if a function's disassembly matches a list of regex patterns.
    
    Args:
        ea: Function address
        patterns: List of regex patterns to match against each line of disassembly
        strict: If True, requires exact number of lines to match patterns
               If False, allows additional lines between matches
        disasm_lines: Optional pre-cached disassembly lines. If not provided, will fetch them.
    
    Returns:
        (success, matches) tuple where:
            success: Boolean indicating if all patterns matched
            matches: Dictionary of named capture groups from the patterns
    """
    func = idaapi.get_func(ea)
    if not func:
        return False, {}
        
    # Get function disassembly
    if disasm_lines is None:
        disasm_lines = get_function_disasm_lines(ea)
        
    matches = {}
    pattern_idx = 0
    line_idx = 0
    
    while pattern_idx < len(patterns) and line_idx < len(disasm_lines):
        pattern = patterns[pattern_idx]
        line = disasm_lines[line_idx]
        
        # Skip lines that don't contain instructions
        if not line.strip() or line.startswith(';'):
            line_idx += 1
            continue
            
        # Try to match the current pattern
        match = re.search(pattern, line)
        if match:
            # Add named groups to matches dict
            matches.update(match.groupdict())
            pattern_idx += 1
            line_idx += 1
        else:
            if strict:
                return False, {}
            line_idx += 1
            
    # Check if we matched all patterns
    if pattern_idx < len(patterns):
        return False, {}
        
    return True, matches



def get_string_array_initializer_members(ea):
    func = idaapi.get_func(ea)
    if not func:
        return False, None, None, []
        
    func_name = idc.get_func_name(func.start_ea)

    # Get function disassembly
    disasm_lines = []
    curr_ea = func.start_ea
    while curr_ea < func.end_ea:
        line = idc.GetDisasm(curr_ea)
        if line:
            disasm_lines.append(line)
        curr_ea = idc.next_head(curr_ea)
        
    members = []
    line_idx = 0

    array_name = None
    cleanup_func = None
    while line_idx < len(disasm_lines):
        line = disasm_lines[line_idx]
        
        match = re.search(r"push\s+offset\s+(?P<string_name>\S+)", line)
        if match:
            members.append(match.group('string_name').strip(';'))
            line_idx += 1
            line = disasm_lines[line_idx]
        else:
            return False, None, None, []
        
        if "mov     ecx," in line:
            if array_name is None:
                array_name = line.split("offset ")[1].split(" ")[0].strip(';')
            line_idx += 1
            line = disasm_lines[line_idx]
        else:
            return False, None, None, []
        
        if "call" in line and "PStringBase" in line:
            line_idx += 1
            line = disasm_lines[line_idx]
        else:
            return False, None, None, []
        
        # check for ending
        if "retn" in disasm_lines[line_idx + 3] and "_atexit" in disasm_lines[line_idx + 1]:
            cleanup_func = line.split("offset ")[1].split(" ")[0].strip(';')
            break

    return True, array_name, cleanup_func, members


def name_until_free_index(ea, name):
  """Return the name until the first free index"""

  # if the name already ends with an index, don't add another one
  if name.split("_")[-1].isdigit():
    new_name = name
    name = "_".join(name.split("_")[:-1])
  else:
    new_name = name

  # Check cache for the last used index for this base name
  if name in _name_index_cache:
    idx = _name_index_cache[name]
  else:
    idx = 1

  while not ida_name.set_name(ea, new_name, ida_name.SN_NOWARN):
    new_name = f"{name}_{idx}"
    idx += 1

  # Update cache with the successful index
  _name_index_cache[name] = idx
  return new_name.split("_")[-1]

def get_data_value(ea):
    """
    Get the string value of a data symbol at the given address.
    
    Args:
        ea: Address of the data symbol
    """

    
    size = idc.get_item_size(ea)
    type_name = get_symbol_type_from_addr(ea)

    if type_name.endswith("*") or type_name.endswith("[]"):
        return None
    if type_name == "char":
        return idc.get_wide_byte(ea) != 0
    if type_name == "int":
        return idc.get_wide_word(ea)
    elif type_name == "float":
        return idc.GetFloat(ea)
    elif type_name == "double":
        return idc.GetDouble(ea)

    is_char_array = re.match(r"w?char(_t)?\[(\d+)\]", type_name)
    is_pstring = re.match(r"PStringBase<(\w+)>", type_name)

    if is_pstring or is_char_array:
        try:
            t = idc.get_str_type(ea)
            if t == None:
                return None
            rdata_value = str(idc.get_strlit_contents(ea, -1, t))
        except:
            print(f"    [-] Error: Failed to get string value for {type_name} ({t}) at 0x{ea:08X}")
            return None

        if rdata_value.startswith("b\"") or rdata_value.startswith("b'"):
            rdata_value = rdata_value[2:-1]
            if rdata_value.endswith("\"") or rdata_value.endswith("'"):
                rdata_value = rdata_value[:-1]
        return rdata_value

_last_update = 0
def update_wait_box(text):
    """
    Update the wait box with the given text.
    """
    global _last_update
    if time.time() - _last_update > 0.1:
        ida_kernwin.replace_wait_box(text)
        _last_update = time.time()


def get_struct_member_offset(t_info, member_name):
    """
    Check if t_info represents a struct and if so, get the offset of the named member
    
    Args:
        t_info: Type info object from IDA (tinfo_t)
        member_name: Name of the struct member to find
        
    Returns:
        Offset of the member if found, None otherwise
    """
    if not t_info.is_struct():
        return None
        
    # Get the struct ID
    struct_id = ida_struct.get_struc_id(t_info.get_type_name())
    if struct_id == ida_idaapi.BADADDR:
        return None
        
    # Get the struct object
    struct = ida_struct.get_struc(struct_id)
    if not struct:
        return None
        
    # Get the member by name
    member = ida_struct.get_member_by_name(struct, member_name)
    if not member:
        return None
        
    return member.soff

def get_local_types():
    """
    Get all local types defined in the IDB.
    
    Returns:
        A list of tuples containing (type_name, type_info) for each local type.
    """
    local_types = []
    til = ida_typeinf.get_idati()  # Get type info library
    
    # Get count of local types
    ordinal = 1  # Local types start at ordinal 1
    max_ordinal = ida_typeinf.get_ordinal_qty(til)
    
    # Iterate through all ordinals
    while ordinal <= max_ordinal:
        # Get type name for current ordinal
        type_name = ida_typeinf.get_numbered_type_name(til, ordinal)
        
        if type_name:
            # Get type info
            tinfo = ida_typeinf.tinfo_t()
            if ida_typeinf.get_numbered_type(til, ordinal, tinfo):
                local_types.append((type_name, tinfo.local))
        
        ordinal += 1
        
    return local_types
