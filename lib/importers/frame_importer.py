import re

import idautils
import idc
import idaapi
import ida_typeinf
import ida_funcs
import ida_name
import ida_frame
import ida_struct
import ida_bytes
import importlib 

import lib.idahelpers as idahelpers
importlib.reload(idahelpers) 

import lib.idahelpers as idahelpers

debug = False
count_args_failed = 0
count_args = 0
count_funcs = 0
def should_skip_stack_member_name(name):
    return name == " s" or name == " r"

def find_arg_with_name_r(data, name):
    for k, arg in data.items():
        if arg["name"] == name:
            return arg
    return None

def wipe_function_frame_stack(func_addr):
    global debug
    """Delete all existing function arguments and create a single argument in the frame."""
    func = idaapi.get_func(func_addr)
    if not func:
        if debug: print(f"Could not find func at 0x{func_addr:x}")
        return False
    
    frame = ida_frame.get_frame(func)
    if not frame:
        if debug: print(f"Could not find frame for func at 0x{func_addr:x}")
        return False
    
    member_offset = ida_struct.get_struc_first_offset(frame)
    offsets_to_delete = []
    while member_offset != -1 and member_offset < 0xFFFF:
        member = idaapi.get_member(frame, member_offset)
        if not member:
            member_offset = ida_struct.get_struc_next_offset(frame, member_offset)
            continue
        member_name = idaapi.get_member_name(member.id)
        if member_offset >= 0 and not should_skip_stack_member_name(member_name):
            offsets_to_delete.append(member_offset)
        member_offset = ida_struct.get_struc_next_offset(frame, member_offset)
    
    for offset in offsets_to_delete:
        ida_struct.del_struc_member(frame, offset)

    return True

def clean_type_name(type_name):
    global debug
    return type_name.replace("struct ", "").replace("unsigned int", "int")

def compare_types(t1, t2):
    global debug
    if t1.endswith('*') and clean_type_name(t2) == "int": return True
    return (clean_type_name(t1) == clean_type_name(t2))

def create_func_args_from_type(func_ea, db_entry):
    global debug
    global count_args
    global count_funcs
    global count_args_failed
    """Create function arguments based on the function's type information with proper types."""
    func = ida_funcs.get_func(func_ea)
    if not func:
        if debug: print(f"Could not find func for {func_ea:x}")
        return False
    
    func_name = idc.get_func_name(func_ea)
    frame = ida_frame.get_frame(func)
    if not frame:
        if debug: print(f"Could not find frame for {func_ea:x} {func_name}")
        return False
    
    # Get the function type information
    tinfo = ida_typeinf.tinfo_t()
    if not ida_typeinf.guess_tinfo(tinfo, func_ea):
        if debug: print(f"Could not guess_tinfo for {func_ea:x} {func_name}")
        return False
    
    funcdata = idaapi.func_type_data_t()
    if not tinfo.get_func_details(funcdata):
        if debug: print(f"Could not get_func_details for {func_ea:x} {func_name}")
        return False
    
    # Delete existing stack frame struct first
    if not wipe_function_frame_stack(func_ea):
        print(f"Failed to wipe function stack {func_ea:x} {func_name}")
    
    if not func_name.startswith("?"):
        if debug: print(f"Skipping: 0x{func_ea:x} {func_name}")
        return False

    args = db_entry["args"]
    new_return_offset = idahelpers.get_function_stack_return_offset(func_ea)
    old_return_offset = find_arg_with_name_r(args, " r")

    adj_offset = 0
    if old_return_offset and "offset" in old_return_offset:
        old_return_offset = old_return_offset["offset"]
        if old_return_offset != new_return_offset:
            if debug: print(f"Adjusting offset because r changed: Old offset: {old_return_offset:x} New: {new_return_offset:x} diff: {old_return_offset - new_return_offset:x} on 0x{func_ea:x} {func_name}")
            adj_offset = new_return_offset - old_return_offset

    start_count_args = count_args
    member_idx = 0
    member = member_idx in args and args[member_idx] or None
    while member:
        name = member["name"]
        offset = member["offset"] + adj_offset
        size = member["size"]
        flags = member["flags"]
        type_str = str(member["type"])

        if size > 0xFFFF:
            if debug: print(f"  Skipping {name} because size is weird? {size}")
            member_idx += 1
            member = member_idx in args and args[member_idx] or None
            continue

        if not should_skip_stack_member_name(name):
          # Parse the type string to create appropriate type info
          #if type_str.endswith(" *"):
          #    type_str = type_str[:-2]
          tinfo = idahelpers.create_tinfo_from_string(type_str, size)
          flags = idahelpers.get_flags_from_arg_tinfo(tinfo, size)
          mt = None
          mt = idaapi.opinfo_t()
          mt.tid = ida_struct.get_struc_id(tinfo.get_type_name())
          # Create the new member
          if ida_struct.add_struc_member(frame, name, offset, flags, mt, size) == 0:
              # Get the member by offset rather than index
              member = ida_struct.get_member_by_name(frame, name)
              if member:
                  ida_struct.set_member_tinfo(frame, member, 0, tinfo, 0)
                  if debug: print(f"    Created argument: {name} ({tinfo}:{tinfo.get_ordinal()}) at offset 0x{offset:x} with size {size} and flags 0x{flags:x}")
                  count_args += 1
              else:
                  print(f"    FAILED to find created member {name} ({tinfo}:{tinfo.get_ordinal()}) at offset 0x{offset:x} with size {size} and flags 0x{flags:x} on {func_name}")
                  count_args_failed += 1
          else:
              print(f"    FAILED to create member {name} ({tinfo}:{tinfo.get_ordinal()}) at offset 0x{offset:x} with size {size} and flags 0x{flags:x} on {func_name}")
              count_args_failed += 1
        member_idx += 1
        member = member_idx in args and args[member_idx] or None
    
    if start_count_args != count_args:
        count_funcs += 1

def __build_args_db(function_args_file):
  global debug
  db = {}
  current_symbol = None
  current_info = { "args": {} }
  with open(function_args_file, 'r') as f:
    for line in f:
      # ?Event_ModifyCharacterSquelch@CM_Communication@@YA_NHKABV?$PStringBase@D@AC1Legacy@@K@Z size:0x2c return_offset:0x18 arg_base:0x0 local_base:0x18
      matches = re.match("^#(\S+) size:0x([a-f0-9]+) return_offset:0x([a-f0-9]+) arg_base:0x([a-f0-9]+) local_base:0x([a-f0-9]+)$", line, re.IGNORECASE)
      if matches is not None:
        if current_symbol is not None:
            db[current_symbol] = current_info
            current_info = { "args": {} }
        
        current_symbol = matches.group(1)
        current_info["return_offset"] = int(matches.group(2), 16)
        current_info["arg_base"] = int(matches.group(3), 16)
        current_info["local_base"] = int(matches.group(4), 16)
        continue

      # #0 buf @ 0xc void *
      matches = re.match("^#(\d+) (\s*\S+) \@ 0x([0-9a-z]+) size:0x([0-9a-z]+) flags:0x([0-9a-z]+) (.*)", line.strip(), re.IGNORECASE)
      if matches is not None:
          idx = int(matches.group(1))
          current_info["args"][idx] = {}
          current_info["args"][idx]["name"] = matches.group(2)
          current_info["args"][idx]["offset"] = int(matches.group(3), 16)
          current_info["args"][idx]["size"] = int(matches.group(4), 16)
          current_info["args"][idx]["flags"] = int(matches.group(5), 16)
          current_info["args"][idx]["type"] = matches.group(6)
          continue
    
    db[current_symbol] = current_info
  return db

def update_function_args(function_args_file):
    global count_args
    global count_funcs
    global count_args_failed
    db = __build_args_db(function_args_file)

    for func_name, dbval in db.items():
      func_ea = idc.get_name_ea_simple(func_name)
      if func_ea and func_ea == 0x005B5490 and dbval:
        create_func_args_from_type(func_ea, dbval)

    print(f"Updated {count_args:,} (failed {count_args_failed:,}) variable names in {count_funcs:,} functions")
