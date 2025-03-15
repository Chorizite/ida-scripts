import re
import os
import idc
import idaapi
import idautils
import ida_kernwin
import ida_name
import ida_funcs
import math
import ida_typeinf
from lib import idahelpers
from lib.importers.symbols_renamer import rename_patterned_subroutines
from collections import defaultdict

def import_subroutines(cursor):
  """import pre-mapped subroutine symbols from `diaphora_map` table in pdbdata.sqlite"""

  print("  [+] Importing subroutine symbols")

  cursor.execute("SELECT symbol, mapped_address FROM diaphora_map")
  symbols = cursor.fetchall()
  total_symbols = len(symbols)
  processed = 0
  imported_symbols = 0
  
  for symbol, address in symbols:
    processed += 1
    if processed % (max(math.floor(total_symbols / 100), 100)) == 0:
      percentage = (processed / total_symbols) * 100
      ida_kernwin.replace_wait_box(f"Importing subroutine symbols... {processed}/{total_symbols} ({percentage:.1f}%)")
      
    # Convert address to integer if it's not already
    addr_int = int(address) if not isinstance(address, int) else address

    # Only import subroutines that are not already named
    if idc.get_name(addr_int).startswith("sub_"):
      idc.set_name(addr_int, symbol, idc.SN_NOWARN)
      imported_symbols += 1

  print(f"    [+] Imported {imported_symbols:,} of {total_symbols:,} subroutine symbols")


def try_match_subroutine_xrefs(cursor):
  """Try to match unnamed subroutines by comparing their xref patterns with the database."""
  
  print("  [+] Matching subroutines by xref patterns")
  
  # Build current subroutines map with their xrefs
  current_subroutines = {}
  xref_cache = defaultdict(list)
  
  # Pre-cache all xrefs for faster lookup
  ida_kernwin.replace_wait_box("Pre-caching xrefs...")
  for func_ea in idautils.Functions():
    for xref in idautils.XrefsTo(func_ea):
      xref_cache[func_ea].append(xref)
  
  # Count total functions for progress
  total_funcs = len(list(idautils.Functions()))
  processed = 0
  
  # Build map of current subroutines and their xrefs
  for func_ea in idautils.Functions():
    processed += 1
    if processed % (max(math.floor(total_funcs / 100), 100)) == 0:
      percentage = (processed / total_funcs) * 100
      ida_kernwin.replace_wait_box(f"Building subroutine map: {processed}/{total_funcs} ({percentage:.1f}%)")
    
    name = idc.get_name(func_ea)
    if name and name.startswith("sub_"):  # Only process unnamed subroutines
      xref_signatures = []
      
      for xref in xref_cache[func_ea]:
        xref_addr = xref.frm
        xref_func = idaapi.get_func(xref_addr)
        
        if xref_func:
          xref_func_addr = xref_func.start_ea
          xref_func_name = idc.get_func_name(xref_func_addr)
          xref_offset = xref_addr - xref_func_addr
          xref_type = idahelpers.get_xref_type(xref)
          xref_signatures.append((xref_func_name, xref_offset, xref_type))
      
      if xref_signatures:  # Only store subroutines with xrefs
        xref_signatures.sort()  # Sort for consistent comparison
        current_subroutines[func_ea] = {
          "name": name,
          "xrefs": tuple(xref_signatures)  # Convert to tuple for hashability
        }
  
  # Fetch symbols and xrefs from database
  cursor.execute('SELECT id, name FROM symbols WHERE section = ?', ('.text',))
  db_symbols = {row[0]: {"name": row[1], "xrefs": []} for row in cursor.fetchall()}
  
  # Fetch xrefs in batches
  BATCH_SIZE = 5000
  cursor.execute('SELECT symbol_id, xref_function, xref_offset, xref_type FROM data_xrefs WHERE symbol_id IN (SELECT id FROM symbols WHERE section = ?)', ('.text',))
  
  while True:
    rows = cursor.fetchmany(BATCH_SIZE)
    if not rows:
      break
    
    for symbol_id, func, offset, xref_type in rows:
      if symbol_id in db_symbols:
        db_symbols[symbol_id]["xrefs"].append((func, offset, xref_type))
  
  # Sort xrefs and convert to tuples
  for symbol_data in db_symbols.values():
    symbol_data["xrefs"].sort()
    symbol_data["xrefs"] = tuple(symbol_data["xrefs"])
  
  # Create lookup dictionary by xref signature for O(1) matching
  current_subroutines_by_xrefs = {}
  for addr, symbol_data in current_subroutines.items():
    current_subroutines_by_xrefs[symbol_data["xrefs"]] = (addr, symbol_data["name"])
  
  # Process database symbols
  total_symbols = len(db_symbols)
  processed = 0
  renamed_count = 0
  
  for symbol_id, symbol_data in db_symbols.items():
    processed += 1
    if processed % (max(math.floor(total_symbols / 100), 100)) == 0:
      percentage = (processed / total_symbols) * 100
      ida_kernwin.replace_wait_box(f"Matching subroutines by xrefs: {processed}/{total_symbols} ({percentage:.1f}%)")
    
    xrefs = symbol_data["xrefs"]
    if not xrefs:
      continue
    
    # O(1) lookup for matching xref pattern
    if xrefs in current_subroutines_by_xrefs:
      curr_addr, curr_name = current_subroutines_by_xrefs[xrefs]
      if curr_name.startswith("sub_"):  # Only rename if still unnamed
        symbol_name = symbol_data["name"]
        idc.set_name(curr_addr, symbol_name, idc.SN_NOWARN)
        renamed_count += 1
  
  print(f"    [+] Renamed {renamed_count:,} subroutines based on xref patterns")
  return renamed_count

def rename_unnamed_subroutines(cursor):
  """rename unnamed subroutines with a name that starts with sub_ or nullsub_"""
  
  print("  [+] Renaming unnamed subroutines")

  # Get total count first for progress
  total_funcs = len(list(idautils.Functions()))
  processed = 0
  sub_count = 0
  nullsub_count = 0
  
  for func_ea in idautils.Functions():
    processed += 1
    if processed % (max(math.floor(total_funcs / 100), 100)) == 0:
      percentage = (processed / total_funcs) * 100
      ida_kernwin.replace_wait_box(f"Renaming unnamed subroutines... {processed}/{total_funcs} ({percentage:.1f}%)")
    
    # Get the function object
    func = ida_funcs.get_func(func_ea)
    if not func:
        continue
        
    # Get the function name
    func_name = ida_name.get_name(func_ea)
    if not func_name:
        continue
    
    if func_name.startswith("sub_") and f"sub_{func_ea:08X}" != func_name:
      idc.set_name(func_ea, f"sub_{func_ea:08X}", idc.SN_NOWARN)
      sub_count += 1
    elif func_name.startswith("nullsub_"):
      idc.set_name(func_ea, f"xxgen__nullsub_{func_ea:08X}", idc.SN_NOWARN)
      nullsub_count += 1

  print(f"    [+] Updated {sub_count:,} matched subroutines with new offsets")
  print(f"    [+] Renamed {nullsub_count:,} nullsubroutines")