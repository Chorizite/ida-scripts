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