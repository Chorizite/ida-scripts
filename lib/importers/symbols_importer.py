import re
import os
import idc

def import_subroutines(cursor):
  """import pre-mapped subroutine symbols from `diaphora_map` table in pdbdata.sqlite"""
  cursor.execute("SELECT symbol, mapped_address FROM diaphora_map")
  symbols = cursor.fetchall()
  for symbol, address in symbols:
    idc.set_name(address, symbol, idc.SN_NOWARN)
