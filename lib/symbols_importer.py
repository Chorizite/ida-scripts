import re
import os
import idc

def import_symbols(symbols):
   for offset, symbol in symbols.items():
    idc.set_name(offset, symbol, idc.SN_NOWARN)

def parse_map_line(line):
    """Parses a map file line. returns offset and symbol"""
    matches = re.match("([0-9a-f]+) (.*)", line.strip(), re.IGNORECASE);
    if matches is not None:
        offset = int(matches.group(1), 16)
        symbol = matches.group(2)
        return offset, symbol

def parse_symbols_map(symbols, file):
  """import offsets / symbols from diaphora.map and load them into global symbols
  if they dont already exist
  """
  count = 0
  with open(file, 'r') as f:
    for line in f:
      offset, symbol = parse_map_line(line)
      if not offset in symbols:
        symbols[offset] = symbol
        count = count + 1
  print(f"Imported {count} symbols from {file}")