import os
import idaapi
 

import lib.importers.symbols_importer
import lib.importers.frame_importer
import lib.importers.data_symbols_importer

import importlib 
importlib.reload(lib.importers.symbols_importer) 
importlib.reload(lib.importers.frame_importer) 
importlib.reload(lib.importers.data_symbols_importer) 


"""
Sets up a new acclient.exe eor database in ida.

- open acclient.exe (dont load pdb)
- wait for build
- File -> Script File -> setup-new-db.py

"""

def get_file_path(relative_path):
  """Returns the absolute path of a file relative to the script's directory."""
  script_dir = os.path.dirname(os.path.abspath(__file__))
  return os.path.join(script_dir, relative_path)

def main():
  return
  print("Setting up")

  db_file = get_file_path("tmp/pdbdata.sqlite")
  lib.importers.data_symbols_importer.load_and_compare_symbols(db_file)

  print(f"Updating method args")
  lib.frame_importer.update_function_args(get_file_path("data/dumped_function_args.txt"))

  # import types
  types_file = get_file_path("data/types.idc")
  print(f"Importing types from {types_file}")
  idaapi.exec_idc_script(None, types_file, "main", None, 0)

  # import offsets / symbols
  symbols = {}
  print(f"Importing symbols from map files")
  lib.symbols.parse_symbols_map(symbols, "data/diaphora.map")
  lib.symbols.parse_symbols_map(symbols, "data/yonneh.map")

  lib.symbols.import_symbols(symbols)

  print("Finished setting up")

if __name__ == "__main__":
    main()