"""
Imports data into a pdb client ida session

- make sure you have the pdbdata.sqlite database ready
- open pdb acclient.exe (load pdb)
- File -> Script File -> import-pdb-data.py

"""

import os
import idaapi
import sqlite3
import ida_kernwin
import idautils
import idc
import ida_name
import importlib

import lib.importers.symbols_importer as symbols_importer
import lib.importers.data_symbols_importer as data_symbols_importer
import lib.importers.method_stackframe_importer as method_stackframe_importer
import lib.importers.symbols_renamer as symbols_renamer
import lib.importers.method_innards_importer as method_innards_importer
import lib.importers.vtable_importer as vtable_importer
import lib.idahelpers as idahelpers

importlib.reload(symbols_importer)
importlib.reload(data_symbols_importer)
importlib.reload(method_stackframe_importer)
importlib.reload(symbols_renamer)
importlib.reload(method_innards_importer)
importlib.reload(vtable_importer)
importlib.reload(idahelpers)


def get_file_path(relative_path):
    """Returns the absolute path of a file relative to the script's directory."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.abspath(os.path.join(script_dir, relative_path))
    if os.path.isdir(path):
        path += "/"
    return path

# File paths
db_path = get_file_path("../pdbdata.sqlite")
types_file = get_file_path("../pdb/types.idc")

def print_stats(cursor):
    compiler_count = 0
    unnamed_count = 0
    for func in idautils.Functions():
        func_name = ida_name.get_name(func)
        if func_name.startswith("sub_"):
            unnamed_count += 1
        if func_name.startswith("$"):
            compiler_count += 1

    print(f"  [+] Compiler subroutinescount: {compiler_count}")
    print(f"  [+] Unnamed subroutines count: {unnamed_count}")

def patch_buffer_symbols():
    _patch_buffer_offset(0x0083FF90)
    _patch_buffer_offset(0x008F1B60)
    _patch_buffer_offset(0x008F1760)
    _patch_buffer_offset(0x008388D0)

def _patch_buffer_offset(buffer_ea):
    # convert the buffer int a bunch of dwords
    buffer_size = idc.get_item_size(buffer_ea)
    for i in range(buffer_size // 4):
        dword_ea = buffer_ea + i * 4
        idc.create_dword(dword_ea)
        ida_name.set_name(dword_ea, f"unk_{dword_ea:X}", ida_name.SN_NOWARN)

def main():
    global db_path

    print("[+] Importing pdb client data")
    print(f"  [+] db_path: {db_path}")

    # Check if database exists
    if not os.path.exists(db_path):
        print(f"  [-] Error: Database does not exist: {db_path}")
        return

    # Connect to SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    """
    # import types
    print(f"  [+] Importing types from {types_file}")
    idahelpers.update_wait_box(f"Importing types from {types_file}")
    idaapi.exec_idc_script(None, types_file, "main", None, 0)

    # order is important here:
    patch_buffer_symbols()

    # rename start to _WinMainCRTStartup
    idc.set_name(0x005DF16A, "_WinMainCRTStartup", idc.SN_NOWARN)

    # Import subroutine symbols
    symbols_importer.import_subroutines(cursor)

    # try to match subroutine xrefs
    #symbols_importer.try_match_subroutine_xrefs(cursor)

    # Import data symbols
    #data_symbols_importer.load_and_compare_symbols(cursor)

    # import method innards
    method_innards_importer.import_method_innards(cursor)

    # import method innards
    method_innards_importer.import_method_innards(cursor)

    # import method stackframes
    # method_stackframe_importer.import_method_stackframes(cursor)

    # rename unnamed subroutines
    symbols_importer.rename_unnamed_subroutines(cursor)

    # rename patterned subroutines
    symbols_renamer.rename_patterned_subroutines(cursor)

    # import vtables
    vtable_importer.import_vtables(cursor)

    """
    # rename unnamed subroutines
    symbols_importer.retype_functions(cursor)

    # hide wait box
    ida_kernwin.hide_wait_box()

    #print_stats(cursor)

    # Commit changes and close connection
    conn.commit()
    conn.close()
    print("  [+] Finished importing data!")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"  [-] Error: {e}")
        ida_kernwin.hide_wait_box()
        # print stack trace
        import traceback
        traceback.print_exc()
    ida_kernwin.hide_wait_box()
