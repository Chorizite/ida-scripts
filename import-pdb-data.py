"""
Imports data into a pdb client ida session

- make sure you have the pdbdata.sqlite database ready
- open pdb acclient.exe (load pdb)
- File -> Script File -> import-pdb-data.py

"""

import os
import sqlite3
import importlib

import lib.importers.symbols_importer as symbols_importer

importlib.reload(symbols_importer)

def get_file_path(relative_path):
    """Returns the absolute path of a file relative to the script's directory."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.abspath(os.path.join(script_dir, relative_path))
    if os.path.isdir(path):
        path += "/"
    return path

# File paths
tmp_dir = get_file_path("../")
db_path = tmp_dir + "pdbdata.sqlite"

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

    # Import subroutine symbols
    symbols_importer.import_subroutines(cursor)

    # Import data symbols
    #symbols_importer.import_segment_symbols(".data", cursor)
    #symbols_importer.import_segment_symbols(".rdata", cursor)

    # Commit changes and close connection
    conn.commit()
    conn.close()
    print("  [+] Finished importing data!")

if __name__ == "__main__":
    main() 