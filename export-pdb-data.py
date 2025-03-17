"""
Exports data from a pdb client ida session

- make sure you build diaphora dbs first (see readme)
- open pdb acclient.exe (load pdb)
- File -> Script File -> export-pdb-data.py

"""

import os
import sqlite3
import importlib
import math
import ida_typeinf
import ida_kernwin
 
import lib.exporters.symbols_exporter as symbols_exporter
import lib.exporters.diaphora_exporter as diaphora_exporter
import lib.exporters.method_stackframe_exporter as method_stackframe_exporter
import lib.exporters.pstring_array_exporter as pstring_array_exporter
import lib.exporters.wstring_exporter as wstring_exporter
import lib.exporters.method_innards_exporter as method_innards_exporter
import lib.exporters.vtable_exporter as vtable_exporter

importlib.reload(symbols_exporter)
importlib.reload(diaphora_exporter)
importlib.reload(method_stackframe_exporter)
importlib.reload(pstring_array_exporter)
importlib.reload(wstring_exporter)
importlib.reload(method_innards_exporter)
importlib.reload(vtable_exporter)

def get_file_path(relative_path):
  """Returns the absolute path of a file relative to the script's directory."""
  script_dir = os.path.dirname(os.path.abspath(__file__))
  path = os.path.abspath(os.path.join(script_dir, relative_path))
  if os.path.isdir(path):
    path += "/"
  return path

# File paths
log_dir = get_file_path("../")
db_path = get_file_path("../pdbdata.sqlite")
diff_db_path = get_file_path("../diff.sqlite")
pdb_db_path = get_file_path("../pdb/acclient.exe.sqlite")
yonneh_map_path = get_file_path("data/yonneh.map")
unmatched_symbols_path = log_dir + "unmatched_symbols.txt"

def create_tables(cursor):
    # Create tables if they don't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS symbols (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        address INTEGER,
        mapped_address INTEGER,
        size INTEGER,
        type TEXT,
        section TEXT,
        value TEXT,
        func_type TEXT
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS data_xrefs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        symbol_id INTEGER,
        xref_address INTEGER,
        xref_type TEXT,
        xref_function TEXT,
        xref_function_address INTEGER,
        xref_offset INTEGER,
        FOREIGN KEY (symbol_id) REFERENCES symbols (id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS diaphora_map (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        symbol TEXT,
        address TEXT,
        mapped_address TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS diaphora_multimatches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        address INTEGER,
        address2 INTEGER,
        ratio TEXT,
        description TEXT
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS method_stackframes (
        id INTEGER PRIMARY KEY,
        function_name TEXT NOT NULL,
        function_address INTEGER NOT NULL,
        frame_size INTEGER NOT NULL,
        return_offset INTEGER NOT NULL,
        arg_base INTEGER NOT NULL,
        local_base INTEGER NOT NULL
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS stackframe_members (
        id INTEGER PRIMARY KEY,
        frame_id INTEGER NOT NULL,
        member_name TEXT NOT NULL,
        member_offset INTEGER NOT NULL,
        member_size INTEGER NOT NULL,
        member_flags INTEGER NOT NULL,
        member_type TEXT NOT NULL,
        FOREIGN KEY (frame_id) REFERENCES method_stackframes (id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS pstring_arrays (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        array_name TEXT NOT NULL,
        array_address INTEGER NOT NULL,
        array_size INTEGER NOT NULL,
        cleanup_func TEXT NOT NULL,
        data_size INTEGER NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS pstring_array_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        array_id INTEGER NOT NULL,
        member_index INTEGER NOT NULL,
        member_name TEXT NOT NULL,
        member_value TEXT NOT NULL,
        FOREIGN KEY (array_id) REFERENCES pstring_arrays (id)
    )
    ''')

    # Create wstrings table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS wstrings (
            func_name TEXT,
            func_offset INTEGER,
            data_name TEXT,
            rdata_name TEXT,
            text_value TEXT
        )
    """)
    
    # Create disasm table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS disasm (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            symbol_id INTEGER NOT NULL,
            line_number INTEGER NOT NULL,
            address INTEGER NOT NULL,
            line_text TEXT NOT NULL,
            FOREIGN KEY (symbol_id) REFERENCES symbols (id)
        )
    """)

    # Create vtables table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS vtables (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        address INTEGER NOT NULL,
        size INTEGER NOT NULL,
        class_name TEXT NOT NULL
    )
    ''')

    # Create vtable members table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS vtable_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vtable_id INTEGER NOT NULL,
        member_index INTEGER NOT NULL,
        member_name TEXT NOT NULL,
        member_address INTEGER NOT NULL,
        member_type TEXT,
        FOREIGN KEY (vtable_id) REFERENCES vtables (id)
    )
    ''')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_stackframes_func_name ON method_stackframes(function_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_stackframes_func_addr ON method_stackframes(function_address)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_members_frame_id ON stackframe_members(frame_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_diaphora_map_mapped_addr ON diaphora_map(mapped_address)')
    
    # Add new indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_symbols_section ON symbols(section)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_diaphora_multimatches_address ON diaphora_multimatches(address)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_diaphora_map_symbol ON diaphora_map(symbol)')
    
    # Add indexes to optimize data_xrefs queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_data_xrefs_symbol_id ON data_xrefs(symbol_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_data_xrefs_function ON data_xrefs(xref_function)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_data_xrefs_composite ON data_xrefs(symbol_id, xref_function, xref_offset, xref_type)')

    # Add indexes for pstring arrays
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_pstring_arrays_name ON pstring_arrays(array_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_pstring_arrays_address ON pstring_arrays(array_address)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_pstring_array_members_array_id ON pstring_array_members(array_id)')

    # Add indexes for disasm table
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_disasm_symbol_id ON disasm(symbol_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_disasm_address ON disasm(address)')

    # Add indexes for vtables
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_vtables_name ON vtables(name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_vtables_address ON vtables(address)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_vtable_members_vtable_id ON vtable_members(vtable_id)')

def is_undefined_function_name(name):
    """Check if a function name is undefined."""
    return name.startswith("sub_") or name.startswith("nullsub_") or name.startswith("$")

def print_unmatched_symbols(cursor):
    """Print a report of symbols that don't have any matches in diaphora_map."""
    print("  [+] Generating unmatched symbols report")
    
    cursor.execute('''
    SELECT s.name, s.address, s.section
    FROM symbols s
    LEFT JOIN diaphora_map d ON s.name = d.symbol
    WHERE d.symbol IS NULL
    ORDER BY s.section, s.name
    ''')
    
    results = cursor.fetchall()
    
    # Write results to file
    with open(unmatched_symbols_path, 'w') as f:
        f.write("Unmatched Symbols Report\n")
        f.write("=======================\n\n")
        
        current_section = None
        for name, addr, section in results:
            if section != current_section:
                f.write(f"\n{section} Section:\n")
                f.write("-" * (len(section) + 9) + "\n")
                current_section = section
            
            f.write(f"{name} at {hex(addr)}\n")
    
    print(f"    [+] Found {len(results)} unmatched symbols")
    print(f"    [+] Report saved to: {unmatched_symbols_path}")



def main():
    global tmp_dir, log_dir, db_path, diff_db_path, pdb_db_path, yonneh_map_path, unmatched_symbols_path
    print("[+] Exporting pdb client data")
    print(f"  [+] db_path: {db_path}")

    # Clear existing database, make log dirs
    if os.path.exists(db_path):
        os.remove(db_path)

    # Connect to SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    create_tables(cursor)

    # Export subroutine symbols
    symbols_exporter.dump_subroutines(cursor)

    # Export data symbols
    symbols_exporter.dump_segment_symbols(".data", cursor)
    symbols_exporter.dump_segment_symbols(".rdata", cursor)

    # Export yonneh map
    if not os.path.exists(yonneh_map_path):
      print(f"  [-] Error: yonneh_map_path does not exist: {yonneh_map_path}")
      return

    diaphora_exporter.export_yonneh_map(yonneh_map_path, cursor)

    # Export diaphora map
    if not os.path.exists(diff_db_path):
      print(f"  [-] Error: diff_db_path does not exist: {diff_db_path}")
      return
    if not os.path.exists(pdb_db_path):
      print(f"  [-] Error: pdb_db_path does not exist: {pdb_db_path}")
      return

    diaphora_exporter.export_diaphora_map(diff_db_path, pdb_db_path, cursor)
    diaphora_exporter.export_diaphora_multimatches(diff_db_path, pdb_db_path, cursor)

    # Export method disassembly
    method_innards_exporter.dump_method_disasm(cursor)

    # Export stack frames
    method_stackframe_exporter.dump_method_stackframes(cursor)

    # Export PStringBase arrays
    pstring_array_exporter.dump_pstring_arrays(cursor)

    # Export wide string initializer functions and symbols
    wstring_exporter.export_wide_string_init_funcs(cursor)

    # Export vtables
    vtable_exporter.dump_vtables(cursor)

    # Print unmatched symbols report
    print_unmatched_symbols(cursor)

    # Commit changes and close connection
    conn.commit()
    conn.close()
    print(f"  [+] Finished!  Database saved to: {db_path}")

if __name__ == "__main__":
    main()