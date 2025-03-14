"""
Exports data from a pdb client ida session

- open pdb acclient.exe (load pdb)
- wait for build
- File -> Script File -> export-pdb-data.py

"""

import os
import sqlite3
import importlib
 
import lib.exporters.symbols_exporter as symbols_exporter
import lib.exporters.diaphora_exporter as diaphora_exporter
import lib.exporters.method_stackframe_exporter as method_stackframe_exporter

importlib.reload(symbols_exporter)
importlib.reload(diaphora_exporter)
importlib.reload(method_stackframe_exporter)

def get_file_path(relative_path):
  """Returns the absolute path of a file relative to the script's directory."""
  script_dir = os.path.dirname(os.path.abspath(__file__))
  path = os.path.abspath(os.path.join(script_dir, relative_path))
  if os.path.isdir(path):
    path += "/"
  return path

tmp_dir = get_file_path("../")
log_dir = get_file_path("../")
db_path = tmp_dir + "pdbdata.sqlite"

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
        section TEXT
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
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_stackframes_func_name ON method_stackframes(function_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_stackframes_func_addr ON method_stackframes(function_address)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_members_frame_id ON stackframe_members(frame_id)')

def is_undefined_function_name(name):
    """Check if a function name is undefined."""
    return name.startswith("sub_") or name.startswith("nullsub_") or name.startswith("$")

def print_unmatched_symbols(cursor):
    global log_dir
    print("  [+] Checking for unmatched symbols...")
    
    # Query to find .text symbols that don't have matching entries in diaphora_map
    cursor.execute('''
        SELECT s.name, s.address 
        FROM symbols s 
        LEFT JOIN diaphora_map d ON s.name = d.symbol
        WHERE s.section = '.text' AND d.symbol IS NULL
    ''')
    
    unmatched = cursor.fetchall()
    
    total_unmatched = 0
    # log unmatched symbols
    with open(log_dir + "unmatched_symbols.txt", "w") as f:
      if unmatched:
          for name, addr in unmatched:
              if is_undefined_function_name(name): continue
              f.write(f"{name} at 0x{addr:x}\n")
              total_unmatched += 1
              # Query to find any multimatches for this address that don't exist in diaphora_map
              cursor.execute('''
                  SELECT m.name, m.address2, m.ratio, m.description
                  FROM diaphora_multimatches m
                  LEFT JOIN diaphora_map d ON CAST(d.address AS INTEGER) = m.address2
                  WHERE m.address = ? AND d.address IS NULL
                  ORDER BY CAST(m.ratio AS FLOAT) DESC
              ''', (addr,))
              
              multimatches = cursor.fetchall()
              if multimatches:
                  for match_name, match_addr, ratio, desc in multimatches:
                      f.write(f"  - 0x{match_addr:x} (Ratio: {ratio} | {desc})\n")
              else:
                  f.write("  - No potential matches found\n")
                
    print(f"    [+] Found Total {total_unmatched:,} unmatched subroutine symbols (logged to {log_dir}unmatched_symbols.txt)")


def main():
    global tmp_dir, log_dir, db_path
    print("[+] Exporting pdb client data")
    print(f"  [+] db_path: {db_path}")

    # Clear existing database
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    if os.path.exists(db_path):
        os.remove(db_path)

    # Connect to SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    create_tables(cursor)

    # Export data symbols
    symbols_exporter.dump_segment_symbols(".data", cursor)
    symbols_exporter.dump_segment_symbols(".rdata", cursor)

    # Export subroutine symbols
    symbols_exporter.dump_subroutines(cursor)

    # Export diaphora map
    diff_db_path = get_file_path("../out.sqlite") 
    pdb_db_path = get_file_path("../pdb/acclient.exe.sqlite")

    if not os.path.exists(diff_db_path):
      print(f"  [-] Error: diff_db_path does not exist: {diff_db_path}")
      return
    if not os.path.exists(pdb_db_path):
      print(f"  [-] Error: pdb_db_path does not exist: {pdb_db_path}")
      return

    diaphora_exporter.export_diaphora_map(diff_db_path, pdb_db_path, cursor)
    diaphora_exporter.export_diaphora_multimatches(diff_db_path, pdb_db_path, cursor)

    # Export yonneh map
    yonneh_map_path = get_file_path("data/yonneh.map")

    if not os.path.exists(yonneh_map_path):
      print(f"  [-] Error: yonneh_map_path does not exist: {yonneh_map_path}")
      return

    diaphora_exporter.export_yonneh_map(yonneh_map_path, cursor)

    # Export stack frames
    method_stackframe_exporter.dump_method_stackframes(cursor)

    # Print unmatched symbols report
    print_unmatched_symbols(cursor)

    # Commit changes and close connection
    conn.commit()
    conn.close()
    print(f"  [+] Finished!  Database saved to: {db_path}")

if __name__ == "__main__":
    main()