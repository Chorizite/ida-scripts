import sqlite3
import os
import importlib
import math

import ida_kernwin
import lib.idahelpers as idahelpers
importlib.reload(idahelpers)

def _get_mangled_name(pdb_cursor, address):
  """Helper function to get mangled name from PDB database for a given address"""
  pdb_cursor.execute('''SELECT mangled_function FROM functions where address=?''', (str(int(address, 16)),))
  output = pdb_cursor.fetchall()
  
  if len(output) > 0:
    return output[0][0]
  else:
    print(f"    [-] No mangled name found for {address}")
    return None

def export_diaphora_map(diff_db_path, pdb_db_path, out_cursor):
  print("  [+] Exporting diaphora best / partial matches")

  if not os.path.exists(diff_db_path):
    print(f"    [-] Diff database not found: {diff_db_path}")
    return

  if not os.path.exists(pdb_db_path):
    print(f"    [-] PDB database not found: {pdb_db_path}")
    return

  conn = sqlite3.connect(diff_db_path)
  cursor = conn.cursor()

  conn2 = sqlite3.connect(pdb_db_path)
  cursor2 = conn2.cursor()

  cursor.execute('''SELECT name, address, address2, type FROM results where type="partial" or type="best"''') 
    
  output = cursor.fetchall()
  total_matches = len(output)
  partial_count = 0
  best_count = 0
  processed = 0

  for row in output:
    processed += 1
    if processed % (max(math.floor(total_matches / 100), 100)) == 0:
      percentage = (processed / total_matches) * 100
      ida_kernwin.replace_wait_box(f"Exporting diaphora matches... {processed}/{total_matches} ({percentage:.1f}%)")
    
    method_name = _get_mangled_name(cursor2, row[1])
    if method_name is None:
      continue
    
    # Insert into diaphora_map table
    out_cursor.execute('''
      INSERT INTO diaphora_map (symbol, address, mapped_address)
      VALUES (?, ?, ?)
    ''', (method_name, int(row[1], 16), int(row[2], 16)))
    
    if row[3] == "partial":
      partial_count += 1
    elif row[3] == "best":
      best_count += 1

  total = partial_count + best_count

  print(f"    [+] Exported Partial matches: {partial_count:,}")
  print(f"    [+] Exported Best matches: {best_count:,}")
  print(f"    [+] Exported {total:,} matches")

  conn.close()
  conn2.close()

def export_diaphora_multimatches(diff_db_path, pdb_db_path, out_cursor):
  print("  [+] Exporting diaphora multi-matches")

  if not os.path.exists(diff_db_path):
    print(f"    [-] Diff database not found: {diff_db_path}")
    return

  if not os.path.exists(pdb_db_path):
    print(f"    [-] PDB database not found: {pdb_db_path}")
    return

  conn = sqlite3.connect(diff_db_path)
  cursor = conn.cursor()

  conn2 = sqlite3.connect(pdb_db_path)
  cursor2 = conn2.cursor()

  cursor.execute('''SELECT name, address, address2, ratio, description FROM results where type="multimatch"''')
  output = cursor.fetchall()
  total_matches = len(output)

  export_count = 0
  for row in output:
    export_count += 1
    if export_count % (max(math.floor(total_matches / 100), 100)) == 0:
      percentage = (export_count / total_matches) * 100
      ida_kernwin.replace_wait_box(f"Exporting multi-matches... {export_count}/{total_matches} ({percentage:.1f}%)")
    
    method_name = _get_mangled_name(cursor2, row[1])
    if method_name is None:
      continue

    out_cursor.execute('''
      INSERT INTO diaphora_multimatches (name, address, address2, ratio, description)
      VALUES (?, ?, ?, ?, ?)
    ''', (method_name, int(row[1], 16), int(row[2], 16), row[3], row[4]))

  print(f"    [+] Exported {export_count:,} multi-matches")
  conn.close()
  conn2.close()

def export_yonneh_map(map_file, out_cursor):
    """Import symbols from yonneh.map into diaphora_map table if they don't exist"""
    print("  [+] Exporting symbols from yonneh.map")
    
    if not os.path.exists(map_file):
        print(f"      [-] Map file not found: {map_file}")
        return
        
    # First count total valid lines
    total_lines = 0
    with open(map_file, 'r') as f:
        for line in f:
            if line.startswith("#") or len(line) < 5:
                continue
            parts = line.strip().split(' ', 1)
            if len(parts) != 2:
                continue
            total_lines += 1
    
    # Load all existing mapped addresses into memory
    out_cursor.execute('SELECT mapped_address FROM diaphora_map')
    existing_addresses = set(int(row[0]) for row in out_cursor.fetchall())
    
    count = 0
    processed = 0
    batch_size = 1000
    pending_inserts = []
    
    with open(map_file, 'r') as f:
        for line in f:
            if line.startswith("#"): continue
            if len(line) < 5: continue
            
            # Parse address and symbol from line
            parts = line.strip().split(' ', 1)
            if len(parts) != 2:
                continue
                
            processed += 1
            if processed % (max(math.floor(total_lines / 100), 100)) == 0:
                percentage = (processed / total_lines) * 100
                ida_kernwin.replace_wait_box(f"Importing symbols from yonneh.map... {processed}/{total_lines} ({percentage:.1f}%)")
            
            address = int(parts[0], 16)
            symbol = parts[1]

            if not idahelpers.is_named_data_symbol(symbol):
                continue
            
            # Check if address exists in our set
            if address not in existing_addresses:
                pending_inserts.append((symbol, address, address))
                count += 1
                
                # Execute batch insert when we reach batch_size
                if len(pending_inserts) >= batch_size:
                    out_cursor.executemany(
                        'INSERT INTO diaphora_map (symbol, address, mapped_address) VALUES (?, ?, ?)',
                        pending_inserts
                    )
                    pending_inserts = []
    
    # Insert any remaining entries
    if pending_inserts:
        out_cursor.executemany(
            'INSERT INTO diaphora_map (symbol, address, mapped_address) VALUES (?, ?, ?)',
            pending_inserts
        )
                
    print(f"    [+] Imported {count:,} new symbols from yonneh.map") 