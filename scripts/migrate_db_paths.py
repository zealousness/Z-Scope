import sqlite3
import sys
import argparse
from pathlib import Path
"""
# 1. 迁移代码知识库 (Code Knowledge DB)
python scripts/migrate_db_paths.py .zscope_knowledge/code_knowledge.db "/usr/xxx/project" "/home/yyy/project"

# 2. 迁移大模型生成的语义快照库 (Snapshots DB)
python scripts/migrate_db_paths.py .zscope_knowledge/snapshots.db "/usr/xxx/project" "/home/yyy/project"
"""
def migrate_database(db_path: str, old_prefix: str, new_prefix: str):
    """
    Migrate absolute paths in the Z-Scope SQLite database from old_prefix to new_prefix.
    """
    db_file = Path(db_path)
    if not db_file.exists():
        print(f"Error: Database file not found: {db_path}")
        return False

    # Normalize prefixes to use the right slashes
    old_prefix = old_prefix.replace('\\', '/')
    new_prefix = new_prefix.replace('\\', '/')

    print(f"Connecting to database: {db_path}")
    print(f"Migrating paths starting with:\n  '{old_prefix}'\n->'{new_prefix}'")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Tables and their path columns in code_knowledge.db
    knowledge_updates = [
        ("translation_units", ["file_path"]),
        ("functions", ["file_path"]),
        ("type_definitions", ["file_path"]),
        ("global_variables", ["file_path"]),
        ("include_edges", ["source_file", "included_file"]),
        ("call_edges", ["caller_file", "callee_file"]),
        ("indirect_calls", ["call_file"]),
        ("taint_signatures", ["file_path"]),
    ]

    # Tables and their path columns in snapshots.db
    snapshot_updates = [
        ("snapshots", ["file_path", "location"])
    ]

    modified_tables = 0
    total_rows = 0

    try:
        # Get list of all tables in the current DB
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables_in_db = {row[0] for row in cursor.fetchall()}

        all_updates = knowledge_updates + snapshot_updates

        for table, columns in all_updates:
            if table not in tables_in_db:
                continue
                
            for col in columns:
                # Use REPLACE() to update paths. 
                # Note: We replace backslashes with forward slashes during query to ensure match.
                update_sql = f"""
                    UPDATE {table} 
                    SET {col} = REPLACE(REPLACE({col}, '\\', '/'), ?, ?)
                    WHERE REPLACE({col}, '\\', '/') LIKE ?
                """
                # The LIKE pattern needs a wildcard if we are matching prefixes
                like_pattern = f"{old_prefix}%"
                
                cursor.execute(update_sql, (old_prefix, new_prefix, like_pattern))
                rows_affected = cursor.rowcount
                
                if rows_affected > 0:
                    print(f"Updated {rows_affected:5d} rows in {table}.{col}")
                    modified_tables += 1
                    total_rows += rows_affected

        conn.commit()
        print(f"\nMigration complete! Updated {total_rows} paths across {modified_tables} columns.")
        return True

    except sqlite3.Error as e:
        print(f"Database error occurred: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate Z-Scope absolute paths in SQLite databases.")
    parser.add_argument("db_path", help="Path to the SQLite database (e.g. .zscope_knowledge/code_knowledge.db)")
    parser.add_argument("old_prefix", help="The absolute path on Machine A (e.g. /usr/xxx/project)")
    parser.add_argument("new_prefix", help="The absolute path on Machine B (e.g. /home/yyy/project)")
    
    args = parser.parse_args()
    migrate_database(args.db_path, args.old_prefix, args.new_prefix)
