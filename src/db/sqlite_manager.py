import sqlite3
import os

def initialize_database(db_path):
    """
    Creates or recreates the SQLite database.
    Deletes existing DB file if it exists.
    """
    try:
        if os.path.exists(db_path):
            os.remove(db_path)

        conn = sqlite3.connect(db_path)
        conn.close()
    except Exception as e:
        raise RuntimeError(f"Failed to initialize database: {e}")

def execute_single_query(db_path, sql_query, params=None):
    """
    Executes a single SQL query using the provided SQLite database path.
    """
    conn = None
    cursor = None

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        if params is not None:
            cursor.execute(sql_query, params)
        else:
            cursor.execute(sql_query)
        conn.commit()
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        raise RuntimeError(f"Database query failed.\nQuery: {sql_query}\nError: {e}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error occurred during query execution: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def execute_multi_query(db_path, sql, values_list):
    """
    Executes multiple SQL statements in a batch using the provided SQLite database path.
    Includes exception handling and rollback on failure.
    """
    conn = None
    cursor = None

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.executemany(sql, values_list)
        conn.commit()
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        raise RuntimeError(f"Database batch insert failed.\nQuery: {sql}\nError: {e}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error during batch query execution: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()