import sqlite3
import os

from src.types.ntfs_structs import *
from src.db.sqlite_manager import *
from src.utils.util import *

def extract_timestamps_standard_information(data_hex: str, attr_offset: int, utc: int):
    times = [None] * 4
    field_map = {
        0x18: [0, 1, 2, 3],  # C, M, MFT, A
        0x20: [1, 2, 3],     #    M, MFT, A
        0x28: [2, 3],        #       MFT, A
        0x30: [3],           #            A
    }
    positions = field_map.get(attr_offset, [])
    for i, field_idx in enumerate(positions):
        hex_str = data_hex[i * 16:(i + 1) * 16]
        if len(hex_str) == 16:
            times[field_idx] = convert_windows_timestamp(hex_str, utc)
    return times

def extract_timestamps_file_name(data_hex: str, attr_offset: int, utc: int):
    times = [None] * 4
    field_map = {
        0x18: [0, 1, 2, 3],  # skip first 8 bytes
        0x20: [0, 1, 2, 3],
        0x28: [1, 2, 3],
        0x30: [2, 3],
        0x38: [3],
    }
    positions = field_map.get(attr_offset, [])
    start_byte = 8 if attr_offset == 0x18 else 0
    for i, field_idx in enumerate(positions):
        hex_start = (start_byte + i * 8) * 2
        hex_str = data_hex[hex_start:hex_start + 16]
        if len(hex_str) == 16:
            times[field_idx] = convert_windows_timestamp(hex_str, utc)
    return times

def init_timestomp_db(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS TimeStomp (
            this_lsn INTEGER,
            undo_create_time TEXT,
            undo_modified_time TEXT,
            undo_mft_modified_time TEXT,
            undo_last_access_time TEXT,
            redo_create_time TEXT,
            redo_modified_time TEXT,
            redo_mft_modified_time TEXT,
            redo_last_access_time TEXT,
            is_timestomped BOOLEAN,
            attr_name TEXT,
            target_vcn INTEGER,
            cluster_number INTEGER,
            record_offset INTEGER,
            attr_offset INTEGER
        )
    ''')
    conn.commit()

def process_and_insert(conn, rows, utc_offset, attr):
    cursor = conn.cursor()
    for this_lsn, redo_hex, undo_hex, target_vcn, cluster_number, record_offset, attr_offset in rows:
        try:
            offset = int(str(attr_offset), 16)
        except ValueError:
            continue
        if isinstance(redo_hex, bytes):
            redo_hex = redo_hex.hex()
        if isinstance(undo_hex, bytes):
            undo_hex = undo_hex.hex()
        if attr == 'STANDARD_INFORMATION':
            undo_times = extract_timestamps_standard_information(undo_hex, offset, utc_offset)
            redo_times = extract_timestamps_standard_information(redo_hex, offset, utc_offset)
        elif attr == 'FILE_NAME':
            undo_times = extract_timestamps_file_name(undo_hex, offset, utc_offset)
            redo_times = extract_timestamps_file_name(redo_hex, offset, utc_offset)
        else:
            continue
        is_timestomped = any(
            undo and redo and undo > redo
            for undo, redo in zip(undo_times, redo_times)
        )
        cursor.execute('''
            INSERT INTO TimeStomp (
                this_lsn,
                undo_create_time, undo_modified_time, undo_mft_modified_time, undo_last_access_time,
                redo_create_time, redo_modified_time, redo_mft_modified_time, redo_last_access_time,
                is_timestomped, attr_name,
                target_vcn, cluster_number, record_offset, attr_offset
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            this_lsn,
            *(t if t else None for t in undo_times),
            *(t if t else None for t in redo_times),
            is_timestomped, attr,
            target_vcn, cluster_number, record_offset, attr_offset
        ))
    conn.commit()

def fetch_relevant_rows_standard_information(conn):
    cursor = conn.cursor()
    cursor.execute('''
        SELECT "log_record.this_lsn",
               "log_record.redo_data",
               "log_record.undo_data",
               "log_record.target_vcn",
               "log_record.cluster_number",
               "log_record.record_offset",
               "log_record.attr_offset"
        FROM LogFile
        WHERE "log_record.record_offset" = "0x0000000000000038"
          AND "log_record.redo_op" = "0x0000000000000007"
          AND "log_record.undo_op" = "0x0000000000000007"
          AND "log_record.attr_offset" IN ("0x0000000000000018", "0x0000000000000020", "0x0000000000000028", "0x0000000000000030")
    ''')
    return cursor.fetchall()

def fetch_relevant_rows_file_name(conn):
    cursor = conn.cursor()
    cursor.execute('''
        SELECT "log_record.this_lsn",
               "log_record.redo_data",
               "log_record.undo_data",
               "log_record.target_vcn",
               "log_record.cluster_number",
               "log_record.record_offset",
               "log_record.attr_offset"
        FROM LogFile
        WHERE "log_record.record_offset" = "0x0000000000000098"
          AND "log_record.redo_op" = "0x0000000000000007"
          AND "log_record.undo_op" = "0x0000000000000007"
          AND "log_record.attr_offset" IN ("0x0000000000000018", "0x0000000000000020", "0x0000000000000028", "0x0000000000000030", "0x0000000000000038")
    ''')
    return cursor.fetchall()

def verify_timestomp(output_path, utc):
    conn = sqlite3.connect(output_path)
    try:
        init_timestomp_db(conn)
        rows_std = fetch_relevant_rows_standard_information(conn)
        process_and_insert(conn, rows_std, utc, 'STANDARD_INFORMATION')
        rows_fn = fetch_relevant_rows_file_name(conn)
        process_and_insert(conn, rows_fn, utc, 'FILE_NAME')
    finally:
        conn.close()

def parse_logfile(logfile_path, output_path):
    execute_single_query(output_path, CREATE_TABLE_SQL)
    row_buffer = []
    def flush_buffer():
        if row_buffer:
            execute_multi_query(output_path, INSERT_SQL, row_buffer)
            row_buffer.clear()
    with open(logfile_path, "rb") as logfile:
        max_number_of_logfile_page = os.path.getsize(logfile_path) // LOGFILE_PAGE_SIZE
        current_number_of_logfile_page = 4  # Skip RSTR and Buffer
        while current_number_of_logfile_page < max_number_of_logfile_page:
            logfile.seek(current_number_of_logfile_page * LOGFILE_PAGE_SIZE)  # Move to 'RCRD Page'
            rcrd_header = read_struct(logfile, RCRD_HEADER_STRUCTURE, RCRDHeader)
            current_page_data = logfile.read(rcrd_header.next_record_offset - struct.calcsize(RCRD_HEADER_STRUCTURE))
            record_types = [1, 2]  # 0x01 : Update Record, Commit Record / 0x02 : Checkpoint Record
            offset_to_log_records = find_hex(current_page_data, record_types, 2)
            for offset_to_log_record in offset_to_log_records:
                logfile.seek((current_number_of_logfile_page * LOGFILE_PAGE_SIZE) + struct.calcsize(RCRD_HEADER_STRUCTURE) + offset_to_log_record)  # Move to each 'Log Record'
                log_record_header = read_struct(logfile, RECORD_HEADER_STRUCTURE, LogRecordHeader)
                if (log_record_header.redo_offset == 0x28 and  # Condition filter to become a 'Log Record'
                    0x00 <= log_record_header.redo_op <= 0x21 and
                    0x00 <= log_record_header.undo_op <= 0x21 and
                    log_record_header.cluster_number in (0x00, 0x02, 0x04, 0x06) and
                    log_record_header.page_size == 0x02 and
                    log_record_header.redo_length != 0x00 and 
                    log_record_header.undo_length != 0x00):
                    redo_offset = (current_number_of_logfile_page * LOGFILE_PAGE_SIZE) + offset_to_log_record + RECORD_HEADER_SIZE + log_record_header.redo_offset + 0x28  # Skip Record Header
                    undo_offset =  (current_number_of_logfile_page * LOGFILE_PAGE_SIZE) + offset_to_log_record + RECORD_HEADER_SIZE + log_record_header.undo_offset + 0x28  # Skip Record Header
                    if ((redo_offset % LOGFILE_PAGE_SIZE) + log_record_header.redo_length <= rcrd_header.next_record_offset and  # Check if rodo and undo data exceeds the page
                        (undo_offset % LOGFILE_PAGE_SIZE) + log_record_header.undo_length <= rcrd_header.next_record_offset):
                        logfile.seek(redo_offset)
                        redo_data = logfile.read(log_record_header.redo_length)
                        logfile.seek(undo_offset)
                        undo_data = logfile.read(log_record_header.undo_length)
                        row = make_row(log_record_header, redo_data, undo_data)
                        row_buffer.append(row)
                if len(row_buffer) >= BATCH_SIZE:
                    flush_buffer()
            current_number_of_logfile_page = current_number_of_logfile_page + 1
        flush_buffer()

def find_hex(logfile_data, search_hexs, byte_size):
    if not isinstance(search_hexs, list):
        search_hexs = [search_hexs]
    compiled = []
    for p in search_hexs:
        if isinstance(p, int):
            compiled.append(p.to_bytes(byte_size, 'little'))
        elif isinstance(p, bytes) and len(p) == byte_size:
            compiled.append(p)
        else:
            raise TypeError("Patterns must be int or exact-length bytes.")
    hits = []
    off = 0
    end = len(logfile_data)
    while off + byte_size <= end:
        if logfile_data[off:off + byte_size] in compiled:
            hits.append(off)
        off += 8
    return sorted(o - 0x20 for o in hits if o >= 0x20)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS LogFile (
    "log_record.this_lsn" INTEGER,
    "log_record.previous_lsn" INTEGER,
    "log_record.client_undo_lsn" INTEGER,
    "log_record.client_data_length" INTEGER,
    "log_record.client_id" INTEGER,
    "log_record.record_type" INTEGER,
    "log_record.transaction_id" INTEGER,
    "log_record.flag" INTEGER,
    "log_record.align_1" INTEGER,
    "log_record.align_2" INTEGER,
    "log_record.redo_op" INTEGER,
    "log_record.undo_op" INTEGER,
    "log_record.redo_offset" INTEGER,
    "log_record.redo_length" INTEGER,
    "log_record.redo_data" BLOB,
    "log_record.undo_offset" INTEGER,
    "log_record.undo_length" INTEGER,
    "log_record.undo_data" BLOB,
    "log_record.target_attribute" INTEGER,
    "log_record.lcn_to_follow" INTEGER,
    "log_record.record_offset" INTEGER,
    "log_record.attr_offset" INTEGER,
    "log_record.cluster_number" INTEGER,
    "log_record.page_size" INTEGER,
    "log_record.target_vcn" INTEGER,
    "log_record.target_lcn" BLOB
);
"""

INSERT_COLUMNS = (
    "log_record.this_lsn",
    "log_record.previous_lsn",
    "log_record.client_undo_lsn",
    "log_record.client_data_length",
    "log_record.client_id",
    "log_record.record_type",
    "log_record.transaction_id",
    "log_record.flag",
    "log_record.align_1",
    "log_record.align_2",
    "log_record.redo_op",
    "log_record.undo_op",
    "log_record.redo_offset",
    "log_record.redo_length",
    "log_record.redo_data",
    "log_record.undo_offset",
    "log_record.undo_length",
    "log_record.undo_data",
    "log_record.target_attribute",
    "log_record.lcn_to_follow",
    "log_record.record_offset",
    "log_record.attr_offset",
    "log_record.cluster_number",
    "log_record.page_size",
    "log_record.target_vcn",
    "log_record.target_lcn" 
)

def make_row(log_record, redo_data, undo_data):
    hx = lambda v: f"0x{(v & MASK64):016X}"
    return (
        hx(log_record.this_lsn),
        hx(log_record.previous_lsn),
        hx(log_record.client_undo_lsn),
        hx(log_record.client_data_length),
        hx(log_record.client_id),
        hx(log_record.record_type),
        hx(log_record.transaction_id),
        hx(log_record.flag),
        hx(log_record.align_1),
        hx(log_record.align_2),
        hx(log_record.redo_op),
        hx(log_record.undo_op),
        hx(log_record.redo_offset),
        hx(log_record.redo_length),
        redo_data,
        hx(log_record.undo_offset),
        hx(log_record.undo_length),
        undo_data,
        hx(log_record.target_attribute),
        hx(log_record.lcn_to_follow),
        hx(log_record.record_offset),
        hx(log_record.attr_offset),
        hx(log_record.cluster_number),
        hx(log_record.page_size),
        hx(log_record.target_vcn),
        hx(log_record.target_lcn),
    )

INSERT_SQL = "INSERT INTO LogFile ({cols}) VALUES ({ph});".format(
    cols=", ".join(f'"{c}"' for c in INSERT_COLUMNS),
    ph=", ".join(["?"] * len(INSERT_COLUMNS))
)
