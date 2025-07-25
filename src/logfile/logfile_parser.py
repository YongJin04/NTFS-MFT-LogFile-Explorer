import os

from src.types.ntfs_structs import *
from src.db.sqlite_manager import *
from src.utils.util import *

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
