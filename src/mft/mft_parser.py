import sqlite3
import os
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from src.types.ntfs_structs import *
from src.db.sqlite_manager import *
from src.utils.util import *

def parse_mft(mft_path, output_path):
    execute_single_query(output_path, CREATE_TABLE_SQL)

    row_buffer = []
    def flush_buffer():
        if row_buffer:
            execute_multi_query(output_path, INSERT_SQL, row_buffer)
            row_buffer.clear()

    with open(mft_path, "rb") as mft:
        max_number_of_mft_entry = os.path.getsize(mft_path) // MFT_ENTRY_SIZE
        current_number_of_mft_entry = 0

        while current_number_of_mft_entry < max_number_of_mft_entry:
            mft.seek(current_number_of_mft_entry * MFT_ENTRY_SIZE)  # Move to 'MFT Entry Header'
            mft_entry_header = read_struct(mft, MFT_ENTRY_HEADER, MFTEntryHeader)

            if (mft_entry_header.signature == MFT_ENTRY_SIGNATURE and  # Valid MFT Entry
                current_number_of_mft_entry == mft_entry_header.mft_entry_number):
                mft.seek(current_number_of_mft_entry * MFT_ENTRY_SIZE + mft_entry_header.offset_to_first_attr)  # Move to 'First Attribute'

                standard_information_attribute = None
                file_name_attribute = None
                next_file_name_attribute = None
                file_name = None
                file_name_long = None
                file_name_short = None
                data_resident_flag = None
                data_file_size = None
                data_slack_size = None
                data_data = None

                while(True):                    
                    common_attribute_header = read_struct(mft, COMMON_ATTRIBUTE_HEADER_STRUCTURE, CommonAttributeHeader)

                    if (common_attribute_header.attr_type == 0xFFFFFFFF):  # End of MFT Entry
                        break

                    elif (common_attribute_header.attr_type == 0x10 and  # $STANDARD_INFORMATION
                        common_attribute_header.flag == 0x00):
                        resident_attribute_header = read_struct(mft, RESIDENT_ATTRIBUTE_HEADER_STRUCTURE, ResidentAttributeHeader)
                        standard_information_attribute = read_struct(mft, STANDARD_INFORMATION, StandardInformation)

                    elif (common_attribute_header.attr_type == 0x30 and  # $FILE_NAME
                        common_attribute_header.flag == 0x00):
                        mft.seek(common_attribute_header.attr_length - struct.calcsize(COMMON_ATTRIBUTE_HEADER_STRUCTURE), 1)
                        next_common_attribute_header = read_struct(mft, COMMON_ATTRIBUTE_HEADER_STRUCTURE, CommonAttributeHeader)  # Read next attribute

                        if (next_common_attribute_header.attr_type == 0x30 and  # Second $FILE_NAME
                            next_common_attribute_header.flag == 0x00):
                            if (common_attribute_header.attr_length < next_common_attribute_header.attr_length):
                                next_resident_attribute_header = read_struct(mft, RESIDENT_ATTRIBUTE_HEADER_STRUCTURE, ResidentAttributeHeader)
                                next_file_name_attribute = read_struct(mft, FILE_NAME, FileName)
                                file_name_long = read_file_name(mft, next_file_name_attribute)
                                mft.seek(((mft.tell() + 0x07) & ~0x07))

                                print(f"3 {hex(current_number_of_mft_entry)} {hex((mft.tell() + 0x07) & ~0x07)} File Name : {file_name_long}")

                            else:
                                mft.seek(-(common_attribute_header.attr_length), 1)  # Move first $FILE_NAME
                                resident_attribute_header = read_struct(mft, RESIDENT_ATTRIBUTE_HEADER_STRUCTURE, ResidentAttributeHeader)
                                file_name_attribute = read_struct(mft, FILE_NAME, FileName)
                                file_name_short = read_file_name(mft, file_name_attribute)
                                mft.seek(((mft.tell() + 0x07) & ~0x07))

                                print(f"2 {hex(current_number_of_mft_entry)} {hex((mft.tell() + 0x07) & ~0x07)} File Name : {file_name_short}")
                        
                        else:
                            mft.seek(-(common_attribute_header.attr_length), 1)  # Move first $FILE_NAME
                            resident_attribute_header = read_struct(mft, RESIDENT_ATTRIBUTE_HEADER_STRUCTURE, ResidentAttributeHeader)
                            file_name_attribute = read_struct(mft, FILE_NAME, FileName)
                            file_name_long = read_file_name(mft, file_name_attribute)
                            mft.seek(((mft.tell() + 0x07) & ~0x07))

                            print(f"1 {hex(current_number_of_mft_entry)} {hex((mft.tell() + 0x07) & ~0x07)} File Name : {file_name_long}")

                    elif (common_attribute_header.attr_type == 0x80):  # $DATA
                        COMMON_HDR_SIZE = struct.calcsize(COMMON_ATTRIBUTE_HEADER_STRUCTURE)
                        NONRES_HDR_SIZE = struct.calcsize(NON_RESIDENT_ATTRIBUTE_HEADER_STRUCTURE)

                        is_nonresident = getattr(common_attribute_header, "non_resident_flag", getattr(common_attribute_header, "flag", 0x00)) == 0x01

                        if is_nonresident:  # Non-Resident
                            if (common_attribute_header.attr_length == 0x40):
                                break

                            non_resident_attribute_header = read_struct(mft, NON_RESIDENT_ATTRIBUTE_HEADER_STRUCTURE, NonResidentAttributeHeader)

                            file_size = non_resident_attribute_header.used_size_of_content
                            file_slack_size = 0x1000 - (file_size % 0x1000)
                            size_of_runlist = common_attribute_header.attr_length - (COMMON_HDR_SIZE + NONRES_HDR_SIZE)
                            if size_of_runlist < 0:
                                size_of_runlist = 0
                            runlist = mft.read(size_of_runlist)

                            pos = 0
                            while pos < len(runlist):
                                hdr = runlist[pos]
                                pos += 1
                                if hdr == 0x00:
                                    break
                                len_len  = hdr & 0x0F
                                off_len  = hdr >> 4
                                pos += len_len + off_len
                            runlist = runlist[:pos]

                            runlist_preview = runlist.hex() if runlist else ""
                            print(f"File Size: 0x{file_size:X}, Slack Size: 0x{file_slack_size:X}, Runlist: {runlist_preview}, LengthOfRunlist: 0x{size_of_runlist:X}")

                            data_resident_flag = 0x01
                            data_file_size = file_size
                            data_slack_size = file_slack_size
                            data_data = "0x" + (runlist.hex() if runlist else "")

                        else:  # Resident
                            if (common_attribute_header.attr_length == 0x18):
                                break

                            resident_attribute_header = read_struct(mft, RESIDENT_ATTRIBUTE_HEADER_STRUCTURE, ResidentAttributeHeader)

                            file_size = resident_attribute_header.size_of_content
                            file_allocation_size = (resident_attribute_header.size_of_content + 3) & ~0x03
                            slack_size = resident_attribute_header.size_of_content % 4
                            if file_size < 0:
                                file_size = 0
                            file_data = mft.read(file_size)
                            data_preview = file_data.hex() if file_data else ""
                            print(f"File Size: 0x{file_size:X},  slack Size: 0x{slack_size:X}, Data: 0x{data_preview}")

                            data_resident_flag = 0x00
                            data_file_size = file_size
                            data_slack_size = slack_size
                            data_data = "0x" + (file_data.hex() if file_data else "")

                        break
                    
                    elif (0x90 <= common_attribute_header.attr_type):  # $DATA does not exist
                        break

                    else:
                        mft.seek(common_attribute_header.attr_length - struct.calcsize(COMMON_ATTRIBUTE_HEADER_STRUCTURE), 1)  # Move next Attribute
                        # print(f"Next Attribute : {hex(common_attribute_header.attr_length - struct.calcsize(COMMON_ATTRIBUTE_HEADER_STRUCTURE))}")

                if standard_information_attribute is not None:
                    if next_file_name_attribute is not None:  # Second $FILE_NAME attribute exists
                        row = make_row(
                            mft_entry_header,
                            standard_information_attribute,
                            next_file_name_attribute,
                            (file_name_long if file_name_long is not None else file_name_short),
                            data_resident_flag, data_file_size, data_slack_size, data_data
                        )
                    elif file_name_attribute is not None:  # First $FILE_NAME attribute exists
                        row = make_row(
                            mft_entry_header,
                            standard_information_attribute,
                            file_name_attribute,
                            (file_name_long if file_name_long is not None else file_name_short),
                            data_resident_flag, data_file_size, data_slack_size, data_data
                        )
                    else:
                        row = make_row(
                            mft_entry_header,
                            standard_information_attribute,
                            None, None,
                            data_resident_flag, data_file_size, data_slack_size, data_data
                        )

                    row_buffer.append(row)
                    if len(row_buffer) >= BATCH_SIZE:
                        flush_buffer()

            else:
                pass

            current_number_of_mft_entry = current_number_of_mft_entry + 1
            print()

        flush_buffer()

def calculate_abs_path(output_path):
    def _to_int(v):
        """Convert INTEGER or '0x..' string to int; keep None as None."""
        if v is None or v == "":
            return None
        if isinstance(v, int):
            return v
        s = str(v).strip()
        return int(s, 16) if s.lower().startswith("0x") else int(s)

    root_mft = _to_int(globals().get("ROOT_MFT", ROOT_MFT))

    conn = sqlite3.connect(output_path)
    cur = conn.cursor()

    cur.execute("""
        SELECT rowid,
               "mft_entry_header.mft_entry_number",
               "file_name.file_reference_address",
               "file_name.file_name"
        FROM MFT
    """)
    rows = cur.fetchall()

    info = {}
    for rowid, entry_no_raw, parent_ref_raw, name in rows:
        entry_no = _to_int(entry_no_raw)
        parent_ref = _to_int(parent_ref_raw)
        if entry_no is None:
            continue
        parent_no = (parent_ref & MASK_48) if parent_ref is not None else None
        info[entry_no] = (rowid, parent_no, name)

    cache = {}

    def build_path(entry_no):
        if entry_no in cache:
            return cache[entry_no]

        data = info.get(entry_no)
        if data is None:
            cache[entry_no] = None
            return None

        rowid, parent_no, name = data

        if entry_no == root_mft or parent_no is None:
            cache[entry_no] = "\\"
            return "\\"

        if parent_no == entry_no:
            cache[entry_no] = "\\" + (name or "")
            return cache[entry_no]

        parent_path = build_path(parent_no) or "\\"
        if parent_path != "\\":
            path = f"{parent_path}\\{name}" if name else parent_path
        else:
            path = f"\\{name}" if name else "\\"

        cache[entry_no] = path
        return path

    updates = []
    for entry_no, (rowid, _, _) in info.items():
        path = build_path(entry_no)
        updates.append((path, rowid))

    cur.executemany('UPDATE MFT SET "file_path" = ? WHERE rowid = ?', updates)
    conn.commit()
    conn.close()

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS MFT (
    "mft_entry_header.signature" INTEGER,
    "mft_entry_header.offset_to_fixup_array" INTEGER,
    "mft_entry_header.number_of_fixup_entry" INTEGER,
    "mft_entry_header.lsn" INTEGER,
    "mft_entry_header.sequence_number" INTEGER,
    "mft_entry_header.number_of_hard_link" INTEGER,
    "mft_entry_header.offset_to_first_attr" INTEGER,
    "mft_entry_header.flag" INTEGER,
    "mft_entry_header.used_size_of_mft_entry" INTEGER,
    "mft_entry_header.allocated_size_of_mft_entry" INTEGER,
    "mft_entry_header.file_reference_to_base_entry" INTEGER,
    "mft_entry_header.next_attr_id" INTEGER,
    "mft_entry_header.align" INTEGER,
    "mft_entry_header.mft_entry_number" INTEGER,

    "standard_information.created_time" INTEGER,
    "standard_information.modified_time" INTEGER,
    "standard_information.mft_modified_time" INTEGER,
    "standard_information.accessed_time" INTEGER,
    "standard_information.flag" INTEGER,
    "standard_information.number_of_maximum_version" INTEGER,
    "standard_information.version" INTEGER,
    "standard_information.class_id" INTEGER,
    "standard_information.owner_id" INTEGER,
    "standard_information.security_id" INTEGER,
    "standard_information.quite_charged" INTEGER,
    "standard_information.ucn" INTEGER,

    "file_name.file_reference_address" INTEGER,
    "file_name.created_time" INTEGER,
    "file_name.modified_time" INTEGER,
    "file_name.mft_modified_time" INTEGER,
    "file_name.accessed_time" INTEGER,
    "file_name.allocated_size_of_file" INTEGER,
    "file_name.used_size_of_file" INTEGER,
    "file_name.flag" INTEGER,
    "file_name.reparse" INTEGER,
    "file_name.length_of_name" INTEGER,
    "file_name.name_space" INTEGER,
    "file_name.file_name" TEXT,

    "data.resident_flag" INTEGER,
    "data.file_size" INTEGER,
    "data.slack_size" INTEGER,
    "data.data" TEXT,

    "file_path" TEXT
);
"""

INSERT_COLUMNS = (
    "mft_entry_header.signature",
    "mft_entry_header.offset_to_fixup_array",
    "mft_entry_header.number_of_fixup_entry",
    "mft_entry_header.lsn",
    "mft_entry_header.sequence_number",
    "mft_entry_header.number_of_hard_link",
    "mft_entry_header.offset_to_first_attr",
    "mft_entry_header.flag",
    "mft_entry_header.used_size_of_mft_entry",
    "mft_entry_header.allocated_size_of_mft_entry",
    "mft_entry_header.file_reference_to_base_entry",
    "mft_entry_header.next_attr_id",
    "mft_entry_header.align",
    "mft_entry_header.mft_entry_number",

    "standard_information.created_time",
    "standard_information.modified_time",
    "standard_information.mft_modified_time",
    "standard_information.accessed_time",
    "standard_information.flag",
    "standard_information.number_of_maximum_version",
    "standard_information.version",
    "standard_information.class_id",
    "standard_information.owner_id",
    "standard_information.security_id",
    "standard_information.quite_charged",
    "standard_information.ucn",

    "file_name.file_reference_address",
    "file_name.created_time",
    "file_name.modified_time",
    "file_name.mft_modified_time",
    "file_name.accessed_time",
    "file_name.allocated_size_of_file",
    "file_name.used_size_of_file",
    "file_name.flag",
    "file_name.reparse",
    "file_name.length_of_name",
    "file_name.name_space",
    "file_name.file_name",

    "data.resident_flag",
    "data.file_size",
    "data.slack_size",
    "data.data",
)

def make_row(mft_entry_header, standard_information_attribute, file_name_attribute, file_name,
             data_resident_flag, data_file_size, data_slack_size, data_data):
    def hx(v, width=None):
        if v is None:
            return None
        if width is None:
            w = max(8, min(16, ((v.bit_length() + 3) // 4)))
        else:
            w = width
        return f"0x{v:0{w}X}"

    return (
        hx(mft_entry_header.signature, 8),
        hx(mft_entry_header.offset_to_fixup_array, 8),
        hx(mft_entry_header.number_of_fixup_entry, 8),
        hx(mft_entry_header.lsn, 16),
        hx(mft_entry_header.sequence_number, 8),
        hx(mft_entry_header.number_of_hard_link, 8),
        hx(mft_entry_header.offset_to_first_attr, 8),
        hx(mft_entry_header.flag, 8),
        hx(mft_entry_header.used_size_of_mft_entry, 8),
        hx(mft_entry_header.allocated_size_of_mft_entry, 8),
        hx(mft_entry_header.file_reference_to_base_entry, 16),
        hx(mft_entry_header.next_attr_id, 8),
        hx(mft_entry_header.align, 8),
        hx(mft_entry_header.mft_entry_number, 8),

        hx(standard_information_attribute.created_time, 16),
        hx(standard_information_attribute.modified_time, 16),
        hx(standard_information_attribute.mft_modified_time, 16),
        hx(standard_information_attribute.accessed_time, 16),
        hx(standard_information_attribute.flag, 8),
        hx(standard_information_attribute.number_of_maximum_version, 8),
        hx(standard_information_attribute.version, 8),
        hx(standard_information_attribute.class_id, 8),
        hx(standard_information_attribute.owner_id, 8),
        hx(standard_information_attribute.security_id, 8),
        hx(standard_information_attribute.quite_charged, 8),
        hx(standard_information_attribute.ucn, 8),

        hx(getattr(file_name_attribute, 'file_reference_address', None), 16),
        hx(getattr(file_name_attribute, 'created_time', None), 16),
        hx(getattr(file_name_attribute, 'modified_time', None), 16),
        hx(getattr(file_name_attribute, 'mft_modified_time', None), 16),
        hx(getattr(file_name_attribute, 'accessed_time', None), 16),
        hx(getattr(file_name_attribute, 'allocated_size_of_file', None), 16),
        hx(getattr(file_name_attribute, 'used_size_of_file', None), 16),
        hx(getattr(file_name_attribute, 'flag', None), 8),
        hx(getattr(file_name_attribute, 'reparse', None), 8),
        hx(getattr(file_name_attribute, 'length_of_name', None), 8),
        hx(getattr(file_name_attribute, 'name_space', None), 8),
        file_name,

        hx(data_resident_flag, 2),
        hx(data_file_size, 16),
        hx(data_slack_size, 16),
        data_data
    )

INSERT_SQL = "INSERT INTO MFT ({cols}) VALUES ({ph});".format(
    cols=", ".join(f'"{c}"' for c in INSERT_COLUMNS),
    ph=", ".join(["?"] * len(INSERT_COLUMNS))
)

def read_file_name(file_obj, file_name_attribute):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

    """
    Reads a UTF-16LE-encoded file name from the file,
    skipping invalid surrogate pairs if needed.
    """
    try:
        name_length = file_name_attribute.length_of_name
    except AttributeError as e:
        raise AttributeError(f"'file_name_attribute' object must have 'length_of_name': {e}")

    byte_length = name_length * 2

    try:
        raw_bytes = file_obj.read(byte_length)
        if len(raw_bytes) != byte_length:
            raise EOFError(f"Expected {byte_length} bytes, got {len(raw_bytes)}.")
    except (OSError, IOError) as e:
        raise IOError(f"Failed to read {byte_length} bytes from file: {e}")

    try:
        return raw_bytes.decode("utf-16le")
    except UnicodeDecodeError:
        try:
            chars, i = [], 0
            while i + 1 < len(raw_bytes):
                unit = int.from_bytes(raw_bytes[i:i+2], "little")
                if 0xD800 <= unit <= 0xDBFF and i + 3 < len(raw_bytes):
                    next_unit = int.from_bytes(raw_bytes[i+2:i+4], "little")
                    if 0xDC00 <= next_unit <= 0xDFFF:
                        cp = 0x10000 + ((unit - 0xD800) << 10) + (next_unit - 0xDC00)
                        chars.append(chr(cp))
                        i += 4
                        continue
                if unit < 0xD800 or unit > 0xDFFF:
                    chars.append(chr(unit))
                i += 2
            return ''.join(chars)

        except Exception as e:
            raise ValueError(f"Failed to decode file name using surrogate-skip fallback: {e}")
