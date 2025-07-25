from dataclasses import dataclass

# SQLite
BATCH_SIZE = 100_000
MASK_48 = 0xFFFFFFFFFFFF
MASK64 = (1 << 64) - 1

# $MFT
MFT_ENTRY_SIZE = 0x400
MFT_ENTRY_SIGNATURE = 0x454C4946  # b'FILE'
ROOT_MFT = 0x05

MFT_ENTRY_HEADER = '<IHHQHHHHIIQHHI'  # IHHQ HHHHII QHHI (sizeof = 0x30)
COMMON_ATTRIBUTE_HEADER_STRUCTURE = '<IIBBHHH'  # IIBBHHH (sizeof = 0x10)
RESIDENT_ATTRIBUTE_HEADER_STRUCTURE = '<IHBB'  # IHBB (sizeof = 0x08)
NON_RESIDENT_ATTRIBUTE_HEADER_STRUCTURE = '<QQHHIQQQ'  # QQ HHIQ QQ (sizeof == 0x30)
STANDARD_INFORMATION = '<QQQQIIIIIIQQ'  # QQ QQ IIII IIQ Q (sizeof == 0x48)
FILE_NAME = '<QQQQQQQIIBB'  # QQ QQ QQ QII BB (sizeof == 0x42)

# $LogFile
LOGFILE_PAGE_SIZE = 0x1000
RSTR_HEADER_SIGNATURE = 0x52535452  # b'RSTR'
RCRD_HEADER_SIGNATURE = 0x52435244  # b'RCRD'
RECORD_HEADER_SIZE = 0x30

RSTR_HEADER_STRUCTURE = '<4sHHQIIHHH18sQHHI'  # 4sHHQ IIHHH 18s QHHI (sizeof = 0x40)
RCRD_HEADER_STRUCTURE = '<4sHHQIHHHHIQ'  # 4sHHQ IHHHHI Q (sizeof = 0x28)
RECORD_HEADER_STRUCTURE = '<QQQIIIIHIHHHHHHHHHHHHHQQ'  # QQ QII IIHIH HHHHHHHH HHHHQ Q (sizeof = 0x58)

@dataclass
class MFTEntryHeader:
    signature: int
    offset_to_fixup_array: int
    number_of_fixup_entry: int
    lsn: int
    sequence_number: int
    number_of_hard_link: int
    offset_to_first_attr: int
    flag: int
    used_size_of_mft_entry: int
    allocated_size_of_mft_entry: int
    file_reference_to_base_entry: int
    next_attr_id: int
    align: int
    mft_entry_number: int

@dataclass
class CommonAttributeHeader:
    attr_type: int
    attr_length: int
    non_resident_flag: int
    size_of_name: int
    offset_to_name: int
    flag: int
    attr_identifier: int

@dataclass
class ResidentAttributeHeader:
    size_of_content: int
    offset_to_content: int
    indexed_flag: int
    unused: int

@dataclass
class NonResidentAttributeHeader:
    start_vcn: int
    end_vcn: int
    offset_to_runlist: int
    compression_flag: int
    align: int
    allocated_size_of_content: int
    used_size_of_content: int
    initialized_size_of_content: int

@dataclass
class StandardInformation:
    created_time: int
    modified_time: int
    mft_modified_time: int
    accessed_time: int
    flag: int
    number_of_maximum_version: int
    version: int
    class_id: int
    owner_id: int
    security_id: int
    quite_charged: int
    ucn: int

@dataclass
class FileName:
    file_reference_address: int
    created_time: int
    modified_time: int
    mft_modified_time: int
    accessed_time: int
    allocated_size_of_file: int
    used_size_of_file: int
    flag: int
    reparse: int
    length_of_name: int
    name_space: int



@dataclass
class RSTRHeader:
    magic_number: bytes
    update_sequence_offset: int
    update_sequence_count: int
    check_disk_lsn: int
    system_page_size: int
    log_page_size: int
    restart_offset: int
    minor_version: int
    major_version: int
    update_sequence_array: bytes
    current_lsn: int
    log_client_offset: int
    client_list_offset: int
    flag: int

@dataclass
class RCRDHeader:
    magic_number: bytes
    update_sequence_offset: int
    update_sequence_count: int
    last_lsn: int
    flag: int
    page_count: int
    page_position: int
    next_record_offset: int
    word_align: int
    dword_align: int
    last_end_lsn: int

@dataclass
class LogRecordHeader:
    this_lsn: int
    previous_lsn: int
    client_undo_lsn: int
    client_data_length: int
    client_id: int
    record_type: int
    transaction_id: int
    flag: int
    align_1: int
    align_2: int
    redo_op: int
    undo_op: int
    redo_offset: int
    redo_length: int
    undo_offset: int
    undo_length: int
    target_attribute: int
    lcn_to_follow: int
    record_offset: int
    attr_offset: int
    cluster_number: int
    page_size: int
    target_vcn: int
    target_lcn: int

OPCODE_MAP = {
    0x00: "Noop",
    0x01: "Compensation Log Record",
    0x02: "Initialize File Record Segment",
    0x03: "Deallocate File Record Segment",
    0x04: "Write End Of File Record Segment",
    0x05: "Create Attribute",
    0x06: "Delete Attribute",
    0x07: "Update Resident Value",
    0x08: "Update Non Resident Value",
    0x09: "Update Mapping Pairs",
    0x0A: "Delete Dirty Clusters",
    0x0B: "Set New Attribute Size",
    0x0C: "Add Index Entry Root",
    0x0D: "Delete Index Entry Root",
    0x0E: "Add Index Entry Allocation",
    0x0F: "Delete Index Entry Allocation",
    0x12: "Set Index Entry Ven Allocation",
    0x13: "Update File Name Root",
    0x14: "Update File Name Allocation",
    0x15: "Set Bits In Non Resident Bitmap",
    0x16: "Clear Bits In Non Resident Bitmap",
    0x19: "Prepare Transaction",
    0x1A: "Commit Transaction",
    0x1B: "Forget Transaction",
    0x1C: "Open Non Resident Attribute",
    0x1D: "Open Attribute Table Dump",
    0x1F: "Dirty Page Table Dump",
    0x20: "Transaction Table Dump",
    0x21: "Update Record Data Root",
}
