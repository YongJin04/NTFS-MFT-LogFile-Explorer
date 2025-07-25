from datetime import datetime, timedelta
import struct

def read_struct(file_obj, struct_format, result_class=None):
    try:
        expected_size = struct.calcsize(struct_format)
    except struct.error as e:
        raise ValueError(f"Invalid struct format '{struct_format}': {e}")

    try:
        raw_bytes = file_obj.read(expected_size)
        if len(raw_bytes) != expected_size:
            raise EOFError(f"Expected {expected_size} bytes, but only got {len(raw_bytes)}.")
    except (OSError, IOError) as e:
        raise IOError(f"Failed to read {expected_size} bytes from file: {e}")

    try:
        unpacked_data = struct.unpack(struct_format, raw_bytes)
    except struct.error as e:
        raise struct.error(f"Failed to unpack data with format '{struct_format}': {e}")

    if result_class:
        try:
            return result_class(*unpacked_data)
        except TypeError as e:
            raise TypeError(f"Could not instantiate {result_class.__name__} with data {unpacked_data}: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error when creating instance of {result_class.__name__}: {e}")

    return unpacked_data

def convert_windows_timestamp(hex_str, utc=0):
    if hex_str in (None, "", 0):
        return hex_str

    try:
        if not isinstance(hex_str, str):
            return hex_str
        if len(hex_str) != 16:
            return hex_str

        filetime_int = int.from_bytes(bytes.fromhex(hex_str), byteorder="little")
        if filetime_int == 0:
            return hex_str

        epoch_start = datetime(1601, 1, 1)
        dt = epoch_start + timedelta(microseconds=filetime_int // 10) + timedelta(hours=utc)

        if dt.year < 1601 or dt > datetime.max:
            return hex_str

        return f"{dt:%Y-%m-%d %H:%M:%S}.{dt.microsecond // 1000:03d}"

    except Exception:
        return hex_str
    