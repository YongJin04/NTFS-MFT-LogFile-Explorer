import argparse
import sys
import os

from src.db.sqlite_manager import initialize_database
from src.mft.mft_parser import parse_mft, calculate_abs_path
from src.logfile.logfile_parser import parse_logfile
from src.logfile.timestomp import verify_timestomp

def parse_args():
    parser = argparse.ArgumentParser(description="Parses NTFS $LogFile and $MFT data and stores the extracted information into a SQLite database.")
    parser.add_argument("-mft_path", required=True, help="Enter $MFT file path.")
    parser.add_argument("-logfile_path", required=True, help="Enter $LogFile file path.")
    parser.add_argument("-utc", required=True, help="Enter UTC time (e.g., 9).")
    parser.add_argument("-output_path", required=True, help="Output SQLite DB file path.")
    return parser.parse_args()

def main():
    args = parse_args()

    try:
        output_path = os.path.abspath(args.output_path)
        initialize_database(output_path)
        print(f"[SUCCESS] Database initialized.")
    except Exception as e:
        sys.exit(f"Error initializing database: {e}")

    try:
        with open(args.mft_path, "rb") as mft:
            parse_mft(args.mft_path, output_path)
            calculate_abs_path(output_path)
        print(f"[SUCCESS] $MFT parsed & absolute paths calculated.")
    except (FileNotFoundError, PermissionError) as e:
        sys.exit(f"Error reading MFT file: {e}")
    except Exception as e:
        sys.exit(f"Error: Failed to parse $MFT file: {e}")

    try:
        with open(args.logfile_path, "rb") as logfile:
            parse_logfile(args.logfile_path, output_path)
        print(f"[SUCCESS] $LogFile parsed.")
        verify_timestomp(output_path, int(args.utc))
        print(f"[SUCCESS] Timestomp verification completed.\n")
    except (FileNotFoundError, PermissionError) as e:
        sys.exit(f"Error reading LogFile: {e}")
    except Exception as e:
        sys.exit(f"Error: Failed to parse $LogFile file: {e}")

if __name__ == "__main__":
    main()
