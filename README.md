# NTFS **$MFT / $LogFile Parser & TimeStomp Detector**
Parses **all fields** of **$MFT (MFT Entry Header, $STANDARD_INFORMATION, $FILE_NAME)** and **all Log Records** inside **$LogFile**, stores them into **SQLite** (`MFT` and `LogFile` tables), and
automatically detects **time rollback (Timestomping)** on `$STANDARD_INFORMATION` / `$FILE_NAME` timestamps based on $LogFile’s parsed information, saving the result into a `TimeStomp` table.

> TL;DR  
> ```bash
> python main.py \
>   -mft_path /path/to/$MFT \
>   -logfile_path /path/to/$LogFile \
>   -utc 9 \
>   -output_path ntfs_forensics.db
> ```

---

## 📌 Key Features

- **Full $MFT parsing**
  - Stores every field of `MFT Entry Header`, `$STANDARD_INFORMATION`, `$FILE_NAME` into the **MFT** table in SQLite
  - Post-calculates and stores the **absolute `file_path`**
- **Full $LogFile parsing**
  - Filters and saves all **valid Log Records** into the **LogFile** table
  - Keeps `redo_data`, `undo_data` **as-is in BLOB**
- **TimeStomp detection**
  - For `Created / Modified / MFT Modified / Accessed` timestamps in `$STANDARD_INFORMATION` and `$FILE_NAME`,  
    marks `is_timestomped = 1` if **Undo > Redo (moved to the past)**, and stores it into the **TimeStomp** table
- **Batch insert for large volumes**
  - Uses `BATCH_SIZE = 100_000` to ingest huge numbers of records efficiently
- **UTC offset support**
  - `-utc` option adjusts Windows FILETIME → local time conversion

---

## 🗂️ SQLite Tables

### 1) `MFT`
Stores all fields extracted from `$MFT` plus the computed `file_path`. The path is reconstructed by `calculate_abs_path()` as a post-processing step.

> **CREATE TABLE** (excerpt)
```sql
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
  "file_path" TEXT
);
```
> `file_path` is reconstructed using a DFS-like approach by walking the `$FILE_NAME.file_reference_address` (parent) chain.

---

### 2) `LogFile`
Stores every **valid Log Record** determined from $LogFile.

> **CREATE TABLE** (excerpt)
```sql
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
```

- **Valid Log Record filter conditions** (summary)
  - `redo_offset == 0x28`
  - `redo_op / undo_op ∈ [0x00, 0x21]`
  - `cluster_number ∈ {0x00, 0x02, 0x04, 0x06}`
  - `page_size == 0x02`
  - `redo_length != 0x00 && undo_length != 0x00`
  - Ensure redo/undo data does **not cross the current RCRD page boundary**

---

### 3) `TimeStomp`
Parses Undo/Redo data from $LogFile, compares timestamps in `$STANDARD_INFORMATION` / `$FILE_NAME` to see if they were changed **to the past (Timestomping)**, and stores the results.

> **CREATE TABLE**
```sql
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
);
```

- **Detection logic (core)**
  - For each record, compare `undo_times` vs `redo_times`
  - If **any** `undo_time > redo_time`, set `is_timestomped = 1`
- **Target offsets**
  - `$STANDARD_INFORMATION`  
    - `record_offset = 0x38`, `attr_offset ∈ {0x18, 0x20, 0x28, 0x30}`
  - `$FILE_NAME`  
    - `record_offset = 0x98`, `attr_offset ∈ {0x18, 0x20, 0x28, 0x30, 0x38}`

---

## 🔧 Installation

```bash
git clone <your-repo-url>
cd <your-repo>
python -m venv .venv
source .venv/bin/activate  # (Windows) .venv\Scripts\activate
pip install -r requirements.txt
```

> The `requirements.txt` only contains `dataclasses`. Since it’s part of Python 3.7+ standard library, this tool effectively has no external dependency.

---

## ▶️ Usage

```bash
python main.py \
  -mft_path /path/to/$MFT \
  -logfile_path /path/to/$LogFile \
  -utc 9 \
  -output_path ntfs_forensics.db
```

### Arguments
| Argument | Description |
|---|---|
| `-mft_path` | Path to the **$MFT file** |
| `-logfile_path` | Path to the **$LogFile file** |
| `-utc` | **Time zone offset (hours)** applied when converting Windows FILETIME → human-readable string (e.g., `9` for Korea). |
| `-output_path` | Output **SQLite DB** file path |

---

## 🧪 Quick Checks (SQLite CLI examples)

```sql
-- 1) Top 20 suspicious TimeStomp records
SELECT this_lsn, attr_name, is_timestomped,
       undo_create_time, redo_create_time,
       undo_modified_time, redo_modified_time
FROM TimeStomp
WHERE is_timestomped = 1
ORDER BY this_lsn DESC
LIMIT 20;

-- 2) Look up a specific file (including absolute path) in MFT
SELECT "file_path",
       "standard_information.created_time",
       "file_name.created_time"
FROM MFT
WHERE "file_path" LIKE '%\\Windows\\System32\\cmd.exe';

-- 3) View raw Redo/Undo binary for a specific LSN in LogFile
SELECT "log_record.this_lsn",
       hex("log_record.redo_data") AS redo_hex,
       hex("log_record.undo_data") AS undo_hex
FROM LogFile
WHERE "log_record.this_lsn" = '0x0000000000000000'; -- example LSN
```

---

## 🧠 TimeStomp Detection Algorithm (Short Summary)

1. Among **Update Resident Value (redo_op/undo_op == 0x07)** records in $LogFile:
   - `$STANDARD_INFORMATION` → `record_offset = 0x38`
   - `$FILE_NAME` → `record_offset = 0x98`
   - Each attribute’s **partial update** is indicated by `attr_offset` (`0x18`, `0x20`, …)
2. Convert Undo/Redo FILETIMEs to human-readable strings with **UTC offset adjustment**.
3. For each corresponding field, compare Undo vs Redo; if **Undo > Redo** (moving to the past), mark `is_timestomped = 1`.

---

## 📁 (Recommended) Project Layout

```
.
├─ main.py
├─ requirements.txt
└─ src
   ├─ db
   │  └─ sqlite_manager.py
   ├─ mft
   │  └─ mft_parser.py
   ├─ logfile
   │  ├─ logfile_parser.py
   │  └─ timestomp.py
   ├─ types
   │  └─ ntfs_structs.py
   └─ utils
      └─ util.py
```

---

## ⚠️ Limitations / Caveats

- TimeStomp detection currently targets **Update Resident Value (`redo_op = undo_op = 0x07`)** only.
- When only **partial regions (`attr_offset`)** of `$STANDARD_INFORMATION`, `$FILE_NAME` are modified, the comparison is performed based on an offset mapping table (`0x18`, `0x20`, `0x28`, `0x30`, ...).
- The **RSTR/Buffer (first 4 pages)** of `$LogFile` is skipped.
- `file_path` reconstruction might not be accurate if the `$FILE_NAME.file_reference_address` chain is broken.

---

## 🧭 References / Advanced Tips

- With `OPCODE_MAP`, you can map `redo_op / undo_op` values to human-readable meanings.
- Using `log_record.transaction_id` / `this_lsn` / `previous_lsn`, you can reconstruct by **transaction**.
- Cross-reference `lsn` in MFT with `this_lsn` in LogFile to understand what was manipulated within the same LSN range.

---

## 🤝 Contributing

- Bug reports, feature requests, and PRs are all welcome.
- There are plenty of contribution opportunities: performance optimization, broader parsing coverage (non-resident attributes / other opcodes), more tables, etc.

---

## 📄 License

- (Choose one you prefer, e.g., MIT, Apache-2.0, GPL-3.0, etc.)

---

> For questions / feedback, please open an issue or PR.  
> Happy Hunting & Keep Your Timeline Straight! 🔍🕒
