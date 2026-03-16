# InstallShield 3 Extractor

Extract files from **InstallShield 3** (`.z`) cabinet archives on Linux/macOS — no Windows needed.

## Background

InstallShield 3 was everywhere in the mid-to-late 90s. Its `.z` archive format uses PKWARE DCL "implode" compression and has essentially zero Linux tooling support. This extractor was reverse-engineered from:

- [`stix`](https://github.com/DeclanHoare/stix) by Veit Kannegieser (Pascal source, Linux port by DeclanHoare)
- Original research extracting game files from a 1997 Westwood CD

### The Key Discovery

There's one non-obvious design decision in the IS3 format that breaks every naive parsing attempt:

> **`datei_kopf.laenge` is the COMPRESSED size, not the uncompressed size.**

Files are stored sequentially in the data section, each a standalone PKWARE DCL compressed stream. The compressed size in each directory entry is what you advance by to find the next file. The decompressed output size is whatever blast produces — there's no pre-stated uncompressed size in the directory at all.

Self-verification: after extracting all files, the sequential read position lands exactly on `namenanfang` (the directory table offset). If you get this wrong, the math won't close.

## Requirements

- Python 3.6+
- GCC

## Quick Start

```bash
# 1. Build the blast decompression library
bash build_blast.sh   # compiles blast.c (bundled, zlib License)

# 2. Extract
python3 is3extract.py data.z ./output --verbose

# 3. List contents without extracting
python3 is3extract.py data.z --list
```

## Usage

```
usage: is3extract.py [-h] [-l] [-v] [--blast-lib BLAST_LIB] z_file [output_dir]

positional arguments:
  z_file                Path to the .z archive file
  output_dir            Output directory (omit to list only)

options:
  -h, --help            show this help message and exit
  -l, --list            List contents only
  -v, --verbose         Verbose output
  --blast-lib BLAST_LIB Path to libblast.so
```

## File Format Reference

### Archive Header (255 bytes at magic `0x13 0x5d 0x65 0x8c`)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | sig | Magic: `13 5D 65 8C` |
| 0x0C | 2 | datei_anzahl | File count |
| 0x12 | 4 | archiv_laenge | Total archive length |
| 0x29 | 4 | namenanfang | Offset to directory table |
| 0x31 | 2 | verzeichnisse | Directory count |

### Directory Record (variable length)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 2 | anzahl | Files in this directory |
| 0x02 | 2 | blocklaenge | Total record size |
| 0x04 | variable | name | Directory name (null-terminated) |

### File Record (variable length, `blocklaenge` at offset 0x17)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 7 | u_00 | Unknown (flags?) |
| 0x07 | 4 | **laenge** | **COMPRESSED size** (⚠️ not uncompressed!) |
| 0x0B | 4 | u_0b | Unknown (checksum?) |
| 0x0F | 2 | datum | DOS date |
| 0x11 | 2 | zeit | DOS time |
| 0x13 | 4 | u_13 | Unknown |
| 0x17 | 2 | blocklaenge | Total size of this record |
| 0x19 | 4 | u_19 | Unknown |
| 0x1D | 1 | name_len | Pascal string length byte |
| 0x1E | variable | dateiname | Filename characters |

### Data Layout

```
[255-byte header]
[file_0 compressed data: laenge bytes]
[file_1 compressed data: laenge bytes]
...
[file_N compressed data: laenge bytes]
[directory table at namenanfang]
```

Each file is a standalone PKWARE DCL "implode" stream. Self-terminating — blast knows where it ends.

## Tested Against

**Command & Conquer: Sole Survivor** (1997, Westwood Studios) — `setup.z` from the retail CD-ROM, 28 files including the main executable `SOLE.EXE` (1.33MB PE32). 28/28 extracted cleanly, seq_pos == namenanfang.

## Notes on the FAT at End of `.z`

Some IS3 archives have what looks like a file allocation table appended near the end of the `.z` file, with per-file entries containing offset, size, and filename fields. Don't use it for extraction — the field values are shifted/inconsistent relative to the actual sequential layout. The sequential directory approach is correct and self-verifying.

## License

MIT — see `LICENSE`

## Credits

- **Veit Kannegieser** — original `stix` extractor (Pascal/Assembly, 1997-2001)
- **DeclanHoare** — Linux port of stix
- **Mark Adler** — `blast.c` PKWARE DCL decompressor (zlib contrib)
- **cmoski** — Python reimplementation, format documentation
