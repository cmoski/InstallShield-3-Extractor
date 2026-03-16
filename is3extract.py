#!/usr/bin/env python3
"""
InstallShield 3 (.z) Extractor
================================
Extracts files from InstallShield 3 cabinet archives (.z files).

Format reverse-engineered from:
- stix by Veit Kannegieser (http://kannegieser.net/veit)
- Linux port by DeclanHoare (https://github.com/DeclanHoare/stix)

The IS3 .z format:
  - 255-byte archive header at magic signature 0x13 0x5d 0x65 0x8c
  - Sequential PKWARE DCL "implode" compressed file data
  - Directory table at offset namenanfang (from header)
  - Each directory entry: file count (2B) + block length (2B) + name (variable)
  - Each file entry: u_00[7B] + compressed_size[4B] + u_0b[4B] + datum[2B] +
                     zeit[2B] + u_13[4B] + blocklen[2B] + u_19[4B] +
                     pascal_string_name[variable]
  - KEY INSIGHT: datei_kopf.laenge (at offset 0x07) is the COMPRESSED size,
    not the uncompressed size. Files are stored sequentially from HDR_SIZE.

Requires: libblast.so (built from zlib/contrib/blast)
See build_blast.sh for compilation instructions.

Usage:
    python3 is3extract.py data.z output_dir [--verbose]

Author: cmoski
License: MIT
"""

import struct
import sys
import os
import ctypes
import argparse

MAGIC = b'\x13\x5d\x65\x8c'
HDR_SIZE = 255  # sizeof(dateikopf_typ) in Pascal


def load_blast(lib_path=None):
    """Load the blast decompression library."""
    search_paths = []
    if lib_path:
        search_paths.append(lib_path)
    search_paths += [
        './libblast.so',
        '/tmp/libblast.so',
        os.path.join(os.path.dirname(__file__), 'libblast.so'),
    ]
    for path in search_paths:
        if os.path.exists(path):
            try:
                lib = ctypes.CDLL(path)
                lib.blast_decompress.restype = ctypes.POINTER(ctypes.c_ubyte)
                lib.blast_decompress.argtypes = [
                    ctypes.c_char_p,
                    ctypes.c_size_t,
                    ctypes.POINTER(ctypes.c_size_t),
                ]
                return lib
            except Exception:
                continue
    raise RuntimeError(
        "Could not load libblast.so. Run build_blast.sh first.\n"
        "Or specify path with --blast-lib"
    )


def blast_decompress(lib, data):
    """Decompress PKWARE DCL implode data. Returns decompressed bytes or None."""
    out_len = ctypes.c_size_t(0)
    result = lib.blast_decompress(data, len(data), ctypes.byref(out_len))
    if result and out_len.value > 0:
        return bytes(result[:out_len.value])
    return None


def parse_header(data, offset):
    """Parse the 255-byte IS3 archive header."""
    hdr = data[offset:offset + HDR_SIZE]
    if hdr[:4] != MAGIC:
        raise ValueError(f"Invalid magic at offset {offset}")
    return {
        'datei_anzahl':  struct.unpack_from('<H', hdr, 0x0c)[0],  # file count
        'archiv_laenge': struct.unpack_from('<I', hdr, 0x12)[0],  # archive length
        'namenanfang':   struct.unpack_from('<I', hdr, 0x29)[0],  # dir table offset
        'verzeichnisse': struct.unpack_from('<H', hdr, 0x31)[0],  # dir count
    }


def parse_directory(data, base, namenanfang, verzeichnisse, datei_anzahl):
    """Parse directory and file records from the directory table."""
    o = namenanfang
    dirs = []

    # Parse directory name records
    for _ in range(verzeichnisse):
        pos = base + o
        anzahl, blocklaenge = struct.unpack_from('<HH', data, pos)
        name_raw = data[pos + 4:pos + blocklaenge]
        name = name_raw.split(b'\x00')[0].decode('cp437', errors='replace')
        name = name.replace('\\', '/')
        dirs.append({'count': anzahl, 'name': name})
        o += blocklaenge

    # Build dir->file assignment
    file_to_dir = []
    for d in dirs:
        for _ in range(d['count']):
            file_to_dir.append(d['name'])
    # Pad if needed
    while len(file_to_dir) < datei_anzahl:
        file_to_dir.append('')

    # Parse file records
    # datei_kopf layout (offsets within record):
    #   0x00-0x06: u_00 (7 bytes, flags/unknown)
    #   0x07-0x0a: laenge (4 bytes) = COMPRESSED size of file data
    #   0x0b-0x0e: u_0b (4 bytes, checksum/unknown)
    #   0x0f-0x10: datum (2 bytes, DOS date)
    #   0x11-0x12: zeit  (2 bytes, DOS time)
    #   0x13-0x16: u_13 (4 bytes)
    #   0x17-0x18: blocklaenge (2 bytes) = total size of this directory record
    #   0x19-0x1c: u_19 (4 bytes)
    #   0x1d:      name_len (1 byte, Pascal string length)
    #   0x1e+:     filename characters
    files = []
    for i in range(datei_anzahl):
        pos = base + o
        blocklaenge = struct.unpack_from('<H', data, pos + 0x17)[0]
        rec = data[pos:pos + blocklaenge]

        comp_size = struct.unpack_from('<I', rec, 0x07)[0]
        datum     = struct.unpack_from('<H', rec, 0x0f)[0]
        zeit      = struct.unpack_from('<H', rec, 0x11)[0]
        name_len  = rec[0x1d]
        fname     = rec[0x1e:0x1e + name_len].decode('cp437', errors='replace')

        files.append({
            'name':      fname,
            'dir':       file_to_dir[i] if i < len(file_to_dir) else '',
            'comp_size': comp_size,
            'datum':     datum,
            'zeit':      zeit,
        })
        o += blocklaenge

    return dirs, files


def extract(z_path, out_dir, blast_lib=None, verbose=False):
    """Extract all files from an IS3 .z archive."""
    lib = load_blast(blast_lib)
    data = open(z_path, 'rb').read()

    # Find the archive magic (supports SFX and multi-file archives)
    archiv_anfang = data.find(MAGIC)
    if archiv_anfang == -1:
        raise ValueError(f"IS3 magic {MAGIC.hex()} not found in {z_path}")

    hdr = parse_header(data, archiv_anfang)

    if verbose:
        print(f"Archive: {z_path}")
        print(f"  Files:       {hdr['datei_anzahl']}")
        print(f"  Directories: {hdr['verzeichnisse']}")
        print(f"  Data size:   {hdr['namenanfang'] - HDR_SIZE} bytes")
        print()

    dirs, files = parse_directory(
        data, archiv_anfang,
        hdr['namenanfang'], hdr['verzeichnisse'], hdr['datei_anzahl']
    )

    os.makedirs(out_dir, exist_ok=True)

    # Create subdirectories
    for d in dirs:
        if d['name']:
            full_dir = os.path.join(out_dir, d['name'])
            os.makedirs(full_dir, exist_ok=True)
            if verbose:
                print(f"  + mkdir {d['name']}")

    # Extract files sequentially from data section
    seq_pos = archiv_anfang + HDR_SIZE
    ok = fail = 0

    for entry in files:
        rel_path = (entry['dir'] + '/' + entry['name']).lstrip('/')
        out_path = os.path.join(out_dir, rel_path)
        os.makedirs(os.path.dirname(out_path) or out_dir, exist_ok=True)

        comp_size = entry['comp_size']
        # Feed compressed data + small buffer for blast self-termination
        chunk = data[seq_pos:seq_pos + comp_size + 64]

        if comp_size == 0:
            open(out_path, 'wb').close()
            if verbose:
                print(f"  (empty) {rel_path}")
        else:
            decompressed = blast_decompress(lib, chunk)
            if decompressed:
                open(out_path, 'wb').write(decompressed)
                if verbose:
                    ratio = len(decompressed) / comp_size if comp_size else 0
                    print(f"  OK  {rel_path:<30s} "
                          f"{comp_size:>8d} -> {len(decompressed):>8d} "
                          f"({ratio:.2f}x)")
                ok += 1
            else:
                print(f"  FAIL {rel_path} (comp_size={comp_size})", file=sys.stderr)
                fail += 1

        seq_pos += comp_size

    # Verify: seq_pos should equal archiv_anfang + namenanfang
    expected_end = archiv_anfang + hdr['namenanfang']
    if seq_pos != expected_end:
        print(f"WARNING: seq_pos={seq_pos} != expected {expected_end} "
              f"(delta={seq_pos - expected_end})", file=sys.stderr)
    elif verbose:
        print(f"\nVerification: seq_pos == namenanfang ✓ ({seq_pos})")

    return ok, fail


def list_contents(z_path, blast_lib=None):
    """List contents of an IS3 .z archive without extracting."""
    lib = load_blast(blast_lib)
    data = open(z_path, 'rb').read()
    archiv_anfang = data.find(MAGIC)
    if archiv_anfang == -1:
        raise ValueError(f"IS3 magic not found in {z_path}")

    hdr = parse_header(data, archiv_anfang)
    dirs, files = parse_directory(
        data, archiv_anfang,
        hdr['namenanfang'], hdr['verzeichnisse'], hdr['datei_anzahl']
    )

    print(f"{'Name':<25s} {'Dir':<15s} {'CompSize':>10s}")
    print("-" * 55)
    for f in files:
        print(f"  {f['name']:<23s} {f['dir']:<15s} {f['comp_size']:>10d}")
    print(f"\n{hdr['datei_anzahl']} files in {hdr['verzeichnisse']} director(ies)")


def main():
    parser = argparse.ArgumentParser(
        description='Extract files from an InstallShield 3 (.z) archive.',
        epilog='Build libblast.so first with: bash build_blast.sh'
    )
    parser.add_argument('z_file', help='Path to the .z archive file')
    parser.add_argument('output_dir', nargs='?', help='Output directory (omit to list only)')
    parser.add_argument('-l', '--list', action='store_true', help='List contents only')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--blast-lib', help='Path to libblast.so')
    args = parser.parse_args()

    if args.list or not args.output_dir:
        list_contents(args.z_file, args.blast_lib)
    else:
        ok, fail = extract(args.z_file, args.output_dir, args.blast_lib, args.verbose)
        print(f"\nExtracted {ok} files ({fail} failed) to {args.output_dir}")
        sys.exit(0 if fail == 0 else 1)


if __name__ == '__main__':
    main()
