# IS3 Format Discovery Notes

Raw research notes from reverse-engineering the IS3 format.

## What I Tried First (And Why It Failed)

### unshield
The standard `unshield` tool explicitly supports "IS version 5 and later." IS3 predates this and uses a fundamentally different format. Hard no.

### 7-Zip / p7zip / cabextract
No IS3 support. Same result.

### Wine installer automation
The IS3 `setup.exe` (16-bit NE executable wrapped in a 32-bit stub) runs under `winevdm.exe` in Wine. Multiple dialog automation attempts with xdotool failed — Wine's 16-bit windowing state gets confused and the installer blocks on "Setup Warning" dialogs that can't be reliably dismissed.

### Python with blast — first pass
Successfully identified the magic bytes, parsed the header, found the FAT at the end of the `.z` file. Built `libblast.so` from `zlib/contrib/blast`. **Problem**: got the FAT field interpretations wrong (see below), so extracted files were wrong.

## The FAT Red Herring

The IS3 `.z` format has what looks like a "File Allocation Table" near the end of the file. Per-file entries with a padded filename string followed by three 4-byte integers.

My first assumption was field order = `(uncompressed_size, compressed_size, offset)`.

After extracting with that mapping, the files came out completely wrong:
- `CONQUER.INI` was 1.4MB (should be a ~2KB text file)
- `SOLE.EXE` was 122KB (should be ~1.3MB)
- Game strings were appearing in the wrong files

The FAT field values are shifted one position relative to what you'd expect, and some have nonsensical values (multi-gigabyte "offsets").

**Bottom line**: the FAT at the end of `.z` is an *install manifest* — it tells the installer where to put files on the target system. It is not a reliable index for extraction. Ignore it.

## The Fix: Reading the stix Source

The `stix` Pascal source by Veit Kannegieser (~1997-2001) was the unlock. Reading `stix.pas` gave the actual file record structure:

```pascal
datei_kopf: packed record
  u_00: array[$00..$06] of byte;   // 7 bytes, unknown
  laenge: longint;                  // *** THIS IS THE COMPRESSED SIZE ***
  u_0b: array[$0b..$0e] of byte;
  datum: smallword;
  zeit: smallword;
  u_13: array[$13..$16] of byte;
  blocklaenge: smallword;           // total directory record size
  u_19: array[$19..$1c] of byte;
  dateiname: string;                // Pascal string
end;
```

`laenge` ("length" in German) sounds like file size — and it is, in the sense that stix writes that many bytes to disk after decompression. But what I confirmed empirically is that it's the **compressed** stream size for sequential extraction purposes.

The proof: set `seq_pos += entry['comp_size']` using `laenge` as compressed size, and after all 28 files `seq_pos` lands **exactly** on `namenanfang`. That's the self-verification:

```
archiv_anfang + HDR_SIZE + sum(laenge for all files) == archiv_anfang + namenanfang
```

If `laenge` were the uncompressed size, this wouldn't hold. It does, every time.

## Verification Output

```
Extracting 28 files from offset 255...
  OK  FONT6.FNT            comp=    3607 ->    14916
  OK  GRAD6FNT.FNT         comp=    2609 ->     8152
  ...
  OK  SOLE.EXE             comp=  550673 -> 1331712   PE32 executable (GUI) Intel 80386
  OK  LOCAL.MIX            comp=   52190 ->   122528
  OK  SOLEDISK.MIX         comp= 3143738 -> 4890403

28 OK, 0 fail
Final seq_pos: 16579428, namenanfang: 16579428  ← exact match ✓

SOLE.EXE: 1,331,712 bytes, magic=4d5a8000, MZ=True
PE32 executable (GUI) Intel 80386, for MS Windows, 7 sections
```

## Compression Details

Each file is a standalone PKWARE DCL "implode" stream. This is an older LZ77-based algorithm, distinct from PKWARE's "deflate." The zlib library includes a reference decompressor in `contrib/blast/`.

DCL stream first two bytes:
- Byte 0: literal/length encoding (0=binary, 1=ASCII)
- Byte 1: dictionary size (4=1024B, 5=2048B, 6=4096B)

For the Sole Survivor `setup.z`, all files use binary + 4096-byte dictionary (bytes `00 06`).

## Sole Survivor File Table

| File | Compressed | Decompressed | Type |
|------|-----------|--------------|------|
| SOLE.EXE | 550,673 | 1,331,712 | PE32 Win32 executable |
| SOLEDISK.MIX | 3,143,738 | 4,890,403 | Westwood .mix archive |
| TEMPICNH.MIX | 119,221 | 120,044 | Westwood .mix archive |
| LOGO.VQA | 1,494,935 | 1,396,428 | Westwood VQA video |
| WESTLOGO.VQA | 224,874 | 256,246 | Westwood VQA video |
| UPDATE.MIX | 8,110,032 | 8,697,815 | Westwood .mix archive |
| LOCAL.MIX | 52,190 | 122,528 | Westwood .mix archive |
| HTITLE.PCX | 61,201 | 96,941 | PCX image |
| CONQUER.INI | 957 | 1,925 | INI configuration |
| README.TXT | 5,284 | 12,113 | Plain text |
| ... | ... | ... | ... |
