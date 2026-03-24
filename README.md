# cloak.ps1 / cloak.py

A PowerShell and Python utility for polyglot/carrier file embedding, payload encoding, header spoofing, and file hashing. Built for CTF, red team, and advanced file manipulation workflows.

---

## Versions

| File | Language | Requirements |
|------|----------|--------------|
| `cloak.ps1` | PowerShell 5.1+ | Windows (built-in) |
| `cloak.py` | Python 3.9+ | Cross-platform, stdlib only |

Both versions are **fully compatible** — a polyglot file created with one can be extracted with the other. The trailer format, magic marker, and all embedding strategies are identical.

---

## Modes

| Mode | Description |
|------|-------------|
| `Embed` | Hide a payload inside a carrier file |
| `Extract` | Recover a hidden payload from a polyglot file |
| `Info` | Inspect a file for an embedded payload marker |
| `Util` | Encode, rename, or spoof a file without embedding |

---

## Embedding Strategies

| Strategy | Layout | Best For |
|----------|--------|----------|
| `Append` *(default)* | `[carrier][payload][trailer]` | JPEG, PNG, MP4, EXE — parsers ignore trailing data |
| `Prepend` | `[trailer][payload][carrier]` | ZIP, RAR — formats parsed from the end |
| `Insert` | `[carrier[:offset]][payload][trailer][carrier[offset:]]` | Custom offsets inside a file |

> **Note:** Append and Prepend are auto-detected on extraction. Insert is not auto-detectable — the offset must be known.

> **Real image tip:** Use a real image file as your carrier with `Append`. Most JPEG viewers stop reading at the end-of-image marker (`FF D9`) and ignore trailing data, so the file will still open normally.

---

## Encoding Techniques

When `-Encode` (PS1) or `--encode` (Python) is passed, an interactive menu appears. The encoding is applied to the payload **before** embedding (in `Embed` mode) or directly to the file (in `Util` mode).

| # | Technique | Output type | Reversible |
|---|-----------|-------------|------------|
| 1 | Base64 | Text | Yes — decode with Base64 |
| 2 | Hex | Text | Yes — parse hex pairs back to bytes |
| 3 | XOR | Binary | Yes — XOR again with the same key |
| 4 | Reverse bytes | Binary | Yes — reverse again |
| 5 | XOR → Base64 | Text | Yes — Base64 decode, then XOR |
| 6 | XOR → Hex | Text | Yes — parse hex, then XOR |

### XOR Key Format

When XOR is selected you will be prompted for a key. Both formats are accepted:

```
XOR key: 0x41    # hex
XOR key: 65      # decimal
```

Both use the same key (`A` / `0x41`). The key is a single byte (0–255).

### When to use each

**Base64** — good default for making binary data text-safe. Output is ~33% larger than input. Paste-friendly, widely recognised.

**Hex** — human-readable representation of every byte. Output is 2× the input size. Easy to inspect manually.

**XOR** — lightweight obfuscation. Output is the same size as input (binary). Not encryption — use a non-obvious key and combine with Base64 or Hex for transport.

**Reverse** — trivial byte-flip. Useful for defeating naive pattern matching on file headers or known byte sequences.

**XOR → Base64** — XOR first for obfuscation, then Base64 for text-safe output. Good balance of obfuscation and transportability.

**XOR → Hex** — XOR first, then hex-encode. Fully printable output, easy to paste into scripts or logs.

---

## Parameters

### PowerShell (`cloak.ps1`)

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Mode` | `Embed \| Extract \| Info \| Util` | Operation to run *(required)* |
| `-Carrier` | string | Carrier file for embedding, or input file for Util mode |
| `-Payload` | string | File to hide inside the carrier *(Embed only)* |
| `-Output` | string | Output file path |
| `-Strategy` | `Append \| Prepend \| Insert` | Embedding strategy *(default: Append)* |
| `-InsertOffset` | long | Byte offset for Insert strategy *(default: 0)* |
| `-Encode` | switch | Show interactive encoding menu before processing |
| `-NewExtension` | string | Replace all extensions with this one (e.g. `.pdf`) |
| `-AddExtension` | string | Append to existing filename (e.g. `.bak` → `file.txt.bak`) |
| `-SpoofHeader` | switch | Overwrite first bytes with magic bytes matching the target extension |
| `-ShowHashes` | switch | Display MD5, SHA1, and SHA256 of the output file |
| `-Quiet` | switch | Suppress the banner |

### Python (`cloak.py`)

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `mode` | — | positional | `embed \| extract \| info \| util` *(required)* |
| `--carrier` | `-c` | string | Carrier file, or input file for util mode |
| `--payload` | `-p` | string | File to hide inside the carrier *(embed only)* |
| `--output` | `-o` | string | Output file path |
| `--strategy` | `-s` | string | `append \| prepend \| insert` *(default: append)* |
| `--insert-offset` | `-i` | int | Byte offset for insert strategy *(default: 0)* |
| `--encode` | `-e` | flag | Show interactive encoding menu |
| `--new-extension` | `-n` | string | Replace all extensions (e.g. `.pdf`) |
| `--add-extension` | `-a` | string | Append to filename (e.g. `.bak`) |
| `--spoof-header` | `-x` | flag | Overwrite header with magic bytes |
| `--show-hashes` | `-H` | flag | Display MD5, SHA1, SHA256 |
| `--quiet` | `-q` | flag | Suppress the banner |

### `-NewExtension` vs `-AddExtension`

```
-NewExtension ".pdf"   →  file.bin.enc  becomes  file.pdf
-AddExtension ".bak"   →  file.txt      becomes  file.txt.bak
```

---

## Examples

### Basic embed and extract

```powershell
# PowerShell
.\cloak.ps1 -Mode Embed -Carrier photo.jpg -Payload secret.zip -Output poly.jpg
.\cloak.ps1 -Mode Extract -Carrier poly.jpg -Output recovered.zip
```

```bash
# Python
python cloak.py embed -c photo.jpg -p secret.zip -o poly.jpg
python cloak.py extract -c poly.jpg -o recovered.zip
```

### Embed with encoding + header spoof

```powershell
# PowerShell
.\cloak.ps1 -Mode Embed -Carrier document.docx -Payload data.bin `
    -Output disguised.pdf -Encode -NewExtension ".pdf" -SpoofHeader -ShowHashes
```

```bash
# Python
python cloak.py embed -c document.docx -p data.bin -o disguised.pdf \
    --encode --new-extension .pdf --spoof-header --show-hashes
```

### Embed using Prepend (ZIP-compatible)

```powershell
.\cloak.ps1 -Mode Embed -Strategy Prepend -Carrier archive.zip -Payload note.txt -Output poly.zip
```

```bash
python cloak.py embed -s prepend -c archive.zip -p note.txt -o poly.zip
```

### Inspect a file

```powershell
.\cloak.ps1 -Mode Info -Carrier poly.jpg -ShowHashes
```

```bash
python cloak.py info -c poly.jpg --show-hashes
```

Output (both versions):
```
[+] Layout detected              : Append
    Magic marker at offset       : 42183
    Payload at offset            : 38762
    Carrier portion              : 38.76 KB
    Payload portion              : 3.34 KB
    Trailer                      : 16 bytes
```

### Encode a file and rename it

```powershell
.\cloak.ps1 -Mode Util -Carrier payload.exe -Encode -NewExtension ".txt"
```

```bash
python cloak.py util -c payload.exe --encode --new-extension .txt
```

### Spoof magic bytes only

```powershell
.\cloak.ps1 -Mode Util -Carrier file.bin -NewExtension ".pdf" -SpoofHeader
```

```bash
python cloak.py util -c file.bin --new-extension .pdf --spoof-header
```

### Add a double extension

```powershell
.\cloak.ps1 -Mode Util -Carrier file.txt -AddExtension ".pdf"
```

```bash
python cloak.py util -c file.txt --add-extension .pdf
```

### Cross-version: embed with PS1, extract with Python

```powershell
.\cloak.ps1 -Mode Embed -Carrier photo.jpg -Payload secret.zip -Output poly.jpg
```

```bash
python cloak.py extract -c poly.jpg -o recovered.zip
```

---

## Supported Magic Bytes

| Extension | Signature |
|-----------|-----------|
| `.pdf` | `25 50 44 46` |
| `.png` | `89 50 4E 47 0D 0A 1A 0A` |
| `.jpg` / `.jpeg` | `FF D8 FF` |
| `.gif` | `47 49 46 38` |
| `.zip` / `.docx` / `.xlsx` / `.pptx` | `50 4B 03 04` |
| `.7z` | `37 7A BC AF 27 1C` |
| `.gz` | `1F 8B` |
| `.rar` | `52 61 72 21 1A 07` |
| `.exe` / `.dll` | `4D 5A` |
| `.elf` | `7F 45 4C 46` |
| `.mp3` | `49 44 33` |
| `.mp4` | `00 00 00 18 66 74 79 70` |
| `.wav` | `52 49 46 46` |
| `.bmp` | `42 4D` |
| `.sqlite` | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33` |
| `.class` | `CA FE BA BE` |
| `.iso` | `43 44 30 30 31` |

---

## How the Trailer Works

Every polyglot file created by this tool contains a 16-byte trailer that records where the payload is:

```
[ MAGIC (8 bytes) ][ PAYLOAD LENGTH as int64-LE (8 bytes) ]
  DE AD BE EF CA FE BA BE
```

On extraction the tool checks the **tail** of the file for Append layout and the **head** for Prepend layout — no strategy hint needed. This trailer format is identical in both versions, making them fully interoperable.

---

## Notes

- No intermediate temp files are left behind after any operation
- Original carrier and payload files are never modified
- Paths with spaces are fully supported
- `cloak.ps1` requires PowerShell 5.1 or later
- `cloak.py` requires Python 3.9 or later, no external packages needed
