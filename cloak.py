#!/usr/bin/env python3
"""
filer.py — Polyglot/Carrier File Utility
Python port of filer.ps1

Modes:   embed | extract | info | util
For educational / research / CTF use.
"""

import argparse
import base64
import hashlib
import os
import struct
import sys
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

MAGIC        = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
MAGIC_LEN    = len(MAGIC)   # 8
SIZE_BYTES   = 8            # int64-LE payload length field
TRAILER_LEN  = MAGIC_LEN + SIZE_BYTES  # 16

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
    print(cyan("  ║   Polyglot Embed + File Utility  (Python)     ║"))
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

# ═══════════════════════════════════════════════════════════════════════════════
#  POLYGLOT HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def make_trailer(payload_len: int) -> bytes:
    """Build 16-byte trailer: MAGIC(8) + payload_len as int64-LE(8)"""
    return MAGIC + struct.pack("<q", payload_len)

def find_magic(data: bytes):
    """
    Check tail (Append) then head (Prepend) for our magic marker.
    Returns dict {offset, layout} or None.
    """
    # Append — trailer at the very end
    if len(data) >= TRAILER_LEN:
        tail = len(data) - TRAILER_LEN
        if data[tail:tail + MAGIC_LEN] == MAGIC:
            return {"offset": tail, "layout": "Append"}

    # Prepend — trailer at the very start
    if len(data) >= TRAILER_LEN:
        if data[:MAGIC_LEN] == MAGIC:
            return {"offset": 0, "layout": "Prepend"}

    return None

def read_trailer(data: bytes, trailer_at: int) -> int:
    """Extract payload length from trailer at given offset."""
    len_offset = trailer_at + MAGIC_LEN
    return struct.unpack("<q", data[len_offset:len_offset + SIZE_BYTES])[0]

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
    Returns path to encoded file (temp .enc file — caller must clean up).
    If no encoding selected returns original path unchanged.
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
    print(magenta("  └───────────────────────────────┘"))

    choice = input("  Select technique [1-6]: ").strip()
    data   = read_file(file_path)
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
#  EMBED
# ═══════════════════════════════════════════════════════════════════════════════

def do_embed(args):
    carrier_data = read_file(args.carrier)
    payload_data = read_file(args.payload)
    trailer      = make_trailer(len(payload_data))

    info(f"Carrier  : {args.carrier}  ({fmt_bytes(len(carrier_data))})")
    info(f"Payload  : {args.payload}  ({fmt_bytes(len(payload_data))})")
    info(f"Strategy : {args.strategy}")

    strategy = args.strategy.lower()

    if strategy == "append":
        result = carrier_data + payload_data + trailer

    elif strategy == "prepend":
        result = trailer + payload_data + carrier_data

    elif strategy == "insert":
        offset = args.insert_offset
        if offset > len(carrier_data):
            raise ValueError(
                f"InsertOffset ({offset}) exceeds carrier length ({len(carrier_data)})."
            )
        result = (carrier_data[:offset] + payload_data +
                  trailer + carrier_data[offset:])
    else:
        raise ValueError(f"Unknown strategy: {args.strategy}")

    write_file(args.output, result)
    ok(f"Polyglot written → {args.output}  ({fmt_bytes(len(result))})")
    return args.output

# ═══════════════════════════════════════════════════════════════════════════════
#  EXTRACT
# ═══════════════════════════════════════════════════════════════════════════════

def do_extract(args):
    data  = read_file(args.carrier)
    found = find_magic(data)

    if found is None:
        raise ValueError(
            f"Magic marker not found in '{args.carrier}'. "
            "File may not contain an embedded payload, or was embedded "
            "with the Insert strategy (not auto-detectable)."
        )

    layout     = found["layout"]
    trailer_at = found["offset"]
    payload_len = read_trailer(data, trailer_at)

    if payload_len <= 0:
        raise ValueError("Corrupt trailer: payload length is zero or negative.")

    if layout == "Append":
        start = trailer_at - payload_len
        if start < 0:
            raise ValueError("Corrupt trailer: Append payload start is negative.")
        extracted = data[start:start + payload_len]

    else:  # Prepend
        start = TRAILER_LEN
        end   = start + payload_len
        if end > len(data):
            raise ValueError("Corrupt trailer: Prepend payload end exceeds file size.")
        extracted = data[start:end]

    offset_display = (trailer_at - payload_len) if layout == "Append" else TRAILER_LEN

    info(f"Polyglot : {args.carrier}  ({fmt_bytes(len(data))})")
    info(f"Layout   : {layout}")
    info(f"Payload  : {fmt_bytes(payload_len)} at byte offset {offset_display}")

    write_file(args.output, extracted)
    ok(f"Payload extracted → {args.output}  ({fmt_bytes(len(extracted))})")
    return args.output

# ═══════════════════════════════════════════════════════════════════════════════
#  INFO
# ═══════════════════════════════════════════════════════════════════════════════

def do_info(args):
    data  = read_file(args.carrier)
    found = find_magic(data)

    print(cyan(f"[*] File  : {args.carrier}"))
    print(cyan(f"[*] Size  : {fmt_bytes(len(data))}"))

    if found is None:
        print(grey("[-] No magic marker detected (checked both head and tail)."))
    else:
        layout     = found["layout"]
        trailer_at = found["offset"]
        payload_len = read_trailer(data, trailer_at)
        carrier_len = len(data) - payload_len - TRAILER_LEN

        if layout == "Append":
            payload_offset = trailer_at - payload_len
        else:
            payload_offset = TRAILER_LEN

        print(green(f"[+] Layout detected              : {layout}"))
        print(green(f"    Magic marker at offset       : {trailer_at}"))
        print(green(f"    Payload at offset            : {payload_offset}"))
        print(green(f"    Carrier portion              : {fmt_bytes(carrier_len)}"))
        print(green(f"    Payload portion              : {fmt_bytes(payload_len)}"))
        print(green(f"    Trailer                      : {TRAILER_LEN} bytes"))

    if args.show_hashes:
        show_hashes(args.carrier)

# ═══════════════════════════════════════════════════════════════════════════════
#  POST-PROCESS  (extension rename → header spoof → hashes → temp cleanup)
# ═══════════════════════════════════════════════════════════════════════════════

def strip_all_extensions(name: str) -> str:
    """Strip every extension from a filename. 'file.bin.enc' → 'file'"""
    p = Path(name)
    while p.suffix:
        p = p.with_suffix("")
    return p.name

def post_process(work_file: str, args, protected: list[str]) -> str:
    """
    Apply NewExtension / AddExtension / SpoofHeader / ShowHashes.
    Tracks and deletes temp files created along the way.
    protected = list of paths that must never be deleted.
    """
    temps: list[str] = []

    # 1. NewExtension — replace ALL extensions with the target
    if args.new_extension:
        ext      = args.new_extension if args.new_extension.startswith(".") else f".{args.new_extension}"
        base     = strip_all_extensions(Path(work_file).name)
        dir_part = str(Path(work_file).parent)
        new_name = str(Path(dir_part) / f"{base}{ext}")

        resolved_work = str(Path(work_file).resolve())
        resolved_new  = str(Path(new_name).resolve())

        if resolved_work != resolved_new:
            import shutil
            shutil.copy2(work_file, new_name)
            ok(f"Extension replaced → {new_name}")
            if resolved_work in [str(Path(t).resolve()) for t in temps]:
                temps.append(work_file)
        else:
            warn("Output already has target extension, skipping rename.")
            new_name = work_file  # same file, update name so spoof targets correctly

        if args.spoof_header:
            set_magic_bytes(new_name, ext)
        work_file = new_name

    # 2. AddExtension — append to existing filename
    if args.add_extension:
        ext      = args.add_extension if args.add_extension.startswith(".") else f".{args.add_extension}"
        new_name = work_file + ext

        resolved_work = str(Path(work_file).resolve())
        resolved_new  = str(Path(new_name).resolve())

        if resolved_work != resolved_new:
            import shutil
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
    final_resolved = str(Path(work_file).resolve())
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

    info(f"File: {target}")
    work_file = target
    temps     = []

    if args.encode:
        prev      = work_file
        work_file = encoding_menu(work_file)
        if work_file != prev:
            temps.append(work_file)

    # Inject temps into a wrapper so post_process can clean them
    class _Args:
        pass
    pp_args = _Args()
    pp_args.new_extension  = args.new_extension
    pp_args.add_extension  = args.add_extension
    pp_args.spoof_header   = args.spoof_header
    pp_args.show_hashes    = args.show_hashes

    final = post_process_with_temps(work_file, pp_args, protected=[target], temps=temps)
    return final

def post_process_with_temps(work_file: str, args, protected: list[str], temps: list[str]) -> str:
    import shutil

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
                pass  # already in temps
            else:
                # The enc temp is now superseded — mark old work_file for cleanup if it was a temp
                if work_file in temps:
                    pass  # already tracked
        else:
            warn("Output already has target extension, skipping rename.")
            new_name = work_file  # same file, update name so spoof targets correctly

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

    # 4. Cleanup temps
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
#  ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="filer.py",
        description="Polyglot/Carrier File Utility — embed, extract, inspect, encode.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  embed    Hide a payload inside a carrier file
  extract  Recover a payload from a polyglot file
  info     Inspect a file for an embedded marker
  util     Encode / rename / spoof a file (no embedding)

Strategies (--strategy):
  append   carrier | payload | trailer  (default)
  prepend  trailer | payload | carrier
  insert   inject at --insert-offset

Examples:
  python filer.py embed --carrier photo.jpg --payload secret.zip --output poly.jpg
  python filer.py embed --carrier photo.jpg --payload secret.zip --output out.pdf --encode --new-extension .pdf --spoof-header --show-hashes
  python filer.py extract --carrier poly.jpg --output recovered.zip
  python filer.py info --carrier poly.jpg --show-hashes
  python filer.py util --carrier payload.exe --encode --new-extension .txt
        """
    )

    p.add_argument("mode", choices=["embed", "extract", "info", "util"],
                   help="Operation mode")
    p.add_argument("--carrier",        "-c", help="Carrier file (or input file for util)")
    p.add_argument("--payload",        "-p", help="Payload file to embed (embed mode)")
    p.add_argument("--output",         "-o", help="Output file path")
    p.add_argument("--strategy",       "-s", default="append",
                   choices=["append", "prepend", "insert"],
                   help="Embedding strategy (default: append)")
    p.add_argument("--insert-offset",  "-i", type=int, default=0,
                   help="Byte offset for insert strategy (default: 0)")
    p.add_argument("--encode",         "-e", action="store_true",
                   help="Show interactive encoding menu")
    p.add_argument("--new-extension",  "-n",
                   help="Replace all extensions with this one (e.g. .pdf)")
    p.add_argument("--add-extension",  "-a",
                   help="Append to existing filename (e.g. .bak)")
    p.add_argument("--spoof-header",   "-x", action="store_true",
                   help="Overwrite first bytes with magic bytes for target extension")
    p.add_argument("--show-hashes",    "-H", action="store_true",
                   help="Display MD5 / SHA1 / SHA256 of the output file")
    p.add_argument("--quiet",          "-q", action="store_true",
                   help="Suppress banner")

    return p

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    # Force UTF-8 on Windows to handle box-drawing chars in encoding menu
    import io
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')

    parser = build_parser()
    args   = parser.parse_args()

    banner(args.quiet)

    try:
        mode = args.mode.lower()

        # ── EMBED ──────────────────────────────────────────────────────────────
        if mode == "embed":
            if not args.carrier: parser.error("--carrier is required for embed mode.")
            if not args.payload: parser.error("--payload is required for embed mode.")
            if not args.output:  parser.error("--output is required for embed mode.")

            payload_work   = args.payload
            payload_is_temp = False

            if args.encode:
                info("Encoding payload before embedding...")
                payload_work    = encoding_menu(args.payload)
                payload_is_temp = (payload_work != args.payload)

            # Temporarily swap payload path for the encoded version
            original_payload = args.payload
            args.payload = payload_work
            work_file = do_embed(args)
            args.payload = original_payload

            # Clean up encoded payload temp
            if payload_is_temp and Path(payload_work).exists():
                Path(payload_work).unlink()
                warn(f"Cleaned up temp file: {payload_work}")

            # Post-process output (rename, spoof, hashes) — no re-encoding
            saved_encode = args.encode
            args.encode  = False
            post_process(work_file, args, protected=[args.carrier, args.output])
            args.encode  = saved_encode

        # ── EXTRACT ────────────────────────────────────────────────────────────
        elif mode == "extract":
            if not args.carrier: parser.error("--carrier is required for extract mode.")
            if not args.output:  parser.error("--output is required for extract mode.")

            work_file = do_extract(args)
            post_process(work_file, args, protected=[args.carrier, args.output])

        # ── INFO ───────────────────────────────────────────────────────────────
        elif mode == "info":
            if not args.carrier: parser.error("--carrier is required for info mode.")
            do_info(args)

        # ── UTIL ───────────────────────────────────────────────────────────────
        elif mode == "util":
            do_util(args)

    except (FileNotFoundError, ValueError) as exc:
        err(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        warn("Interrupted.")
        sys.exit(0)

if __name__ == "__main__":
    main()