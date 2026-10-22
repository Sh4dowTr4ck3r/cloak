#!/usr/bin/env python3
"""
benchmark.py — Comprehensive Performance Benchmarking Suite:
               Python (cloak.py) vs. Rust (cloak-rs)

Benchmarks core algorithms, memory throughput, and end-to-end CLI execution
across multiple payload sizes and operations.
"""

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Import python implementation
import cloak

# ═══════════════════════════════════════════════════════════════════════════════
#  TERMINAL FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════

USE_COLOR = sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def green(t: str) -> str:
    return _c(t, "92")


def yellow(t: str) -> str:
    return _c(t, "93")


def cyan(t: str) -> str:
    return _c(t, "96")


def magenta(t: str) -> str:
    return _c(t, "95")


def red(t: str) -> str:
    return _c(t, "91")


def bold(t: str) -> str:
    return _c(t, "1")


def grey(t: str) -> str:
    return _c(t, "90")


def fmt_time(ns: float) -> str:
    """Format nanoseconds into human-friendly time string."""
    if ns < 1_000:
        return f"{ns:.1f} ns"
    elif ns < 1_000_000:
        return f"{ns / 1_000:.2f} µs"
    elif ns < 1_000_000_000:
        return f"{ns / 1_000_000:.2f} ms"
    else:
        return f"{ns / 1_000_000_000:.2f} s"


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_speedup(speedup: float) -> str:
    formatted = f"{speedup:.1f}x"
    if speedup >= 10.0:
        return bold(green(formatted))
    elif speedup >= 2.0:
        return green(formatted)
    elif speedup >= 1.0:
        return yellow(formatted)
    else:
        return red(formatted)


# ═══════════════════════════════════════════════════════════════════════════════
#  DATA GENERATION & COMPILATION
# ═══════════════════════════════════════════════════════════════════════════════

RUST_BIN_DIR = Path(__file__).resolve().parent / "cloak-rs"
RUST_BIN = None


def build_rust(profile="release") -> Path:
    """Use Cargo's actual executable artifact, respecting target configuration."""
    command = ["cargo", "build", "--locked", "--message-format=json", "--bin", "cloak-rs",
               "--manifest-path", str(RUST_BIN_DIR / "Cargo.toml")]
    if profile == "release":
        command.append("--release")
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    for line in result.stdout.splitlines():
        event = json.loads(line)
        if (event.get("reason") == "compiler-artifact"
                and event.get("target", {}).get("name") == "cloak-rs"
                and event.get("executable")):
            return Path(event["executable"])
    raise RuntimeError("Cargo succeeded without reporting the cloak-rs executable")


def ensure_rust_binary():
    global RUST_BIN
    print(cyan("[*] Building release binary of cloak-rs..."))
    RUST_BIN = build_rust()
    print(green("[+] Release binary built successfully."))


def generate_test_data(size: int) -> bytes:
    """Generate high-entropy deterministic pseudo-random bytes."""
    state = 0x853C49E6748FEA9B
    out = bytearray(size)
    for i in range(size):
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[i] = (state >> 33) & 0xFF
    return bytes(out)


# ═══════════════════════════════════════════════════════════════════════════════
#  ALGORITHM BENCHMARKS
# ═══════════════════════════════════════════════════════════════════════════════

DEVNULL_STDOUT = io.StringIO()


def bench_python_algo(algo: str, data: bytes, iters: int) -> dict:
    """Benchmark pure python implementation of a specific algorithm."""
    if iters < 1:
        raise ValueError("iterations must be at least 1")
    times_ns = []

    if algo == "entropy":
        for _ in range(iters + 2):
            t0 = time.perf_counter_ns()
            cloak.calc_entropy(data)
            times_ns.append(time.perf_counter_ns() - t0)

    elif algo == "lower-entropy":
        for _ in range(iters + 2):
            t0 = time.perf_counter_ns()
            with contextlib.redirect_stdout(DEVNULL_STDOUT):
                cloak.lower_entropy(data, target=6.0)
            times_ns.append(time.perf_counter_ns() - t0)

    elif algo == "strip-padding":
        with contextlib.redirect_stdout(DEVNULL_STDOUT):
            padded = cloak.lower_entropy(data, target=6.0)
        for _ in range(iters + 2):
            t0 = time.perf_counter_ns()
            with contextlib.redirect_stdout(DEVNULL_STDOUT):
                cloak.strip_null_padding(padded, interval=1)
            times_ns.append(time.perf_counter_ns() - t0)

    elif algo == "rc4":
        key = b"RedTeamSecretKey123456789"
        for _ in range(iters + 2):
            t0 = time.perf_counter_ns()
            cloak.rc4(data, key)
            times_ns.append(time.perf_counter_ns() - t0)

    elif algo == "xor":
        key = 0x5A
        for _ in range(iters + 2):
            t0 = time.perf_counter_ns()
            cloak.xor_bytes(data, key)
            times_ns.append(time.perf_counter_ns() - t0)

    elif algo == "base64-encode":
        for _ in range(iters + 2):
            t0 = time.perf_counter_ns()
            base64.b64encode(data)
            times_ns.append(time.perf_counter_ns() - t0)

    elif algo == "base64-decode":
        enc = base64.b64encode(data)
        for _ in range(iters + 2):
            t0 = time.perf_counter_ns()
            base64.b64decode(enc)
            times_ns.append(time.perf_counter_ns() - t0)

    elif algo == "hex-encode":
        for _ in range(iters + 2):
            t0 = time.perf_counter_ns()
            data.hex().upper()
            times_ns.append(time.perf_counter_ns() - t0)

    elif algo == "hex-decode":
        h = data.hex().upper()
        for _ in range(iters + 2):
            t0 = time.perf_counter_ns()
            bytes.fromhex(h)
            times_ns.append(time.perf_counter_ns() - t0)

    elif algo == "hashes":
        for _ in range(iters + 2):
            t0 = time.perf_counter_ns()
            hashlib.md5(data).hexdigest()
            hashlib.sha1(data).hexdigest()
            hashlib.sha256(data).hexdigest()
            times_ns.append(time.perf_counter_ns() - t0)

    else:
        raise ValueError(f"Unknown algo {algo}")

    times_ns = sorted(times_ns[2:])
    avg_ns = sum(times_ns) / len(times_ns)
    min_ns = times_ns[0]
    max_ns = times_ns[-1]
    median_ns = statistics.median(times_ns)
    sec = avg_ns / 1_000_000_000.0
    mb = len(data) / (1024.0 * 1024.0)
    mb_s = (mb / sec) if sec > 0 else 0.0

    return {
        "algo": algo,
        "size": len(data),
        "iterations": iters,
        "avg_ns": avg_ns,
        "min_ns": min_ns,
        "max_ns": max_ns,
        "median_ns": median_ns,
        "throughput_mb_s": mb_s,
    }


def bench_rust_algo(algo: str, size: int, iters: int) -> dict:
    """Benchmark Rust implementation using its built-in benchmark harness."""
    cmd = [
        str(RUST_BIN),
        "bench",
        "--algo",
        algo,
        "--size",
        str(size),
        "--iterations",
        str(iters),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(res.stdout.strip())


# ═══════════════════════════════════════════════════════════════════════════════
#  END-TO-END CLI BENCHMARKS
# ═══════════════════════════════════════════════════════════════════════════════


def bench_cli_scenario(name: str, py_cmd: list, rs_cmd: list, iters: int) -> dict:
    """Benchmark end-to-end command-line process execution time."""
    if iters < 1:
        raise ValueError("iterations must be at least 1")
    samples = {"python": [], "rust": []}
    commands = {"python": py_cmd, "rust": rs_cmd}
    for iteration in range(iters + 2):
        order = ("python", "rust") if iteration % 2 == 0 else ("rust", "python")
        for implementation in order:
            start = time.perf_counter_ns()
            subprocess.run(commands[implementation], stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, check=True)
            if iteration >= 2:
                samples[implementation].append(time.perf_counter_ns() - start)
    py, rs = samples["python"], samples["rust"]
    return {"scenario": name, "py_avg_ns": statistics.mean(py),
            "rs_avg_ns": statistics.mean(rs), "py_min_ns": min(py), "rs_min_ns": min(rs),
            "py_median_ns": statistics.median(py), "rs_median_ns": statistics.median(rs),
            "speedup": statistics.median(py) / statistics.median(rs)}


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN RUNNER
# ═══════════════════════════════════════════════════════════════════════════════


def verify_ordinary_outputs(data: bytes) -> set[str]:
    """Fail before timing if the ordinary codec/hash implementations disagree."""
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "source"
        source.write_bytes(data)
        for technique, encoded in ((1, base64.b64encode(data)), (2, data.hex().upper().encode())):
            for flag, input_bytes, expected in (("-e", data, encoded), ("-d", encoded, data)):
                source.write_bytes(input_bytes)
                output = Path(directory) / "output"
                subprocess.run([str(RUST_BIN), "util", "-c", str(source), flag,
                                "--technique", str(technique), "-o", str(output), "-q"],
                               check=True, capture_output=True)
                if output.read_bytes() != expected:
                    raise RuntimeError(f"Output mismatch for technique {technique} {flag}")
        source.write_bytes(data)
        result = subprocess.run([str(RUST_BIN), "info", "-c", str(source), "-H", "-q"],
                                check=True, capture_output=True, text=True)
        for digest in (hashlib.md5, hashlib.sha1, hashlib.sha256):
            if digest(data).hexdigest().upper() not in result.stdout:
                raise RuntimeError("Hash output mismatch")
    return {"base64-encode", "base64-decode", "hex-encode", "hex-decode", "hashes"}


def print_header(title: str):
    print()
    print(bold(cyan("═" * 90)))
    print(bold(cyan(f"  {title}")))
    print(bold(cyan("═" * 90)))
    print()


def run_benchmarks(sizes: list[int], iters: int, run_cli: bool = True) -> dict:
    ensure_rust_binary()

    algorithms = [
        ("rc4", "RC4 Stream Cipher"),
        ("entropy", "Shannon Entropy"),
        ("lower-entropy", "Lower Entropy (Null Padding)"),
        ("strip-padding", "Strip Padding"),
        ("xor", "XOR Byte Masking"),
        ("base64-encode", "Base64 Encode"),
        ("base64-decode", "Base64 Decode"),
        ("hex-encode", "Hex Encode"),
        ("hex-decode", "Hex Decode"),
        ("hashes", "Hashes (MD5+SHA1+SHA256)"),
    ]

    all_results = {"microbenchmarks": [], "cli_benchmarks": []}

    for size_index, size in enumerate(sizes):
        size_label = fmt_bytes(size)
        print_header(f"Microbenchmarks: Core Algorithms (Payload Size: {size_label}, Iterations: {iters})")

        header = f"{'Algorithm':<28} | {'Python Median':<12} | {'Python MiB/s':<11} | {'Rust Median':<12} | {'Rust MiB/s':<11} | {'Speedup':<8}"
        sep = "-" * len(header)
        print(bold(header))
        print(grey(sep))

        test_data = generate_test_data(size)

        verified = verify_ordinary_outputs(test_data)
        for algo_index, (algo_key, display_name) in enumerate(algorithms):
            # Alternate the order of measurement batches; each includes warmups.
            if (size_index + algo_index) % 2 == 0:
                py_res = bench_python_algo(algo_key, test_data, iters)
                rs_res = bench_rust_algo(algo_key, size, iters)
            else:
                rs_res = bench_rust_algo(algo_key, size, iters)
                py_res = bench_python_algo(algo_key, test_data, iters)
            speedup = py_res["median_ns"] / rs_res["median_ns"] if rs_res["median_ns"] > 0 else 0.0

            all_results["microbenchmarks"].append(
                {
                    "algo": algo_key,
                    "name": display_name,
                    "size": size,
                    "python": py_res,
                    "rust": rs_res,
                    "speedup": speedup,
                    "output_verified": algo_key in verified,
                }
            )

            py_time_str = fmt_time(py_res["median_ns"])
            rs_time_str = fmt_time(rs_res["median_ns"])
            py_mbs_str = f"{py_res['throughput_mb_s']:.1f}"
            rs_mbs_str = f"{rs_res['throughput_mb_s']:.1f}"
            speedup_str = fmt_speedup(speedup)

            print(
                f"{display_name:<28} | {py_time_str:<12} | {py_mbs_str:<11} | {rs_time_str:<12} | {rs_mbs_str:<11} | {speedup_str}"
            )

    if run_cli:
        print_header("End-to-End CLI Pipeline Benchmarks (Real Process Execution)")
        cli_header = f"{'Scenario':<42} | {'Python CLI':<12} | {'Rust CLI':<12} | {'Speedup':<8}"
        cli_sep = "-" * len(cli_header)
        print(bold(cli_header))
        print(grey(cli_sep))

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_carrier = Path(tmpdir) / "test_carrier.bin"
            tmp_carrier.write_bytes(generate_test_data(512 * 1024))  # 512 KB

            scenarios = [
                (
                    "info mode (-c payload --show-hashes)",
                    [sys.executable, str(Path(__file__).resolve().with_name("cloak.py")), "info", "-c", str(tmp_carrier), "-H", "-q"],
                    [str(RUST_BIN), "info", "-c", str(tmp_carrier), "-H", "-q"],
                ),
                (
                    "util mode (--lower-entropy 5.5 -o out)",
                    [
                        sys.executable,
                        str(Path(__file__).resolve().with_name("cloak.py")),
                        "util",
                        "-c",
                        str(tmp_carrier),
                        "--lower-entropy",
                        "5.5",
                        "-o",
                        str(Path(tmpdir) / "out_py.bin"),
                        "-q",
                    ],
                    [
                        str(RUST_BIN),
                        "util",
                        "-c",
                        str(tmp_carrier),
                        "--lower-entropy",
                        "5.5",
                        "-o",
                        str(Path(tmpdir) / "out_rs.bin"),
                        "-q",
                    ],
                ),
                (
                    "generate mode (--lolbin regsvr32)",
                    [
                        sys.executable,
                        str(Path(__file__).resolve().with_name("cloak.py")),
                        "generate",
                        "--lolbin",
                        "regsvr32",
                        "--lolbin-file",
                        "payload.sct",
                        "--lolbin-url",
                        "http://host/payload.sct",
                        "-q",
                    ],
                    [
                        str(RUST_BIN),
                        "generate",
                        "--lolbin",
                        "regsvr32",
                        "--lolbin-file",
                        "payload.sct",
                        "--lolbin-url",
                        "http://host/payload.sct",
                        "-q",
                    ],
                ),
                (
                    "generate mode (--list)",
                    [sys.executable, str(Path(__file__).resolve().with_name("cloak.py")), "generate", "--list", "-q"],
                    [str(RUST_BIN), "generate", "--list", "-q"],
                ),
            ]

            for name, py_c, rs_c in scenarios:
                res = bench_cli_scenario(name, py_c, rs_c, iters=max(iters, 5))
                all_results["cli_benchmarks"].append(res)

                py_str = fmt_time(res["py_median_ns"])
                rs_str = fmt_time(res["rs_median_ns"])
                sp_str = fmt_speedup(res["speedup"])
                print(f"{name:<42} | {py_str:<12} | {rs_str:<12} | {sp_str}")

    print_header("Benchmark Notes")
    print("Times and speedups use medians; throughput uses mean duration and original input MiB.")
    print("Two warmups precede each measurement batch. Batch order alternates; CLI runs interleave.")
    print("Ordinary codec and hash outputs are checked before timing; other operations are not verified.")
    print("CLI scenarios measure elapsed execution only, not behavioral equivalence.")
    print("Individual rows describe different workloads; no overall speedup is reported.")

    return all_results


def main():
    parser = argparse.ArgumentParser(description="Benchmark Python cloak.py vs Rust cloak-rs.")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run a quick benchmark with smaller sizes and fewer iterations",
    )
    parser.add_argument(
        "--iterations",
        "-i",
        type=int,
        default=5,
        help="Number of iterations per benchmark (default: 5)",
    )
    parser.add_argument(
        "--sizes",
        type=str,
        default="10240,262144,2097152",
        help="Comma-separated data sizes in bytes (e.g. 10240,262144,2097152)",
    )
    parser.add_argument(
        "--no-cli",
        action="store_true",
        help="Skip end-to-end CLI execution benchmarks",
    )
    parser.add_argument(
        "--json",
        type=str,
        metavar="FILE",
        help="Save raw benchmark results to a JSON file",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors",
    )

    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")

    global USE_COLOR
    if args.no_color:
        USE_COLOR = False

    if args.quick:
        sizes = [32 * 1024, 512 * 1024]
        iters = 3
    else:
        try:
            sizes = [int(s.strip()) for s in args.sizes.split(",") if s.strip()]
            if not sizes or any(size < 1 for size in sizes):
                raise ValueError
        except ValueError:
            parser.error("--sizes must contain positive byte counts")
        iters = args.iterations

    results = run_benchmarks(sizes=sizes, iters=iters, run_cli=not args.no_cli)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(green(f"[+] Benchmark results exported to {args.json}"))


if __name__ == "__main__":
    main()
