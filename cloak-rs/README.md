# Vibe-coded Port of Cloak to Rust (Use at your own risk)

A Rust implementation of the original `../cloak.py`, built as both a command-line application (`cloak-rs`) and a reusable library (`cloak_rs`). The Python implementation remains available alongside the port for comparison.

## About the port

The code is organized into modules for encoding and hashing, entropy calculations and padding, file signatures, Windows alternate data streams, command generation, and terminal output. The CLI provides `info`, `util`, `generate`, and `bench` modes. Windows-specific stream operations require Windows/NTFS.

The port follows the Python tool's behavior, but it is not guaranteed to be identical in every edge case. Decoder regressions compare against Python, missing output parents are rejected, and extension copies reject hard-link aliases. Empty RC4 keys are explicitly rejected by both the CLI and library; `rc4` returns a `Result`. Windows runtime behavior still requires verification on Windows. Rust additionally supports non-interactive encoding selections through `--technique` and `--key`, plus a built-in algorithm benchmark harness.

Recent improvements include:

- Reusing the inspection buffer for hashes, avoiding a second file read.
- A faster uppercase hexadecimal encoding loop, using safe Rust and no additional dependencies.
- Computing MD5, SHA1, and SHA256 concurrently for inputs of at least 1 MiB on hosts reporting at least three logical CPUs. Smaller inputs remain sequential, and worker-creation failures fall back to local computation.
- Propagating encoding errors, correcting hidden-file extension handling, validating benchmark iteration counts, and passing Windows paths to PowerShell as data.

Release builds enable optimization level 3, link-time optimization, and a single codegen unit. The improvements above do not imply that Rust is faster for every operation; see the hex-decoding results below.

## Build and run

Install a Rust toolchain with support for edition 2024. From the repository root:

```sh
cargo build --release --locked --manifest-path cloak-rs/Cargo.toml
./cloak-rs/target/release/cloak-rs --help
./cloak-rs/target/release/cloak-rs info -c document.txt -H
```

On Windows, the executable has an `.exe` suffix.

## Compatibility and PR validation

The compatibility target is matching ordinary operation results, filenames, and exit status for supported inputs, not identical Python tracebacks or argparse help text. Rust retains `bench`, `--technique`, and `--key` as extensions. EOF and invalid keys fail explicitly. Ctrl+C prints `Interrupted.` and exits successfully, matching the Python CLI; interrupted operations may leave intermediate files.

File copies reject hard-link aliases and preserve file permission bits and access/modification timestamps where supported. Cross-filesystem moves preserve symlinks rather than copying their target contents and retain the source when copying fails. Ownership, ACLs, extended attributes, and platform-specific metadata are not certified equivalent to Python's `shutil.copy2`. Operations assume paths are not being changed concurrently by another process.

See [VALIDATION.md](VALIDATION.md) for local test results, manual verification commands, and the Windows handoff.

## Benchmarks and validation

From the repository root:

```sh
python3 benchmark.py
```

The Python benchmark rebuilds the release executable with the checked-in lockfile and discovers its path from Cargo’s build output, including custom target directories. Its default run uses five iterations at 10 KiB, 256 KiB, and 2 MiB, followed by CLI scenarios. Python 3.9 or later is required.

For a focused comparison of the previous hex encoder and sequential hashing against the updated implementations:

```sh
cargo run --release --locked --manifest-path cloak-rs/Cargo.toml --example throughput
```

To run the focused throughput correctness tests and CLI regression checks:

```sh
cargo test --release --locked --manifest-path cloak-rs/Cargo.toml --test throughput_correctness
cargo build --manifest-path cloak-rs/Cargo.toml
python3 -m unittest discover -s tests -v
```

## Sample performance benchmark

Captured from a successful default-size `python3 benchmark.py --json /tmp/cloak-final-bench.json` run with `CARGO_TARGET_DIR=/tmp/cloak-final-bench-target` on October 21, 2026, using macOS 26.6.2 (arm64), Python 3.13.0, and rustc 1.95.0. Output is reproduced below with trailing whitespace removed. This historical sample predates the final file-handling and Ctrl+C changes; rerun the benchmark for current timings. Results depend on hardware, system load, input size, and toolchain.

Timings and speedup ratios use medians after two warmups. Microbenchmark batch order alternates; CLI measurements alternate implementations each iteration. Throughput uses mean time and original input MiB. Ordinary Base64, hex, and hash outputs are checked before timing; other operations and CLI scenarios are not verified for equivalence. No aggregate speedup or fixed performance conclusion is reported. This sample is not a complete behavioral-equivalence test.

```text
[*] Building release binary of cloak-rs...
[+] Release binary built successfully.

══════════════════════════════════════════════════════════════════════════════════════════
  Microbenchmarks: Core Algorithms (Payload Size: 10.0 KB, Iterations: 5)
══════════════════════════════════════════════════════════════════════════════════════════

Algorithm                    | Python Median | Python MiB/s | Rust Median  | Rust MiB/s  | Speedup
---------------------------------------------------------------------------------------------------
RC4 Stream Cipher            | 1.39 ms      | 6.7         | 10.96 µs     | 889.2       | 126.5x
Shannon Entropy              | 197.21 µs    | 46.1        | 3.71 µs      | 2639.4      | 53.2x
Lower Entropy (Null Padding) | 8.79 ms      | 1.1         | 151.04 µs    | 66.1        | 58.2x
Strip Padding                | 1.10 ms      | 8.9         | 14.67 µs     | 664.3       | 74.7x
XOR Byte Masking             | 278.38 µs    | 35.0        | 208.0 ns     | 49073.5     | 1338.3x
Base64 Encode                | 10.50 µs     | 930.8       | 3.88 µs      | 2531.3      | 2.7x
Base64 Decode                | 25.21 µs     | 382.3       | 3.96 µs      | 2456.8      | 6.4x
Hex Encode                   | 14.33 µs     | 671.2       | 6.17 µs      | 1550.1      | 2.3x
Hex Decode                   | 7.29 µs      | 669.3       | 87.42 µs     | 111.6       | 0.1x
Hashes (MD5+SHA1+SHA256)     | 25.88 µs     | 380.2       | 24.25 µs     | 361.0       | 1.1x

══════════════════════════════════════════════════════════════════════════════════════════
  Microbenchmarks: Core Algorithms (Payload Size: 256.0 KB, Iterations: 5)
══════════════════════════════════════════════════════════════════════════════════════════

Algorithm                    | Python Median | Python MiB/s | Rust Median  | Rust MiB/s  | Speedup
---------------------------------------------------------------------------------------------------
RC4 Stream Cipher            | 33.46 ms     | 7.5         | 311.46 µs    | 809.1       | 107.4x
Shannon Entropy              | 8.24 ms      | 30.8        | 73.38 µs     | 3409.9      | 112.3x
Lower Entropy (Null Padding) | 243.76 ms    | 1.0         | 3.20 ms      | 75.3        | 76.1x
Strip Padding                | 28.54 ms     | 8.7         | 358.33 µs    | 697.3       | 79.7x
XOR Byte Masking             | 7.40 ms      | 33.8        | 5.62 µs      | 44515.7     | 1315.6x
Base64 Encode                | 277.88 µs    | 868.9       | 97.96 µs     | 2492.8      | 2.8x
Base64 Decode                | 728.62 µs    | 320.7       | 99.92 µs     | 2466.9      | 7.3x
Hex Encode                   | 353.92 µs    | 706.7       | 157.83 µs    | 1568.9      | 2.2x
Hex Decode                   | 194.67 µs    | 1263.3      | 2.53 ms      | 96.8        | 0.1x
Hashes (MD5+SHA1+SHA256)     | 623.04 µs    | 382.2       | 609.58 µs    | 409.1       | 1.0x

══════════════════════════════════════════════════════════════════════════════════════════
  Microbenchmarks: Core Algorithms (Payload Size: 2.0 MB, Iterations: 5)
══════════════════════════════════════════════════════════════════════════════════════════

Algorithm                    | Python Median | Python MiB/s | Rust Median  | Rust MiB/s  | Speedup
---------------------------------------------------------------------------------------------------
RC4 Stream Cipher            | 269.31 ms    | 7.4         | 2.26 ms      | 873.9       | 119.0x
Shannon Entropy              | 56.26 ms     | 35.0        | 587.96 µs    | 3211.4      | 95.7x
Lower Entropy (Null Padding) | 2.30 s       | 0.9         | 26.87 ms     | 71.9        | 85.5x
Strip Padding                | 289.89 ms    | 6.8         | 3.95 ms      | 493.0       | 73.3x
XOR Byte Masking             | 57.45 ms     | 34.5        | 44.58 µs     | 44935.7     | 1288.5x
Base64 Encode                | 2.30 ms      | 853.7       | 783.29 µs    | 2533.0      | 2.9x
Base64 Decode                | 5.14 ms      | 390.8       | 783.00 µs    | 2452.3      | 6.6x
Hex Encode                   | 2.89 ms      | 691.5       | 1.16 ms      | 1689.9      | 2.5x
Hex Decode                   | 1.33 ms      | 1474.3      | 20.00 ms     | 99.9        | 0.1x
Hashes (MD5+SHA1+SHA256)     | 4.94 ms      | 401.1       | 3.23 ms      | 602.5       | 1.5x

══════════════════════════════════════════════════════════════════════════════════════════
  End-to-End CLI Pipeline Benchmarks (Real Process Execution)
══════════════════════════════════════════════════════════════════════════════════════════

Scenario                                   | Python CLI   | Rust CLI     | Speedup
-----------------------------------------------------------------------------------
info mode (-c payload --show-hashes)       | 60.53 ms     | 5.36 ms      | 11.3x
util mode (--lower-entropy 5.5 -o out)     | 525.62 ms    | 12.70 ms     | 41.4x
generate mode (--lolbin regsvr32)          | 42.62 ms     | 3.89 ms      | 11.0x
generate mode (--list)                     | 42.90 ms     | 4.08 ms      | 10.5x

══════════════════════════════════════════════════════════════════════════════════════════
  Benchmark Notes
══════════════════════════════════════════════════════════════════════════════════════════

Times and speedups use medians; throughput uses mean duration and original input MiB.
Two warmups precede each measurement batch. Batch order alternates; CLI runs interleave.
Ordinary codec and hash outputs are checked before timing; other operations are not verified.
CLI scenarios measure elapsed execution only, not behavioral equivalence.
Individual rows describe different workloads; no overall speedup is reported.
[+] Benchmark results exported to /tmp/cloak-final-bench.json
```
