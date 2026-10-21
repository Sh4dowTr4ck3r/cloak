mod file_ops;
use clap::{ArgGroup, Parser};
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

use cloak_rs::ads::{ads_delete, ads_list, ads_read, ads_write};
use cloak_rs::crypto::{
    b64_decode, b64_encode, hex_decode, hex_encode, parse_rc4_key, parse_xor_key, rc4, show_hashes,
    show_hashes_data, xor_bytes,
};
use cloak_rs::entropy::{calc_entropy, lower_entropy, strip_null_padding};
use cloak_rs::lolbins::{LOLBINS, get_lolbin};
use cloak_rs::magic::{match_magic_bytes, set_magic_bytes};
use cloak_rs::ui::{
    banner, bold, cyan, err, fmt_bytes, green, grey, info, init_color, magenta, ok, red, warn,
    yellow,
};

#[derive(Parser, Debug)]
#[command(
    name = "cloak",
    version = "0.1.0",
    about = "Red Team File Utility — encode, ADS, entropy, spoof, inspect, generate LOLBin commands."
)]
#[command(group(
    ArgGroup::new("codec")
        .args(["encode", "decode"])
        .multiple(false)
))]
pub struct Cli {
    #[arg(
        value_name = "MODE",
        required = true,
        value_parser = ["info", "util", "generate", "bench"],
        help = "Operation mode (info | util | generate | bench)"
    )]
    pub mode: Option<String>,

    #[arg(short = 'c', long = "carrier", help = "Input file")]
    pub carrier: Option<String>,

    #[arg(short = 'o', long = "output", help = "Output file path")]
    pub output: Option<String>,

    #[arg(
        short = 'e',
        long = "encode",
        help = "Show interactive encoding menu (includes RC4)"
    )]
    pub encode: bool,

    #[arg(
        short = 'd',
        long = "decode",
        help = "Show interactive decoding menu (includes RC4)"
    )]
    pub decode: bool,

    #[arg(
        long = "lower-entropy",
        value_name = "TARGET",
        help = "Lower entropy via null-byte interleaving to reach target (e.g. 6.0)."
    )]
    pub lower_entropy: Option<f64>,

    #[arg(
        long = "strip-padding",
        value_name = "INTERVAL",
        help = "Reverse null-byte padding. Pass the interval printed during --lower-entropy."
    )]
    pub strip_padding: Option<usize>,

    #[arg(
        short = 'n',
        long = "new-extension",
        value_name = "EXT",
        help = "Replace all extensions (e.g. .pdf)"
    )]
    pub new_extension: Option<String>,

    #[arg(
        short = 'a',
        long = "add-extension",
        value_name = "EXT",
        help = "Append to filename (e.g. .bak)"
    )]
    pub add_extension: Option<String>,

    #[arg(
        short = 'x',
        long = "spoof-header",
        help = "Overwrite first bytes with magic bytes for target extension"
    )]
    pub spoof_header: bool,

    #[arg(
        short = 'H',
        long = "show-hashes",
        help = "Display MD5 / SHA1 / SHA256"
    )]
    pub show_hashes: bool,

    #[arg(short = 'q', long = "quiet", help = "Suppress banner")]
    pub quiet: bool,

    // Non-interactive options for automated / scripted benchmarking
    #[arg(
        long = "technique",
        value_parser = clap::value_parser!(u8).range(1..=7),
        value_name = "NUM",
        help = "Direct encoding/decoding technique [1-7] (skips interactive menu)"
    )]
    pub technique: Option<u8>,

    #[arg(
        long = "key",
        value_name = "KEY",
        help = "Direct key for XOR or RC4 (skips key prompt)"
    )]
    pub key: Option<String>,

    // ADS (Windows only)
    #[arg(
        long = "ads-write",
        value_name = "PAYLOAD",
        help = "Write PAYLOAD into an ADS on --carrier"
    )]
    pub ads_write: Option<String>,

    #[arg(long = "ads-read", help = "Read ADS stream from --carrier to --output")]
    pub ads_read: bool,

    #[arg(long = "ads-list", help = "List all ADS streams on --carrier")]
    pub ads_list: bool,

    #[arg(long = "ads-delete", help = "Delete ADS stream from --carrier")]
    pub ads_delete: bool,

    #[arg(
        long = "ads-stream",
        value_name = "NAME",
        help = "Stream name (e.g. 'hidden' -> file.txt:hidden)"
    )]
    pub ads_stream: Option<String>,

    // LOLBin generate args
    #[arg(
        long = "lolbin",
        value_name = "NAME",
        help = "LOLBin to use (e.g. regsvr32, certutil, mshta). Interactive menu if omitted."
    )]
    pub lolbin: Option<String>,

    #[arg(
        long = "lolbin-file",
        value_name = "PATH",
        help = "Local payload file path to embed in commands"
    )]
    pub lolbin_file: Option<String>,

    #[arg(
        long = "lolbin-url",
        value_name = "URL",
        help = "Remote URL to embed in download cradles"
    )]
    pub lolbin_url: Option<String>,

    #[arg(
        long = "lolbin-arg",
        value_name = "ARG",
        help = "Extra argument (e.g. DLL export name for rundll32)"
    )]
    pub lolbin_arg: Option<String>,

    #[arg(long = "list", help = "List all available LOLBins and exit")]
    pub list: bool,

    // Benchmark args
    #[arg(
        long = "algo",
        help = "Algorithm for bench mode (e.g. rc4, entropy, lower-entropy, strip-padding, xor, base64-encode, base64-decode, hex-encode, hex-decode, hashes)"
    )]
    pub algo: Option<String>,

    #[arg(
        long = "size",
        default_value_t = 1048576,
        help = "Data size in bytes for benchmark"
    )]
    pub size: usize,

    #[arg(
        long = "iterations",
        default_value_t = 10,
        help = "Number of benchmark iterations"
    )]
    pub iterations: usize,
}

fn strip_all_extensions(name: &str) -> String {
    let file_name = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    let mut base = PathBuf::from(file_name);
    while base.extension().is_some_and(|ext| !ext.is_empty()) {
        base.set_extension("");
    }
    base.to_string_lossy().into_owned()
}

fn prompt_line(prompt_text: &str) -> Result<String, String> {
    print!("{}", prompt_text);
    io::Write::flush(&mut io::stdout()).map_err(|e| e.to_string())?;
    let mut input = String::new();
    let stdin = io::stdin();
    let bytes_read = stdin
        .lock()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    if bytes_read == 0 {
        return Err("EOF when reading a line".to_string());
    }
    Ok(input.trim().to_string())
}

fn encoding_menu(
    file_path: &Path,
    preset_technique: Option<u8>,
    preset_key: Option<&str>,
) -> Result<PathBuf, String> {
    let choice_str = if let Some(t) = preset_technique {
        t.to_string()
    } else {
        println!();
        println!("{}", magenta("  ┌───────────────────────────────┐"));
        println!("{}", magenta("  │     Encoding Techniques       │"));
        println!("{}", magenta("  ├───────────────────────────────┤"));
        println!("{}", magenta("  │  [1] Base64                   │"));
        println!("{}", magenta("  │  [2] Hex                      │"));
        println!("{}", magenta("  │  [3] XOR  (key prompted)      │"));
        println!("{}", magenta("  │  [4] Reverse bytes            │"));
        println!("{}", magenta("  │  [5] XOR → Base64             │"));
        println!("{}", magenta("  │  [6] XOR → Hex                │"));
        println!("{}", magenta("  │  [7] RC4  (key prompted)      │"));
        println!("{}", magenta("  └───────────────────────────────┘"));

        prompt_line("  Select technique [1-7]: ")?
    };

    let data = fs::read(file_path).map_err(|e| format!("Cannot read file: {}", e))?;
    let encoded_bytes: Vec<u8>;

    match choice_str.trim() {
        "1" => {
            let encoded = b64_encode(&data);
            encoded_bytes = encoded.into_bytes();
            ok("Base64 encoding applied.");
        }
        "2" => {
            let encoded = hex_encode(&data);
            encoded_bytes = encoded.into_bytes();
            ok("Hex encoding applied.");
        }
        "3" => {
            let raw_key = match preset_key {
                Some(k) => k.to_string(),
                None => prompt_line("  XOR key (hex e.g. 0x41 or decimal e.g. 65): ")?,
            };
            let key = parse_xor_key(&raw_key)?;
            encoded_bytes = xor_bytes(&data, key);
            ok(&format!("XOR applied (key 0x{:02X}).", key));
        }
        "4" => {
            encoded_bytes = data.into_iter().rev().collect();
            ok("Byte order reversed.");
        }
        "5" => {
            let raw_key = match preset_key {
                Some(k) => k.to_string(),
                None => prompt_line("  XOR key (hex e.g. 0x41 or decimal e.g. 65): ")?,
            };
            let key = parse_xor_key(&raw_key)?;
            let xored = xor_bytes(&data, key);
            let encoded = b64_encode(&xored);
            encoded_bytes = encoded.into_bytes();
            ok(&format!("XOR (0x{:02X}) → Base64 applied.", key));
        }
        "6" => {
            let raw_key = match preset_key {
                Some(k) => k.to_string(),
                None => prompt_line("  XOR key (hex e.g. 0x41 or decimal e.g. 65): ")?,
            };
            let key = parse_xor_key(&raw_key)?;
            let xored = xor_bytes(&data, key);
            let encoded = hex_encode(&xored);
            encoded_bytes = encoded.into_bytes();
            ok(&format!("XOR (0x{:02X}) → Hex applied.", key));
        }
        "7" => {
            let raw_key = match preset_key {
                Some(k) => k.to_string(),
                None => prompt_line("  RC4 key (string or hex e.g. 0xDEADBEEF): ")?,
            };
            let key = parse_rc4_key(&raw_key)?;
            let key_len = key.len();
            encoded_bytes = rc4(&data, &key)?;
            ok(&format!("RC4 applied (key length {} bytes).", key_len));
        }
        _ => {
            println!("  Invalid selection — no encoding applied.");
            return Ok(file_path.to_path_buf());
        }
    }

    let out_path = PathBuf::from(format!("{}.enc", file_path.display()));
    fs::write(&out_path, &encoded_bytes)
        .map_err(|e| format!("Failed to write encoded file: {}", e))?;
    ok(&format!("Encoded file saved → {}", out_path.display()));
    Ok(out_path)
}

fn decoding_menu(
    file_path: &Path,
    preset_technique: Option<u8>,
    preset_key: Option<&str>,
) -> Result<PathBuf, String> {
    let choice_str = if let Some(t) = preset_technique {
        t.to_string()
    } else {
        println!();
        println!("{}", magenta("  ┌───────────────────────────────┐"));
        println!("{}", magenta("  │     Decoding Techniques       │"));
        println!("{}", magenta("  ├───────────────────────────────┤"));
        println!("{}", magenta("  │  [1] Base64                   │"));
        println!("{}", magenta("  │  [2] Hex                      │"));
        println!("{}", magenta("  │  [3] XOR  (key prompted)      │"));
        println!("{}", magenta("  │  [4] Reverse bytes            │"));
        println!("{}", magenta("  │  [5] XOR ← Base64             │"));
        println!("{}", magenta("  │  [6] XOR ← Hex                │"));
        println!("{}", magenta("  │  [7] RC4  (key prompted)      │"));
        println!("{}", magenta("  └───────────────────────────────┘"));

        prompt_line("  Select technique [1-7]: ")?
    };

    let data = fs::read(file_path).map_err(|e| format!("Cannot read file: {}", e))?;
    let decoded_bytes: Vec<u8>;

    match choice_str.trim() {
        "1" => {
            decoded_bytes = b64_decode(&data)?;
            ok("Base64 decoding applied.");
        }
        "2" => {
            let s = std::str::from_utf8(&data).map_err(|e| format!("Invalid UTF-8: {e}"))?;
            decoded_bytes = hex_decode(s.trim())?;
            ok("Hex decoding applied.");
        }
        "3" => {
            let raw_key = match preset_key {
                Some(k) => k.to_string(),
                None => prompt_line("  XOR key (hex e.g. 0x41 or decimal e.g. 65): ")?,
            };
            let key = parse_xor_key(&raw_key)?;
            decoded_bytes = xor_bytes(&data, key);
            ok(&format!("XOR decoding applied (key 0x{:02X}).", key));
        }
        "4" => {
            decoded_bytes = data.into_iter().rev().collect();
            ok("Byte order reversed (decode).");
        }
        "5" => {
            let raw_key = match preset_key {
                Some(k) => k.to_string(),
                None => prompt_line("  XOR key (hex e.g. 0x41 or decimal e.g. 65): ")?,
            };
            let key = parse_xor_key(&raw_key)?;
            let b64_res = b64_decode(&data)?;
            decoded_bytes = xor_bytes(&b64_res, key);
            ok(&format!(
                "Base64 → XOR decoding applied (key 0x{:02X}).",
                key
            ));
        }
        "6" => {
            let raw_key = match preset_key {
                Some(k) => k.to_string(),
                None => prompt_line("  XOR key (hex e.g. 0x41 or decimal e.g. 65): ")?,
            };
            let key = parse_xor_key(&raw_key)?;
            let s = std::str::from_utf8(&data).map_err(|e| format!("Invalid UTF-8: {e}"))?;
            let hex_res = hex_decode(s.trim())?;
            decoded_bytes = xor_bytes(&hex_res, key);
            ok(&format!("Hex → XOR decoding applied (key 0x{:02X}).", key));
        }
        "7" => {
            let raw_key = match preset_key {
                Some(k) => k.to_string(),
                None => prompt_line("  RC4 key (string or hex e.g. 0xDEADBEEF): ")?,
            };
            let key = parse_rc4_key(&raw_key)?;
            let key_len = key.len();
            decoded_bytes = rc4(&data, &key)?;
            ok(&format!(
                "RC4 decoding applied (key length {} bytes).",
                key_len
            ));
        }
        _ => {
            println!("  Invalid selection — no decoding applied.");
            return Ok(file_path.to_path_buf());
        }
    }

    let out_path = PathBuf::from(format!("{}.dec", file_path.display()));
    fs::write(&out_path, &decoded_bytes)
        .map_err(|e| format!("Failed to write decoded file: {}", e))?;
    ok(&format!("Decoded file saved → {}", out_path.display()));
    Ok(out_path)
}

fn post_process_with_temps(
    mut work_file: PathBuf,
    args: &Cli,
    protected: &[PathBuf],
    temps: &[PathBuf],
) -> Result<PathBuf, String> {
    // 1. New Extension
    if let Some(ref new_ext) = args.new_extension {
        let ext = if new_ext.starts_with('.') {
            new_ext.clone()
        } else {
            format!(".{}", new_ext)
        };
        let file_name = work_file
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let base = strip_all_extensions(file_name);
        let parent = work_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let new_name = parent.join(format!("{}{}", base, ext));

        let res_work = work_file
            .canonicalize()
            .unwrap_or_else(|_| work_file.clone());
        let res_new = new_name.canonicalize().unwrap_or_else(|_| new_name.clone());

        if res_work != res_new {
            file_ops::copy_preserving_metadata(&work_file, &new_name)
                .map_err(|e| format!("Failed to copy file: {e}"))?;
            ok(&format!("Extension replaced → {}", new_name.display()));
            work_file = new_name;
        } else {
            warn("Output already has target extension, skipping rename.");
        }

        if args.spoof_header {
            set_magic_bytes(&work_file, &ext).map_err(|e| e.to_string())?;
        }
    }

    // 2. Add Extension
    if let Some(ref add_ext) = args.add_extension {
        let ext = if add_ext.starts_with('.') {
            add_ext.clone()
        } else {
            format!(".{}", add_ext)
        };
        let new_name = PathBuf::from(format!("{}{}", work_file.display(), ext));

        let res_work = work_file
            .canonicalize()
            .unwrap_or_else(|_| work_file.clone());
        let res_new = new_name.canonicalize().unwrap_or_else(|_| new_name.clone());

        if res_work != res_new {
            file_ops::copy_preserving_metadata(&work_file, &new_name)
                .map_err(|e| format!("Failed to copy file: {e}"))?;
            ok(&format!("Extension appended → {}", new_name.display()));
            work_file = new_name;
        } else {
            warn("File already has that appended extension, skipping.");
        }

        if args.spoof_header {
            set_magic_bytes(&work_file, &ext).map_err(|e| e.to_string())?;
        }
    }

    // 3. Hashes
    if args.show_hashes {
        show_hashes(&work_file).map_err(|e| e.to_string())?;
    }

    // 4. Clean up temps
    let final_res = work_file
        .canonicalize()
        .unwrap_or_else(|_| work_file.clone());
    let protected_res: Vec<PathBuf> = protected
        .iter()
        .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))
        .collect();

    for tmp in temps {
        let tmp_res = tmp.canonicalize().unwrap_or_else(|_| tmp.clone());
        if tmp_res != final_res && !protected_res.contains(&tmp_res) && tmp.exists() {
            fs::remove_file(tmp)
                .map_err(|e| format!("Failed to remove temporary file {}: {e}", tmp.display()))?;
            warn(&format!("Cleaned up temp file: {}", tmp.display()));
        }
    }

    Ok(work_file)
}

fn do_info(carrier: &str, show_hashes_flag: bool) -> Result<(), String> {
    let path = Path::new(carrier);
    if !path.exists() {
        return Err(format!("Cannot find path '{}'", carrier));
    }
    let data = fs::read(path).map_err(|e| format!("Cannot read file: {}", e))?;

    println!("{}", cyan(&format!("[*] File           : {}", carrier)));
    println!(
        "{}",
        cyan(&format!(
            "[*] Size           : {} ({} bytes)",
            fmt_bytes(data.len() as u64),
            data.len()
        ))
    );

    let entropy = calc_entropy(&data);
    let entropy_label = if entropy < 6.5 {
        green("low — looks benign")
    } else if entropy < 7.2 {
        yellow("medium — mildly suspicious")
    } else {
        red("high — likely packed/encrypted")
    };
    println!(
        "{}({})",
        cyan(&format!("[*] Entropy        : {:.3} / 8.0  ", entropy)),
        entropy_label
    );

    let preview_len = data.len().min(16);
    let hex_preview = data[..preview_len]
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");
    println!("{}", cyan(&format!("[*] First 16 bytes : {}", hex_preview)));

    let matches = match_magic_bytes(&data);
    if !matches.is_empty() {
        ok(&format!(
            "Header matches known format(s): {}",
            matches.join(", ")
        ));
    } else {
        warn("Header does not match any known magic bytes in the map.");
    }

    if show_hashes_flag {
        show_hashes_data(path, &data);
    }

    Ok(())
}

fn do_util(args: &Cli) -> Result<String, String> {
    let target_str = args
        .carrier
        .as_ref()
        .ok_or_else(|| "Provide --carrier for util mode.".to_string())?;
    let target = Path::new(target_str);
    if !target.exists() {
        return Err(format!("File not found: {}", target_str));
    }

    // ADS operations
    if let Some(ref ads_w) = args.ads_write {
        let stream = args
            .ads_stream
            .as_ref()
            .ok_or_else(|| "--ads-stream NAME is required with --ads-write.".to_string())?;
        ads_write(target_str, stream, ads_w)?;
        return Ok(target_str.to_string());
    }

    if args.ads_read {
        let stream = args
            .ads_stream
            .as_ref()
            .ok_or_else(|| "--ads-stream NAME is required with --ads-read.".to_string())?;
        let output = args
            .output
            .as_ref()
            .ok_or_else(|| "--output is required with --ads-read.".to_string())?;
        ads_read(target_str, stream, output)?;
        return Ok(output.to_string());
    }

    if args.ads_list {
        ads_list(target_str)?;
        return Ok(target_str.to_string());
    }

    if args.ads_delete {
        let stream = args
            .ads_stream
            .as_ref()
            .ok_or_else(|| "--ads-stream NAME is required with --ads-delete.".to_string())?;
        ads_delete(target_str, stream)?;
        return Ok(target_str.to_string());
    }

    // Normal util flow
    info(&format!("File: {}", target_str));
    let mut work_file = target.to_path_buf();
    let mut temps: Vec<PathBuf> = Vec::new();

    // Entropy — strip padding (reverse)
    if let Some(interval) = args.strip_padding {
        let data = fs::read(&work_file).map_err(|e| e.to_string())?;
        let recovered = strip_null_padding(&data, interval)?;
        let out_path = PathBuf::from(format!("{}.stripped", work_file.display()));
        fs::write(&out_path, &recovered).map_err(|e| e.to_string())?;
        ok(&format!("Recovered file saved → {}", out_path.display()));
        work_file = out_path.clone();
        temps.push(out_path);
    } else if let Some(target_ent) = args.lower_entropy {
        let data = fs::read(&work_file).map_err(|e| e.to_string())?;
        let (padded, _) = lower_entropy(&data, target_ent);
        let out_path = PathBuf::from(format!("{}.padded", work_file.display()));
        fs::write(&out_path, &padded).map_err(|e| e.to_string())?;
        ok(&format!("Padded file saved → {}", out_path.display()));
        work_file = out_path.clone();
        temps.push(out_path);
    }

    // Encoding / Decoding
    if args.decode {
        let prev = work_file.clone();
        work_file = decoding_menu(&work_file, args.technique, args.key.as_deref())?;
        if work_file != prev {
            temps.push(work_file.clone());
        }
    } else if args.encode {
        let prev = work_file.clone();
        work_file = encoding_menu(&work_file, args.technique, args.key.as_deref())?;
        if work_file != prev {
            temps.push(work_file.clone());
        }
    }

    // Post-process
    let protected = vec![target.to_path_buf()];
    let mut final_file = post_process_with_temps(work_file, args, &protected, &temps)?;

    // If --output is specified
    if let Some(ref out_path_str) = args.output {
        let out_path = Path::new(out_path_str);
        let final_res = final_file
            .canonicalize()
            .unwrap_or_else(|_| final_file.clone());
        let out_res = out_path
            .canonicalize()
            .unwrap_or_else(|_| out_path.to_path_buf());

        if final_res != out_res {
            // Match shutil.move: a directory receives the source basename,
            // and an existing entry inside that directory is an error.
            let destination = if out_path.is_dir() {
                let name = final_file
                    .file_name()
                    .ok_or_else(|| "Output source has no filename".to_string())?;
                let destination = out_path.join(name);
                if destination.symlink_metadata().is_ok() {
                    return Err(format!(
                        "Destination path '{}' already exists",
                        destination.display()
                    ));
                }
                destination
            } else {
                out_path.to_path_buf()
            };
            let out_path = destination.as_path();
            file_ops::move_file(&final_file, out_path)
                .map_err(|e| format!("Failed to move file to {}: {}", out_path_str, e))?;
            ok(&format!("Final output moved/renamed → {}", out_path_str));
            final_file = out_path.to_path_buf();
        }
    }

    Ok(final_file.to_string_lossy().to_string())
}

fn do_generate(args: &Cli) -> Result<(), String> {
    let file_path = args.lolbin_file.as_deref().unwrap_or("");
    let url = args.lolbin_url.as_deref().unwrap_or("");
    let extra_arg = args.lolbin_arg.as_deref().unwrap_or("");

    let ext = if !file_path.is_empty() {
        Path::new(file_path)
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| format!(".{}", s.to_lowercase()))
            .unwrap_or_else(|| "*".to_string())
    } else if !url.is_empty() {
        let before_query = url.split('?').next().unwrap_or("");
        Path::new(before_query)
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| format!(".{}", s.to_lowercase()))
            .unwrap_or_else(|| "*".to_string())
    } else {
        "*".to_string()
    };

    let display_file = if !file_path.is_empty() {
        file_path
    } else if !url.is_empty() {
        let before_query = url.split('?').next().unwrap_or("");
        Path::new(before_query)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("payload")
    } else {
        "payload"
    };

    let mut compatible: Vec<&'static cloak_rs::lolbins::LolBin> = Vec::new();
    for lb in LOLBINS {
        if lb.types.contains(&"*") || lb.types.contains(&ext.as_str()) || ext == "*" {
            compatible.push(lb);
        }
    }

    if compatible.is_empty() {
        let mut all_types: Vec<&'static str> = LOLBINS
            .iter()
            .flat_map(|lb| lb.types.iter().copied())
            .collect();
        all_types.sort();
        all_types.dedup();
        return Err(format!(
            "No LOLBins found for extension '{}'. Try one of: {}",
            ext,
            all_types.join(", ")
        ));
    }

    let chosen_bin: &'static cloak_rs::lolbins::LolBin = if let Some(ref name) = args.lolbin {
        match get_lolbin(name) {
            Some(lb) => lb,
            None => {
                let names: Vec<&str> = LOLBINS.iter().map(|lb| lb.name).collect();
                return Err(format!("Unknown LOLBin '{}'. Available: {:?}", name, names));
            }
        }
    } else {
        println!();
        println!(
            "{}",
            magenta("  ┌─────────────────────────────────────────────┐")
        );
        println!(
            "{}",
            magenta("  │           LOLBin Generator                  │")
        );
        println!("{}", magenta(&format!("  │  Extension : {:<31}│", ext)));
        println!(
            "{}",
            magenta("  ├─────────────────────────────────────────────┤")
        );
        for (i, lb) in compatible.iter().enumerate() {
            let desc_trunc = if lb.desc.len() > 26 {
                &lb.desc[..26]
            } else {
                lb.desc
            };
            println!(
                "{}",
                magenta(&format!(
                    "  │  [{:>2}] {:<14} {:<26}│",
                    i + 1,
                    lb.name,
                    desc_trunc
                ))
            );
        }
        println!(
            "{}",
            magenta("  └─────────────────────────────────────────────┘")
        );

        let line = prompt_line("  Select LOLBin [#]: ")?;
        let idx = line
            .parse::<usize>()
            .map_err(|_| "Invalid selection.".to_string())?;
        if idx == 0 || idx > compatible.len() {
            return Err("Invalid selection.".to_string());
        }
        compatible[idx - 1]
    };

    let commands = (chosen_bin.generate)(display_file, url, extra_arg, &ext);

    println!();
    println!("{}", cyan(&format!("  LOLBin    : {}", chosen_bin.name)));
    println!("{}", cyan(&format!("  Purpose   : {}", chosen_bin.desc)));
    if chosen_bin.os.contains('⚠') {
        println!("{}", red(&format!("  OS        : {}", chosen_bin.os)));
    } else {
        println!("{}", cyan(&format!("  OS        : {}", chosen_bin.os)));
    }
    if !chosen_bin.note.is_empty() {
        println!("{}", yellow(&format!("  Note      : {}", chosen_bin.note)));
    }
    if !file_path.is_empty() {
        println!("{}", cyan(&format!("  File      : {}", file_path)));
    }
    if !url.is_empty() {
        println!("{}", cyan(&format!("  URL       : {}", url)));
    }
    println!();
    println!(
        "{}",
        yellow("  ┌─────────────────────────────────────────────────────────────┐")
    );
    println!(
        "{}",
        yellow("  │                     Generated Commands                      │")
    );
    println!(
        "{}",
        yellow("  └─────────────────────────────────────────────────────────────┘")
    );
    for (i, cmd) in commands.iter().enumerate() {
        println!();
        println!("{} {}", green(&format!("  [{}]", i + 1)), bold(cmd));
    }

    if let Some(ref out_file) = args.output {
        let mut lines = Vec::new();
        lines.push(format!("# LOLBin: {}", chosen_bin.name));
        lines.push(format!("# {}", chosen_bin.desc));
        if !file_path.is_empty() {
            lines.push(format!("# File : {}", file_path));
        }
        if !url.is_empty() {
            lines.push(format!("# URL  : {}", url));
        }
        lines.push(String::new());
        for (i, cmd) in commands.iter().enumerate() {
            lines.push(format!("# Variant {}", i + 1));
            lines.push(cmd.clone());
            lines.push(String::new());
        }
        fs::write(out_file, lines.join("\n").as_bytes())
            .map_err(|e| format!("Failed to save output file: {}", e))?;
        ok(&format!("Commands saved → {}", out_file));
    }
    println!();

    Ok(())
}

fn generate_bench_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut state: u64 = 0x853c49e6748fea9b;
    for _ in 0..size {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        data.push((state >> 33) as u8);
    }
    data
}

fn do_bench(args: &Cli) -> Result<(), String> {
    let algo = args.algo.as_deref().unwrap_or("all");
    let size = args.size;
    let iters = args.iterations;
    if iters == 0 {
        return Err("--iterations must be at least 1".to_string());
    }

    let algos = if algo == "all" {
        vec![
            "entropy",
            "lower-entropy",
            "strip-padding",
            "rc4",
            "xor",
            "base64-encode",
            "base64-decode",
            "hex-encode",
            "hex-decode",
            "hashes",
        ]
    } else {
        vec![algo]
    };

    let data = generate_bench_data(size);

    for a in algos {
        let mut times = Vec::with_capacity(iters);
        match a {
            "entropy" => {
                for _ in 0..iters.saturating_add(2) {
                    let start = std::time::Instant::now();
                    std::hint::black_box(calc_entropy(std::hint::black_box(&data)));
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
            "lower-entropy" => {
                for _ in 0..iters.saturating_add(2) {
                    let start = std::time::Instant::now();
                    std::hint::black_box(cloak_rs::entropy::lower_entropy_raw(
                        std::hint::black_box(&data),
                        6.0,
                    ));
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
            "strip-padding" => {
                let (padded, _) = cloak_rs::entropy::lower_entropy_raw(&data, 6.0);
                for _ in 0..iters.saturating_add(2) {
                    let start = std::time::Instant::now();
                    std::hint::black_box(
                        cloak_rs::entropy::strip_null_padding_raw(std::hint::black_box(&padded), 1)
                            .unwrap(),
                    );
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
            "rc4" => {
                let key = b"RedTeamSecretKey123456789";
                for _ in 0..iters.saturating_add(2) {
                    let start = std::time::Instant::now();
                    std::hint::black_box(rc4(std::hint::black_box(&data), key)?);
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
            "xor" => {
                for _ in 0..iters.saturating_add(2) {
                    let start = std::time::Instant::now();
                    std::hint::black_box(xor_bytes(std::hint::black_box(&data), 0x5A));
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
            "base64-encode" => {
                for _ in 0..iters.saturating_add(2) {
                    let start = std::time::Instant::now();
                    std::hint::black_box(b64_encode(std::hint::black_box(&data)));
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
            "base64-decode" => {
                let encoded = b64_encode(&data);
                let enc_bytes = encoded.as_bytes();
                for _ in 0..iters.saturating_add(2) {
                    let start = std::time::Instant::now();
                    std::hint::black_box(b64_decode(std::hint::black_box(enc_bytes)).unwrap());
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
            "hex-encode" => {
                for _ in 0..iters.saturating_add(2) {
                    let start = std::time::Instant::now();
                    std::hint::black_box(hex_encode(std::hint::black_box(&data)));
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
            "hex-decode" => {
                let hex_str = hex_encode(&data);
                for _ in 0..iters.saturating_add(2) {
                    let start = std::time::Instant::now();
                    std::hint::black_box(hex_decode(std::hint::black_box(&hex_str)).unwrap());
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
            "hashes" => {
                for _ in 0..iters.saturating_add(2) {
                    let start = std::time::Instant::now();
                    let d = std::hint::black_box(&data);
                    std::hint::black_box(cloak_rs::crypto::all_hashes(d));
                    times.push(start.elapsed().as_nanos() as u64);
                }
            }
            other => return Err(format!("Unknown benchmark algorithm '{}'", other)),
        }

        times.drain(..2);
        times.sort_unstable();
        let min_ns = times[0];
        let max_ns = times[times.len() - 1];
        let sum_ns: u64 = times.iter().sum();
        let avg_ns = sum_ns / times.len() as u64;
        let middle = times.len() / 2;
        let median_ns = if times.len().is_multiple_of(2) {
            (times[middle - 1] as f64 + times[middle] as f64) / 2.0
        } else {
            times[middle] as f64
        };
        let sec = avg_ns as f64 / 1_000_000_000.0;
        let mb = size as f64 / (1024.0 * 1024.0);
        let mb_s = if sec > 0.0 { mb / sec } else { 0.0 };

        println!(
            "{{\"algo\":\"{}\",\"size\":{},\"iterations\":{},\"min_ns\":{},\"max_ns\":{},\"avg_ns\":{},\"median_ns\":{},\"throughput_mb_s\":{:.2}}}",
            a, size, iters, min_ns, max_ns, avg_ns, median_ns, mb_s
        );
    }

    Ok(())
}

fn main() {
    let args = Cli::parse();
    init_color(None);
    if let Err(e) = ctrlc::set_handler(|| {
        println!();
        warn("Interrupted.");
        std::process::exit(0);
    }) {
        err(&format!("Cannot install interrupt handler: {e}"));
        std::process::exit(1);
    }

    let mode = match args.mode.as_deref() {
        Some(m) => m.to_lowercase(),
        None => {
            if args.list {
                "generate".to_string()
            } else {
                err("Operation mode (info | util | generate) is required.");
                std::process::exit(1);
            }
        }
    };

    if mode != "bench" {
        banner(args.quiet);
    }

    let result = match mode.as_str() {
        "info" => {
            let carrier = match args.carrier.as_deref() {
                Some(c) => c,
                None => {
                    err("--carrier is required for info mode.");
                    std::process::exit(2);
                }
            };
            let info_res = do_info(carrier, args.show_hashes);
            if info_res.is_ok() && args.encode {
                encoding_menu(Path::new(carrier), args.technique, args.key.as_deref()).map(|_| ())
            } else {
                info_res
            }
        }
        "util" => {
            if args.carrier.is_none() {
                err("--carrier is required for util mode.");
                std::process::exit(2);
            }
            do_util(&args).map(|_| ())
        }
        "bench" => do_bench(&args),
        "generate" => {
            if args.list {
                println!();
                println!("{}", cyan("  Available LOLBins:"));
                println!();
                for lb in LOLBINS {
                    let types = lb.types.join(", ");
                    println!("  {:<30} {}", green(lb.name), lb.desc);
                    println!("{}", cyan(&format!("    os    : {}", lb.os)));
                    println!("{}", yellow(&format!("    note  : {}", lb.note)));
                    println!("{}", grey(&format!("    types : {}", types)));
                    println!();
                }
                println!();
                Ok(())
            } else {
                do_generate(&args)
            }
        }
        unknown => Err(format!(
            "Invalid mode '{}'. Must be 'info', 'util', or 'generate'.",
            unknown
        )),
    };

    if let Err(e) = result {
        err(&e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod file_operation_tests {
    use super::*;

    #[test]
    fn cleanup_failure_is_reported() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("cloak-cleanup-{}-{unique}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let input = root.join("input");
        fs::write(&input, b"preserve me").unwrap();
        let directory = root.join("not-a-file");
        fs::create_dir(&directory).unwrap();
        let args = Cli::try_parse_from(["cloak", "util"]).unwrap();
        let result = post_process_with_temps(
            input.clone(),
            &args,
            std::slice::from_ref(&input),
            std::slice::from_ref(&directory),
        );
        assert!(
            result
                .unwrap_err()
                .contains("Failed to remove temporary file")
        );
        assert_eq!(fs::read(&input).unwrap(), b"preserve me");
        assert!(directory.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
