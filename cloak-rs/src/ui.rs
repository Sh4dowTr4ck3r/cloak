use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

static USE_COLOR_OVERRIDE: AtomicBool = AtomicBool::new(true);

pub fn init_color(enable: Option<bool>) {
    let enabled = enable.unwrap_or_else(|| std::io::stdout().is_terminal());
    USE_COLOR_OVERRIDE.store(enabled, Ordering::Relaxed);
}

pub fn is_color() -> bool {
    USE_COLOR_OVERRIDE.load(Ordering::Relaxed)
}

fn c(text: &str, code: &str) -> String {
    if is_color() {
        format!("\x1b[{}m{}\x1b[0m", code, text)
    } else {
        text.to_string()
    }
}

pub fn green(t: &str) -> String {
    c(t, "92")
}

pub fn yellow(t: &str) -> String {
    c(t, "93")
}

pub fn cyan(t: &str) -> String {
    c(t, "96")
}

pub fn magenta(t: &str) -> String {
    c(t, "95")
}

pub fn grey(t: &str) -> String {
    c(t, "90")
}

pub fn red(t: &str) -> String {
    c(t, "91")
}

pub fn bold(t: &str) -> String {
    c(t, "1")
}

pub fn info(msg: &str) {
    println!("{}", cyan(&format!("[*] {}", msg)));
}

pub fn ok(msg: &str) {
    println!("{}", green(&format!("[+] {}", msg)));
}

pub fn warn(msg: &str) {
    println!("{}", yellow(&format!("[~] {}", msg)));
}

pub fn err(msg: &str) {
    eprintln!("{}", red(&format!("[!] {}", msg)));
}

pub fn banner(quiet: bool) {
    if quiet {
        return;
    }
    println!();
    println!(
        "{}",
        cyan("  ╔════════════════════════════════════════════════╗")
    );
    println!(
        "{}",
        cyan("  ║                   cloak                        ║")
    );
    println!(
        "{}",
        cyan("  ╚════════════════════════════════════════════════╝")
    );
    println!();
}

pub fn fmt_bytes(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut val = n as f64;
    for unit in units {
        if val < 1024.0 {
            return format!("{:.2} {}", val, unit);
        }
        val /= 1024.0;
    }
    format!("{:.2} TB", val)
}
