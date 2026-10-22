#[cfg(windows)]
use crate::ui::{fmt_bytes, info, ok};
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::path::Path;

// Values are passed through environment variables, never parsed as script text.

#[cfg(windows)]
pub fn ads_write(carrier: &str, stream_name: &str, payload_path: &str) -> Result<(), String> {
    let payload = fs::read(payload_path)
        .map_err(|e| format!("Cannot read payload '{}': {}", payload_path, e))?;
    let ads_path = format!("{}:{}", carrier, stream_name);
    fs::write(&ads_path, &payload)
        .map_err(|e| format!("Cannot write to ADS stream '{}': {}", ads_path, e))?;
    ok(&format!(
        "Stream written  : {}  ({})",
        ads_path,
        fmt_bytes(payload.len() as u64)
    ));
    info("Tip: visible only via  dir /r  or  Get-Item -Stream *");
    Ok(())
}

#[cfg(not(windows))]
pub fn ads_write(_carrier: &str, _stream_name: &str, _payload_path: &str) -> Result<(), String> {
    Err(format!(
        "ADS write requires Windows/NTFS. Current platform: {}",
        std::env::consts::OS
    ))
}

#[cfg(windows)]
pub fn ads_read(carrier: &str, stream_name: &str, output: &str) -> Result<(), String> {
    let ads_path = format!("{}:{}", carrier, stream_name);
    let data = match fs::read(&ads_path) {
        Ok(d) => d,
        Err(_) => {
            return Err(format!(
                "Stream '{}' not found on '{}'. Use  dir /r \"{}\"  to list available streams.",
                stream_name, carrier, carrier
            ));
        }
    };
    if let Some(parent) = Path::new(output).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("Cannot create parent dir: {}", e))?;
        }
    }
    fs::write(output, &data)
        .map_err(|e| format!("Cannot write output file '{}': {}", output, e))?;
    ok(&format!(
        "Stream read     : {}  ({})",
        ads_path,
        fmt_bytes(data.len() as u64)
    ));
    ok(&format!("Written to      : {}", output));
    Ok(())
}

#[cfg(not(windows))]
pub fn ads_read(_carrier: &str, _stream_name: &str, _output: &str) -> Result<(), String> {
    Err(format!(
        "ADS read requires Windows/NTFS. Current platform: {}",
        std::env::consts::OS
    ))
}

#[cfg(windows)]
pub fn ads_list(carrier: &str) -> Result<(), String> {
    use crate::ui::cyan;
    use std::process::Command;

    let cmd = "Get-Item -LiteralPath $env:CLOAK_ADS_CARRIER -Stream * -ErrorAction Stop | Select-Object Stream, Length | Format-Table -AutoSize";
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", cmd])
        .env("CLOAK_ADS_CARRIER", carrier)
        .output()
        .map_err(|e| format!("PowerShell error: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "PowerShell error: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    println!();
    println!("{}", cyan(&format!("  ADS streams on: {}", carrier)));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.trim().lines() {
        println!("  {}", line);
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn ads_list(_carrier: &str) -> Result<(), String> {
    Err(format!(
        "ADS list requires Windows/NTFS. Current platform: {}",
        std::env::consts::OS
    ))
}

#[cfg(windows)]
pub fn ads_delete(carrier: &str, stream_name: &str) -> Result<(), String> {
    use std::process::Command;

    let cmd = "Remove-Item -LiteralPath $env:CLOAK_ADS_CARRIER -Stream $env:CLOAK_ADS_STREAM -ErrorAction Stop";
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", cmd])
        .env("CLOAK_ADS_CARRIER", carrier)
        .env("CLOAK_ADS_STREAM", stream_name)
        .output()
        .map_err(|e| format!("PowerShell error: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "PowerShell error: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    ok(&format!("Stream deleted  : {}:{}", carrier, stream_name));
    Ok(())
}

#[cfg(not(windows))]
pub fn ads_delete(_carrier: &str, _stream_name: &str) -> Result<(), String> {
    Err(format!(
        "ADS delete requires Windows/NTFS. Current platform: {}",
        std::env::consts::OS
    ))
}
