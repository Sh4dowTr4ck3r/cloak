#Requires -Version 5.1
<#
.SYNOPSIS
    Combined File Utility — Polyglot/Carrier Embedding + Encoding + Extension/Header Spoofing + Hashing

.DESCRIPTION
    Merges two tools into one:

      1. Polyglot / carrier embedding  (Embed, Extract, Info modes)
      2. Multi-function file utility   (Encode, NewExtension, SpoofHeader, ShowHashes)

    You can chain operations in a single call, for example:
      • Encode a payload, embed it into a carrier, rename + spoof header, then show hashes.

    Embedding Strategies
    --------------------
    Append   – carrier | payload | trailer  (default; most parsers ignore trailing data)
    Prepend  – trailer | payload | carrier  (formats parsed from the end, e.g. ZIP/RAR)
    Insert   – payload injected at -InsertOffset inside the carrier

    Encoding Techniques (interactive menu when -Encode is used)
    -------------------
    1  Base64
    2  Hex
    3  XOR  (key prompted)
    4  Reverse bytes
    5  XOR → Base64
    6  XOR → Hex

.EXAMPLE
    # Encode secret.bin, embed into photo.jpg, rename output to .pdf with spoofed header, show hashes
    .\Invoke-FileUtil.ps1 -Mode Embed `
        -Carrier photo.jpg -Payload secret.bin -Output result.pdf `
        -Encode -SpoofHeader -ShowHashes

.EXAMPLE
    # Embed only (no encoding)
    .\Invoke-FileUtil.ps1 -Mode Embed -Carrier carrier.png -Payload data.zip -Output poly.png

.EXAMPLE
    # Extract payload back out
    .\Invoke-FileUtil.ps1 -Mode Extract -Carrier poly.png -Output recovered.zip

.EXAMPLE
    # Inspect a file for embedded marker
    .\Invoke-FileUtil.ps1 -Mode Info -Carrier poly.png

.EXAMPLE
    # Encoding + extension spoof only (no embedding)
    .\Invoke-FileUtil.ps1 -Mode Util -InputFile payload.exe -Encode -NewExtension ".jpg" -SpoofHeader -ShowHashes

.NOTES
    For educational / research / CTF use.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    # ── Mode ────────────────────────────────────────────────────────────────
    [Parameter(Mandatory)]
    [ValidateSet('Embed', 'Extract', 'Info', 'Util')]
    [string] $Mode,

    # ── Polyglot params ─────────────────────────────────────────────────────
    # Carrier file (also used as InputFile in Util mode)
    [string] $Carrier,

    # Payload to embed (Embed mode)
    [string] $Payload,

    # Output file path (used by all modes)
    [string] $Output,

    # Embedding strategy
    [ValidateSet('Append', 'Prepend', 'Insert')]
    [string] $Strategy = 'Append',

    # Byte offset for Insert strategy
    [long] $InsertOffset = 0,

    # ── File-utility params ──────────────────────────────────────────────────
    # Change file extension (e.g. ".pdf")
    [string] $NewExtension,

    # Append string to filename (e.g. ".bak")
    [string] $AddExtension,

    # Interactive encoding menu
    [switch] $Encode,

    # Overwrite first bytes with magic bytes matching -NewExtension / -AddExtension
    [switch] $SpoofHeader,

    # Show MD5 / SHA1 / SHA256 of the final file
    [switch] $ShowHashes,

    # Suppress decorative banner
    [switch] $Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ═══════════════════════════════════════════════════════════════════════════════
#  SHARED CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

$MAGIC       = [byte[]]@(0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE)
$MAGIC_LEN   = $MAGIC.Length          # 8
$SIZE_BYTES  = 8                       # int64-LE payload length field
$TRAILER_LEN = $MAGIC_LEN + $SIZE_BYTES  # 16 bytes total

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

# ═══════════════════════════════════════════════════════════════════════════════
#  POLYGLOT HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

function New-Trailer([long]$PayloadLen) {
    $lenBytes = [System.BitConverter]::GetBytes([int64]$PayloadLen)
    if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBytes) }
    $t = New-Object byte[] $TRAILER_LEN
    [Array]::Copy($MAGIC,    0, $t, 0,         $MAGIC_LEN)
    [Array]::Copy($lenBytes, 0, $t, $MAGIC_LEN, $SIZE_BYTES)
    return $t
}

# Returns a hashtable: @{ Offset = int; Layout = 'Append'|'Prepend' }
# or $null if no marker is found.
function Find-MagicOffset([byte[]]$Bytes) {
    # --- Append: trailer sits at the very end ---
    $tailPos = $Bytes.Length - $TRAILER_LEN
    if ($tailPos -ge 0) {
        $match = $true
        for ($i = 0; $i -lt $MAGIC_LEN; $i++) {
            if ($Bytes[$tailPos + $i] -ne $MAGIC[$i]) { $match = $false; break }
        }
        if ($match) { return @{ Offset = $tailPos; Layout = 'Append' } }
    }

    # --- Prepend: trailer sits at the very start ---
    if ($Bytes.Length -ge $TRAILER_LEN) {
        $match = $true
        for ($i = 0; $i -lt $MAGIC_LEN; $i++) {
            if ($Bytes[$i] -ne $MAGIC[$i]) { $match = $false; break }
        }
        if ($match) { return @{ Offset = 0; Layout = 'Prepend' } }
    }

    return $null
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FILE-UTILITY HELPERS
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
    Write-Host "  │  [5] Base64 + XOR             │" -ForegroundColor Magenta
    Write-Host "  │  [6] XOR  + Hex               │" -ForegroundColor Magenta
    Write-Host "  └───────────────────────────────┘" -ForegroundColor Magenta
    $choice = Read-Host "  Select technique [1-6]"

    $bytes    = [System.IO.File]::ReadAllBytes($FilePath)
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
            $key = if ($keyInput -match '^0x') { [Convert]::ToByte($keyInput, 16) } else { [byte]$keyInput }
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

function Show-Hashes([string]$FilePath) {
    Write-Host ""
    Write-Host "  Hashes for: $FilePath" -ForegroundColor Cyan
    Write-Host "  MD5:    $(( Get-FileHash $FilePath -Algorithm MD5    ).Hash)"
    Write-Host "  SHA1:   $(( Get-FileHash $FilePath -Algorithm SHA1   ).Hash)"
    Write-Host "  SHA256: $(( Get-FileHash $FilePath -Algorithm SHA256 ).Hash)"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  POLYGLOT OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-Embed {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$CarrierPath, [string]$PayloadPath, [string]$OutPath)

    $carrierBytes = Get-FileBytes $CarrierPath
    $payloadBytes = Get-FileBytes $PayloadPath
    $trailer      = New-Trailer $payloadBytes.Length

    Write-Host "[*] Carrier  : $CarrierPath  ($(Format-Bytes $carrierBytes.Length))" -ForegroundColor Green
    Write-Host "[*] Payload  : $PayloadPath  ($(Format-Bytes $payloadBytes.Length))" -ForegroundColor Green
    Write-Host "[*] Strategy : $Strategy" -ForegroundColor Green

    switch ($Strategy) {
        'Append' {
            $total  = $carrierBytes.Length + $payloadBytes.Length + $TRAILER_LEN
            $result = New-Object byte[] $total
            [Array]::Copy($carrierBytes, 0, $result, 0,                                          $carrierBytes.Length)
            [Array]::Copy($payloadBytes, 0, $result, $carrierBytes.Length,                       $payloadBytes.Length)
            [Array]::Copy($trailer,      0, $result, $carrierBytes.Length + $payloadBytes.Length, $TRAILER_LEN)
        }
        'Prepend' {
            $total  = $TRAILER_LEN + $payloadBytes.Length + $carrierBytes.Length
            $result = New-Object byte[] $total
            [Array]::Copy($trailer,      0, $result, 0,                                          $TRAILER_LEN)
            [Array]::Copy($payloadBytes, 0, $result, $TRAILER_LEN,                               $payloadBytes.Length)
            [Array]::Copy($carrierBytes, 0, $result, $TRAILER_LEN + $payloadBytes.Length,        $carrierBytes.Length)
        }
        'Insert' {
            if ($InsertOffset -gt $carrierBytes.Length) {
                throw "InsertOffset ($InsertOffset) exceeds carrier length ($($carrierBytes.Length))."
            }
            $total     = $carrierBytes.Length + $payloadBytes.Length + $TRAILER_LEN
            $result    = New-Object byte[] $total
            $remaining = $carrierBytes.Length - $InsertOffset
            [Array]::Copy($carrierBytes, 0,             $result, 0,                                                 $InsertOffset)
            [Array]::Copy($payloadBytes, 0,             $result, $InsertOffset,                                     $payloadBytes.Length)
            [Array]::Copy($trailer,      0,             $result, $InsertOffset + $payloadBytes.Length,             $TRAILER_LEN)
            [Array]::Copy($carrierBytes, $InsertOffset, $result, $InsertOffset + $payloadBytes.Length + $TRAILER_LEN, $remaining)
        }
    }

    if ($PSCmdlet.ShouldProcess($OutPath, "Write polyglot file")) {
        Write-FileBytes $OutPath $result
        Write-Host "[+] Polyglot written → $OutPath  ($(Format-Bytes $result.Length))" -ForegroundColor Yellow
    }

    return $OutPath
}

function Invoke-Extract {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$CarrierPath, [string]$OutPath)

    $poly   = Get-FileBytes $CarrierPath
    $found  = Find-MagicOffset $poly
    if ($null -eq $found) {
        throw "Magic marker not found in '$CarrierPath'. File may not contain an embedded payload, or was embedded with the Insert strategy (not auto-detectable)."
    }

    $layout    = $found.Layout
    $trailerAt = $found.Offset

    # Read payload length from the 8 bytes after the magic marker
    $lenOffset  = $trailerAt + $MAGIC_LEN
    $lenBytes   = $poly[$lenOffset..($lenOffset + $SIZE_BYTES - 1)]
    if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBytes) }
    $payloadLen = [System.BitConverter]::ToInt64($lenBytes, 0)

    if ($payloadLen -le 0) { throw "Corrupt trailer: payload length is zero or negative." }

    # Slice payload — position depends on layout
    switch ($layout) {
        'Append' {
            # Layout: [ carrier ][ payload ][ trailer ]
            $payloadStart = $trailerAt - $payloadLen
            if ($payloadStart -lt 0) { throw "Corrupt trailer: Append payload start is negative." }
            $extracted = $poly[$payloadStart..($payloadStart + $payloadLen - 1)]
        }
        'Prepend' {
            # Layout: [ trailer ][ payload ][ carrier ]
            $payloadStart = $TRAILER_LEN
            $payloadEnd   = $payloadStart + $payloadLen - 1
            if ($payloadEnd -ge $poly.Length) { throw "Corrupt trailer: Prepend payload end exceeds file size." }
            $extracted = $poly[$payloadStart..$payloadEnd]
        }
    }

    $offsetDisplay = if ($layout -eq 'Append') { $trailerAt - $payloadLen } else { $TRAILER_LEN }
    Write-Host "[*] Polyglot : $CarrierPath  ($(Format-Bytes $poly.Length))" -ForegroundColor Green
    Write-Host "[*] Layout   : $layout" -ForegroundColor Green
    Write-Host "[*] Payload  : $(Format-Bytes $payloadLen) at byte offset $offsetDisplay" -ForegroundColor Green

    if ($PSCmdlet.ShouldProcess($OutPath, "Write extracted payload")) {
        Write-FileBytes $OutPath $extracted
        Write-Host "[+] Payload extracted → $OutPath  ($(Format-Bytes $extracted.Length))" -ForegroundColor Yellow
    }

    return $OutPath
}

function Invoke-Info {
    param([string]$FilePath)
    $bytes = Get-FileBytes $FilePath
    $found = Find-MagicOffset $bytes

    Write-Host "[*] File  : $FilePath" -ForegroundColor Cyan
    Write-Host "[*] Size  : $(Format-Bytes $bytes.Length)" -ForegroundColor Cyan

    if ($null -eq $found) {
        Write-Host "[-] No magic marker detected (checked both head and tail)." -ForegroundColor DarkGray
    } else {
        $layout    = $found.Layout
        $trailerAt = $found.Offset

        $lenOffset  = $trailerAt + $MAGIC_LEN
        $lenBytes   = $bytes[$lenOffset..($lenOffset + $SIZE_BYTES - 1)]
        if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBytes) }
        $payloadLen = [System.BitConverter]::ToInt64($lenBytes, 0)

        switch ($layout) {
            'Append' {
                $carrierLen    = $bytes.Length - $payloadLen - $TRAILER_LEN
                $payloadOffset = $trailerAt - $payloadLen
            }
            'Prepend' {
                $carrierLen    = $bytes.Length - $payloadLen - $TRAILER_LEN
                $payloadOffset = $TRAILER_LEN
            }
        }

        Write-Host "[+] Layout detected              : $layout" -ForegroundColor Green
        Write-Host "    Magic marker at offset       : $trailerAt" -ForegroundColor Green
        Write-Host "    Payload at offset            : $payloadOffset" -ForegroundColor Green
        Write-Host "    Carrier portion              : $(Format-Bytes $carrierLen)" -ForegroundColor Green
        Write-Host "    Payload portion              : $(Format-Bytes $payloadLen)" -ForegroundColor Green
        Write-Host "    Trailer                      : $TRAILER_LEN bytes" -ForegroundColor Green
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SHARED POST-PROCESSING  (encoding → extension rename → header spoof → hashes)
#  Used by both Embed and Util modes on the working file.
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-PostProcess {
    param(
        [string]   $WorkFile,
        [string[]] $ProtectedFiles = @()   # files that must never be deleted (originals)
    )

    # Track every intermediate file created so we can clean them up at the end.
    # Only files we create are added — originals and the final output are never deleted.
    $temps = [System.Collections.Generic.List[string]]::new()

    # 1. Optional encoding (interactive) — saves .enc temp, we track it
    if ($Encode) {
        $prev     = $WorkFile
        $WorkFile = Invoke-EncodingMenu -FilePath $WorkFile
        # If encoding created a new file (different path), mark the enc file as temp
        $resolvedPrev = (Resolve-Path $prev).Path
        $resolvedCurr = [System.IO.Path]::GetFullPath($WorkFile)
        if ($resolvedPrev -ne $resolvedCurr) { $temps.Add($resolvedCurr) }
    }

    # 2. Change extension — replaces ALL existing extensions with the target.
    #    e.g. testfile.bin.enc  -NewExtension .txt  →  testfile.txt
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
            # Previous WorkFile is now superseded — mark it temp if we created it
            if ($temps.Contains($resolvedWork)) {
                $null = $temps.Remove($resolvedWork)
                $temps.Add($resolvedWork)   # keep in list so it gets deleted
            }
        } else {
            Write-Host "  [~] Output already has target extension, skipping rename." -ForegroundColor DarkYellow
        }
        if ($SpoofHeader) { Set-MagicBytes -FilePath $newName -Extension $ext }
        $WorkFile = $newName
    }

    # 3. Append extension — adds to whatever the current filename already is.
    #    e.g. testfile.txt  -AddExtension .bak  →  testfile.txt.bak
    if ($AddExtension) {
        $ext     = if ($AddExtension.StartsWith('.')) { $AddExtension } else { ".$AddExtension" }
        $newName = "$WorkFile$ext"
        $resolvedWork = (Resolve-Path $WorkFile).Path
        $resolvedNew  = [System.IO.Path]::GetFullPath($newName)
        if ($resolvedWork -ne $resolvedNew) {
            Copy-Item $WorkFile $newName -Force
            Write-Host "  [+] Extension appended → $newName" -ForegroundColor Green
            if ($temps.Contains($resolvedWork)) {
                $null = $temps.Remove($resolvedWork)
                $temps.Add($resolvedWork)
            }
        } else {
            Write-Host "  [~] File already has that appended extension, skipping." -ForegroundColor DarkYellow
        }
        if ($SpoofHeader) { Set-MagicBytes -FilePath $newName -Extension $ext }
        $WorkFile = $newName
    }

    # 4. Hashes
    if ($ShowHashes) { Show-Hashes $WorkFile }

    # 5. Clean up all temp files — skip originals, skip the final output
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
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

Write-Banner

switch ($Mode) {

    'Embed' {
        if (-not $Carrier) { throw "-Carrier is required for Embed mode." }
        if (-not $Payload) { throw "-Payload is required for Embed mode." }
        if (-not $Output)  { throw "-Output is required for Embed mode."  }

        # Optionally encode the PAYLOAD before embedding
        $payloadWork  = $Payload
        $payloadIsTemp = $false
        if ($Encode) {
            Write-Host "[*] Encoding payload before embedding..." -ForegroundColor Cyan
            $payloadWork   = Invoke-EncodingMenu -FilePath $Payload
            $payloadIsTemp = ($payloadWork -ne $Payload)
        }

        # Embed
        $workFile = Invoke-Embed -CarrierPath $Carrier -PayloadPath $payloadWork -OutPath $Output

        # Clean up encoded payload temp now that it is embedded
        if ($payloadIsTemp -and (Test-Path $payloadWork)) {
            Remove-Item $payloadWork -Force
            Write-Host "  [~] Cleaned up temp file: $payloadWork" -ForegroundColor DarkGray
        }

        # Post-process the OUTPUT polyglot (extension rename, header spoof, hashes)
        # Skip re-encoding since we already encoded the payload above
        $encodeSwitch = $Encode
        $Encode       = $false
        Invoke-PostProcess -WorkFile $workFile -ProtectedFiles @($Carrier, $Output) | Out-Null
        $Encode       = $encodeSwitch
    }

    'Extract' {
        if (-not $Carrier) { throw "-Carrier is required for Extract mode." }
        if (-not $Output)  { throw "-Output is required for Extract mode."  }

        $workFile = Invoke-Extract -CarrierPath $Carrier -OutPath $Output
        Invoke-PostProcess -WorkFile $workFile -ProtectedFiles @($Carrier, $Output) | Out-Null
    }

    'Info' {
        if (-not $Carrier) { throw "-Carrier is required for Info mode." }
        Invoke-Info -FilePath $Carrier
        if ($ShowHashes) { Show-Hashes $Carrier }
    }

    'Util' {
        # Pure file-utility mode — no embedding
        $target = if ($Carrier) { $Carrier } elseif ($Output) { $Output } else {
            throw "Provide -Carrier (source file) for Util mode."
        }
        if (!(Test-Path $target)) { throw "File not found: $target" }

        Write-Host "[*] File: $target" -ForegroundColor Cyan
        Invoke-PostProcess -WorkFile $target -ProtectedFiles @($target) | Out-Null
    }
}