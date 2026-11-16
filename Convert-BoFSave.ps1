<#
.SYNOPSIS
    Converts Blades of Fire saves (Profile.BoF) between the Epic Games and Steam versions.

.DESCRIPTION
    Profile.BoF layout (both platforms, same game build):
      0x0000-0x2027  plain header ("RGMH", version, GUID, "Mercury Engine")
      0x2028-0x102047  AES-256-CBC (zero IV, no padding) encrypted payload of 0x100020 bytes:
                         [0x000000] "0002" magic, uint32 LZ4 compressed size, LZ4 block (save data)
                         [0x100000] SHA-256 of the first 0x100000 bytes, each byte XOR 0x01

    The AES key is the 64-hex-digit string below, hex-decoded, after the platform user ID string
    has been written over its start:
      Steam : no ID is mixed in -> the base key is used unchanged
      Epic  : the 32-hex-char Epic account ID (the save folder name) replaces the first 32 hex digits

    The decrypted save contents contain no platform IDs, so converting is simply
    decrypt-with-source-key -> encrypt-with-target-key. The source file is never modified.

.EXAMPLE
    .\Convert-BoFSave.ps1 -Source "$env:LOCALAPPDATA\MercurySteam\Blades of Fire\0123456789abcdef0123456789abcdef" `
                          -Destination "$env:LOCALAPPDATA\MercurySteam\Blades of Fire\76561198000000000"

    Converts an Epic save to Steam. Replace the folder names with your own Epic and Steam account folders.
#>
[CmdletBinding()]
param(
    # Source save folder (named after the account ID) or a Profile.BoF file inside it.
    [Parameter(Mandatory)][string]$Source,
    # Destination save folder (named after the account ID) or a Profile.BoF path inside it.
    [Parameter(Mandatory)][string]$Destination,
    # Override the account ID used for the source key (default: source folder name, then Steam key).
    [string]$SourceId,
    # Override the account ID used for the destination key (default: destination folder name).
    [string]$TargetId,
    # Don't back up an existing destination Profile.BoF before overwriting it.
    [switch]$NoBackup
)

$ErrorActionPreference = 'Stop'

$BaseKey     = 'c458429a015d51ed12616515526ee3004bb3dad22345547d94146d2e3dc172eb'
$HeaderSize  = 0x2028
$PayloadSize = 0x100020
$BodySize    = 0x100000
$FileSize    = $HeaderSize + $PayloadSize

function Resolve-SavePath([string]$Path) {
    # Returns @{ File = <Profile.BoF path>; Id = <account folder name> }
    if ((Test-Path -LiteralPath $Path -PathType Container) -or -not ($Path -like '*.BoF')) {
        $dir = $Path; $file = Join-Path $Path 'Profile.BoF'
    } else {
        $file = $Path; $dir = Split-Path -Parent $Path
    }
    @{ File = [IO.Path]::GetFullPath($file); Id = Split-Path -Leaf ([IO.Path]::GetFullPath($dir)) }
}

function Get-KeyPrefix([string]$Id) {
    # Epic account IDs are 32 hex chars and are mixed into the key; Steam uses the base key as-is.
    if ($Id -match '^[0-9a-fA-F]{32}$') { return $Id }
    if ($Id -match '^\d{17}$' -or $Id -eq '') { return '' }
    throw "Can't tell whether '$Id' is a Steam ID (17 digits) or Epic ID (32 hex chars). Use -SourceId/-TargetId."
}

function Get-AesKey([string]$Prefix) {
    $hex = $Prefix + $BaseKey.Substring($Prefix.Length)
    $key = New-Object byte[] 32
    for ($i = 0; $i -lt 32; $i++) { $key[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    $key
}

function Invoke-Aes([byte[]]$Data, [int]$Offset, [byte[]]$Key, [bool]$Encrypt) {
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::None
        $aes.Key = $Key
        $aes.IV = New-Object byte[] 16
        $t = if ($Encrypt) { $aes.CreateEncryptor() } else { $aes.CreateDecryptor() }
        try { $t.TransformFinalBlock($Data, $Offset, $PayloadSize) } finally { $t.Dispose() }
    } finally { $aes.Dispose() }
}

function Test-Plaintext([byte[]]$Plain) {
    # Valid if it has the "0002" magic and the trailing SHA-256 matches (XORed with a constant byte).
    if ([Text.Encoding]::ASCII.GetString($Plain, 0, 4) -ne '0002') { return $false }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($Plain, 0, $BodySize) } finally { $sha.Dispose() }
    $x = $hash[0] -bxor $Plain[$BodySize]
    for ($i = 1; $i -lt 32; $i++) { if (($hash[$i] -bxor $Plain[$BodySize + $i]) -ne $x) { return $false } }
    $true
}

function Read-Save([string]$File) {
    if (-not (Test-Path -LiteralPath $File)) { throw "Save not found: $File" }
    $bytes = [IO.File]::ReadAllBytes($File)
    if ($bytes.Length -ne $FileSize) { throw "Unexpected size $($bytes.Length) for $File (expected $FileSize)." }
    if ([Text.Encoding]::ASCII.GetString($bytes, 0, 4) -ne 'RGMH') { throw "$File is not a Blades of Fire save (missing RGMH header)." }
    $bytes
}

$src = Resolve-SavePath $Source
$dst = Resolve-SavePath $Destination
if ($src.File -eq $dst.File) { throw 'Source and destination are the same file.' }

# --- Decrypt source --------------------------------------------------------------------------
$srcBytes = Read-Save $src.File
$candidates = if ($PSBoundParameters.ContainsKey('SourceId')) { @(Get-KeyPrefix $SourceId) }
              else { @(try { Get-KeyPrefix $src.Id } catch { }) + '' | Select-Object -Unique }
$plain = $null
foreach ($prefix in $candidates) {
    $p = Invoke-Aes $srcBytes $HeaderSize (Get-AesKey $prefix) $false
    if (Test-Plaintext $p) { $plain = $p; $srcPrefix = $prefix; break }
}
if (-not $plain) { throw "Could not decrypt $($src.File) with any known key. Try -SourceId <account id>." }
$srcPlatform = if ($srcPrefix) { "Epic ($srcPrefix)" } else { 'Steam' }
Write-Host "Decrypted source  : $($src.File)  [$srcPlatform key]"

# --- Encrypt for destination -----------------------------------------------------------------
$tgtId = if ($PSBoundParameters.ContainsKey('TargetId')) { $TargetId } else { $dst.Id }
$tgtPrefix = Get-KeyPrefix $tgtId
$tgtKey = Get-AesKey $tgtPrefix
$out = New-Object byte[] $FileSize
[Array]::Copy($srcBytes, 0, $out, 0, $HeaderSize)
$enc = Invoke-Aes $plain 0 $tgtKey $true
[Array]::Copy($enc, 0, $out, $HeaderSize, $PayloadSize)

# Round-trip check before touching the destination.
$check = Invoke-Aes $out $HeaderSize $tgtKey $false
if (-not (Test-Plaintext $check)) { throw 'Internal error: re-encrypted save failed verification. Nothing was written.' }

# --- Write ------------------------------------------------------------------------------------
$dstDir = Split-Path -Parent $dst.File
if (-not (Test-Path -LiteralPath $dstDir)) { New-Item -ItemType Directory -Path $dstDir | Out-Null }
if ((Test-Path -LiteralPath $dst.File) -and -not $NoBackup) {
    $backup = "$($dst.File).bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item -LiteralPath $dst.File -Destination $backup
    Write-Host "Backed up existing: $backup"
}
[IO.File]::WriteAllBytes($dst.File, $out)
$tgtPlatform = if ($tgtPrefix) { "Epic ($tgtPrefix)" } else { 'Steam' }
Write-Host "Wrote destination : $($dst.File)  [$tgtPlatform key]"
Write-Host 'Done.'
