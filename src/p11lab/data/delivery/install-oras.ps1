# SPDX-License-Identifier: Apache-2.0
# Install the pinned ORAS CLI for Windows amd64 with hash verification.
# No Docker required. Pins must match p11lab.publish.ORAS_PIN (parity-tested).
param(
  [Parameter(Mandatory = $true)][string]$OutputDir
)
$ErrorActionPreference = "Stop"

$OrasVersion = '1.3.4'
$OrasRevision = 'db9e29505c3059f2b8fde34ae8cae266c5c765e9'
$OrasUrl = 'https://github.com/oras-project/oras/releases/download/v1.3.4/oras_1.3.4_windows_amd64.zip'
$OrasSha256 = 'ffdb6aa40267686b5d507da1f21a57fc502a9a7c86b90c54557d335644c99dbd'
$OrasSize = 4834833

if (-not $IsWindows) { throw "install-oras.ps1 covers Windows amd64 only" }
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($arch -ne "X64") { throw "install-oras.ps1 covers Windows amd64 only (got $arch)" }

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("oras-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $work | Out-Null
try {
  $archive = Join-Path $work "oras.zip"
  Invoke-WebRequest -Uri $OrasUrl -OutFile $archive -UseBasicParsing
  $size = (Get-Item $archive).Length
  if ($size -ne $OrasSize) { throw "size mismatch: got $size want $OrasSize" }
  $digest = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLower()
  if ($digest -ne $OrasSha256) { throw "checksum mismatch: got $digest" }
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
  try {
    $entries = @($zip.Entries | Select-Object -ExpandProperty FullName | Sort-Object)
  } finally {
    $zip.Dispose()
  }
  $want = @("LICENSE", "oras.exe")
  if (($entries -join "`n") -ne ($want -join "`n")) { throw "unexpected archive roster: $($entries -join ', ')" }
  [System.IO.Compression.ZipFile]::ExtractToDirectory($archive, (Join-Path $work "unzip"))
  $report = & (Join-Path $work "unzip\oras.exe") version
  if ($LASTEXITCODE) { throw "oras version failed" }
  $text = $report -join "`n"
  if ($text -notmatch "Version:" -or $text -notmatch [regex]::Escape($OrasVersion)) { throw "version self-report mismatch" }
  if ($text -notmatch "commit:" -or $text -notmatch $OrasRevision) { throw "commit self-report mismatch" }
  New-Item -ItemType Directory -Force $OutputDir | Out-Null
  Copy-Item (Join-Path $work "unzip\oras.exe") (Join-Path $OutputDir "oras.exe") -Force
  Copy-Item (Join-Path $work "unzip\LICENSE") (Join-Path $OutputDir "ORAS-LICENSE") -Force
  Join-Path $OutputDir "oras.exe"
} finally {
  Remove-Item $work -Force -Recurse -ErrorAction SilentlyContinue
}
