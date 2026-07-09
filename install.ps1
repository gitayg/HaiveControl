#requires -version 5
# HaiveControl one-line installer (Windows). Downloads the agent and registers it to your hub.
# Usage:  & ([scriptblock]::Create((irm https://raw.githubusercontent.com/gitayg/HaiveControl/main/install.ps1))) <mac-id> [password]
param(
  [Parameter(Position=0)][string]$MacId = $env:HIVE_MAC,
  [Parameter(Position=1)][string]$Password = $env:HIVE_PW
)
$ErrorActionPreference = "Stop"
if (-not $MacId) { Write-Error "Mac ID required (the id shown by HaiveHub). Pass it as the first argument."; return }
$url  = "https://github.com/gitayg/HaiveControl/releases/latest/download/HaiveControl-windows.exe"
$dir  = Join-Path $env:LOCALAPPDATA "HaiveControl"
$dest = Join-Path $dir "HaiveControl.exe"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Write-Host "Downloading HaiveControl agent..."
Invoke-WebRequest -Uri $url -OutFile $dest
Write-Host "Registering to hub '$MacId'..."
if ($Password) { & $dest $MacId $Password } else { & $dest $MacId }
