<#
.SYNOPSIS
    Parse-only test for Invoke-AzBench.ps1 -- reports parser errors with line/column.

.DESCRIPTION
    Runs the PowerShell parser against the script without executing anything. Use this
    on the AVD to capture exact error locations when you see parse-time errors like
    "missing ) in method call" or "the < operator is reserved".

.EXAMPLE
    PS> .\Test-ScriptSyntax.ps1
    Reports any parser errors with file/line/column and shows the offending line.
#>
[CmdletBinding()]
param(
    [string] $Path
)

# Resolve default path with fallback chain: explicit param -> script's folder -> current dir
if (-not $Path) {
    $root = if ($PSScriptRoot) { $PSScriptRoot }
            elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
            else { (Get-Location).Path }
    $Path = Join-Path -Path $root -ChildPath 'Invoke-AzBench.ps1'
    if (-not (Test-Path -LiteralPath $Path)) {
        $alt = Join-Path -Path (Get-Location).Path -ChildPath 'Invoke-AzBench.ps1'
        if (Test-Path -LiteralPath $alt) { $Path = $alt }
    }
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Host "Script not found: $Path" -ForegroundColor Red
    Write-Host "Pass an explicit path: .\Test-ScriptSyntax.ps1 -Path C:\full\path\to\Invoke-AzBench.ps1" -ForegroundColor Yellow
    exit 1
}

$resolved = (Resolve-Path $Path).Path
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
Write-Host "Parsing:           $resolved"
Write-Host ""

$tokens = $null
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($resolved, [ref]$tokens, [ref]$errors)

Write-Host ("Total parse errors: {0}" -f @($errors).Count) -ForegroundColor $(if ($errors) { 'Red' } else { 'Green' })
Write-Host ""

if ($errors) {
    $lines = [System.IO.File]::ReadAllLines($resolved)
    foreach ($e in $errors) {
        $ln  = $e.Extent.StartLineNumber
        $col = $e.Extent.StartColumnNumber
        Write-Host ("[L{0}:C{1}] {2}" -f $ln, $col, $e.Message) -ForegroundColor Yellow
        if ($ln -ge 1 -and $ln -le $lines.Length) {
            Write-Host ("       {0}" -f $lines[$ln-1])              -ForegroundColor Gray
            Write-Host ("       {0}^" -f (' ' * ($col-1)))          -ForegroundColor Red
        }
        Write-Host ""
    }
    exit 2
}

Write-Host "No parse errors. The script is syntactically valid for this PowerShell version." -ForegroundColor Green

# File-level sanity reporting (PS 5.1 + 7 compatible)
$fi = Get-Item -LiteralPath $resolved
$bytes = [System.IO.File]::ReadAllBytes($resolved)
$hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
$crCount = 0; $lfCount = 0
foreach ($b in $bytes) { if ($b -eq 0x0D) { $crCount++ } elseif ($b -eq 0x0A) { $lfCount++ } }
$lineEnding = if ($crCount -gt 0 -and $crCount -eq $lfCount) { 'CRLF' }
              elseif ($crCount -eq 0)                         { 'LF' }
              else                                            { 'mixed' }
Write-Host ""
Write-Host "File:        $resolved"
Write-Host "Size:        $($fi.Length) bytes"
Write-Host "UTF-8 BOM:   $hasBom"
Write-Host "Line ending: $lineEnding (CR=$crCount LF=$lfCount)"
exit 0
