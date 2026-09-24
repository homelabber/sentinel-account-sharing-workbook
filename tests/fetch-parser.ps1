<#
.SYNOPSIS
    Downloads the Microsoft Kusto.Language parser used by the KQL validators.

.DESCRIPTION
    validate.ps1 and semantic.ps1 parse every query in the workbook using
    Microsoft's own Kusto grammar, which catches errors that eyeballing does not.
    The parser is a NuGet package and is not committed to this repository.

    Run this once before running the validators.

.NOTES
    Some networks break TLS to api.nuget.org via schannel. This script uses the
    globalcdn host and probes a few known-good versions, which works where the
    API endpoint does not.
#>
[CmdletBinding()]
param(
    [string] $Destination = (Split-Path -Parent $PSScriptRoot),
    [string[]] $Versions = @("12.2.0", "12.1.0", "12.0.0", "11.5.4", "11.2.0", "11.0.0")
)

$ErrorActionPreference = 'Stop'
$target = Join-Path $Destination 'kqllib'

if (Test-Path (Join-Path $target 'lib\net6.0\Kusto.Language.dll')) {
    Write-Host "[+] Parser already present at $target" -ForegroundColor Green
    exit 0
}

$tmp = Join-Path $env:TEMP "kusto-lang-$(Get-Random).nupkg"

foreach ($v in $Versions) {
    $url = "https://globalcdn.nuget.org/packages/microsoft.azure.kusto.language.$v.nupkg"
    Write-Host "[*] Trying $v ..." -ForegroundColor Cyan
    try {
        curl.exe -sS -L --max-time 60 $url -o $tmp 2>&1 | Out-Null
    } catch {
        continue
    }
    if ((Test-Path $tmp) -and (Get-Item $tmp).Length -gt 100000) {
        $zip = [System.IO.Path]::ChangeExtension($tmp, 'zip')
        Move-Item $tmp $zip -Force
        Expand-Archive $zip -DestinationPath $target -Force
        Remove-Item $zip -Force
        Write-Host "[+] Kusto.Language $v extracted to $target" -ForegroundColor Green
        Write-Host "    Now run: .\tests\validate.ps1  and  .\tests\semantic.ps1"
        exit 0
    }
}

Write-Host "[!] Could not download the parser from any known version." -ForegroundColor Red
Write-Host "    Install manually:  nuget install Microsoft.Azure.Kusto.Language" -ForegroundColor Yellow
Write-Host "    then place lib\net6.0\Kusto.Language.dll under $target" -ForegroundColor Yellow
exit 1
