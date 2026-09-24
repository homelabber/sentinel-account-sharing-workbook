$RepoRoot = Split-Path -Parent $PSScriptRoot
Add-Type -Path (Join-Path $RepoRoot 'kqllib\lib\net6.0\Kusto.Language.dll')

$wb = Get-Content (Join-Path $RepoRoot 'AccountSharingVisibility.workbook.json') -Raw | ConvertFrom-Json

$subs = @{
    '{TimeRange}'         = 'between (datetime(2026-09-17) .. datetime(2026-09-24))'
    '{ConcurrencyWindow}' = '15m'
    '{MaxIPs}'            = '8'
    '{MaxDevices}'        = '3'
    '{MaxCountries}'      = '2'
    '{MaxUsersPerDevice}' = '4'
    '{MaxOnPremHosts}'    = '5'
    '{DormantDays}'       = '90'
    '{MinScore}'          = '15'
    '{ExcludedUsers}'     = 'none@example.invalid'
    '{TargetUser}'        = 'someone@contoso.com'
    '{RotationWindow}'    = '10m'
    '{MinSyncedRotations}'= '2'
    '{MinBulkReset}'      = '5'
    '{MaxAccountsPerHost}'= '3'
    '{MinCohortSize}'     = '3'
}

function Get-Queries($node, $path) {
    $out = @()
    if ($node.type -eq 3 -and $node.content.version -eq 'KqlItem/1.0') {
        $out += [pscustomobject]@{ Name = $node.name; Title = $node.content.title; Query = $node.content.query }
    }
    if ($node.type -eq 12) { foreach ($i in $node.content.items) { $out += Get-Queries $i $path } }
    if ($node.type -eq 9) {
        foreach ($p in $node.content.parameters) {
            if ($p.queryType -eq 0 -and $p.query) {
                $out += [pscustomobject]@{ Name = "param:$($p.name)"; Title = $p.label; Query = $p.query }
            }
        }
    }
    return $out
}

$queries = @()
foreach ($item in $wb.items) { $queries += Get-Queries $item '' }

Write-Host "Parsing $($queries.Count) KQL statements`n" -ForegroundColor Cyan

$bad = 0
foreach ($q in $queries) {
    $text = $q.Query
    foreach ($k in $subs.Keys) { $text = $text.Replace($k, $subs[$k]) }

    $code = [Kusto.Language.KustoCode]::Parse($text)
    $diags = $code.GetSyntaxDiagnostics()

    if ($diags.Count -gt 0) {
        $bad++
        Write-Host "FAIL  $($q.Name)  --  $($q.Title)" -ForegroundColor Red
        foreach ($d in $diags) {
            $line = ($text.Substring(0, [Math]::Min($d.Start, $text.Length)) -split "`n").Count
            $snippet = $text.Substring([Math]::Max(0, $d.Start - 45), [Math]::Min(95, $text.Length - [Math]::Max(0, $d.Start - 45))) -replace "`r?`n", ' ~ '
            Write-Host ("      line {0}: {1}" -f $line, $d.Message) -ForegroundColor Yellow
            Write-Host ("      ...{0}..." -f $snippet) -ForegroundColor DarkGray
        }
        Write-Host ""
    }
    else {
        Write-Host "ok    $($q.Name)" -ForegroundColor Green
    }
}

Write-Host ""
if ($bad -eq 0) { Write-Host "ALL $($queries.Count) QUERIES PARSE CLEAN" -ForegroundColor Green }
else { Write-Host "$bad of $($queries.Count) queries have syntax errors" -ForegroundColor Red }
exit $bad
