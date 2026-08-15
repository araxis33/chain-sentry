<#
.SYNOPSIS
    chain-sentry - a config-driven watcher for quiet on-chain activity.

.DESCRIPTION
    Reads a JSON config describing addresses to watch on Blockscout-compatible
    explorers, compares what it finds against the previous run, and writes one
    line to a log when nothing changed - or a block of alerts when something did.

    Designed to be run once a day by a scheduler. No dependencies beyond
    Windows PowerShell 5.1.

.PARAMETER Config
    Path to a config JSON file. See config/example.json.

.PARAMETER Quiet
    Suppress console output; still writes the log file.

.EXAMPLE
    .\watch.ps1 -Config config\unipeg.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Config,
    [switch]$Quiet
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Utf8    = New-Object System.Text.UTF8Encoding($false)

# --- helpers ----------------------------------------------------------------

function Read-JsonFile($path) {
    if (-not (Test-Path $path)) { return $null }
    try { return ([System.IO.File]::ReadAllText($path, $Utf8) | ConvertFrom-Json) }
    catch { return $null }
}

function Write-JsonFile($path, $object) {
    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    [System.IO.File]::WriteAllText($path, ($object | ConvertTo-Json -Depth 8), $Utf8)
}

# ConvertFrom-Json hands back PSCustomObject; we want hashtables we can mutate.
function ConvertTo-Hashtable($obj) {
    if ($null -eq $obj) { return @{} }
    $h = @{}
    foreach ($p in $obj.PSObject.Properties) {
        if ($p.Value -is [System.Management.Automation.PSCustomObject]) {
            $h[$p.Name] = ConvertTo-Hashtable $p.Value
        } else {
            $h[$p.Name] = $p.Value
        }
    }
    return $h
}

function Get-Body($url) {
    try { return (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30).Content }
    catch { return $null }
}

# Messages live in lang/*.json so this script stays plain ASCII.
function Get-Messages($language) {
    $lang = if ($language) { $language } else { 'en' }
    $file = Join-Path $RootDir "lang\$lang.json"
    $msg  = Read-JsonFile $file
    if ($null -eq $msg) {
        $msg = Read-JsonFile (Join-Path $RootDir 'lang\en.json')
    }
    return $msg
}

function Format-Message($template, $values) {
    $text = $template
    foreach ($k in $values.Keys) { $text = $text.Replace("{$k}", [string]$values[$k]) }
    return $text
}

# --- load config ------------------------------------------------------------

$cfg = Read-JsonFile $Config
if ($null -eq $cfg) { throw "Cannot read config: $Config" }

$M          = Get-Messages $cfg.language
$configName = [System.IO.Path]::GetFileNameWithoutExtension($Config)
$outDir     = if ($cfg.outputDir) { $cfg.outputDir } else { Join-Path $RootDir 'state' }
$logPath    = Join-Path $outDir "$configName.log"
$statePath  = Join-Path $outDir "$configName-state.json"
$stamp      = (Get-Date).ToString('yyyy-MM-dd HH:mm')

$alerts = New-Object System.Collections.Generic.List[string]
$notes  = New-Object System.Collections.Generic.List[string]

$state = ConvertTo-Hashtable (Read-JsonFile $statePath)
if (-not $state.ContainsKey('chains')) { $state['chains'] = @{} }

# --- watch each chain -------------------------------------------------------

foreach ($chain in @($cfg.chains)) {
    $chainName = $chain.name
    $api       = "$($chain.explorer)/api/v2"

    if (-not $state['chains'].ContainsKey($chainName)) { $state['chains'][$chainName] = @{} }
    $cs = $state['chains'][$chainName]
    if (-not $cs.ContainsKey('tx')) { $cs['tx'] = @{} }
    $txState = ConvertTo-Hashtable $cs['tx']

    foreach ($entry in @($chain.addresses)) {
        $addr  = $entry.address
        $label = if ($entry.label) { $entry.label } else { $addr.Substring(0, 10) }
        $short = $addr.Substring(0, 10)

        $body = Get-Body "$api/addresses/$addr/transactions"
        if ($null -eq $body) {
            $notes.Add((Format-Message $M.fetchFailed @{ chain = $chainName; label = $label }))
            continue
        }

        try {
            $items = @(($body | ConvertFrom-Json).items)
        } catch {
            $notes.Add((Format-Message $M.parseFailed @{ chain = $chainName; label = $label }))
            continue
        }

        $count = $items.Count
        $key   = $addr.ToLower()
        $was   = 0
        if ($txState.ContainsKey($key)) { $was = [int]$txState[$key] }

        # Alert on the *increase* only. Alerting on "count > 0" would repeat the
        # same discovery every single run and train the reader to ignore the log.
        if ($count -gt 0 -and $was -eq 0) {
            $alerts.Add((Format-Message $M.addressAppeared @{
                chain = $chainName; label = $label; address = $addr; count = $count }))
        } elseif ($count -gt $was) {
            $alerts.Add((Format-Message $M.addressGrew @{
                chain = $chainName; label = $label; address = $addr
                new = ($count - $was); count = $count }))
        } elseif ($count -gt 0) {
            $notes.Add((Format-Message $M.addressQuiet @{
                chain = $chainName; label = $label; short = $short; count = $count }))
        } else {
            $notes.Add((Format-Message $M.addressClean @{
                chain = $chainName; label = $label; short = $short }))
        }

        $txState[$key] = $count
    }

    $cs['tx'] = $txState
}

# --- write log --------------------------------------------------------------

Write-JsonFile $statePath $state

$out = New-Object System.Text.StringBuilder
if ($alerts.Count -gt 0) {
    [void]$out.AppendLine('')
    [void]$out.AppendLine("=========== $stamp - $($M.headerChanged) ===========")
    foreach ($a in $alerts) { [void]$out.AppendLine("!! $a") }
    foreach ($n in $notes)  { [void]$out.AppendLine("   . $n") }
    [void]$out.AppendLine('===============================================')
} else {
    [void]$out.AppendLine("$stamp  $($M.headerQuiet)")
    foreach ($n in $notes) { [void]$out.AppendLine("   . $n") }
}

if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force $outDir | Out-Null }
$previous = ''
if (Test-Path $logPath) { $previous = [System.IO.File]::ReadAllText($logPath, $Utf8) }
[System.IO.File]::WriteAllText($logPath, $previous + $out.ToString(), $Utf8)

if (-not $Quiet) { Write-Output $out.ToString().TrimEnd() }
