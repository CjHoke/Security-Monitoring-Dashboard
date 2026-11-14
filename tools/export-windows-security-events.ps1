<#
.SYNOPSIS
    Exports Windows logon events (4624 and 4625) to normalized JSON for Sentinel.

.DESCRIPTION
    Reads the local Windows Security event log (read-only) and writes a JSON
    file that Sentinel can import.

      Event 4624 = successful logon   -> type SUCCESS_LOGIN
      Event 4625 = failed logon       -> type FAILED_LOGIN

    Log data is treated as untrusted: values are only copied into JSON.
    Nothing read from the log is ever executed.

    By default, noise from system accounts (machine accounts ending in "$",
    NT AUTHORITY accounts, DWM-n and UMFD-n) is skipped.

    The output contains real usernames and IP addresses. It is written to the
    data folder, which must stay out of Git.

    Permissions: reading the Security log requires either an elevated
    PowerShell window, or membership in the local "Event Log Readers" group.
    One-time setup from an elevated prompt:
        net localgroup "Event Log Readers" %USERNAME% /add
    then sign out and back in.

.PARAMETER Hours
    How far back to read. Default 24. Range 1-720.

.PARAMETER MaxEvents
    Maximum number of events to read (newest first). Default 5000.

.PARAMETER OutputPath
    Output file. Default: ..\data\windows-security-events.json

.PARAMETER IncludeSystemAccounts
    Include machine/service/system account logons (very noisy).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\tools\export-windows-security-events.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\tools\export-windows-security-events.ps1 -Hours 72
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 720)]
    [int]$Hours = 24,

    [ValidateRange(1, 50000)]
    [int]$MaxEvents = 5000,

    [string]$OutputPath = (Join-Path $PSScriptRoot '..\data\windows-security-events.json'),

    [switch]$IncludeSystemAccounts
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'


# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

$LogonTypeNames = @{
    2  = 'Interactive'
    3  = 'Network'
    4  = 'Batch'
    5  = 'Service'
    7  = 'Unlock'
    8  = 'NetworkCleartext'
    9  = 'NewCredentials'
    10 = 'RemoteInteractive'
    11 = 'CachedInteractive'
}

# Keys are lowercase hex strings, as found in the Status / SubStatus fields.
$FailureReasons = @{
    '0xc000006a' = @{ Code = 'WRONG_PASSWORD';          Text = 'Known user name, wrong password' }
    '0xc000006d' = @{ Code = 'LOGON_FAILURE';           Text = 'Unknown user name or bad password' }
    '0xc0000064' = @{ Code = 'UNKNOWN_USER';            Text = 'User name does not exist' }
    '0xc0000234' = @{ Code = 'ACCOUNT_LOCKED_OUT';      Text = 'Account is locked out' }
    '0xc0000072' = @{ Code = 'ACCOUNT_DISABLED';        Text = 'Account is disabled' }
    '0xc0000193' = @{ Code = 'ACCOUNT_EXPIRED';         Text = 'Account has expired' }
    '0xc0000071' = @{ Code = 'PASSWORD_EXPIRED';        Text = 'Password has expired' }
    '0xc0000224' = @{ Code = 'PASSWORD_MUST_CHANGE';    Text = 'Password must be changed at next logon' }
    '0xc000006f' = @{ Code = 'OUTSIDE_LOGON_HOURS';     Text = 'Logon outside allowed hours' }
    '0xc0000070' = @{ Code = 'WORKSTATION_RESTRICTED';  Text = 'Logon from this workstation is not allowed' }
    '0xc000015b' = @{ Code = 'LOGON_TYPE_NOT_GRANTED';  Text = 'Logon type not granted to this user' }
    '0xc0000133' = @{ Code = 'CLOCK_SKEW';              Text = 'Clock out of sync with domain controller' }
}


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

function Get-EventDataMap {
    <# Returns a hashtable of the event's named <Data> fields. #>
    param([xml]$EventXml)

    $map = @{}

    foreach ($node in $EventXml.SelectNodes("//*[local-name()='Data']")) {

        $name = $node.GetAttribute('Name')

        if ($name) {
            $map[$name] = [string]$node.InnerText
        }
    }

    return $map
}


function Get-MapValue {
    <# Returns a trimmed field value, or an empty string when missing. #>
    param($Map, [string]$Key)

    if ($Map.ContainsKey($Key)) {
        return ([string]$Map[$Key]).Trim()
    }

    return ''
}


function ConvertTo-NullIfBlank {
    <# Windows uses "-" for "not applicable"; JSON gets null instead. #>
    param([string]$Value)

    $text = $Value.Trim()

    if ($text -eq '' -or $text -eq '-') {
        return $null
    }

    return $text
}


function ConvertTo-SourceIp {
    <# Returns the raw source address, or null when the event has none. #>
    param([string]$Value)

    $text = $Value.Trim()

    if ($text -eq '' -or $text -eq '-') {
        return $null
    }

    # Convert IPv4-mapped IPv6 (::ffff:1.2.3.4) to plain IPv4.
    if ($text.StartsWith('::ffff:', [System.StringComparison]::OrdinalIgnoreCase)) {
        $text = $text.Substring(7)
    }

    return $text
}


function Resolve-FailureReason {
    <# Maps Status / SubStatus codes to a stable code and readable text. #>
    param([string]$Status, [string]$SubStatus)

    $primary = $Status.Trim().ToLowerInvariant()
    $secondary = $SubStatus.Trim().ToLowerInvariant()

    # SubStatus is the more specific code, so it is checked first.
    foreach ($candidate in @($secondary, $primary)) {

        if ($candidate -and $FailureReasons.ContainsKey($candidate)) {

            return [pscustomobject]@{
                Code = $FailureReasons[$candidate].Code
                Text = $FailureReasons[$candidate].Text
            }
        }
    }

    return [pscustomobject]@{
        Code = 'UNRECOGNIZED'
        Text = 'Unrecognized failure status'
    }
}


function Test-SystemAccount {
    <# True for machine, service and session-manager accounts. #>
    param([string]$UserName, [string]$Domain)

    if (-not $UserName) {
        return $false
    }

    return (
        $UserName.EndsWith('$') -or
        ($Domain -in @('NT AUTHORITY', 'Window Manager', 'Font Driver Host')) -or
        ($UserName -match '^(DWM|UMFD)-\d+$')
    )
}


function ConvertTo-SentinelRecord {
    <# Converts one Windows event into a normalized Sentinel record. #>
    param([Parameter(Mandatory)] $WinEvent)

    $eventId = [int]$WinEvent.Id

    if ($eventId -ne 4624 -and $eventId -ne 4625) {
        return $null
    }

    if ($null -eq $WinEvent.TimeCreated -or $null -eq $WinEvent.RecordId) {
        return $null
    }

    $data = Get-EventDataMap -EventXml ([xml]$WinEvent.ToXml())

    $recordId = [int64]$WinEvent.RecordId

    $timestamp = $WinEvent.TimeCreated.ToUniversalTime().ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
        [System.Globalization.CultureInfo]::InvariantCulture
    )

    $isFailure = ($eventId -eq 4625)

    $logonType = 0
    $logonTypeName = $null

    if ([int]::TryParse((Get-MapValue $data 'LogonType'), [ref]$logonType)) {

        if ($LogonTypeNames.ContainsKey($logonType)) {
            $logonTypeName = $LogonTypeNames[$logonType]
        }

    } else {
        $logonType = $null
    }

    $failureCode = $null
    $failureText = $null
    $statusCode = $null
    $subStatusCode = $null

    if ($isFailure) {

        $statusCode = ConvertTo-NullIfBlank (Get-MapValue $data 'Status')
        $subStatusCode = ConvertTo-NullIfBlank (Get-MapValue $data 'SubStatus')

        $reason = Resolve-FailureReason `
            -Status (Get-MapValue $data 'Status') `
            -SubStatus (Get-MapValue $data 'SubStatus')

        $failureCode = $reason.Code
        $failureText = $reason.Text
    }

    $eventType = 'SUCCESS_LOGIN'
    $eventStatus = 'SUCCESS'

    if ($isFailure) {
        $eventType = 'FAILED_LOGIN'
        $eventStatus = 'FAILED'
    }

    return [pscustomobject][ordered]@{
        id                    = "windows-$eventId-$recordId"
        recordId              = $recordId
        eventId               = $eventId
        timestamp             = $timestamp
        type                  = $eventType
        status                = $eventStatus
        username              = ConvertTo-NullIfBlank (Get-MapValue $data 'TargetUserName')
        domain                = ConvertTo-NullIfBlank (Get-MapValue $data 'TargetDomainName')
        sourceIp              = ConvertTo-SourceIp (Get-MapValue $data 'IpAddress')
        sourcePort            = ConvertTo-NullIfBlank (Get-MapValue $data 'IpPort')
        logonType             = $logonType
        logonTypeName         = $logonTypeName
        workstation           = ConvertTo-NullIfBlank (Get-MapValue $data 'WorkstationName')
        authenticationPackage = ConvertTo-NullIfBlank (Get-MapValue $data 'AuthenticationPackageName')
        logonProcess          = ConvertTo-NullIfBlank (Get-MapValue $data 'LogonProcessName')
        failureCode           = $failureCode
        failureReason         = $failureText
        statusCode            = $statusCode
        subStatusCode         = $subStatusCode
    }
}


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

function Invoke-SentinelExport {

    $since = (Get-Date).AddHours(-$Hours)

    # Resolve relative paths against PowerShell's current location.
    $resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

    Write-Host "Reading Security log events 4624/4625 from the last $Hours hour(s)..."

    $filter = @{
        LogName   = 'Security'
        Id        = 4624, 4625
        StartTime = $since
    }

    try {

        $winEvents = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)

    } catch [System.UnauthorizedAccessException] {

        Write-Host ''
        Write-Host 'ERROR: Access denied reading the Security log.' -ForegroundColor Red
        Write-Host 'Run PowerShell as Administrator, or add your account to the' -ForegroundColor Red
        Write-Host '"Event Log Readers" group (see the script help), then sign out and in.' -ForegroundColor Red
        exit 1

    } catch {

        # "No events found" is a normal result, not a failure.
        if ($_.FullyQualifiedErrorId -like 'NoMatching*' -or
            $_.Exception.Message -like '*No events were found*') {

            $winEvents = @()

        } else {

            Write-Host "ERROR: Could not read the Security log: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }

    $records = New-Object System.Collections.Generic.List[object]
    $skippedSystem = 0
    $skippedMalformed = 0

    foreach ($winEvent in $winEvents) {

        try {

            $record = ConvertTo-SentinelRecord -WinEvent $winEvent

            if ($null -eq $record) {
                $skippedMalformed++
                continue
            }

            if (-not $IncludeSystemAccounts -and
                (Test-SystemAccount -UserName ([string]$record.username) -Domain ([string]$record.domain))) {
                $skippedSystem++
                continue
            }

            $records.Add($record)

        } catch {
            $skippedMalformed++
        }
    }

    $sortedRecords = @($records | Sort-Object timestamp, recordId)

    $output = [ordered]@{
        schemaVersion         = 1
        source                = 'Windows Security Event Log'
        host                  = $env:COMPUTERNAME
        exportedAt            = (Get-Date).ToUniversalTime().ToString(
                                    "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                                    [System.Globalization.CultureInfo]::InvariantCulture)
        windowHours           = $Hours
        truncated             = ($winEvents.Count -ge $MaxEvents)
        skippedSystemAccounts = $skippedSystem
        skippedMalformed      = $skippedMalformed
        events                = $sortedRecords
    }

    $json = ConvertTo-Json -InputObject $output -Depth 5

    $outputDirectory = Split-Path -Parent $resolvedOutputPath

    if (-not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    }

    # Write UTF-8 without a BOM, via a temporary file so a failed export
    # never leaves a half-written file behind.
    $temporaryPath = "$resolvedOutputPath.tmp"

    [System.IO.File]::WriteAllText(
        $temporaryPath,
        $json,
        (New-Object System.Text.UTF8Encoding($false))
    )

    Move-Item -LiteralPath $temporaryPath -Destination $resolvedOutputPath -Force

    $failedCount = @($sortedRecords | Where-Object { $_.eventId -eq 4625 }).Count
    $successCount = @($sortedRecords | Where-Object { $_.eventId -eq 4624 }).Count

    Write-Host ''
    Write-Host "Exported $($sortedRecords.Count) event(s): $successCount successful (4624), $failedCount failed (4625)."
    Write-Host "Skipped $skippedSystem system-account event(s) and $skippedMalformed unreadable event(s)."
    Write-Host "Output: $resolvedOutputPath"
    Write-Host 'This file contains real usernames and IP addresses. Do not commit it to Git.' -ForegroundColor Yellow

    if ($output.truncated) {
        Write-Warning "MaxEvents ($MaxEvents) was reached; older events were not read. Increase -MaxEvents or reduce -Hours."
    }

    if ($winEvents.Count -eq 0) {
        Write-Warning 'No logon events were found. Check that logon auditing is enabled:'
        Write-Warning '  auditpol /get /subcategory:"Logon"   (needs Success and Failure)'
    }
}


# Run the export unless the script was dot-sourced (e.g. for testing).
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SentinelExport
}
