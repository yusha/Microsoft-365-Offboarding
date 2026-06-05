<#
.SYNOPSIS
    Detect whether a person was offboarded before (a rehire) so you can restore
    the existing account instead of creating a new one.

.DESCRIPTION
    Read-only companion to Invoke-M365Offboarding.ps1. Given a display name
    and/or a user principal name, it looks for evidence of a prior offboarding
    from two sources and prints a verdict with a recommended next step. It makes
    no changes.

    Sources checked:
      1. Audit history. Scans an audit root for past audit.json records produced
         by the offboarding tool and matches them by UPN or display name.
      2. Live tenant. Looks for existing accounts that match by UPN or display
         name and flags those that look offboarded (disabled, unlicensed, in the
         "Offboarded Users" group, or backed by a shared mailbox).

    Verdicts:
      RehireLikely        A previously offboarded account still exists. Restore
                          it with Invoke-M365OffboardingReversal.ps1.
      PriorRecordOnly     A past offboarding record exists but no matching live
                          account. The account may have been deleted; check the
                          deleted users list (restorable for 30 days).
      AccountAlreadyExists A matching active account exists that does not look
                          offboarded.
      NoEvidence          Nothing found. Treat as a new hire.

.PARAMETER DisplayName
    Display name to match, for example "Jane Doe".

.PARAMETER UserPrincipalName
    UPN to match, for example jdoe@contoso.com.

.PARAMETER AuditRoot
    Folder that holds past offboarding audit packets to scan. Optional.

.PARAMETER SkipTenantCheck
    Do not connect to Microsoft 365. Only scan the audit history.

.PARAMETER OffboardedGroupName
    Security group used by the Conditional Access block. Default "Offboarded Users".

.PARAMETER TenantId
    Tenant id or domain. Required for app-only auth.

.PARAMETER ClientId
    App registration (client) id for app-only auth.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only auth.

.PARAMETER Organization
    Tenant domain (for example contoso.onmicrosoft.com). Required for app-only
    Exchange Online auth (used for the shared-mailbox check).

.PARAMETER JsonOutPath
    Optional path to write a structured rehire-report.json.

.PARAMETER Unattended
    No prompts. Prints the report and exits.

.EXAMPLE
    .\Test-M365Rehire.ps1 -UserPrincipalName jdoe@contoso.com -AuditRoot C:\Audits
    Checks the tenant and the audit history for prior offboarding of jdoe.

.EXAMPLE
    .\Test-M365Rehire.ps1 -DisplayName "Jane Doe" -AuditRoot C:\Audits -SkipTenantCheck
    Audit-history-only check (no sign-in) by display name.

.NOTES
    Read-only. PowerShell 5.1+ (Windows) or 7+ (any platform). Installs the
    Microsoft Graph and Exchange Online modules on first run if needed for the
    tenant check. MIT licensed. No warranty.
#>

[CmdletBinding()]
param(
    [string]$DisplayName,
    [string]$UserPrincipalName,
    [string]$AuditRoot,
    [switch]$SkipTenantCheck,
    [string]$OffboardedGroupName = 'Offboarded Users',
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$Organization,
    [string]$JsonOutPath,
    [switch]$Unattended
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

# ================================================================
# Console helpers
# ================================================================
function Write-Banner {
    param([string]$Text, [ConsoleColor]$Color = 'Cyan')
    $line = '=' * 64
    Write-Host ''; Write-Host $line -ForegroundColor $Color
    Write-Host $Text -ForegroundColor $Color; Write-Host $line -ForegroundColor $Color
}
function Write-Info    { param([string]$m); Write-Host "  $m" -ForegroundColor White }
function Write-Action  { param([string]$m); Write-Host "  > $m" -ForegroundColor Cyan }
function Write-Ok      { param([string]$m); Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-WarnMsg { param([string]$m); Write-Host "  [!]  $m" -ForegroundColor Yellow }

# ================================================================
# Audit history scan (no sign-in required)
# ================================================================
function Find-PriorOffboardingRecords {
    # Scans an audit root for offboarding audit.json files and returns the ones
    # that match the given UPN or display name.
    param([string]$Root, [string]$Upn, [string]$Name)
    $records = @()
    if (-not $Root -or -not (Test-Path $Root)) { return $records }

    $jsonFiles = Get-ChildItem -Path $Root -Filter 'audit.json' -Recurse -File -ErrorAction SilentlyContinue
    foreach ($f in $jsonFiles) {
        try {
            $data = Get-Content $f.FullName -Raw | ConvertFrom-Json
        } catch { continue }
        if ($data.tool -ne 'Invoke-M365Offboarding') { continue }

        $recordUpn = "$($data.targetUpn)"
        $recordName = "$($data.finalState.'Display name')"
        $upnMatch  = $Upn  -and $recordUpn  -and ($recordUpn.ToLower()  -eq $Upn.ToLower())
        $nameMatch = $Name -and $recordName -and ($recordName.ToLower() -eq $Name.ToLower())
        if ($upnMatch -or $nameMatch) {
            $records += [PSCustomObject]@{
                Source      = 'auditHistory'
                Path        = $f.FullName
                Date        = "$($data.offboardingDate)"
                Upn         = $recordUpn
                DisplayName = $recordName
                PerformedBy = "$($data.performedBy)"
                MatchedBy   = if ($upnMatch) { 'upn' } else { 'displayName' }
            }
        }
    }
    return $records
}

# ================================================================
# Tenant connection (read-only)
# ================================================================
function Connect-ReadOnly {
    $scopes = @('User.Read.All', 'Directory.Read.All', 'Group.Read.All', 'GroupMember.Read.All')
    $appOnly = $ClientId -and $CertificateThumbprint -and $TenantId
    Write-Action 'Connecting to Microsoft Graph (read-only)...'
    if ($appOnly) {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
    } else {
        Connect-MgGraph -Scopes $scopes -NoWelcome
    }
    $ctx = Get-MgContext
    Write-Ok "Connected as $(if ($ctx.Account) { $ctx.Account } else { $ctx.AppName })"

    # Exchange Online is only needed for the shared-mailbox signal; degrade if it fails.
    try {
        Write-Action 'Connecting to Exchange Online...'
        if ($appOnly) {
            if ($Organization) {
                Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -Organization $Organization -ShowBanner:$false
                return $true
            } else {
                Write-WarnMsg 'App-only Exchange check needs -Organization. Skipping mailbox signal.'
                return $false
            }
        } else {
            Connect-ExchangeOnline -ShowBanner:$false
            return $true
        }
    } catch {
        Write-WarnMsg "Exchange Online connect failed; skipping mailbox signal: $_"
        return $false
    }
}

function Disconnect-ReadOnly {
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
}

function Get-OffboardedGroupId {
    param([string]$Name)
    $filter = $Name -replace "'", "''"
    $g = Get-MgGroup -Filter "displayName eq '$filter'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($g) { return $g.Id } else { return $null }
}

function Find-TenantAccounts {
    # Finds tenant users matching by UPN or display name and assesses whether
    # each looks like it was offboarded.
    param([string]$Upn, [string]$Name, [string]$GroupId, [bool]$HaveExchange)
    $found = @{}

    $users = @()
    if ($Upn) {
        $f = $Upn -replace "'", "''"
        $users += Get-MgUser -Filter "userPrincipalName eq '$f'" -Property Id, DisplayName, UserPrincipalName, AccountEnabled, AssignedLicenses -ErrorAction SilentlyContinue
    }
    if ($Name) {
        $f = $Name -replace "'", "''"
        $users += Get-MgUser -Filter "displayName eq '$f'" -Property Id, DisplayName, UserPrincipalName, AccountEnabled, AssignedLicenses -ErrorAction SilentlyContinue
    }

    $results = @()
    foreach ($u in $users) {
        if (-not $u) { continue }
        if ($found.ContainsKey($u.Id)) { continue }
        $found[$u.Id] = $true

        $inGroup = $false
        if ($GroupId) {
            try {
                $member = Get-MgGroupMember -GroupId $GroupId -All -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $u.Id }
                $inGroup = [bool]$member
            } catch { $inGroup = $false }
        }

        $mailboxType = $null
        if ($HaveExchange) {
            try {
                $mbx = Get-Mailbox -Identity $u.UserPrincipalName -ErrorAction SilentlyContinue
                if ($mbx) { $mailboxType = "$($mbx.RecipientTypeDetails)" }
            } catch { $mailboxType = $null }
        }

        $licenseCount = ($u.AssignedLicenses | Measure-Object).Count
        $looksOffboarded = (-not $u.AccountEnabled) -and ($licenseCount -eq 0 -or $inGroup -or $mailboxType -eq 'SharedMailbox')

        $results += [PSCustomObject]@{
            Source            = 'tenant'
            Id                = $u.Id
            Upn               = $u.UserPrincipalName
            DisplayName       = $u.DisplayName
            AccountEnabled    = [bool]$u.AccountEnabled
            LicenseCount      = $licenseCount
            InOffboardedGroup = $inGroup
            MailboxType       = $mailboxType
            LooksOffboarded   = $looksOffboarded
        }
    }
    return $results
}

# ================================================================
# Verdict
# ================================================================
function Get-RehireVerdict {
    param($HistoryMatches, $TenantMatches)
    $offboardedAccounts = @($TenantMatches | Where-Object { $_.LooksOffboarded })
    $anyHistory = @($HistoryMatches).Count -gt 0
    $anyTenant  = @($TenantMatches).Count -gt 0

    if ($offboardedAccounts.Count -gt 0) {
        return [PSCustomObject]@{
            Verdict        = 'RehireLikely'
            Recommendation = "A previously offboarded account exists. Restore it instead of creating a new one: Invoke-M365OffboardingReversal.ps1 -UserPrincipalName $($offboardedAccounts[0].Upn)"
            RestoreUpn     = $offboardedAccounts[0].Upn
        }
    }
    if ($anyHistory -and -not $anyTenant) {
        return [PSCustomObject]@{
            Verdict        = 'PriorRecordOnly'
            Recommendation = 'A past offboarding record exists but no matching account was found. The account may have been deleted; check the deleted users list (restorable for 30 days) before recreating.'
            RestoreUpn     = $null
        }
    }
    if ($anyTenant) {
        return [PSCustomObject]@{
            Verdict        = 'AccountAlreadyExists'
            Recommendation = 'An active account already exists with this identity and does not look offboarded. Confirm whether this is the same person before creating another account.'
            RestoreUpn     = $null
        }
    }
    return [PSCustomObject]@{
        Verdict        = 'NoEvidence'
        Recommendation = 'No prior offboarding found. Treat as a new hire.'
        RestoreUpn     = $null
    }
}

# ================================================================
# Output
# ================================================================
function Write-RehireReport {
    param([string]$Path, [string]$Upn, [string]$Name, $HistoryMatches, $TenantMatches, $Verdict)
    $obj = [ordered]@{
        tool           = 'Test-M365Rehire'
        schemaVersion  = '1.0'
        queriedUpn     = $Upn
        queriedName    = $Name
        verdict        = $Verdict.Verdict
        recommendation = $Verdict.Recommendation
        restoreUpn     = $Verdict.RestoreUpn
        historyMatches = @($HistoryMatches)
        tenantMatches  = @($TenantMatches)
    }
    [System.IO.File]::WriteAllText($Path, ($obj | ConvertTo-Json -Depth 12), [System.Text.Encoding]::UTF8)
    return $Path
}

# ================================================================
# Main
# ================================================================
function Main {
    if (-not $DisplayName -and -not $UserPrincipalName) {
        if ($Unattended) { throw 'Provide -UserPrincipalName and/or -DisplayName.' }
        Write-Banner 'REHIRE / PRIOR OFFBOARDING CHECK'
        $UserPrincipalName = Read-Host '  UPN to check (ENTER to skip)'
        $DisplayName = Read-Host '  Display name to check (ENTER to skip)'
        if (-not $DisplayName -and -not $UserPrincipalName) { throw 'Nothing to check.' }
    }

    Write-Banner 'CHECKING AUDIT HISTORY'
    $history = @(Find-PriorOffboardingRecords -Root $AuditRoot -Upn $UserPrincipalName -Name $DisplayName)
    if ($history.Count) {
        Write-WarnMsg "Found $($history.Count) prior offboarding record(s):"
        foreach ($h in $history) { Write-Info "  $($h.Date)  $($h.Upn)  (matched by $($h.MatchedBy))  -  $($h.Path)" }
    } else {
        Write-Info 'No matching offboarding records in the audit history.'
    }

    $tenant = @()
    if (-not $SkipTenantCheck) {
        Write-Banner 'CHECKING THE TENANT'
        $haveExchange = Connect-ReadOnly
        try {
            $groupId = Get-OffboardedGroupId -Name $OffboardedGroupName
            $tenant = @(Find-TenantAccounts -Upn $UserPrincipalName -Name $DisplayName -GroupId $groupId -HaveExchange $haveExchange)
            if ($tenant.Count) {
                foreach ($t in $tenant) {
                    $flag = if ($t.LooksOffboarded) { 'LOOKS OFFBOARDED' } else { 'active' }
                    $mbxText = if ($t.MailboxType) { $t.MailboxType } else { 'n/a' }
                    Write-Info ("  {0}  enabled={1} licenses={2} group={3} mailbox={4}  [{5}]" -f $t.Upn, $t.AccountEnabled, $t.LicenseCount, $t.InOffboardedGroup, $mbxText, $flag)
                }
            } else {
                Write-Info 'No matching accounts found in the tenant.'
            }
        } finally {
            Disconnect-ReadOnly
        }
    } else {
        Write-Info 'Tenant check skipped (-SkipTenantCheck).'
    }

    $verdict = Get-RehireVerdict -HistoryMatches $history -TenantMatches $tenant

    $color = switch ($verdict.Verdict) {
        'RehireLikely'         { 'Yellow' }
        'PriorRecordOnly'      { 'Yellow' }
        'AccountAlreadyExists' { 'Yellow' }
        default                { 'Green' }
    }
    Write-Banner "VERDICT: $($verdict.Verdict)" $color
    Write-Host "  $($verdict.Recommendation)" -ForegroundColor $color

    if ($JsonOutPath) {
        $p = Write-RehireReport -Path $JsonOutPath -Upn $UserPrincipalName -Name $DisplayName -HistoryMatches $history -TenantMatches $tenant -Verdict $verdict
        Write-Ok "Wrote $p"
    }
}

try {
    Main
} catch {
    Write-Host "  [X]  FATAL: $_" -ForegroundColor Red
    Disconnect-ReadOnly
    if (-not $Unattended) { Read-Host 'Press ENTER to exit' }
    exit 1
}
