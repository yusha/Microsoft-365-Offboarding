<#
.SYNOPSIS
    Reverse a Microsoft 365 user offboarding that was run by mistake.

.DESCRIPTION
    Companion to Invoke-M365Offboarding.ps1. Safely undoes the reversible parts
    of an offboarding and clearly reports the parts that cannot be undone.

    What it restores, in order:
      1. Re-enable sign-in (AccountEnabled = true)
      2. Remove the user from the "Offboarded Users" group (lifts the
         Conditional Access block)
      3. Re-assign a Microsoft 365 license
      4. Convert the shared mailbox back to a regular user mailbox
      5. Reset the password (optional) so the user can sign in again
      6. Clear mailbox forwarding that the offboarding set (optional)
      7. Optionally remove delegation (Full Access / Send As) added during offboarding

    The order matters: the account is re-enabled and licensed before the mailbox
    is converted back, because a regular user mailbox needs a license. License
    assignment is verified before the conversion is attempted.

    What CANNOT be restored automatically (and is reported so you can follow up):
      - Removed authentication (MFA) methods. The user must re-register them.
      - Removed mobile device (ActiveSync) partnerships. The device re-enrolls.
      - Revoked OAuth app grants. The user re-consents on next use.

    The original license SKUs can be recovered automatically from the offboarding
    audit.json with -FromAuditJson, or supplied with -LicenseSkuId /
    -LicenseSkuPartNumber, or chosen from a list interactively.

    Runs interactively (browser sign-in) or unattended (app-only certificate
    auth). Supports -WhatIf. Writes a reversal audit record (REVERSAL_AUDIT.md
    and reversal-audit.json).

.PARAMETER UserPrincipalName
    The UPN of the account to restore. Required in unattended mode.

.PARAMETER AuditRoot
    Parent folder for the reversal audit record. A subfolder named
    <user>_reversal_<yyyy-MM-dd> is created inside it. Folder picker if omitted
    interactively.

.PARAMETER FromAuditJson
    Path to the offboarding audit.json produced by Invoke-M365Offboarding.ps1.
    The original license SKUs (and the forwarding address to clear) are read
    from it.

.PARAMETER LicenseSkuId
    One or more license SKU GUIDs to assign. Overrides -FromAuditJson.

.PARAMETER LicenseSkuPartNumber
    One or more license SKU part numbers (for example SPE_E3) to assign. Resolved
    against the tenant's subscribed SKUs.

.PARAMETER ResetPassword
    Reset the password to a random temporary value (shown once) and force a
    change at next sign-in.

.PARAMETER KeepForwarding
    Do not clear mailbox forwarding. By default forwarding is cleared so the
    restored user receives their own mail.

.PARAMETER RemoveDelegation
    Remove explicitly granted Full Access and Send As delegations on the mailbox.

.PARAMETER SkipMailboxConversion
    Do not convert the mailbox back to a regular mailbox.

.PARAMETER OffboardedGroupName
    Display name of the security group used by the Conditional Access block.
    Default: "Offboarded Users".

.PARAMETER TenantId
    Tenant id or domain. Required for app-only auth.

.PARAMETER ClientId
    App registration (client) id for app-only auth.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only auth.

.PARAMETER Organization
    Tenant domain (for example contoso.onmicrosoft.com). Required for app-only
    Exchange Online auth.

.PARAMETER Unattended
    No prompts. Requires -UserPrincipalName and -AuditRoot.

.PARAMETER JsonOutPath
    Optional explicit path for reversal-audit.json.

.EXAMPLE
    .\Invoke-M365OffboardingReversal.ps1 -UserPrincipalName jdoe@contoso.com -FromAuditJson C:\Audits\jdoe_2026-06-05\audit.json -ResetPassword
    Interactive: recovers the original licenses from the offboarding record,
    restores the account, and resets the password.

.EXAMPLE
    .\Invoke-M365OffboardingReversal.ps1 -Unattended -UserPrincipalName jdoe@contoso.com `
        -AuditRoot C:\Audits -LicenseSkuPartNumber SPE_E3 `
        -TenantId contoso.onmicrosoft.com -ClientId <app-id> `
        -CertificateThumbprint <thumbprint> -Organization contoso.onmicrosoft.com
    Headless reversal assigning the SPE_E3 license.

.NOTES
    PowerShell 5.1+ (Windows) or 7+ (any platform). Installs the Microsoft Graph
    and Exchange Online modules on first run if missing. MIT licensed. No
    warranty. Test against a non-production account before production use.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$UserPrincipalName,
    [string]$AuditRoot,
    [string]$FromAuditJson,
    [string[]]$LicenseSkuId,
    [string[]]$LicenseSkuPartNumber,
    [switch]$ResetPassword,
    [switch]$KeepForwarding,
    [switch]$RemoveDelegation,
    [switch]$SkipMailboxConversion,
    [string]$OffboardedGroupName = 'Offboarded Users',
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$Organization,
    [switch]$Unattended,
    [string]$JsonOutPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

$script:IsWindowsHost = $true
if ($PSVersionTable.PSObject.Properties.Name -contains 'Platform') {
    if ($PSVersionTable.Platform -and $PSVersionTable.Platform -ne 'Win32NT') {
        $script:IsWindowsHost = $false
    }
}

# ================================================================
# Console output helpers
# ================================================================
function Write-Banner {
    param([string]$Text, [ConsoleColor]$Color = 'Cyan')
    $line = '=' * 64
    Write-Host ''
    Write-Host $line -ForegroundColor $Color
    Write-Host $Text -ForegroundColor $Color
    Write-Host $line -ForegroundColor $Color
}

function Write-Credit { Write-Host '  Developed by Yusha  |  https://yusha.ca' -ForegroundColor DarkCyan }

function Wait-ForCondition {
    # Poll $Check until it returns truthy or $TimeoutSeconds elapses. Microsoft 365
    # writes replicate asynchronously, so a single fixed sleep + read can falsely
    # report failure while the change is still propagating. $true if satisfied in time.
    param(
        [Parameter(Mandatory)][scriptblock]$Check,
        [int]$TimeoutSeconds = 60,
        [int]$IntervalSeconds = 3
    )
    $script:WaitLastError = $null
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        try { if (& $Check) { return $true } } catch { $script:WaitLastError = $_ }
        if ((Get-Date) -ge $deadline) { return $false }
        Start-Sleep -Seconds $IntervalSeconds
    }
}

function Write-StepHeader {
    param([string]$Title)
    Write-Host ''
    Write-Host ('-' * 64) -ForegroundColor Yellow
    Write-Host (" $Title") -ForegroundColor Yellow
    Write-Host ('-' * 64) -ForegroundColor Yellow
}

function Write-Info    { param([string]$m); Write-Host "  $m" -ForegroundColor White }
function Write-Action  { param([string]$m); Write-Host "  > $m" -ForegroundColor Cyan }
function Write-Ok      { param([string]$m); Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-WarnMsg { param([string]$m); Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Write-ErrMsg  { param([string]$m); Write-Host "  [X]  $m" -ForegroundColor Red }

# ================================================================
# Inputs (interactive)
# ================================================================
function Get-AuditRootFolderInteractive {
    Write-Banner 'REVERSAL AUDIT FOLDER LOCATION'
    Write-Info 'Choose where to save the reversal audit record.'
    Write-Host ''
    if (-not $script:IsWindowsHost) {
        return (Read-Host '  Enter the parent folder path')
    }
    Add-Type -AssemblyName System.Windows.Forms
    $picker = New-Object System.Windows.Forms.FolderBrowserDialog
    $picker.Description = 'Select the parent folder for the reversal audit record'
    $picker.ShowNewFolderButton = $true
    if ($picker.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        throw 'No folder selected. Aborting.'
    }
    return $picker.SelectedPath
}

# ================================================================
# Modules and connection
# ================================================================
function Initialize-Modules {
    $required = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Users.Actions',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Groups',
        'ExchangeOnlineManagement'
    )
    Write-Banner 'CHECKING REQUIRED POWERSHELL MODULES'
    foreach ($m in $required) {
        if (Get-Module -ListAvailable -Name $m) {
            Write-Ok "$m is installed"
        } else {
            Write-WarnMsg "$m is missing. Installing for the current user..."
            Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            Write-Ok "$m installed"
        }
    }
}

function Connect-Services {
    Write-Banner 'CONNECTING TO MICROSOFT 365'
    $graphScopes = @(
        'User.ReadWrite.All',
        'User-PasswordProfile.ReadWrite.All',  # -ResetPassword resets passwordProfile, which requires this dedicated scope (User.ReadWrite.All alone returns 403).
        'Directory.ReadWrite.All',
        'Group.ReadWrite.All',
        'GroupMember.ReadWrite.All',
        'Organization.Read.All'
    )
    $appOnly = $ClientId -and $CertificateThumbprint -and $TenantId

    Write-Action 'Connecting to Microsoft Graph...'
    if ($appOnly) {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
    } else {
        Connect-MgGraph -Scopes $graphScopes -NoWelcome
    }
    $ctx = Get-MgContext
    $operatorId = if ($ctx.Account) { $ctx.Account } else { $ctx.AppName }
    Write-Ok "Connected to Graph as $operatorId in tenant $($ctx.TenantId)"

    Write-Action 'Connecting to Exchange Online...'
    if ($appOnly) {
        if (-not $Organization) { throw 'App-only Exchange Online auth requires -Organization.' }
        Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -Organization $Organization -ShowBanner:$false
    } else {
        Connect-ExchangeOnline -ShowBanner:$false
    }
    Write-Ok 'Connected to Exchange Online'
    return $operatorId
}

function Disconnect-Services {
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
}

# ================================================================
# Audit log
# ================================================================
$script:AuditLog = @()

function Add-AuditEntry {
    param([string]$Action, [string]$Result, [string]$Details = $null)
    $script:AuditLog += [PSCustomObject]@{
        Timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
        Action    = $Action
        Result    = $Result
        Details   = $Details
    }
}

function Write-ReversalMarkdown {
    param([string]$OutputFolder, [string]$TargetUpn, [string]$Operator, [hashtable]$FinalState, [string[]]$NotRestored)
    $startTime = $script:AuditLog | Select-Object -First 1 -ExpandProperty Timestamp
    $endTime   = $script:AuditLog | Select-Object -Last 1 -ExpandProperty Timestamp

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('# Microsoft 365 Offboarding Reversal Record')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Field | Value |')
    [void]$sb.AppendLine('|---|---|')
    [void]$sb.AppendLine("| Target user (UPN) | $TargetUpn |")
    [void]$sb.AppendLine("| Reversal date | $(Get-Date -Format 'yyyy-MM-dd') |")
    [void]$sb.AppendLine("| Started (UTC) | $startTime |")
    [void]$sb.AppendLine("| Completed (UTC) | $endTime |")
    [void]$sb.AppendLine("| Performed by | $Operator |")
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('## Timeline')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Time (UTC) | Action | Result |')
    [void]$sb.AppendLine('|---|---|---|')
    foreach ($e in $script:AuditLog) {
        $a = ($e.Action -replace '\|', '\|'); $r = ($e.Result -replace '\|', '\|')
        [void]$sb.AppendLine("| $($e.Timestamp) | $a | $r |")
    }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('## Detailed notes')
    [void]$sb.AppendLine('')
    foreach ($e in ($script:AuditLog | Where-Object { $_.Details })) {
        [void]$sb.AppendLine("### $($e.Action) at $($e.Timestamp)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("$($e.Details)")
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('## Final state')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Attribute | Value |')
    [void]$sb.AppendLine('|---|---|')
    foreach ($k in $FinalState.Keys) { [void]$sb.AppendLine("| $k | $($FinalState[$k]) |") }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('## Could not be restored automatically')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('These were removed during offboarding and cannot be put back by this tool:')
    [void]$sb.AppendLine('')
    foreach ($n in $NotRestored) { [void]$sb.AppendLine("- $n") }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('_Generated by the Microsoft 365 Offboarding Reversal tool._')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('_Developed by [Yusha](https://yusha.ca)._')

    $path = Join-Path $OutputFolder 'REVERSAL_AUDIT.md'
    [System.IO.File]::WriteAllText($path, $sb.ToString(), [System.Text.Encoding]::UTF8)
    return $path
}

function Write-ReversalJson {
    param([string]$Path, [string]$TargetUpn, [string]$Operator, [hashtable]$FinalState, [string[]]$NotRestored)
    $obj = [ordered]@{
        tool          = 'Invoke-M365OffboardingReversal'
        schemaVersion = '1.0'
        developer     = 'Yusha'
        developerUrl  = 'https://yusha.ca'
        targetUpn     = $TargetUpn
        performedBy   = $Operator
        reversalDate  = (Get-Date -Format 'yyyy-MM-dd')
        startedUtc    = ($script:AuditLog | Select-Object -First 1 -ExpandProperty Timestamp)
        completedUtc  = ($script:AuditLog | Select-Object -Last 1 -ExpandProperty Timestamp)
        actions       = @($script:AuditLog | ForEach-Object {
            [ordered]@{ timestampUtc = $_.Timestamp; action = $_.Action; result = $_.Result; details = $_.Details }
        })
        finalState    = $FinalState
        notRestored   = $NotRestored
        success       = (-not ($script:AuditLog | Where-Object { $_.Result -like 'FAILED*' }))
    }
    [System.IO.File]::WriteAllText($Path, ($obj | ConvertTo-Json -Depth 12), (New-Object System.Text.UTF8Encoding($false)))
    return $Path
}

# ================================================================
# License resolution
# ================================================================
function Get-SkuIdFromAuditJson {
    # Extracts the license SKU GUIDs recorded in the offboarding audit.json
    # (step 9 details look like: "Removed N license SKUs: <guid>, <guid>.").
    param([string]$JsonPath)
    if (-not (Test-Path $JsonPath)) { throw "Audit JSON not found: $JsonPath" }
    $data = Get-Content $JsonPath -Raw | ConvertFrom-Json
    $step9 = $data.steps | Where-Object { $_.step -eq 9 } | Select-Object -First 1
    if (-not $step9 -or -not $step9.details) { return @() }
    $guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    return @([regex]::Matches($step9.details, $guidPattern) | ForEach-Object { $_.Value } | Select-Object -Unique)
}

function Resolve-LicenseSkuIds {
    # Returns the SKU GUIDs to assign based on the supplied parameters, the audit
    # JSON, or an interactive picker. Returns an empty array if none chosen.
    param()
    if ($LicenseSkuId) { return @($LicenseSkuId) }

    if ($LicenseSkuPartNumber) {
        $subscribed = Get-MgSubscribedSku -All
        $resolved = @()
        foreach ($part in $LicenseSkuPartNumber) {
            $match = $subscribed | Where-Object { $_.SkuPartNumber -eq $part } | Select-Object -First 1
            if ($match) { $resolved += $match.SkuId } else { Write-WarnMsg "SKU part number not found in tenant: $part" }
        }
        return @($resolved)
    }

    if ($FromAuditJson) {
        $fromJson = Get-SkuIdFromAuditJson -JsonPath $FromAuditJson
        if ($fromJson.Count) { Write-Info "Recovered $($fromJson.Count) license SKU(s) from the offboarding record." }
        return @($fromJson)
    }

    if (-not $Unattended) {
        $subscribed = Get-MgSubscribedSku -All | Sort-Object SkuPartNumber
        if (-not $subscribed) { return @() }
        Write-Info 'Available license SKUs in this tenant:'
        $i = 0
        foreach ($s in $subscribed) {
            $avail = $s.PrepaidUnits.Enabled - $s.ConsumedUnits
            Write-Host ("    [{0}] {1}  (available: {2})" -f $i, $s.SkuPartNumber, $avail)
            $i++
        }
        $sel = Read-Host '  Enter the number(s) to assign, comma-separated (ENTER to skip)'
        if ([string]::IsNullOrWhiteSpace($sel)) { return @() }
        $ids = @()
        foreach ($n in ($sel -split ',')) {
            $n = $n.Trim()
            if ($n -match '^\d+$' -and [int]$n -lt $subscribed.Count) { $ids += $subscribed[[int]$n].SkuId }
        }
        return @($ids)
    }

    return @()
}

# ================================================================
# Reversal steps
# ================================================================
function Restore-Step-Enable {
    param([string]$Upn)
    Write-StepHeader 'Re-enable sign-in'
    if ($PSCmdlet.ShouldProcess($Upn, 'Set AccountEnabled = true')) {
        Update-MgUser -UserId $Upn -AccountEnabled:$true
        $confirmed = Wait-ForCondition -Check { (Get-MgUser -UserId $Upn -Property AccountEnabled).AccountEnabled }
        if (-not $confirmed) { throw 'Account is still disabled 60s after the update.' }
        Write-Ok 'Account is enabled (AccountEnabled = true)'
    }
    Add-AuditEntry -Action 'Re-enable sign-in' -Result 'Success' -Details 'Set AccountEnabled = true.'
}

function Restore-Step-RemoveFromGroup {
    param([string]$Upn)
    Write-StepHeader "Remove from '$OffboardedGroupName' (lift Conditional Access block)"
    $nameFilter = $OffboardedGroupName -replace "'", "''"
    $group = Get-MgGroup -Filter "displayName eq '$nameFilter'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $group) {
        Write-Info "Group '$OffboardedGroupName' not found. Nothing to remove."
        Add-AuditEntry -Action 'Remove from offboarded group' -Result 'Skipped' -Details 'Group not found.'
        return
    }
    $user = Get-MgUser -UserId $Upn -Property Id
    if ($PSCmdlet.ShouldProcess($Upn, "Remove from '$OffboardedGroupName'")) {
        try {
            Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $user.Id -ErrorAction Stop
            Write-Ok "Removed from '$OffboardedGroupName'"
        } catch {
            if ("$_" -match 'does not exist|not found|Request_ResourceNotFound') {
                Write-Info 'User was not a member of the group.'
            } else { throw }
        }
    }
    Add-AuditEntry -Action 'Remove from offboarded group' -Result 'Success' -Details "Group '$OffboardedGroupName' (Id: $($group.Id))."
}

function Restore-Step-AssignLicense {
    param([string]$Upn, [string[]]$SkuIds)
    Write-StepHeader 'Re-assign Microsoft 365 license'
    if (-not $SkuIds -or $SkuIds.Count -eq 0) {
        Write-WarnMsg 'No license SKU specified. Skipping license assignment.'
        Write-WarnMsg 'The mailbox conversion to a regular mailbox needs a license. Assign one and re-run if needed.'
        Add-AuditEntry -Action 'Re-assign license' -Result 'Skipped' -Details 'No SKU supplied or chosen.'
        return $false
    }
    $user = Get-MgUser -UserId $Upn -Property Id
    $addLicenses = @($SkuIds | ForEach-Object { @{ SkuId = $_ } })
    if ($PSCmdlet.ShouldProcess($Upn, "Assign $($SkuIds.Count) license(s)")) {
        Set-MgUserLicense -UserId $user.Id -AddLicenses $addLicenses -RemoveLicenses @() | Out-Null
        $confirmed = Wait-ForCondition -Check { (Get-MgUser -UserId $Upn -Property AssignedLicenses).AssignedLicenses.Count -gt 0 }
        if (-not $confirmed) { throw ('License assignment did not take effect within 60s.' + $(if ($script:WaitLastError) { " Last check error: $($script:WaitLastError)" })) }
        Write-Ok "Assigned $($SkuIds.Count) license(s)."
    }
    Add-AuditEntry -Action 'Re-assign license' -Result 'Success' -Details "Assigned SKUs: $($SkuIds -join ', ')."
    return $true
}

function Restore-Step-ConvertMailbox {
    param([string]$Upn)
    Write-StepHeader 'Convert mailbox back to a regular user mailbox'
    if ($SkipMailboxConversion) {
        Write-WarnMsg 'Skipping mailbox conversion (-SkipMailboxConversion).'
        Add-AuditEntry -Action 'Convert mailbox to regular' -Result 'Skipped' -Details 'Skipped by request.'
        return
    }
    $mbx = Get-Mailbox -Identity $Upn -ErrorAction SilentlyContinue
    if (-not $mbx) {
        Write-WarnMsg 'No mailbox found.'
        Add-AuditEntry -Action 'Convert mailbox to regular' -Result 'Skipped' -Details 'No mailbox found.'
        return
    }
    if ($mbx.RecipientTypeDetails -eq 'UserMailbox') {
        Write-Info 'Mailbox is already a regular user mailbox. Nothing to convert.'
        Add-AuditEntry -Action 'Convert mailbox to regular' -Result 'Skipped' -Details 'Already a UserMailbox.'
        return
    }
    if ($PSCmdlet.ShouldProcess($Upn, 'Convert to regular mailbox')) {
        Set-Mailbox -Identity $Upn -Type Regular
        Write-Action 'Waiting for Exchange to confirm the conversion (up to 2 minutes)...'
        $confirmed = Wait-ForCondition -TimeoutSeconds 120 -IntervalSeconds 5 -Check { (Get-Mailbox -Identity $Upn).RecipientTypeDetails -eq 'UserMailbox' }
        if (-not $confirmed) {
            $current = (Get-Mailbox -Identity $Upn -ErrorAction SilentlyContinue).RecipientTypeDetails
            throw ("Conversion did not complete within 120s. RecipientTypeDetails is '$current'." + $(if ($script:WaitLastError) { " Last check error: $($script:WaitLastError)" }))
        }
        Write-Ok 'Mailbox converted back to UserMailbox.'
    }
    Add-AuditEntry -Action 'Convert mailbox to regular' -Result 'Success' -Details 'Set-Mailbox -Type Regular; verified UserMailbox.'
}

function Restore-Step-ResetPassword {
    param([string]$Upn)
    Write-StepHeader 'Reset password'
    if (-not $ResetPassword) {
        Write-Info 'Password reset not requested (-ResetPassword not set).'
        Write-Info 'The user cannot sign in until the password is reset (offboarding set a random one).'
        Add-AuditEntry -Action 'Reset password' -Result 'Skipped' -Details 'Not requested.'
        return
    }
    $bytes = New-Object 'byte[]' 18
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $temp = [Convert]::ToBase64String($bytes) + '!Aa9'
    $body = @{ passwordProfile = @{ forceChangePasswordNextSignIn = $true; password = $temp } }
    if ($PSCmdlet.ShouldProcess($Upn, 'Reset password and force change at next sign-in')) {
        Update-MgUser -UserId $Upn -BodyParameter $body
        Write-Ok 'Password reset. The user must change it at next sign-in.'
        Write-Host ''
        Write-Host '  Temporary password (shown once, share securely, do not store):' -ForegroundColor Magenta
        Write-Host "      $temp" -ForegroundColor Magenta
        Write-Host ''
    }
    # The password value itself is never written to the audit record.
    Add-AuditEntry -Action 'Reset password' -Result 'Success' -Details 'Temporary password set with forced change at next sign-in (value not recorded).'
}

function Restore-Step-ClearForwarding {
    param([string]$Upn)
    Write-StepHeader 'Clear mailbox forwarding'
    if ($KeepForwarding) {
        Write-Info 'Keeping forwarding in place (-KeepForwarding).'
        Add-AuditEntry -Action 'Clear forwarding' -Result 'Skipped' -Details 'Kept by request.'
        return
    }
    $mbx = Get-Mailbox -Identity $Upn -ErrorAction SilentlyContinue
    if ($mbx -and ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress)) {
        if ($PSCmdlet.ShouldProcess($Upn, 'Clear forwarding')) {
            Set-Mailbox -Identity $Upn -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false
            Write-Ok 'Forwarding cleared.'
        }
        Add-AuditEntry -Action 'Clear forwarding' -Result 'Success' -Details 'Removed ForwardingSmtpAddress and ForwardingAddress.'
    } else {
        Write-Info 'No forwarding configured.'
        Add-AuditEntry -Action 'Clear forwarding' -Result 'Skipped' -Details 'No forwarding set.'
    }
}

function Restore-Step-RemoveDelegation {
    param([string]$Upn)
    Write-StepHeader 'Remove delegation (Full Access / Send As)'
    if (-not $RemoveDelegation) {
        Add-AuditEntry -Action 'Remove delegation' -Result 'Skipped' -Details 'Not requested (-RemoveDelegation not set).'
        Write-Info 'Delegation left as-is (-RemoveDelegation not set).'
        return
    }
    $removed = @()
    $fa = Get-MailboxPermission -Identity $Upn | Where-Object {
        $_.AccessRights -contains 'FullAccess' -and -not $_.IsInherited -and $_.User -notmatch 'NT AUTHORITY|S-1-5'
    }
    foreach ($p in $fa) {
        if ($PSCmdlet.ShouldProcess($Upn, "Remove Full Access for $($p.User)")) {
            Remove-MailboxPermission -Identity $Upn -User $p.User -AccessRights FullAccess -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            $removed += "FullAccess: $($p.User)"
        }
    }
    $sa = Get-RecipientPermission -Identity $Upn | Where-Object {
        $_.AccessRights -contains 'SendAs' -and $_.Trustee -notmatch 'NT AUTHORITY|S-1-5'
    }
    foreach ($p in $sa) {
        if ($PSCmdlet.ShouldProcess($Upn, "Remove Send As for $($p.Trustee)")) {
            Remove-RecipientPermission -Identity $Upn -Trustee $p.Trustee -AccessRights SendAs -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            $removed += "SendAs: $($p.Trustee)"
        }
    }
    if ($removed.Count) {
        Write-Ok "Removed $($removed.Count) delegation(s)."
        Add-AuditEntry -Action 'Remove delegation' -Result 'Success' -Details ($removed -join "`n")
    } else {
        Write-Info 'No explicit Full Access or Send As delegations found.'
        Add-AuditEntry -Action 'Remove delegation' -Result 'Skipped' -Details 'None found.'
    }
}

# ================================================================
# Final state
# ================================================================
function Get-FinalState {
    param([string]$Upn)
    $state = [ordered]@{}
    try {
        $u = Get-MgUser -UserId $Upn -Property Id, DisplayName, UserPrincipalName, AccountEnabled, AssignedLicenses
        $state['User principal name'] = $u.UserPrincipalName
        $state['Display name']        = $u.DisplayName
        $state['Account enabled']     = $u.AccountEnabled
        $state['Assigned licenses']   = if ($u.AssignedLicenses.Count -eq 0) { 'None' } else { $u.AssignedLicenses.Count }
    } catch { $state['User lookup'] = "Failed: $_" }
    try {
        $mbx = Get-Mailbox -Identity $Upn -ErrorAction SilentlyContinue
        if ($mbx) {
            $state['Recipient type details'] = $mbx.RecipientTypeDetails
            $state['Forwarding address']     = if ($mbx.ForwardingSmtpAddress) { $mbx.ForwardingSmtpAddress } else { 'None' }
        }
    } catch { $state['Mailbox lookup'] = "Failed: $_" }
    return $state
}

# ================================================================
# Orchestration
# ================================================================
function Resolve-AuditFolder {
    param([string]$Root, [string]$Upn)
    $userSafe = ($Upn -split '@')[0] -replace '[^a-zA-Z0-9_-]', '_'
    $folder = Join-Path $Root ("{0}_reversal_{1}" -f $userSafe, (Get-Date -Format 'yyyy-MM-dd'))
    if (Test-Path $folder) {
        $folder = Join-Path $Root ("{0}_reversal_{1}_{2}" -f $userSafe, (Get-Date -Format 'yyyy-MM-dd'), (Get-Date -Format 'HHmmss'))
    }
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    return $folder
}

function Invoke-Restore {
    param([scriptblock]$Action, [string]$Label)
    try { & $Action }
    catch {
        Write-ErrMsg "$Label failed: $_"
        Add-AuditEntry -Action $Label -Result "FAILED: $_" -Details "Exception: $($_.Exception.Message)"
        if (-not $Unattended) {
            $c = Read-Host '  Continue with the remaining reversal steps? (y/N)'
            if ($c -notmatch '^[Yy]') { throw 'Reversal stopped by operator.' }
        }
    }
}

function Main {
    if (-not $Unattended) {
        Clear-Host
        Write-Banner 'MICROSOFT 365 OFFBOARDING REVERSAL' 'Green'
        Write-Credit
        Write-Host '  This restores the reversible parts of an offboarding.' -ForegroundColor Yellow
        Write-Host '  It cannot restore removed MFA methods, mobile device' -ForegroundColor Yellow
        Write-Host '  partnerships, or revoked OAuth grants.' -ForegroundColor Yellow
        Write-Host ''
        $proceed = Read-Host '  Type RESTORE to continue, or anything else to exit'
        if ($proceed -ne 'RESTORE') { Write-Host '  Aborted.' -ForegroundColor Yellow; return }
    }

    $upn = $UserPrincipalName
    if (-not $upn) {
        if ($Unattended) { throw '-UserPrincipalName is required in unattended mode.' }
        $upn = Read-Host '  User principal name to restore (for example jdoe@contoso.com)'
    }
    if ($upn -notmatch '@') { throw "Invalid UserPrincipalName: $upn" }

    $root = $AuditRoot
    if (-not $root) {
        if ($Unattended) { throw '-AuditRoot is required in unattended mode.' }
        $root = Get-AuditRootFolderInteractive
    }
    if (-not (Test-Path $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
    $auditFolder = Resolve-AuditFolder -Root $root -Upn $upn
    Write-Ok "Reversal audit folder: $auditFolder"

    Initialize-Modules
    $operator = Connect-Services
    Add-AuditEntry -Action 'Connected to Microsoft Graph and Exchange Online' -Result "Authenticated as $operator" -Details "Target: $upn."

    # Resolve which licenses to assign before running the steps.
    $skuIds = Resolve-LicenseSkuIds

    # Run the reversal in order.
    Invoke-Restore -Label 'Re-enable sign-in'            -Action { Restore-Step-Enable -Upn $upn }
    Invoke-Restore -Label 'Remove from offboarded group' -Action { Restore-Step-RemoveFromGroup -Upn $upn }
    Invoke-Restore -Label 'Re-assign license'            -Action { Restore-Step-AssignLicense -Upn $upn -SkuIds $skuIds | Out-Null }
    Invoke-Restore -Label 'Convert mailbox to regular'   -Action { Restore-Step-ConvertMailbox -Upn $upn }
    Invoke-Restore -Label 'Reset password'               -Action { Restore-Step-ResetPassword -Upn $upn }
    Invoke-Restore -Label 'Clear forwarding'             -Action { Restore-Step-ClearForwarding -Upn $upn }
    Invoke-Restore -Label 'Remove delegation'            -Action { Restore-Step-RemoveDelegation -Upn $upn }

    # Reversal record
    Write-Banner 'WRITING REVERSAL RECORD'
    $notRestored = @(
        'Authentication (MFA) methods: the user must re-register them at https://aka.ms/mfasetup.',
        'Mobile device (ActiveSync) partnerships: the device re-creates the partnership on next connect.',
        'OAuth app grants: the user re-consents to apps on next use.'
    )
    $finalState = Get-FinalState -Upn $upn
    $md = Write-ReversalMarkdown -OutputFolder $auditFolder -TargetUpn $upn -Operator $operator -FinalState $finalState -NotRestored $notRestored
    Write-Ok "Wrote $md"
    $jsonPath = if ($JsonOutPath) { $JsonOutPath } else { Join-Path $auditFolder 'reversal-audit.json' }
    Write-ReversalJson -Path $jsonPath -TargetUpn $upn -Operator $operator -FinalState $finalState -NotRestored $notRestored | Out-Null
    Write-Ok "Wrote $jsonPath"

    Write-Banner 'REVERSAL COMPLETE' 'Green'
    Write-Host "  Audit folder: $auditFolder" -ForegroundColor Green
    Write-Host ''
    Write-Host '  Remind the user to:' -ForegroundColor Yellow
    Write-Host '    - Re-register MFA (https://aka.ms/mfasetup)'
    Write-Host '    - Re-add their mailbox on mobile devices'
    Write-Host '    - Re-consent to any third-party apps they used'

    if (-not $Unattended -and $script:IsWindowsHost) {
        try { Start-Process explorer.exe $auditFolder } catch { }
    }
    Disconnect-Services
}

try {
    Main
} catch {
    Write-ErrMsg "FATAL: $_"
    Write-Host "  $($_.ScriptStackTrace)" -ForegroundColor Red
    Disconnect-Services
    if (-not $Unattended) { Read-Host 'Press ENTER to exit' }
    exit 1
}
