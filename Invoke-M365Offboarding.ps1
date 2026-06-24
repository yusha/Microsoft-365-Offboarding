<#
.SYNOPSIS
    Microsoft 365 user offboarding and decommissioning tool.

.DESCRIPTION
    Executes a fixed, ordered offboarding procedure against Microsoft Graph and
    Exchange Online, captures an audit trail (optional per-step screenshots, an
    AUDIT.md timeline, and a machine-readable audit.json), and leaves the mailbox
    intact as a shared mailbox.

    The procedure runs in three phases:

      Phase 1  Immediate lockout
        1. Reset password and revoke all sign-in sessions
        2. Block sign-in (disable the account)
        3. Remove ActiveSync mobile device partnerships

      Phase 2  Authorization cleanup
        4. Remove registered authentication (MFA) methods
        5. Revoke OAuth app grants
        6. Remove from groups and distribution lists

      Phase 3  Mailbox transition and hardening
        7. Configure forwarding / delegation (optional)
        8. Convert the user mailbox to a shared mailbox
        9. Remove Microsoft 365 licenses
       10. Apply a Conditional Access block on the user principal

    The ordering is deliberate and aligned with Microsoft's documentation. In
    particular, the mailbox is converted to shared (step 8) BEFORE the license
    is removed (step 9), because Microsoft hides the conversion option once the
    license is gone. See the README for the documentation references behind each
    step.

    The tool runs interactively by default (menu driven, browser sign-in) and
    can also run unattended for automation (app-only certificate auth, no
    prompts, JSON output). See the -Unattended examples below.

.PARAMETER UserPrincipalName
    The UPN of the account to offboard, for example jdoe@contoso.com.
    Prompted for if omitted in interactive mode. Required in unattended mode.

.PARAMETER AuditRoot
    Parent folder for the audit packet. A subfolder named <user>_<yyyy-MM-dd> is
    created inside it. In interactive mode a folder picker is shown if omitted.

.PARAMETER Steps
    One or more step numbers (1-10) to run instead of all ten. Example: -Steps 1,2,3.

.PARAMETER All
    Run all ten steps in order without showing the menu (interactive mode).

.PARAMETER DryRun
    Training mode. Walks through all ten steps and narrates exactly what each one
    would do (and which cmdlets it uses) WITHOUT signing in, touching the tenant,
    or making any change. Produces a clearly marked sample audit packet. Works
    offline and on any platform. Use this to learn or demonstrate the tool. For a
    live preview against a real account that reads real data but makes no changes,
    use -WhatIf instead.

.PARAMETER Unattended
    No prompts. Requires -UserPrincipalName and -AuditRoot. Runs the requested
    steps (all ten by default) and exits. Combine with app-only auth parameters
    for headless automation.

.PARAMETER NoScreenshots
    Skip screenshot capture. Screenshots are Windows-only and are skipped
    automatically on PowerShell 7 on non-Windows platforms.

.PARAMETER ForwardingAddress
    If supplied, configures SMTP forwarding from the mailbox to this address
    during step 7.

.PARAMETER ForwardKeepCopy
    When forwarding is configured, also keep a copy in the original mailbox
    (DeliverToMailboxAndForward). Default is to keep a copy.

.PARAMETER DelegateTo
    If supplied, grants this user Full Access and Send As on the mailbox during
    step 7.

.PARAMETER SkipMailboxConversion
    Skip step 8. Use only when the mailbox will be handled separately (for
    example a hard delete). Leaving this off is recommended.

.PARAMETER OffboardedGroupName
    Display name of the security group used by the Conditional Access block.
    Default: "Offboarded Users". Created automatically if missing.

.PARAMETER BlockPolicyName
    Display name of the Conditional Access policy. Default:
    "Block sign-in for offboarded users". Created in report-only mode if missing.

.PARAMETER TenantId
    Tenant id (GUID) or domain. Required for app-only auth.

.PARAMETER ClientId
    App registration (client) id for app-only auth.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only auth (certificate must be in the local
    certificate store and uploaded to the app registration).

.PARAMETER Organization
    Tenant domain (for example contoso.onmicrosoft.com). Required for app-only
    Exchange Online auth.

.PARAMETER JsonOutPath
    Optional explicit path for the machine-readable audit.json. Defaults to
    audit.json inside the audit folder.

.PARAMETER SharePointSiteUrl
    SharePoint site URL to upload the finished audit packet to, for example
    https://contoso.sharepoint.com/sites/IT. When supplied, the audit folder is
    uploaded to that site's default document library after the run. When omitted
    in interactive mode you are asked whether to link a site; if you decline, the
    packet stays local and you are reminded to upload it manually.

.PARAMETER SharePointFolderPath
    Destination folder inside the site's document library, for example
    "Offboarding Audits". The per-user audit subfolder is created beneath it.
    Defaults to the library root.

.PARAMETER SkipSharePointUpload
    Do not upload to SharePoint and do not prompt. The packet stays local.

.EXAMPLE
    .\Invoke-M365Offboarding.ps1
    Interactive: prompts for everything, browser sign-in, menu driven.

.EXAMPLE
    .\Invoke-M365Offboarding.ps1 -UserPrincipalName jdoe@contoso.com -AuditRoot C:\Audits -All
    Interactive sign-in, then runs all ten steps for the given user.

.EXAMPLE
    .\Invoke-M365Offboarding.ps1 -Unattended -UserPrincipalName jdoe@contoso.com `
        -AuditRoot C:\Audits -NoScreenshots `
        -TenantId contoso.onmicrosoft.com -ClientId <app-id> `
        -CertificateThumbprint <thumbprint> -Organization contoso.onmicrosoft.com `
        -JsonOutPath C:\Audits\jdoe.json
    Headless automation suitable for calling from a scheduler, an AI agent, or a
    web portal. Emits audit.json describing every step's result.

.NOTES
    Requires PowerShell 5.1+ (Windows) or PowerShell 7+ (any platform), and the
    Microsoft Graph and Exchange Online PowerShell modules (installed on first
    run if missing). MIT licensed. No warranty. Test against a non-production
    account before using in production.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$UserPrincipalName,
    [string]$AuditRoot,
    [ValidateRange(1, 10)][int[]]$Steps,
    [switch]$All,
    [switch]$DryRun,
    [switch]$Unattended,
    [switch]$NoScreenshots,
    [string]$ForwardingAddress,
    [bool]$ForwardKeepCopy = $true,
    [string]$DelegateTo,
    [switch]$SkipMailboxConversion,
    [string]$OffboardedGroupName = 'Offboarded Users',
    [string]$BlockPolicyName = 'Block sign-in for offboarded users',
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$Organization,
    [string]$JsonOutPath,
    [string]$SharePointSiteUrl,
    [string]$SharePointFolderPath,
    [switch]$SkipSharePointUpload
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Force UTF-8 so non-ASCII display names are not mangled in the audit log.
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

# Detect Windows. The folder picker is Windows-only; screenshot support varies
# by platform and is resolved by Initialize-ScreenshotCapability (called in Main).
$script:IsWindowsHost = $true
if ($PSVersionTable.PSObject.Properties.Name -contains 'Platform') {
    if ($PSVersionTable.Platform -and $PSVersionTable.Platform -ne 'Win32NT') {
        $script:IsWindowsHost = $false
    }
}

# Screenshot capability, set by Initialize-ScreenshotCapability:
#   'windows'  full-screen capture via System.Windows.Forms
#   'linux'    capture via a CLI tool (grim/scrot/gnome-screenshot/import)
#   'none'     no graphical desktop (for example Azure Cloud Shell)
$script:ScreenshotMode = 'none'
$script:ScreenshotTool = $null
$script:IsCloudShell   = $false
$script:HasDisplay     = $false
$script:TranscriptOn   = $false

# ================================================================
# SECTION 1: Console output helpers
# ================================================================
function Write-Banner {
    param([string]$Text, [ConsoleColor]$Color = 'Cyan')
    $line = '=' * 64
    Write-Host ''
    Write-Host $line -ForegroundColor $Color
    Write-Host $Text -ForegroundColor $Color
    Write-Host $line -ForegroundColor $Color
}

function Write-StepHeader {
    param([int]$Number, [string]$Title)
    Write-Host ''
    Write-Host ('-' * 64) -ForegroundColor Yellow
    Write-Host (' STEP {0}: {1}' -f $Number, $Title) -ForegroundColor Yellow
    Write-Host ('-' * 64) -ForegroundColor Yellow
}

function Write-Info    { param([string]$m); Write-Host "  $m" -ForegroundColor White }
function Write-Action  { param([string]$m); Write-Host "  > $m" -ForegroundColor Cyan }
function Write-Ok      { param([string]$m); Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-WarnMsg { param([string]$m); Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Write-ErrMsg  { param([string]$m); Write-Host "  [X]  $m" -ForegroundColor Red }
function Write-Credit  { Write-Host '  Developed by Yusha  |  https://yusha.ca' -ForegroundColor DarkCyan }

function Wait-ForCondition {
    # Poll $Check until it returns truthy or $TimeoutSeconds elapses. Microsoft 365
    # writes (account disable, mailbox conversion, license removal) replicate
    # asynchronously, so a single fixed sleep + read can falsely report failure
    # while the change is still propagating. Returns $true if satisfied in time.
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

# ================================================================
# SECTION 2: Inputs (interactive only)
# ================================================================
function Get-AuditRootFolderInteractive {
    Write-Banner 'AUDIT FOLDER LOCATION'
    Write-Info 'Choose where to save the audit packet for this offboarding.'
    Write-Info 'A subfolder will be created as: <user>_<yyyy-MM-dd>'
    Write-Host ''

    if (-not $script:IsWindowsHost) {
        return (Read-Host '  Enter the parent folder path for the audit packet')
    }
    return (Show-WindowsFolderPicker)
}

# Isolated so the WinForms type literals only compile when called on Windows.
function Show-WindowsFolderPicker {
    Add-Type -AssemblyName System.Windows.Forms
    $picker = New-Object System.Windows.Forms.FolderBrowserDialog
    $picker.Description = 'Select the parent folder for the audit packet'
    $picker.ShowNewFolderButton = $true
    if ($picker.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        throw 'No folder selected. Aborting.'
    }
    return $picker.SelectedPath
}

function Get-TargetUserInteractive {
    Write-Banner 'TARGET USER TO OFFBOARD'
    Write-Host ''
    $upn = Read-Host '  User principal name (for example jdoe@contoso.com)'
    if ([string]::IsNullOrWhiteSpace($upn) -or $upn -notmatch '@') {
        throw 'A valid user principal name is required.'
    }
    return $upn.Trim()
}

# ================================================================
# SECTION 3: Module bootstrap and connections
# ================================================================
function Initialize-Modules {
    $required = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Users.Actions',
        'Microsoft.Graph.Identity.SignIns',
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
        'User-PasswordProfile.ReadWrite.All',  # Step 1 password reset: passwordProfile updates require this dedicated scope; User.ReadWrite.All alone returns 403 Authorization_RequestDenied.
        'RoleManagement.ReadWrite.Directory',  # Pre-step: remove the target's admin role assignments (a privileged account cannot be disabled/managed until its roles are removed).
        'Directory.ReadWrite.All',
        'Policy.ReadWrite.ConditionalAccess',
        'Application.ReadWrite.All',
        'Group.ReadWrite.All',
        'GroupMember.ReadWrite.All',
        'DelegatedPermissionGrant.ReadWrite.All',
        'UserAuthenticationMethod.ReadWrite.All'
    )

    # Only request SharePoint write access when an upload could actually occur:
    # not explicitly skipped, and either a site URL was supplied or we are
    # interactive (where the end-of-run prompt may choose to upload).
    $mayUploadToSharePoint = (-not $SkipSharePointUpload) -and ($SharePointSiteUrl -or (-not $Unattended))
    if ($mayUploadToSharePoint) {
        $graphScopes += 'Sites.ReadWrite.All'
        Write-Info 'Requesting the SharePoint (Sites.ReadWrite.All) scope for the audit packet upload.'
    }

    $script:GraphScopes = $graphScopes  # remembered so the CA pre-step can re-request consent

    $appOnly = $ClientId -and $CertificateThumbprint -and $TenantId

    Write-Action 'Connecting to Microsoft Graph...'
    if ($appOnly) {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
    } else {
        # Disconnect any cached session first: a stale token from a previous run (or a
        # narrow by-hand Connect-MgGraph) can be reused and NOT contain every requested
        # scope, which then surfaces as a confusing 403 deep in the run (e.g. step 10's
        # Conditional Access call). A fresh connect requests the full scope set.
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        Connect-MgGraph -Scopes $graphScopes -NoWelcome
    }
    $ctx = Get-MgContext
    $operatorId = if ($ctx.Account) { $ctx.Account } else { $ctx.AppName }
    Write-Ok "Connected to Graph as $operatorId in tenant $($ctx.TenantId)"

    # Verify the delegated token carries every scope we need, and obtain consent for
    # any that are missing without the operator touching the Entra portal. Admin-
    # restricted scopes (e.g. Policy.ReadWrite.ConditionalAccess) are only granted when
    # an admin consents on behalf of the organization, so if one is absent we re-prompt
    # right here and tell the operator to tick that box -- they just accept the dialog.
    if (-not $appOnly -and $ctx.Scopes) {
        $missingScopes = @($graphScopes | Where-Object { $_ -notin $ctx.Scopes })
        if ($missingScopes.Count) {
            Write-WarnMsg ("The token is missing these scopes: {0}." -f ($missingScopes -join ', '))
            Write-Action 'Opening a consent window for them. Accept it, and TICK "Consent on behalf of your organization" so admin-restricted permissions are granted.'
            try {
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                Connect-MgGraph -Scopes $graphScopes -NoWelcome
                $ctx = Get-MgContext
            } catch {
                Write-WarnMsg "Consent prompt failed: $_"
            }
            $missingScopes = @($graphScopes | Where-Object { $_ -notin $ctx.Scopes })
        }
        if ($missingScopes.Count) {
            Write-WarnMsg ("Still missing after the consent prompt: {0}." -f ($missingScopes -join ', '))
            Write-WarnMsg 'The core offboarding still runs; steps needing these scopes are skipped with guidance (for example, step 10 Conditional Access).'
        } else {
            Write-Ok 'All required Microsoft Graph scopes are present in the token.'
        }
    }

    Write-Action 'Connecting to Exchange Online...'
    if ($appOnly) {
        if (-not $Organization) { throw 'App-only Exchange Online auth requires -Organization (for example contoso.onmicrosoft.com).' }
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

function Stop-TranscriptSafe {
    if ($script:TranscriptOn) {
        try { Stop-Transcript | Out-Null } catch { }
        $script:TranscriptOn = $false
    }
}

# ================================================================
# SECTION 4: Screenshot capability and capture
# ================================================================
function Get-LinuxScreenshotTool {
    # Returns the name of an available CLI screenshot tool, or $null.
    $candidates = @()
    if ($env:WAYLAND_DISPLAY) { $candidates += 'grim' }
    $candidates += @('scrot', 'gnome-screenshot', 'import', 'spectacle')
    foreach ($c in $candidates) {
        if (Get-Command $c -ErrorAction SilentlyContinue) { return $c }
    }
    return $null
}

function Get-LinuxPackageManager {
    foreach ($pm in @('apt-get', 'dnf', 'yum', 'zypper', 'pacman')) {
        if (Get-Command $pm -ErrorAction SilentlyContinue) { return $pm }
    }
    return $null
}

function Initialize-ScreenshotCapability {
    # Decides how (or whether) screenshots can be captured on this platform.
    $script:IsCloudShell = ($env:AZUREPS_HOST_ENVIRONMENT -like 'cloud-shell*') -or [bool]$env:ACC_CLOUD
    $script:HasDisplay   = [bool]($env:DISPLAY -or $env:WAYLAND_DISPLAY)
    $script:ScreenshotMode = 'none'
    $script:ScreenshotTool = $null

    if ($NoScreenshots) { return }

    if ($script:IsWindowsHost) {
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            Add-Type -AssemblyName System.Drawing -ErrorAction Stop
            $script:ScreenshotMode = 'windows'
        } catch {
            $script:ScreenshotMode = 'none'
        }
        return
    }

    # Linux/macOS: screenshots need a graphical desktop and a capture tool.
    if ($script:HasDisplay) {
        $tool = Get-LinuxScreenshotTool
        if ($tool) {
            $script:ScreenshotMode = 'linux'
            $script:ScreenshotTool = $tool
        }
    }
}

function Request-ScreenshotToolInstall {
    # Linux desktop only: offer to install a capture tool when none is present.
    # Never offered on a headless host (no display) such as Azure Cloud Shell.
    if ($script:IsWindowsHost -or -not $script:HasDisplay -or $Unattended -or $NoScreenshots) { return }
    if ($script:ScreenshotMode -ne 'none') { return }

    $pm = Get-LinuxPackageManager
    if (-not $pm) { return }
    $pkg = if ($env:WAYLAND_DISPLAY) { 'grim' } else { 'scrot' }

    Write-WarnMsg "A graphical desktop was detected but no screenshot tool is installed."
    $ans = Read-Host "  Install '$pkg' now with sudo $pm to enable screenshots? (y/N)"
    if ($ans -notmatch '^[Yy]') { return }

    try {
        if ($pm -eq 'apt-get') { & sudo apt-get update | Out-Null }
        switch ($pm) {
            'apt-get' { & sudo apt-get install -y $pkg }
            'dnf'     { & sudo dnf install -y $pkg }
            'yum'     { & sudo yum install -y $pkg }
            'zypper'  { & sudo zypper --non-interactive install $pkg }
            'pacman'  { & sudo pacman -S --noconfirm $pkg }
        }
        $tool = Get-LinuxScreenshotTool
        if ($tool) {
            $script:ScreenshotMode = 'linux'
            $script:ScreenshotTool = $tool
            Write-Ok "Screenshots enabled using '$tool'."
        } else {
            Write-WarnMsg 'Install completed but no tool was detected. Continuing without screenshots.'
        }
    } catch {
        Write-WarnMsg "Install failed: $_. Continuing without screenshots."
    }
}

# The Windows capture lives in its own function so the System.Drawing /
# System.Windows.Forms type literals are only JIT-compiled when actually called
# on Windows. Referencing them on a headless host (for example Azure Cloud Shell)
# would otherwise throw a type-initializer error even on an unreached branch.
function Save-ScreenshotWindows {
    param([string]$Path)
    $bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $gfx.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $gfx.Dispose(); $bmp.Dispose()
}

function Save-ScreenshotLinux {
    param([string]$Path)
    switch ($script:ScreenshotTool) {
        'grim'             { & grim $Path }
        'scrot'            { & scrot -o $Path }
        'gnome-screenshot' { & gnome-screenshot -f $Path }
        'import'           { & import -window root $Path }
        'spectacle'        { & spectacle -b -n -o $Path }
        default            { return }
    }
    if (-not (Test-Path $Path)) { throw "screenshot tool '$($script:ScreenshotTool)' produced no file" }
}

function Save-Screenshot {
    param([string]$OutputFolder, [int]$StepNumber, [string]$Label)

    if ($script:ScreenshotMode -eq 'none') { return $null }

    $safe = ($Label -replace '[^a-zA-Z0-9_-]', '_')
    $fname = ('step_{0:D2}_{1}_{2}.png' -f $StepNumber, $safe, (Get-Date -Format 'HHmmss'))
    $path = Join-Path $OutputFolder $fname

    try {
        # Let the terminal finish painting the step's output before the screen grab.
        # Windows Terminal renders asynchronously, so too short a wait captures the
        # PREVIOUS step's frame (the screenshot ends up one step behind its filename).
        Start-Sleep -Milliseconds 1000
        if ($script:ScreenshotMode -eq 'windows') {
            Save-ScreenshotWindows -Path $path
        } else {
            Save-ScreenshotLinux -Path $path
        }
        if (-not (Test-Path $path)) { return $null }
        Write-Ok "Screenshot saved: $fname"
        return $path
    } catch {
        Write-WarnMsg "Screenshot failed: $_"
        return $null
    }
}

# ================================================================
# SECTION 5: Audit log
# ================================================================
$script:AuditLog = @()
# Conditional Access setup decision, made by the pre-step before any destructive step:
#   'pending' = pre-step did not run (Step 10 sets things up itself, gracefully)
#   'ready'   = group + policy are in place
#   'skip'    = operator chose to continue without the CA policy
#   'abort'   = operator aborted at the pre-step; run no offboarding steps
$script:CaPolicyDecision = 'pending'
$script:OffboardedGroupId = $null  # resolved by the CA pre-step; reused by Step 10

function Add-AuditEntry {
    param(
        [int]$StepNumber,
        [string]$Action,
        [string]$Result,
        [string]$Screenshot = $null,
        [string]$Details = $null
    )
    $script:AuditLog += [PSCustomObject]@{
        Timestamp  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
        StepNumber = $StepNumber
        Action     = $Action
        Result     = $Result
        Screenshot = $Screenshot
        Details    = $Details
    }
}

function Write-AuditMarkdown {
    param([string]$OutputFolder, [string]$TargetUpn, [string]$Operator, [hashtable]$FinalState, [string]$SharePointUrl, [bool]$DryRun)

    $startTime = $script:AuditLog | Select-Object -First 1 -ExpandProperty Timestamp
    $endTime   = $script:AuditLog | Select-Object -Last 1 -ExpandProperty Timestamp

    $sb = [System.Text.StringBuilder]::new()
    if ($DryRun) {
        [void]$sb.AppendLine('# Microsoft 365 Offboarding Audit Packet (DRY RUN / TRAINING)')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('> **This is a training dry run. No sign-in occurred and no changes were made.** It shows what a real offboarding would do.')
    } else {
        [void]$sb.AppendLine('# Microsoft 365 Offboarding Audit Packet')
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Identification')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Field | Value |')
    [void]$sb.AppendLine('|---|---|')
    [void]$sb.AppendLine("| Target user (UPN) | $TargetUpn |")
    [void]$sb.AppendLine("| Offboarding date | $(Get-Date -Format 'yyyy-MM-dd') |")
    [void]$sb.AppendLine("| Started (UTC) | $startTime |")
    [void]$sb.AppendLine("| Completed (UTC) | $endTime |")
    [void]$sb.AppendLine("| Performed by | $Operator |")
    if ($SharePointUrl) { [void]$sb.AppendLine("| Stored in SharePoint | $SharePointUrl |") }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('## Timeline')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('All timestamps are UTC.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Time (UTC) | Step | Action | Result | Screenshot |')
    [void]$sb.AppendLine('|---|---|---|---|---|')
    foreach ($e in $script:AuditLog) {
        $shot = if ($e.Screenshot) { "[$(Split-Path $e.Screenshot -Leaf)]($(Split-Path $e.Screenshot -Leaf))" } else { '_n/a_' }
        $actionEscaped = ($e.Action -replace '\|', '\|')
        $resultEscaped = ($e.Result -replace '\|', '\|')
        [void]$sb.AppendLine("| $($e.Timestamp) | $($e.StepNumber) | $actionEscaped | $resultEscaped | $shot |")
    }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('## Detailed notes')
    [void]$sb.AppendLine('')
    foreach ($e in ($script:AuditLog | Where-Object { $_.Details })) {
        [void]$sb.AppendLine("### Step $($e.StepNumber) at $($e.Timestamp)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("$($e.Details)")
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('## Final state confirmation')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Attribute | Value |')
    [void]$sb.AppendLine('|---|---|')
    foreach ($k in $FinalState.Keys) {
        [void]$sb.AppendLine("| $k | $($FinalState[$k]) |")
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('_Generated by the Microsoft 365 Offboarding tool. Actions were executed against the Microsoft Graph and Exchange Online APIs._')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('_Developed by [Yusha](https://yusha.ca)._')

    $auditPath = Join-Path $OutputFolder 'AUDIT.md'
    [System.IO.File]::WriteAllText($auditPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
    return $auditPath
}

function Write-AuditJson {
    param([string]$Path, [string]$TargetUpn, [string]$Operator, [hashtable]$FinalState, [string]$SharePointUrl, [bool]$DryRun)

    $obj = [ordered]@{
        tool            = 'Invoke-M365Offboarding'
        schemaVersion   = '1.0'
        developer       = 'Yusha'
        developerUrl    = 'https://yusha.ca'
        dryRun          = $DryRun
        targetUpn       = $TargetUpn
        performedBy     = $Operator
        offboardingDate = (Get-Date -Format 'yyyy-MM-dd')
        startedUtc      = ($script:AuditLog | Select-Object -First 1 -ExpandProperty Timestamp)
        completedUtc    = ($script:AuditLog | Select-Object -Last 1 -ExpandProperty Timestamp)
        steps           = @($script:AuditLog | ForEach-Object {
            [ordered]@{
                step       = $_.StepNumber
                timestampUtc = $_.Timestamp
                action     = $_.Action
                result     = $_.Result
                screenshot = if ($_.Screenshot) { Split-Path $_.Screenshot -Leaf } else { $null }
                details    = $_.Details
            }
        })
        finalState      = $FinalState
        sharePointUrl   = $SharePointUrl
        success         = (-not ($script:AuditLog | Where-Object { $_.Result -like 'FAILED*' }))
    }
    $json = $obj | ConvertTo-Json -Depth 12
    # Write without a BOM so strict JSON parsers (PHP json_decode, Python json,
    # etc.) accept the file. The BOM is invisible to PowerShell's ConvertFrom-Json.
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
    return $Path
}

function ConvertTo-HtmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}

function Get-ResultBadgeClass {
    param([string]$Result)
    if ($Result -like 'FAILED*')         { return 'b-fail' }
    if ($Result -like 'Dry run*')         { return 'b-dry' }
    if ($Result -like 'Skipped*')         { return 'b-skip' }
    if ($Result -like 'Aborted*')         { return 'b-warn' }
    if ($Result -like 'Completed with*')  { return 'b-warn' }
    return 'b-ok'
}

function Write-AuditHtml {
    # Writes a self-contained, offline-viewable audit.html (inline CSS, no external
    # resources). Screenshots are referenced by relative filename, so open the
    # file from inside the audit folder.
    param([string]$OutputFolder, [string]$TargetUpn, [string]$Operator, [hashtable]$FinalState, [string]$SharePointUrl, [bool]$DryRun)

    $startTime = $script:AuditLog | Select-Object -First 1 -ExpandProperty Timestamp
    $endTime   = $script:AuditLog | Select-Object -Last 1 -ExpandProperty Timestamp
    $date      = Get-Date -Format 'yyyy-MM-dd'
    $title     = if ($DryRun) { 'Offboarding Audit (Dry Run)' } else { 'Microsoft 365 Offboarding Audit' }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine("<title>$(ConvertTo-HtmlText $title) - $(ConvertTo-HtmlText $TargetUpn)</title>")
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine(@'
:root{--brand:#0b5e3b;--brand2:#13935c;--ink:#1f2933;--muted:#6b7785;--line:#e6e9ee;--bg:#f5f7fa;--card:#fff;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.55}
.wrap{max-width:980px;margin:0 auto;padding:24px}
header.hero{background:linear-gradient(135deg,var(--brand),var(--brand2));color:#fff;border-radius:16px;padding:28px 30px;box-shadow:0 10px 30px rgba(11,94,59,.25)}
header.hero h1{margin:0 0 6px;font-size:26px;letter-spacing:.2px}
header.hero .sub{opacity:.92;font-size:15px}
.dry{margin-top:16px;background:#fff3cd;color:#7a5b00;border:1px solid #ffe08a;border-left:6px solid #e0a800;border-radius:10px;padding:12px 16px;font-weight:600}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px 22px;margin:18px 0;box-shadow:0 1px 3px rgba(16,24,40,.04)}
.card h2{margin:0 0 14px;font-size:18px;color:var(--brand)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
tr:last-child td{border-bottom:none}
.kv td:first-child{color:var(--muted);width:230px;font-weight:600}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700;white-space:normal;overflow-wrap:anywhere;max-width:100%;vertical-align:top}
.b-ok{background:#e7f7ee;color:#127a40}.b-dry{background:#e9f0ff;color:#1b50b5}.b-skip{background:#eef1f4;color:#5a6672}
.b-warn{background:#fff4e5;color:#9a5b00}.b-fail{background:#fdecea;color:#b42318;white-space:pre-wrap;border-radius:8px;text-align:left}
.notes{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;white-space:pre-wrap;background:#fafbfc;border:1px solid var(--line);border-radius:8px;padding:10px 12px;color:#36414c}
.shots{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px}
.shots figure{margin:0;border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#fff}
.shots img{display:block;width:100%;height:150px;object-fit:cover;background:#f0f2f5}
.shots figcaption{padding:8px 10px;font-size:12px;color:var(--muted);border-top:1px solid var(--line);word-break:break-all}
footer{color:var(--muted);font-size:12.5px;text-align:center;margin:26px 0 10px}
a{color:var(--brand2)}
'@)
    [void]$sb.AppendLine('</style></head><body><div class="wrap">')

    [void]$sb.AppendLine('<header class="hero">')
    [void]$sb.AppendLine("<h1>$(ConvertTo-HtmlText $title)</h1>")
    [void]$sb.AppendLine("<div class=`"sub`">$(ConvertTo-HtmlText $TargetUpn) &bull; $date</div>")
    if ($DryRun) { [void]$sb.AppendLine('<div class="dry">DRY RUN / TRAINING - no sign-in occurred and no changes were made.</div>') }
    [void]$sb.AppendLine('</header>')

    # Identification
    [void]$sb.AppendLine('<div class="card"><h2>Identification</h2><table class="kv">')
    [void]$sb.AppendLine("<tr><td>Target user (UPN)</td><td>$(ConvertTo-HtmlText $TargetUpn)</td></tr>")
    [void]$sb.AppendLine("<tr><td>Offboarding date</td><td>$date</td></tr>")
    [void]$sb.AppendLine("<tr><td>Started (UTC)</td><td>$(ConvertTo-HtmlText $startTime)</td></tr>")
    [void]$sb.AppendLine("<tr><td>Completed (UTC)</td><td>$(ConvertTo-HtmlText $endTime)</td></tr>")
    [void]$sb.AppendLine("<tr><td>Performed by</td><td>$(ConvertTo-HtmlText $Operator)</td></tr>")
    if ($SharePointUrl) { [void]$sb.AppendLine("<tr><td>Stored in SharePoint</td><td><a href=`"$(ConvertTo-HtmlText $SharePointUrl)`">$(ConvertTo-HtmlText $SharePointUrl)</a></td></tr>") }
    [void]$sb.AppendLine('</table></div>')

    # Timeline
    [void]$sb.AppendLine('<div class="card"><h2>Timeline</h2><table><thead><tr><th>Time (UTC)</th><th>Step</th><th>Action</th><th>Result</th></tr></thead><tbody>')
    foreach ($e in $script:AuditLog) {
        $cls = Get-ResultBadgeClass $e.Result
        [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlText $e.Timestamp)</td><td>$($e.StepNumber)</td><td>$(ConvertTo-HtmlText $e.Action)</td><td><span class=`"badge $cls`">$(ConvertTo-HtmlText $e.Result)</span></td></tr>")
    }
    [void]$sb.AppendLine('</tbody></table></div>')

    # Screenshots (relative references; open from inside the folder)
    $shots = @($script:AuditLog | Where-Object { $_.Screenshot } | ForEach-Object { Split-Path $_.Screenshot -Leaf })
    if ($shots.Count) {
        [void]$sb.AppendLine('<div class="card"><h2>Screenshots</h2><div class="shots">')
        foreach ($s in $shots) {
            $enc = ConvertTo-HtmlText $s
            [void]$sb.AppendLine("<figure><a href=`"$enc`"><img src=`"$enc`" alt=`"$enc`"></a><figcaption>$enc</figcaption></figure>")
        }
        [void]$sb.AppendLine('</div></div>')
    }

    # Detailed notes
    [void]$sb.AppendLine('<div class="card"><h2>Detailed notes</h2>')
    foreach ($e in ($script:AuditLog | Where-Object { $_.Details })) {
        [void]$sb.AppendLine("<p style=`"margin:0 0 4px;font-weight:600`">Step $($e.StepNumber) &bull; $(ConvertTo-HtmlText $e.Timestamp)</p>")
        [void]$sb.AppendLine("<div class=`"notes`">$(ConvertTo-HtmlText $e.Details)</div>")
    }
    [void]$sb.AppendLine('</div>')

    # Final state
    [void]$sb.AppendLine('<div class="card"><h2>Final state confirmation</h2><table class="kv">')
    foreach ($k in $FinalState.Keys) {
        [void]$sb.AppendLine("<tr><td>$(ConvertTo-HtmlText $k)</td><td>$(ConvertTo-HtmlText "$($FinalState[$k])")</td></tr>")
    }
    [void]$sb.AppendLine('</table></div>')

    [void]$sb.AppendLine('<footer>Generated by the Microsoft 365 Offboarding tool. Actions were executed against the Microsoft Graph and Exchange Online APIs.<br>Developed by <a href="https://yusha.ca">Yusha</a>.</footer>')
    [void]$sb.AppendLine('</div></body></html>')

    $htmlPath = Join-Path $OutputFolder 'audit.html'
    [System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    return $htmlPath
}

# ================================================================
# SECTION 6: The ten steps
# ================================================================

# ---------- Step 1: Reset password and revoke sessions ----------
function Invoke-Step1 {
    param([string]$Upn, [string]$Folder)
    Write-StepHeader 1 'Reset password and revoke all sign-in sessions'

    $user = Get-MgUser -UserId $Upn -Property Id, DisplayName, UserPrincipalName, AccountEnabled
    Write-Info "Target: $($user.DisplayName) ($($user.UserPrincipalName))"

    if ($PSCmdlet.ShouldProcess($Upn, 'Reset password and revoke sessions')) {
        $bytes = New-Object 'byte[]' 18
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        # Append a fixed complexity suffix so the value always satisfies Entra
        # password policy (upper, lower, digit, symbol) regardless of the random bytes.
        $newPwd = [Convert]::ToBase64String($bytes) + '!Aa9'
        $body = @{ passwordProfile = @{ forceChangePasswordNextSignIn = $true; password = $newPwd } }

        Write-Action 'Resetting password to a random value (not stored)...'
        Update-MgUser -UserId $user.Id -BodyParameter $body
        Write-Ok 'Password reset'

        Write-Action 'Revoking all active sign-in sessions...'
        Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
        Write-Ok 'All sessions revoked'
    }

    $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 1 -Label 'password_reset_and_sessions_revoked'
    Add-AuditEntry -StepNumber 1 -Action 'Reset password and revoked all sign-in sessions' -Result 'Success' -Screenshot $shot `
        -Details 'Password set to a random value (not retained). Revoke-MgUserSignInSession invalidates issued refresh tokens.'
}

# ---------- Step 2: Block sign-in ----------
function Invoke-Step2 {
    param([string]$Upn, [string]$Folder)
    Write-StepHeader 2 'Block sign-in (disable the account)'

    if ($PSCmdlet.ShouldProcess($Upn, 'Set AccountEnabled = false')) {
        Update-MgUser -UserId $Upn -AccountEnabled:$false
        $confirmed = Wait-ForCondition -Check { -not (Get-MgUser -UserId $Upn -Property AccountEnabled).AccountEnabled }
        if (-not $confirmed) { throw 'Failed to disable account. AccountEnabled is still true after 60s.' }
        Write-Ok 'Account is now disabled (AccountEnabled = false)'
    }

    $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 2 -Label 'account_disabled'
    Add-AuditEntry -StepNumber 2 -Action 'Set AccountEnabled to false' -Result 'Success' -Screenshot $shot `
        -Details 'Confirmed via Get-MgUser: AccountEnabled = false.'
}

# ---------- Step 3: Remove mobile device partnerships ----------
function Invoke-Step3 {
    param([string]$Upn, [string]$Folder)
    Write-StepHeader 3 'Remove ActiveSync mobile device partnerships'
    Write-Info 'A cached mobile mail client keeps a device partnership that tries to'
    Write-Info 'refresh tokens after offboarding. Removing it stops repeated failed'
    Write-Info 'sign-in attempts (and the sign-in prompts they trigger on the device).'

    $devices = Get-MobileDevice -Mailbox $Upn -ErrorAction SilentlyContinue
    if ($devices) {
        $count = ($devices | Measure-Object).Count
        Write-Info "Found $count partnership(s)."
        $removed = @()
        foreach ($d in $devices) {
            if ($PSCmdlet.ShouldProcess($d.FriendlyName, 'Remove mobile device partnership')) {
                Remove-MobileDevice -Identity $d.Identity -Confirm:$false
                Write-Ok "Removed: $($d.DeviceModel)"
            }
            $removed += "  - $($d.DeviceModel) [$($d.DeviceID)]"
        }
        $details = "Removed $count ActiveSync partnership(s):`n" + ($removed -join "`n")
    } else {
        Write-Info 'No ActiveSync partnerships found.'
        $details = 'No ActiveSync partnerships were registered for this mailbox.'
    }

    $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 3 -Label 'mobile_devices_removed'
    Add-AuditEntry -StepNumber 3 -Action 'Removed ActiveSync mobile device partnerships' -Result 'Success' -Screenshot $shot -Details $details
}

# ---------- Step 4: Remove authentication (MFA) methods ----------
function Invoke-Step4 {
    param([string]$Upn, [string]$Folder)
    Write-StepHeader 4 'Remove registered authentication (MFA) methods'

    $user = Get-MgUser -UserId $Upn -Property Id
    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -All -ErrorAction SilentlyContinue

    # The password method cannot be removed and is skipped.
    $removable = @($methods | Where-Object {
        $_.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod'
    })

    Write-Info "Found $($removable.Count) removable authentication method(s)."
    $details = "Removable methods: $($removable.Count)`n"
    $failures = 0

    foreach ($m in $removable) {
        $type = $m.AdditionalProperties.'@odata.type'
        $id = $m.Id
        if (-not $PSCmdlet.ShouldProcess("$type ($id)", 'Remove authentication method')) { continue }
        try {
            switch ($type) {
                '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' { Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $user.Id -MicrosoftAuthenticatorAuthenticationMethodId $id }
                '#microsoft.graph.phoneAuthenticationMethod'                  { Remove-MgUserAuthenticationPhoneMethod -UserId $user.Id -PhoneAuthenticationMethodId $id }
                '#microsoft.graph.fido2AuthenticationMethod'                  { Remove-MgUserAuthenticationFido2Method -UserId $user.Id -Fido2AuthenticationMethodId $id }
                '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'{ Remove-MgUserAuthenticationWindowsHelloForBusinessMethod -UserId $user.Id -WindowsHelloForBusinessAuthenticationMethodId $id }
                '#microsoft.graph.emailAuthenticationMethod'                  { Remove-MgUserAuthenticationEmailMethod -UserId $user.Id -EmailAuthenticationMethodId $id }
                '#microsoft.graph.softwareOathAuthenticationMethod'           { Remove-MgUserAuthenticationSoftwareOathMethod -UserId $user.Id -SoftwareOathAuthenticationMethodId $id }
                '#microsoft.graph.temporaryAccessPassAuthenticationMethod'    { Remove-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.Id -TemporaryAccessPassAuthenticationMethodId $id }
                default {
                    Write-WarnMsg "No remover for method type $type. Remove it manually in the Entra admin center."
                    $details += "  Skipped (no API remover): $type ($id)`n"
                    continue
                }
            }
            Write-Ok "Removed method: $type"
            $details += "  Removed: $type ($id)`n"
        } catch {
            $failures++
            Write-WarnMsg "Could not remove $type ($id): $_"
            $details += "  Failed: $type ($id) - $_`n"
        }
    }

    if ($removable.Count -eq 0) { $details = 'No removable authentication methods were registered.' }

    $result = if ($failures -gt 0) { "Completed with $failures failure(s)" } else { 'Success' }
    $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 4 -Label 'mfa_methods_removed'
    Add-AuditEntry -StepNumber 4 -Action 'Removed registered authentication (MFA) methods' -Result $result -Screenshot $shot -Details $details
}

# ---------- Step 5: Revoke OAuth grants ----------
function Invoke-Step5 {
    param([string]$Upn, [string]$Folder)
    Write-StepHeader 5 'Revoke OAuth app grants'

    $user = Get-MgUser -UserId $Upn -Property Id
    $grants = Get-MgUserOauth2PermissionGrant -UserId $user.Id -All -ErrorAction SilentlyContinue
    $grantCount = ($grants | Measure-Object).Count
    Write-Info "Found $grantCount delegated OAuth2 grant(s)."

    $details = "OAuth2 grants found: $grantCount`n"
    foreach ($g in $grants) { $details += "  - GrantId=$($g.Id), ClientId=$($g.ClientId), Scope=$($g.Scope)`n" }

    $failures = 0
    foreach ($g in $grants) {
        if (-not $PSCmdlet.ShouldProcess($g.Id, 'Revoke OAuth2 grant')) { continue }
        try {
            Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $g.Id -ErrorAction Stop
            Write-Ok "Revoked grant $($g.Id)"
            $details += "Revoked grant $($g.Id).`n"
        } catch {
            $failures++
            Write-WarnMsg "Could not revoke $($g.Id): $_"
            $details += "Failed to revoke grant $($g.Id): $_`n"
        }
    }

    $result = if ($failures -gt 0) { "Completed with $failures failure(s)" } else { 'Success' }
    $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 5 -Label 'oauth_grants_revoked'
    Add-AuditEntry -StepNumber 5 -Action "Revoked $grantCount OAuth2 grant(s)" -Result $result -Screenshot $shot -Details $details
}

# ---------- Step 6: Remove from groups ----------
function Invoke-Step6 {
    param([string]$Upn, [string]$Folder)
    Write-StepHeader 6 'Remove user from groups and distribution lists'

    $user = Get-MgUser -UserId $Upn -Property Id
    $groups = Get-MgUserMemberOf -UserId $user.Id -All

    $editableGroups = @()
    foreach ($g in $groups) {
        if ($g.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group') {
            $grp = Get-MgGroup -GroupId $g.Id -Property Id, DisplayName, Mail, MailEnabled, GroupTypes, OnPremisesSyncEnabled -ErrorAction SilentlyContinue
            if ($grp -and ($grp.Id -eq $script:OffboardedGroupId -or $grp.DisplayName -eq $OffboardedGroupName)) {
                # Never remove the user from our own Conditional Access block group (Step 10).
                Write-Info "Keeping membership in '$($grp.DisplayName)' (the offboarded-users CA block group)."
            } elseif ($grp -and -not $grp.OnPremisesSyncEnabled) {
                $editableGroups += $grp
            } elseif ($grp -and $grp.OnPremisesSyncEnabled) {
                Write-WarnMsg "Skipping on-prem-synced group '$($grp.DisplayName)' (remove in on-prem AD)."
            }
        }
    }

    Write-Info "Found $($editableGroups.Count) cloud-managed group(s)."
    $details = "Group memberships: $($groups.Count) total, $($editableGroups.Count) cloud-managed.`n"

    $removed = 0; $skipped = 0; $failures = 0
    foreach ($g in $editableGroups) {
        if (-not $PSCmdlet.ShouldProcess($g.DisplayName, 'Remove group membership')) { continue }

        # Dynamic-membership groups are populated by a rule; members cannot be
        # removed manually. Skip them with a note (not removed, not a failure).
        if ($g.GroupTypes -contains 'DynamicMembership') {
            Write-WarnMsg "Skipping '$($g.DisplayName)': dynamic membership (managed by rule, cannot remove directly)."
            $details += "  Skipped: $($g.DisplayName) ($($g.Id)) - dynamic membership group`n"
            $skipped++
            continue
        }

        # Distribution lists and mail-enabled security groups cannot be modified
        # through Microsoft Graph (Remove-MgGroupMemberByRef returns "Cannot Update
        # a mail-enabled security groups and or distribution list"); they must be
        # managed through Exchange Online. Microsoft 365 (Unified) groups stay on Graph.
        $isExchangeManaged = $g.MailEnabled -and ($g.GroupTypes -notcontains 'Unified')

        try {
            if ($isExchangeManaged) {
                # Prefer the primary SMTP; fall back to the object Id (unambiguous),
                # never the non-unique display name.
                $ident = if ($g.Mail) { $g.Mail } else { $g.Id }
                Remove-DistributionGroupMember -Identity $ident -Member $Upn -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop
                Write-Ok "Removed from: $($g.DisplayName) (via Exchange)"
                $details += "  Removed from: $($g.DisplayName) ($($g.Id)) [Exchange distribution / mail-enabled]`n"
            } else {
                Remove-MgGroupMemberByRef -GroupId $g.Id -DirectoryObjectId $user.Id -ErrorAction Stop
                Write-Ok "Removed from: $($g.DisplayName)"
                $details += "  Removed from: $($g.DisplayName) ($($g.Id))`n"
            }
            $removed++
        } catch {
            # "Already not a member" is the desired end state, not a failure (matters
            # when Step 6 is re-run after a partial run).
            if ("$_" -match "isn't a member|not a member|does not exist|Request_ResourceNotFound|ManagementObjectNotFound|couldn't be found") {
                Write-Info "Already not a member of '$($g.DisplayName)'."
                $details += "  Already removed: $($g.DisplayName) ($($g.Id))`n"
                $removed++
            } else {
                $failures++
                Write-WarnMsg "Could not remove from '$($g.DisplayName)': $_"
                $details += "  Failed: $($g.DisplayName) - $_`n"
            }
        }
    }

    $resultParts = @()
    if ($failures -gt 0) { $resultParts += "$failures failure(s)" }
    if ($skipped -gt 0)  { $resultParts += "$skipped skipped" }
    $result = if ($resultParts.Count) { "Completed with $($resultParts -join ', ')" } else { 'Success' }
    $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 6 -Label 'groups_removed'
    Add-AuditEntry -StepNumber 6 -Action "Removed user from $removed of $($editableGroups.Count) cloud-managed group(s)" -Result $result -Screenshot $shot -Details $details
}

# ---------- Step 7: Forwarding / delegation (optional) ----------
function Invoke-Step7 {
    param([string]$Upn, [string]$Folder)
    Write-StepHeader 7 'Configure forwarding and delegation (optional)'

    # Forwarding and delegation act on the mailbox; a user with no Exchange Online
    # mailbox (unlicensed / service account) has nothing to configure here.
    if (-not (Get-Mailbox -Identity $Upn -ErrorAction SilentlyContinue)) {
        Write-WarnMsg 'No Exchange Online mailbox for this user. Skipping forwarding/delegation.'
        $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 7 -Label 'forwarding_delegation'
        Add-AuditEntry -StepNumber 7 -Action 'Configure forwarding / delegation' -Result 'Skipped' -Screenshot $shot -Details 'No Exchange Online mailbox found; forwarding/delegation not applicable.'
        return
    }

    $fwdTarget = $ForwardingAddress
    $delTarget = $DelegateTo

    if (-not $Unattended) {
        if (-not $fwdTarget) {
            $forward = Read-Host '  Configure email forwarding? (y/N)'
            if ($forward -match '^[Yy]') { $fwdTarget = Read-Host '  Forward to which address' }
        }
        if (-not $delTarget) {
            $delegate = Read-Host '  Configure mailbox delegation (Full Access + Send As)? (y/N)'
            if ($delegate -match '^[Yy]') { $delTarget = Read-Host '  Delegate to which user' }
        }
    }

    $details = ''
    if ($fwdTarget) {
        if ($PSCmdlet.ShouldProcess($Upn, "Forward to $fwdTarget")) {
            Set-Mailbox -Identity $Upn -ForwardingSmtpAddress $fwdTarget -DeliverToMailboxAndForward $ForwardKeepCopy
            Write-Ok "Forwarding enabled to $fwdTarget"
        }
        $details += "Forwarding configured: $Upn forwards to $fwdTarget (keep copy: $ForwardKeepCopy).`n"
    }
    if ($delTarget) {
        if ($PSCmdlet.ShouldProcess($Upn, "Delegate Full Access and Send As to $delTarget")) {
            Add-MailboxPermission -Identity $Upn -User $delTarget -AccessRights FullAccess -InheritanceType All -AutoMapping $true | Out-Null
            Add-RecipientPermission -Identity $Upn -Trustee $delTarget -AccessRights SendAs -Confirm:$false | Out-Null
            Write-Ok "Delegation granted to $delTarget"
        }
        $details += "Delegation: $delTarget granted FullAccess and SendAs on $Upn.`n"
    }
    if (-not $fwdTarget -and -not $delTarget) {
        Write-Info 'No forwarding or delegation requested.'
        $details = 'No forwarding or delegation requested for this user.'
    }

    $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 7 -Label 'forwarding_delegation'
    Add-AuditEntry -StepNumber 7 -Action 'Configured forwarding / delegation as requested' -Result 'Success' -Screenshot $shot -Details $details
}

# ---------- Step 8: Convert to shared mailbox ----------
function Invoke-Step8 {
    param([string]$Upn, [string]$Folder)
    Write-StepHeader 8 'Convert user mailbox to a shared mailbox'

    if ($SkipMailboxConversion) {
        Write-WarnMsg 'Skipping mailbox conversion (-SkipMailboxConversion was set).'
        Add-AuditEntry -StepNumber 8 -Action 'Convert mailbox to shared' -Result 'Skipped' -Details 'Skipped by request (-SkipMailboxConversion).'
        return
    }

    $mbx = Get-Mailbox -Identity $Upn -ErrorAction SilentlyContinue
    if (-not $mbx) {
        Write-WarnMsg 'No Exchange Online mailbox for this user. Skipping conversion to shared.'
        $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 8 -Label 'mailbox_converted_to_shared'
        Add-AuditEntry -StepNumber 8 -Action 'Convert mailbox to shared' -Result 'Skipped' -Screenshot $shot -Details 'No Exchange Online mailbox found; nothing to convert.'
        return
    }
    if ($mbx.RecipientTypeDetails -eq 'SharedMailbox') {
        Write-Info 'Mailbox is already a shared mailbox. Nothing to convert.'
        $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 8 -Label 'mailbox_converted_to_shared'
        Add-AuditEntry -StepNumber 8 -Action 'Convert mailbox to shared' -Result 'Skipped' -Screenshot $shot -Details 'Mailbox was already a SharedMailbox.'
        return
    }

    Write-Info 'The license must still be assigned for this to work (Microsoft hides'
    Write-Info 'the convert option once the license is removed). License removal is the'
    Write-Info 'next step, not this one.'

    if ($PSCmdlet.ShouldProcess($Upn, 'Convert to shared mailbox')) {
        Set-Mailbox -Identity $Upn -Type Shared
        # Exchange applies the conversion asynchronously and it can take a minute or
        # more to surface, so poll rather than reading once after a fixed 3s wait.
        Write-Action 'Waiting for Exchange to confirm the conversion (up to 2 minutes)...'
        $confirmed = Wait-ForCondition -TimeoutSeconds 120 -IntervalSeconds 5 -Check { (Get-Mailbox -Identity $Upn).RecipientTypeDetails -eq 'SharedMailbox' }
        if (-not $confirmed) {
            $current = (Get-Mailbox -Identity $Upn -ErrorAction SilentlyContinue).RecipientTypeDetails
            throw ("Conversion not confirmed within 120s. RecipientTypeDetails is still '$current'." + $(if ($script:WaitLastError) { " Last check error: $($script:WaitLastError)" }))
        }
        Write-Ok 'Conversion confirmed. RecipientTypeDetails = SharedMailbox'
    }

    $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 8 -Label 'mailbox_converted_to_shared'
    Add-AuditEntry -StepNumber 8 -Action 'Converted user mailbox to shared mailbox' -Result 'Success' -Screenshot $shot `
        -Details 'Set-Mailbox -Type Shared executed. Verified RecipientTypeDetails = SharedMailbox.'
}

# ---------- Step 9: Remove licenses ----------
function Invoke-Step9 {
    param([string]$Upn, [string]$Folder)
    Write-StepHeader 9 'Remove Microsoft 365 licenses'
    Write-Info 'Safe now: the mailbox is already shared and will not lose data. The'
    Write-Info 'account is not deleted, only unlicensed, so it can anchor the shared'
    Write-Info 'mailbox (Microsoft requires the account to remain).'

    $user = Get-MgUser -UserId $Upn -Property Id, AssignedLicenses
    if (-not $user.AssignedLicenses -or $user.AssignedLicenses.Count -eq 0) {
        Write-Info 'No licenses assigned. Nothing to remove.'
        $details = 'User had no assigned licenses.'
    } else {
        $skuIds = $user.AssignedLicenses | ForEach-Object { $_.SkuId }
        Write-Info "Removing $($skuIds.Count) license SKU(s)."
        if ($PSCmdlet.ShouldProcess($Upn, "Remove $($skuIds.Count) license(s)")) {
            Set-MgUserLicense -UserId $user.Id -AddLicenses @() -RemoveLicenses $skuIds | Out-Null
            # Set-MgUserLicense removes only directly-assigned licenses; group-based
            # (inherited) licenses cannot be removed at the user level, so verify that
            # no DIRECTLY-assigned licenses remain rather than requiring a zero total.
            $confirmed = Wait-ForCondition -Check {
                @((Get-MgUser -UserId $Upn -Property LicenseAssignmentStates).LicenseAssignmentStates | Where-Object { -not $_.AssignedByGroup }).Count -eq 0
            }
            if (-not $confirmed) {
                $directLeft = @((Get-MgUser -UserId $Upn -Property LicenseAssignmentStates).LicenseAssignmentStates | Where-Object { -not $_.AssignedByGroup }).Count
                throw ("License removal incomplete. $directLeft directly-assigned license(s) still present after 60s." + $(if ($script:WaitLastError) { " Last check error: $($script:WaitLastError)" }))
            }
            Write-Ok 'All directly-assigned licenses removed and verified.'
        }
        $details = "Removed $($skuIds.Count) license SKUs: $($skuIds -join ', ')."
    }

    $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 9 -Label 'license_removed'
    Add-AuditEntry -StepNumber 9 -Action 'Removed all Microsoft 365 licenses' -Result 'Success' -Screenshot $shot -Details $details
}

# ---------- Step 10: Conditional Access block ----------
function Invoke-Step10 {
    param([string]$Upn, [string]$Folder)
    Write-StepHeader 10 'Apply a Conditional Access block on the user principal'
    Write-Info 'Defense in depth: even if the account is mistakenly re-enabled,'
    Write-Info 'Conditional Access rejects every sign-in for members of the group.'

    if ($script:CaPolicyDecision -eq 'pending') {
        Write-WarnMsg 'CA pre-step did not run; setting up the group/policy here (after the other steps).'
    }

    # Reuse the exact group the pre-step resolved/created (avoids creating a duplicate
    # same-named group via a separate display-name lookup). Fall back to a lookup only
    # if the pre-step did not run.
    $group = $null
    if ($script:OffboardedGroupId) {
        $group = Get-MgGroup -GroupId $script:OffboardedGroupId -ErrorAction SilentlyContinue
    }
    if (-not $group) {
        # Escape single quotes for the OData filter (a name like O'Brien would break it).
        $groupNameFilter = $OffboardedGroupName -replace "'", "''"
        Write-Action "Looking for security group '$OffboardedGroupName'..."
        $group = Get-MgGroup -Filter "displayName eq '$groupNameFilter'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $group) {
            Write-WarnMsg "Group not found. Creating '$OffboardedGroupName'..."
            $nickname = ($OffboardedGroupName -replace '[^a-zA-Z0-9]', '').ToLower()
            if ([string]::IsNullOrWhiteSpace($nickname)) { $nickname = 'offboardedusers' }
            $group = New-MgGroup -DisplayName $OffboardedGroupName `
                -Description 'Offboarded users. Targeted by the sign-in block Conditional Access policy.' `
                -MailEnabled:$false -MailNickname $nickname -SecurityEnabled:$true
            Start-Sleep -Seconds 3
        }
    }
    Write-Ok "Group '$OffboardedGroupName' (Id: $($group.Id))"

    $user = Get-MgUser -UserId $Upn -Property Id
    Write-Action "Adding $Upn to '$OffboardedGroupName'..."
    try {
        New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id -ErrorAction Stop
        Write-Ok 'User added to group'
    } catch {
        if ($_.Exception.Message -match 'already exist') { Write-Info 'User was already a member.' }
        else { throw }
    }

    # The Conditional Access policy (group target above) was set up -- or consciously
    # skipped -- by the Confirm-CaInfrastructure pre-step BEFORE any destructive step,
    # so by the time we get here the decision is already made. Honor it: 'skip' -> note
    # it; otherwise find the policy the pre-step created (or, if the pre-step did not run,
    # create it best-effort). The group membership above is the durable action.
    $policyOk = $true
    $policyNote = ''
    if ($script:CaPolicyDecision -eq 'skip') {
        $policyOk = $false
        Write-WarnMsg 'No Conditional Access policy (chosen at the pre-step). User is in the group.'
        $policyNote = "Conditional Access policy was not created by the tool (operator continued without it, or created it manually). The user is in '$OffboardedGroupName'; ensure a block policy targets that group to enforce the sign-in block."
    } else {
        try {
            $policyNameFilter = $BlockPolicyName -replace "'", "''"
            Write-Action "Looking for Conditional Access policy '$BlockPolicyName'..."
            $policy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$policyNameFilter'" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $policy) {
                Write-WarnMsg "Policy not found. Creating in REPORT-ONLY mode. An admin must enable it."
                $policyBody = @{
                    displayName   = $BlockPolicyName
                    state         = 'enabledForReportingButNotEnforced'
                    conditions    = @{
                        applications = @{ includeApplications = @('All') }
                        users        = @{ includeGroups = @($group.Id) }
                    }
                    grantControls = @{ operator = 'OR'; builtInControls = @('block') }
                }
                $policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyBody -ErrorAction Stop
                Write-Ok "Created CA policy in report-only mode (Id: $($policy.Id))"
                Write-WarnMsg 'ACTION REQUIRED: enable this policy in the Entra admin center after review.'
            } else {
                Write-Ok "Found CA policy '$BlockPolicyName' (state: $($policy.State))"
            }
            $policyNote = "CA policy '$BlockPolicyName' (Id: $($policy.Id)), state: $($policy.State)."
        } catch {
            $policyOk = $false
            Write-ErrMsg "Conditional Access policy was not created: $_"
            if ("$_" -match 'scopes are missing|AccessDenied|Authorization_RequestDenied|Forbidden|Insufficient privileges') {
                Write-WarnMsg "This needs Policy.ReadWrite.ConditionalAccess. Sign in again and consent on behalf of the organization, then re-run with -Steps 10."
                $policyNote = "CA policy NOT created: the Policy.ReadWrite.ConditionalAccess permission is missing/denied. The user is already in '$OffboardedGroupName'; this report-only policy is defense-in-depth and is NOT required for the lockout. Grant the consent (sign in again and consent for the organization) or create the policy manually targeting the group, then run -Steps 10."
            } else {
                $policyNote = "CA policy NOT created ($_). The user is already in '$OffboardedGroupName'; create or enable the block policy manually."
            }
        }
    }

    $details = "Group '$OffboardedGroupName' (Id: $($group.Id)): user added.`n$policyNote"
    $result = if ($policyOk) { 'Success' } else { 'Completed with warning: CA policy not created' }
    $shot = Save-Screenshot -OutputFolder $Folder -StepNumber 10 -Label 'conditional_access_applied'
    Add-AuditEntry -StepNumber 10 -Action "Added user to '$OffboardedGroupName' (targeted by CA block)" -Result $result -Screenshot $shot -Details $details
}

# ================================================================
# SECTION 7: Final state
# ================================================================
function Get-FinalState {
    param([string]$Upn)
    $state = [ordered]@{}
    try {
        $user = Get-MgUser -UserId $Upn -Property Id, DisplayName, UserPrincipalName, AccountEnabled, AssignedLicenses
        $state['User principal name'] = $user.UserPrincipalName
        $state['Display name']        = $user.DisplayName
        $state['Account enabled']     = $user.AccountEnabled
        $state['Assigned licenses']   = if ($user.AssignedLicenses.Count -eq 0) { 'None' } else { $user.AssignedLicenses.Count }
    } catch { $state['User lookup'] = "Failed: $_" }

    try {
        $mbx = Get-Mailbox -Identity $Upn -ErrorAction SilentlyContinue
        if ($mbx) {
            $state['Recipient type details'] = $mbx.RecipientTypeDetails
            $state['Forwarding address']     = if ($mbx.ForwardingSmtpAddress) { $mbx.ForwardingSmtpAddress } else { 'None' }
        }
    } catch { $state['Mailbox lookup'] = "Failed: $_" }

    try {
        $devices = Get-MobileDevice -Mailbox $Upn -ErrorAction SilentlyContinue
        $state['Mobile device partnerships'] = ($devices | Measure-Object).Count
    } catch { $state['Mobile devices'] = 'Could not enumerate' }

    return $state
}

# ================================================================
# SECTION 7b: SharePoint upload (optional)
# ================================================================
# Uploads the finished audit folder to a SharePoint document library using the
# Microsoft Graph token already established by Connect-MgGraph (no extra module).
# Requires the Sites.ReadWrite.All scope / application permission.

function ConvertTo-DrivePath {
    # URL-encode each path segment for a Graph drive path address.
    param([string]$Path)
    ($Path.Trim('/').Split('/') | Where-Object { $_ } | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'
}

function Resolve-SharePointTarget {
    # Resolves the site and default document library, ensures the destination
    # folder tree exists, and returns the drive id, destination path, and webUrl.
    param([string]$SiteUrl, [string]$FolderPath, [string]$LeafName)

    $uri = [Uri]$SiteUrl
    $siteHost = $uri.Host
    $rel = $uri.AbsolutePath.TrimEnd('/')
    $siteAddr = if ([string]::IsNullOrWhiteSpace($rel) -or $rel -eq '/') { $siteHost } else { "$siteHost`:$rel" }

    Write-Action "Resolving SharePoint site '$SiteUrl'..."
    $site = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$siteAddr" -OutputType PSObject
    if (-not $site.id) { throw "Could not resolve SharePoint site '$SiteUrl'. Check the URL." }

    $drive = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/drive" -OutputType PSObject
    $driveId = $drive.id

    $destFolder = if ([string]::IsNullOrWhiteSpace($FolderPath)) { $LeafName } else { ($FolderPath.Trim('/') + '/' + $LeafName) }

    # Create each folder segment if missing (ignore "already exists").
    $segments = $destFolder.Split('/') | Where-Object { $_ }
    $parent = ''
    foreach ($seg in $segments) {
        $childrenUri = if ($parent) {
            "https://graph.microsoft.com/v1.0/drives/$driveId/root:/$(ConvertTo-DrivePath $parent):/children"
        } else {
            "https://graph.microsoft.com/v1.0/drives/$driveId/root/children"
        }
        $body = @{ name = $seg; folder = @{}; '@microsoft.graph.conflictBehavior' = 'fail' }
        try {
            Invoke-MgGraphRequest -Method POST -Uri $childrenUri -Body ($body | ConvertTo-Json) -ContentType 'application/json' | Out-Null
        } catch {
            $exists = "$_" -match 'nameAlreadyExists|already exists'
            if (-not $exists -and $_.Exception.Response.StatusCode.value__ -ne 409) { throw }
        }
        $parent = if ($parent) { "$parent/$seg" } else { $seg }
    }

    $folderItem = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/root:/$(ConvertTo-DrivePath $destFolder)" -OutputType PSObject
    return @{ DriveId = $driveId; DestFolder = $destFolder; WebUrl = $folderItem.webUrl }
}

function Send-FilesToSharePoint {
    # Simple upload (single PUT, supports files up to 250 MB) for each file.
    # -InputFilePath streams the file as the raw request body.
    param([string]$DriveId, [string]$DestFolder, $Files)
    foreach ($f in $Files) {
        $enc = ConvertTo-DrivePath "$DestFolder/$($f.Name)"
        $uploadUri = "https://graph.microsoft.com/v1.0/drives/$DriveId/root:/$enc`:/content"
        Invoke-MgGraphRequest -Method PUT -Uri $uploadUri -InputFilePath $f.FullName -ContentType 'application/octet-stream' | Out-Null
        Write-Ok "Uploaded $($f.Name)"
    }
}

# ================================================================
# SECTION 8: Orchestration
# ================================================================
function Invoke-StepByNumber {
    param([int]$Number, [string]$Upn, [string]$Folder)
    switch ($Number) {
        1  { Invoke-Step1  -Upn $Upn -Folder $Folder }
        2  { Invoke-Step2  -Upn $Upn -Folder $Folder }
        3  { Invoke-Step3  -Upn $Upn -Folder $Folder }
        4  { Invoke-Step4  -Upn $Upn -Folder $Folder }
        5  { Invoke-Step5  -Upn $Upn -Folder $Folder }
        6  { Invoke-Step6  -Upn $Upn -Folder $Folder }
        7  { Invoke-Step7  -Upn $Upn -Folder $Folder }
        8  { Invoke-Step8  -Upn $Upn -Folder $Folder }
        9  { Invoke-Step9  -Upn $Upn -Folder $Folder }
        10 { Invoke-Step10 -Upn $Upn -Folder $Folder }
        default { Write-WarnMsg "Unknown step number: $Number" }
    }
}

# ----------------------------------------------------------------
# Dry-run / training mode: narrate each step, make no changes.
# ----------------------------------------------------------------
$script:StepInfo = @{
    1  = @{ Title = 'Reset password and revoke all sign-in sessions'; Action = 'Reset password and revoked all sign-in sessions'
            Why = 'Stops new sign-ins and invalidates issued refresh tokens.'
            Cmdlets = 'Update-MgUser (passwordProfile); Revoke-MgUserSignInSession'
            Sim = 'Password reset to a random value; all sessions revoked.' }
    2  = @{ Title = 'Block sign-in (disable the account)'; Action = 'Set AccountEnabled to false'
            Why = 'Prevents the account from authenticating.'
            Cmdlets = 'Update-MgUser -AccountEnabled:$false'
            Sim = 'AccountEnabled set to false.' }
    3  = @{ Title = 'Remove ActiveSync mobile device partnerships'; Action = 'Removed ActiveSync mobile device partnerships'
            Why = 'Stops cached mobile clients from repeatedly trying to refresh tokens.'
            Cmdlets = 'Get-MobileDevice; Remove-MobileDevice'
            Sim = '2 partnerships would be removed.' }
    4  = @{ Title = 'Remove registered authentication (MFA) methods'; Action = 'Removed registered authentication (MFA) methods'
            Why = 'Clears stale MFA registrations.'
            Cmdlets = 'Get-MgUserAuthenticationMethod; Remove-MgUserAuthentication*Method'
            Sim = '2 methods (Authenticator, phone) would be removed; password kept.' }
    5  = @{ Title = 'Revoke OAuth app grants'; Action = 'Revoked OAuth2 grants'
            Why = 'Removes third-party app access tied to the account.'
            Cmdlets = 'Get-MgUserOauth2PermissionGrant; Remove-MgOauth2PermissionGrant'
            Sim = '2 delegated grants would be revoked.' }
    6  = @{ Title = 'Remove from groups and distribution lists'; Action = 'Removed user from cloud-managed groups'
            Why = 'Stops inherited access and mail; on-prem-synced groups are skipped.'
            Cmdlets = 'Get-MgUserMemberOf; Remove-MgGroupMemberByRef'
            Sim = '4 cloud-managed groups would be removed.' }
    7  = @{ Title = 'Configure forwarding and delegation (optional)'; Action = 'Configured forwarding / delegation'
            Why = 'Keeps the work flowing if requested.'
            Cmdlets = 'Set-Mailbox -ForwardingSmtpAddress; Add-MailboxPermission; Add-RecipientPermission'
            Sim = 'No forwarding or delegation requested (training default).' }
    8  = @{ Title = 'Convert user mailbox to a shared mailbox'; Action = 'Converted user mailbox to shared mailbox'
            Why = 'Preserves mail and calendar; must happen BEFORE the license is removed.'
            Cmdlets = 'Set-Mailbox -Type Shared'
            Sim = 'RecipientTypeDetails would become SharedMailbox.' }
    9  = @{ Title = 'Remove Microsoft 365 licenses'; Action = 'Removed all Microsoft 365 licenses'
            Why = 'Safe now that the mailbox is shared; the account remains as the anchor.'
            Cmdlets = 'Set-MgUserLicense -RemoveLicenses'
            Sim = '1 license SKU would be removed.' }
    10 = @{ Title = 'Apply a Conditional Access block on the user principal'; Action = "Added user to the offboarded group (targeted by CA block)"
            Why = 'Defense in depth: blocks sign-in even if the account is re-enabled.'
            Cmdlets = 'New-MgGroup; New-MgGroupMember; New-MgIdentityConditionalAccessPolicy'
            Sim = "User would be added to '$OffboardedGroupName'; report-only CA policy ensured." }
}

function Invoke-DryRunStep {
    param([int]$Number, [string]$Upn, [string]$Folder)
    $info = $script:StepInfo[$Number]
    Write-StepHeader $Number $info.Title
    Write-Host '  [DRY RUN] No change will be made.' -ForegroundColor Magenta
    Write-Info $info.Why
    Write-Action "Would run: $($info.Cmdlets)"
    Write-Ok "Simulated result: $($info.Sim)"

    # In an interactive demo, capture a sample screenshot so the packet shows
    # what the screenshot feature produces. Skipped in unattended preview mode
    # and on headless hosts (Save-Screenshot returns null there).
    $shot = $null
    if (-not $Unattended -and $Folder) {
        $shot = Save-Screenshot -OutputFolder $Folder -StepNumber $Number -Label ($info.Action -replace '[^a-zA-Z0-9_-]', '_')
    }

    Add-AuditEntry -StepNumber $Number -Action $info.Action -Result 'Dry run (no change)' -Screenshot $shot `
        -Details "DRY RUN, no change made. Would execute: $($info.Cmdlets). $($info.Sim)"
}

function Get-DryRunFinalState {
    param([string]$Upn)
    return [ordered]@{
        'User principal name'         = $Upn
        'Display name'                = '(training account)'
        'Account enabled'             = $false
        'Assigned licenses'           = 'None'
        'Recipient type details'      = 'SharedMailbox'
        'Forwarding address'          = 'None'
        'Mobile device partnerships'  = 0
    }
}

function Invoke-StepList {
    param([int[]]$Numbers, [string]$Upn, [string]$Folder, [bool]$StopOnError)
    foreach ($n in $Numbers) {
        try {
            Invoke-StepByNumber -Number $n -Upn $Upn -Folder $Folder
        } catch {
            Write-ErrMsg "Step $n failed: $_"
            Add-AuditEntry -StepNumber $n -Action "Step $n" -Result "FAILED: $_" -Details "Exception: $($_.Exception.Message)"
            if ($StopOnError) { throw }
            if (-not $Unattended) {
                $cont = Read-Host '  Continue with remaining steps? (y/N)'
                if ($cont -notmatch '^[Yy]') { break }
            }
        }
    }
}

function Show-StepMenu {
    param([string]$Upn)
    Write-Host ''
    Write-Host ('=' * 64) -ForegroundColor Cyan
    Write-Host '  OFFBOARDING MENU' -ForegroundColor Cyan
    Write-Host '  Target user: ' -NoNewline; Write-Host $Upn -ForegroundColor Yellow
    Write-Host ('=' * 64) -ForegroundColor Cyan
    Write-Credit
    Write-Host '  Run as a Global Administrator. Any admin roles on the target are' -ForegroundColor DarkGray
    Write-Host '  removed automatically before the steps below.' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Phase 1: Immediate lockout'
    Write-Host '    1) Reset password and revoke sessions'
    Write-Host '    2) Block sign-in'
    Write-Host '    3) Remove mobile device partnerships'
    Write-Host ''
    Write-Host '  Phase 2: Authorization cleanup'
    Write-Host '    4) Remove authentication (MFA) methods'
    Write-Host '    5) Revoke OAuth app grants'
    Write-Host '    6) Remove from groups'
    Write-Host ''
    Write-Host '  Phase 3: Mailbox transition and hardening'
    Write-Host '    7) Configure forwarding / delegation'
    Write-Host '    8) Convert mailbox to shared'
    Write-Host '    9) Remove licenses'
    Write-Host '   10) Apply Conditional Access block'
    Write-Host ''
    Write-Host '   A) Run ALL steps in order (recommended)'
    Write-Host '   Q) Finish and generate the audit packet'
    Write-Host ''
    return (Read-Host '  Choose')
}

function Resolve-AuditFolder {
    param([string]$Root, [string]$Upn)
    $userSafe = ($Upn -split '@')[0] -replace '[^a-zA-Z0-9_-]', '_'
    $dateStamp = Get-Date -Format 'yyyy-MM-dd'
    $folder = Join-Path $Root ("{0}_{1}" -f $userSafe, $dateStamp)
    if (Test-Path $folder) {
        $folder = Join-Path $Root ("{0}_{1}_{2}" -f $userSafe, $dateStamp, (Get-Date -Format 'HHmmss'))
    }
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    return $folder
}

function Test-PriorOffboarding {
    # Scans the audit root for an earlier offboarding of the same UPN, so the
    # technician is warned about a rehire-who-left-again or an accidental re-run.
    param([string]$Root, [string]$Upn)
    $hits = @()
    if (-not $Root -or -not (Test-Path $Root)) { return $hits }
    $jsonFiles = Get-ChildItem -Path $Root -Filter 'audit.json' -Recurse -File -ErrorAction SilentlyContinue
    foreach ($f in $jsonFiles) {
        try { $d = Get-Content $f.FullName -Raw | ConvertFrom-Json } catch { continue }
        if ($d.dryRun) { continue }
        if ($d.tool -eq 'Invoke-M365Offboarding' -and "$($d.targetUpn)".ToLower() -eq $Upn.ToLower()) {
            $hits += [PSCustomObject]@{ Date = "$($d.offboardingDate)"; Path = $f.FullName }
        }
    }
    return $hits
}

# ----------------------------------------------------------------
# Pre-step: strip the target's administrative role assignments.
# A user who holds a privileged Entra role is protected: even a Global
# Administrator cannot disable or fully manage the account until the roles are
# removed (this is why disabling an admin returns 403 Authorization_RequestDenied).
# Removing roles is also correct offboarding hygiene for a departing admin.
# Uses the REST endpoint via Invoke-MgGraphRequest to stay independent of
# Graph PowerShell cmdlet-name changes across SDK versions.
# ----------------------------------------------------------------
function Remove-AdminRoleAssignments {
    param([string]$Upn)
    Write-Banner 'PRE-STEP: ADMINISTRATIVE ROLE CHECK'

    # Read the role memberships under a guard: this runs in Main (outside the
    # per-step try/catch), so an unhandled error here would abort the whole run.
    try {
        $user = Get-MgUser -UserId $Upn -Property Id -ErrorAction Stop
        $memberships = @(Get-MgUserMemberOf -UserId $user.Id -All -ErrorAction Stop)
    } catch {
        Write-WarnMsg "Could not read role memberships: $_"
        Write-WarnMsg 'Admin roles were NOT verified or removed; later steps may fail if this user is an admin.'
        Add-AuditEntry -StepNumber 0 -Action 'Administrative role check' -Result 'FAILED: could not read role memberships' `
            -Details "Could not read directory role memberships: $($_.Exception.Message). Admin roles were NOT verified or removed."
        return
    }

    $roles = @($memberships | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole' })

    if (-not $roles) {
        Write-Info 'User holds no directly-assigned active directory roles.'
        Write-Info 'Note: PIM-eligible (not activated) and role-assignable-group-derived roles are not covered here.'
        Add-AuditEntry -StepNumber 0 -Action 'Administrative role check' -Result 'Success' `
            -Details 'User held no directly-assigned active directory roles. (PIM-eligible and role-assignable-group-derived roles are not covered by this check.)'
        return
    }

    Write-WarnMsg "User is an administrator: $($roles.Count) directly-assigned role(s). Removing before offboarding."
    $removed = @(); $failures = 0
    foreach ($r in $roles) {
        $roleName = $r.AdditionalProperties.displayName
        if (-not $PSCmdlet.ShouldProcess($Upn, "Remove directory role '$roleName'")) { continue }
        try {
            $uri = "https://graph.microsoft.com/v1.0/directoryRoles/$($r.Id)/members/$($user.Id)/`$ref"
            Invoke-MgGraphRequest -Method DELETE -Uri $uri -ErrorAction Stop | Out-Null
            Write-Ok "Removed role: $roleName"
            $removed += "$roleName [$($r.Id)]"
        } catch {
            $failures++
            Write-WarnMsg "Could not remove role '$roleName': $_ (note: the last Global Administrator cannot be removed; assign a replacement first.)"
        }
    }

    $result = if ($failures -gt 0) { "FAILED: $failures of $($roles.Count) role removal(s) failed" } else { 'Success' }
    $details = if ($removed.Count) {
        "Removed directly-assigned roles (name [id]): $($removed -join '; '). PIM-eligible and role-assignable-group-derived roles are NOT covered, and the reversal does not re-grant roles."
    } else {
        "Found $($roles.Count) role(s) but none could be removed (see warnings); the account may remain privileged."
    }
    Add-AuditEntry -StepNumber 0 -Action "Removed $($removed.Count) of $($roles.Count) administrative role assignment(s)" -Result $result -Details $details
}

# ----------------------------------------------------------------
# Pre-step: set up the Conditional Access block (group + report-only policy) BEFORE
# the destructive steps run. Creating the policy needs Policy.ReadWrite.ConditionalAccess,
# an admin-restricted scope that may not be consented. Handling it here means a
# permission problem is resolved -- or consciously skipped -- while nothing has been
# changed yet, instead of failing at Step 10 after the mailbox is already shared.
# Sets $script:CaPolicyDecision to 'ready', 'skip', or 'abort'. Never throws/aborts the
# offboarding by itself -- a group/policy/permission failure is handled, not fatal.
# ----------------------------------------------------------------
function Confirm-CaInfrastructure {
    Write-Banner 'PRE-STEP: CONDITIONAL ACCESS SETUP'
    Write-Info 'Preparing the sign-in block group and policy now, before any change, so a'
    Write-Info 'permission issue is handled up front -- not after the offboarding has run.'

    if ($WhatIfPreference) {
        Write-Info "[WhatIf] Would ensure group '$OffboardedGroupName' and a report-only policy '$BlockPolicyName' exist."
        $script:CaPolicyDecision = 'ready'
        return
    }

    $createdGroup = $false
    $groupNameFilter  = $OffboardedGroupName -replace "'", "''"
    $policyNameFilter = $BlockPolicyName -replace "'", "''"

    # The whole setup (group + policy) is attempted as a unit; ANY failure -- including
    # the group, so a missing Group.ReadWrite.All never aborts the lockout -- drops into
    # the operator's options. The CA block is optional, report-only defense in depth.
    while ($true) {
        try {
            $group = Get-MgGroup -Filter "displayName eq '$groupNameFilter'" -ErrorAction Stop | Select-Object -First 1
            if (-not $group) {
                Write-Action "Creating security group '$OffboardedGroupName'..."
                $nickname = ($OffboardedGroupName -replace '[^a-zA-Z0-9]', '').ToLower()
                if ([string]::IsNullOrWhiteSpace($nickname)) { $nickname = 'offboardedusers' }
                $group = New-MgGroup -DisplayName $OffboardedGroupName `
                    -Description 'Offboarded users. Targeted by the sign-in block Conditional Access policy.' `
                    -MailEnabled:$false -MailNickname $nickname -SecurityEnabled:$true -ErrorAction Stop
                $createdGroup = $true
                # Wait until the new group is queryable so Step 10 reuses it (no duplicate).
                Wait-ForCondition -TimeoutSeconds 30 -Check { [bool](Get-MgGroup -GroupId $group.Id -ErrorAction SilentlyContinue) } | Out-Null
            }
            $script:OffboardedGroupId = $group.Id
            Write-Ok "Group '$OffboardedGroupName' is ready (Id: $($group.Id))."

            $policy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$policyNameFilter'" -ErrorAction Stop | Select-Object -First 1
            if ($policy) {
                Write-Ok "Conditional Access policy '$BlockPolicyName' is in place (state: $($policy.State))."
            } else {
                Write-Action "Creating Conditional Access policy '$BlockPolicyName' in REPORT-ONLY mode..."
                $policyBody = @{
                    displayName   = $BlockPolicyName
                    state         = 'enabledForReportingButNotEnforced'
                    conditions    = @{
                        applications = @{ includeApplications = @('All') }
                        users        = @{ includeGroups = @($group.Id) }
                    }
                    grantControls = @{ operator = 'OR'; builtInControls = @('block') }
                }
                $null = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyBody -ErrorAction Stop
                Write-Ok "Created the policy in report-only mode. ACTION REQUIRED: enable it in Entra to enforce."
            }
            $script:CaPolicyDecision = 'ready'
            return
        } catch {
            Write-ErrMsg "Could not set up the Conditional Access block: $_"

            if ($Unattended) {
                Write-WarnMsg 'Unattended run: continuing WITHOUT the Conditional Access block (optional, report-only defense in depth).'
                $script:CaPolicyDecision = 'skip'
                return
            }

            $changedNote = if ($createdGroup) { " The group '$OffboardedGroupName' was created and remains (harmless; reused next time)." } else { '' }
            Write-Host ''
            Write-Host "  No offboarding steps have run yet.$changedNote" -ForegroundColor Yellow
            Write-Host '  This usually means the Policy.ReadWrite.ConditionalAccess permission' -ForegroundColor Yellow
            Write-Host '  was not consented. Choose:' -ForegroundColor Yellow
            Write-Host '    [R] Retry  - re-open the consent window (tick "Consent on behalf of'
            Write-Host '                 your organization"), then try again'
            Write-Host '    [M] Manual - create the policy yourself in Entra; I will show the steps'
            Write-Host '                 and then re-check'
            Write-Host '    [C] Continue offboarding WITHOUT the Conditional Access policy'
            Write-Host '    [A] Abort   - stop now and run no offboarding steps'
            $choice = (Read-Host '  Choose [R/M/C/A]').ToUpper().Trim()
            switch ($choice) {
                'R' {
                    if ($script:GraphScopes) {
                        Write-Action 'Re-opening the consent window. Accept it, and tick "Consent on behalf of your organization".'
                        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
                        try { Connect-MgGraph -Scopes $script:GraphScopes -NoWelcome } catch { Write-WarnMsg "Sign-in failed: $_" }
                    }
                }
                'M' {
                    Write-Host ''
                    Write-Host '  Create the policy in the Entra admin center, then return here:' -ForegroundColor Cyan
                    Write-Host '   1. https://entra.microsoft.com  ->  Protection  ->  Conditional Access  ->  Policies  ->  + New policy'
                    Write-Host "   2. Name:  $BlockPolicyName"
                    Write-Host "   3. Users:  include the group '$OffboardedGroupName'"
                    Write-Host '   4. Target resources:  All cloud apps'
                    Write-Host '   5. Grant:  Block access'
                    Write-Host '   6. Enable policy:  Report-only   ->   Create'
                    Write-Host '  (If I still cannot read it afterward, choose [C] to continue -- the'
                    Write-Host '   policy you created stays in place and targets the group.)' -ForegroundColor DarkGray
                    Read-Host '  Press ENTER after you have created and saved the policy'
                }
                'C' {
                    Write-WarnMsg 'Continuing without the Conditional Access policy. The user is still added to the group.'
                    $script:CaPolicyDecision = 'skip'
                    return
                }
                'A' {
                    Write-WarnMsg 'Aborted at the Conditional Access pre-step. No offboarding steps will run.'
                    $details = if ($createdGroup) {
                        "Operator aborted at the CA pre-step before any offboarding step. The group '$OffboardedGroupName' was created and remains; no user changes were made."
                    } else {
                        'Operator aborted at the CA pre-step before any offboarding step. No changes were made.'
                    }
                    Add-AuditEntry -StepNumber 0 -Action 'Aborted at Conditional Access pre-step' -Result 'Aborted by operator' -Details $details
                    $script:CaPolicyDecision = 'abort'
                    return
                }
                default { Write-WarnMsg 'Enter R, M, C, or A.' }
            }
        }
    }
}

function Main {
    Initialize-ScreenshotCapability

    if (-not $Unattended) {
        Clear-Host
        if ($DryRun) {
            Write-Banner 'DRY RUN / TRAINING MODE' 'Magenta'
            Write-Credit
            Write-Host '  No sign-in occurs and nothing in the tenant is changed.' -ForegroundColor Magenta
            Write-Host '  This walks through all ten steps and shows what each would do.' -ForegroundColor Magenta
            Write-Host ''
            $proceed = Read-Host '  Type TRAIN to continue, or anything else to exit'
            if ($proceed -ne 'TRAIN') { Write-Host '  Aborted.' -ForegroundColor Yellow; return }
        } else {
            Write-Banner 'MICROSOFT 365 USER OFFBOARDING' 'Green'
            Write-Credit
            Write-Host '  Before starting:' -ForegroundColor Yellow
            Write-Host '    1. Confirm the offboarding is approved.'
            Write-Host '    2. Sign in as a Global Administrator (required to manage admins,'
            Write-Host '       Conditional Access, and to remove the user''s admin roles).'
            Write-Host '    Note: any admin roles on the target are removed automatically first.'
            if ($script:ScreenshotMode -eq 'windows') {
                Write-Host '    3. Close personal windows. Screenshots capture all monitors.'
            }
            Write-Host ''

            # Be clear about screenshots when there is no graphical desktop.
            if ($script:ScreenshotMode -eq 'none' -and -not $NoScreenshots) {
                if ($script:IsCloudShell) {
                    Write-WarnMsg 'Running in Azure Cloud Shell: this is a headless environment with no'
                    Write-Info   'graphical desktop, so per-step screenshots cannot be captured here.'
                } elseif (-not $script:IsWindowsHost -and -not $script:HasDisplay) {
                    Write-WarnMsg 'No graphical desktop detected: per-step screenshots cannot be captured.'
                }
                Write-Info 'The audit packet will still include AUDIT.md, audit.json, and a text'
                Write-Info 'transcript of this session. If your audit policy requires images, take a'
                Write-Info 'screenshot of your own screen (for example the browser) and keep it with'
                Write-Info 'the ticket, or run the tool on a Windows desktop for automatic screenshots.'
            }

            # On a Linux desktop with no capture tool, offer to install one.
            Request-ScreenshotToolInstall

            Write-Host ''
            $proceed = Read-Host '  Type START to continue, or anything else to exit'
            if ($proceed -ne 'START') { Write-Host '  Aborted.' -ForegroundColor Yellow; return }
        }
    } elseif ($DryRun) {
        Write-Banner 'DRY RUN / TRAINING MODE - NO CHANGES WILL BE MADE' 'Magenta'
    }

    # Resolve inputs
    $upn = $UserPrincipalName
    if (-not $upn) {
        if ($DryRun) {
            $upn = 'trainee@contoso.com'
            Write-Info "Dry run using sample user: $upn"
        } elseif ($Unattended) {
            throw '-UserPrincipalName is required in unattended mode.'
        } else {
            $upn = Get-TargetUserInteractive
        }
    }
    if ($upn -notmatch '@') { throw "Invalid UserPrincipalName: $upn" }

    $root = $AuditRoot
    if (-not $root) {
        if ($DryRun) {
            $root = Join-Path ([System.IO.Path]::GetTempPath()) 'M365Offboarding-DryRun'
            Write-Info "Dry run audit packet will be written under: $root"
        } elseif ($Unattended) {
            throw '-AuditRoot is required in unattended mode.'
        } else {
            $root = Get-AuditRootFolderInteractive
        }
    }
    if (-not (Test-Path $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }

    # Rehire / re-run guard: warn if this user was offboarded before (not in dry run).
    $prior = if ($DryRun) { @() } else { @(Test-PriorOffboarding -Root $root -Upn $upn) }
    if ($prior.Count) {
        Write-Banner 'PRIOR OFFBOARDING DETECTED' 'Yellow'
        Write-WarnMsg "This user was offboarded before ($($prior.Count) record(s)):"
        foreach ($p in $prior) { Write-Info "  $($p.Date)  -  $($p.Path)" }
        Write-Info 'If this is a returning employee who left again, this is expected.'
        Write-Info 'If you meant to restore them, use Invoke-M365OffboardingReversal.ps1 instead.'
        if (-not $Unattended) {
            $c = Read-Host '  Continue offboarding anyway? (y/N)'
            if ($c -notmatch '^[Yy]') { Write-WarnMsg 'Aborted by operator.'; return }
        }
    }

    $auditFolder = Resolve-AuditFolder -Root $root -Upn $upn
    Write-Ok "Audit folder: $auditFolder"

    # When screenshots are not available (Cloud Shell) or in a dry run, capture a
    # text transcript of the session as the audit evidence substitute.
    if ($script:ScreenshotMode -eq 'none' -or $DryRun) {
        try {
            Start-Transcript -Path (Join-Path $auditFolder 'transcript.txt') -Append | Out-Null
            $script:TranscriptOn = $true
            Write-Info 'Capturing a text transcript (transcript.txt) in place of screenshots.'
        } catch { }
    }

    $allSteps = 1..10

    if ($DryRun) {
        # Training mode: no modules, no sign-in, no tenant calls.
        $operator = 'DRY RUN (no sign-in)'
        Add-AuditEntry -StepNumber 0 -Action 'Dry run started (no sign-in)' -Result 'Dry run (no change)' -Details "Target (sample): $upn. No connection was made."
        $toRun = if ($Steps) { $Steps } else { $allSteps }
        foreach ($n in $toRun) { Invoke-DryRunStep -Number $n -Upn $upn -Folder $auditFolder }
    } else {
        Initialize-Modules
        $operator = Connect-Services
        Add-AuditEntry -StepNumber 0 -Action 'Connected to Microsoft Graph and Exchange Online' -Result "Authenticated as $operator" `
            -Details "Target: $upn."

        # Decide which steps to run. Two pre-steps run first, BEFORE anything destructive:
        # (1) the Conditional Access setup (so a permission issue/abort happens while
        # nothing has changed), then (2) admin-role removal -- and that one only when a
        # step that disables/manages the account (1 or 2) will actually run, so a targeted
        # subset like -Steps 7 does NOT silently revoke the user's roles.
        if ($Unattended -or $All -or $Steps) {
            $toRun = if ($Steps) { $Steps } else { $allSteps }
            if ($toRun -contains 10) { Confirm-CaInfrastructure }
            if ($script:CaPolicyDecision -eq 'abort') {
                Write-WarnMsg 'Offboarding aborted at the Conditional Access pre-step. No offboarding steps were performed.'
            } else {
                if ($toRun -contains 1 -or $toRun -contains 2) { Remove-AdminRoleAssignments -Upn $upn }
                Invoke-StepList -Numbers $toRun -Upn $upn -Folder $auditFolder -StopOnError:$false
            }
        } else {
            while ($true) {
                $choice = (Show-StepMenu -Upn $upn).ToUpper().Trim()
                if ($choice -eq 'Q') { break }
                if ($choice -eq 'A') {
                    Confirm-CaInfrastructure
                    if ($script:CaPolicyDecision -eq 'abort') { Write-WarnMsg 'Aborted at the Conditional Access pre-step. No steps were run.'; break }
                    Remove-AdminRoleAssignments -Upn $upn
                    Invoke-StepList -Numbers $allSteps -Upn $upn -Folder $auditFolder -StopOnError:$false
                    break
                }
                if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le 10) {
                    if ([int]$choice -eq 1 -or [int]$choice -eq 2) { Remove-AdminRoleAssignments -Upn $upn }
                    if ([int]$choice -eq 10) { Confirm-CaInfrastructure }
                    if ($script:CaPolicyDecision -eq 'abort') { Write-WarnMsg 'Aborted at the Conditional Access pre-step. Step 10 was not run.' }
                    else { Invoke-StepList -Numbers @([int]$choice) -Upn $upn -Folder $auditFolder -StopOnError:$false }
                } else {
                    Write-WarnMsg 'Invalid choice. Use 1-10, A, or Q.'
                }
            }
        }
    }

    # Audit packet
    Write-Banner 'GENERATING AUDIT PACKET'
    $finalState = if ($DryRun) { Get-DryRunFinalState -Upn $upn } else { Get-FinalState -Upn $upn }
    $folderJson = Join-Path $auditFolder 'audit.json'

    # Decide whether and where to upload to SharePoint (never in dry run).
    $spSite = $SharePointSiteUrl
    $spFolder = $SharePointFolderPath
    $doUpload = $false
    if (-not $DryRun -and -not $SkipSharePointUpload) {
        if ($spSite) {
            $doUpload = $true
        } elseif (-not $Unattended) {
            Write-Banner 'SHAREPOINT UPLOAD'
            Write-Info 'The audit packet should be stored in SharePoint for later review.'
            $ans = Read-Host '  Upload it to SharePoint now? (Y/n)'
            if ($ans -notmatch '^[Nn]') {
                $spSite = Read-Host '  SharePoint site URL (e.g. https://contoso.sharepoint.com/sites/IT)'
                if (-not [string]::IsNullOrWhiteSpace($spSite)) {
                    $spFolder = Read-Host '  Folder in the document library (ENTER for root, e.g. Offboarding Audits)'
                    $doUpload = $true
                } else {
                    Write-WarnMsg 'No site URL entered. The packet will stay local.'
                }
            }
        }
    }

    # Resolve the SharePoint destination first so the audit files can record the link.
    $spUrl = $null
    $spTarget = $null
    if ($doUpload) {
        try {
            $spTarget = Resolve-SharePointTarget -SiteUrl $spSite -FolderPath $spFolder -LeafName (Split-Path $auditFolder -Leaf)
            $spUrl = $spTarget.WebUrl
        } catch {
            Write-WarnMsg "Could not prepare the SharePoint destination: $_"
            $doUpload = $false
        }
    }

    # Write the audit files (embedding the SharePoint link when known).
    $auditPath = Write-AuditMarkdown -OutputFolder $auditFolder -TargetUpn $upn -Operator $operator -FinalState $finalState -SharePointUrl $spUrl -DryRun $DryRun
    Write-AuditJson -Path $folderJson -TargetUpn $upn -Operator $operator -FinalState $finalState -SharePointUrl $spUrl -DryRun $DryRun | Out-Null
    $htmlPath = Write-AuditHtml -OutputFolder $auditFolder -TargetUpn $upn -Operator $operator -FinalState $finalState -SharePointUrl $spUrl -DryRun $DryRun
    Write-Ok "Wrote $auditPath"
    Write-Ok "Wrote $folderJson"
    Write-Ok "Wrote $htmlPath"
    if ($JsonOutPath -and ($JsonOutPath -ne $folderJson)) {
        Copy-Item -Path $folderJson -Destination $JsonOutPath -Force
        Write-Ok "Copied audit.json to $JsonOutPath"
    }

    # Finalize the transcript so it is complete and included in the upload.
    Stop-TranscriptSafe

    # Upload the whole folder to SharePoint.
    if ($doUpload) {
        Write-Action 'Uploading audit packet to SharePoint...'
        try {
            Send-FilesToSharePoint -DriveId $spTarget.DriveId -DestFolder $spTarget.DestFolder -Files (Get-ChildItem -File -Path $auditFolder)
            Write-Ok "Audit packet uploaded to SharePoint: $spUrl"
        } catch {
            Write-WarnMsg "SharePoint upload failed: $_"
            $spUrl = $null
            # Rewrite the local audit files so they do not falsely claim a SharePoint copy.
            Write-AuditMarkdown -OutputFolder $auditFolder -TargetUpn $upn -Operator $operator -FinalState $finalState -DryRun $DryRun | Out-Null
            Write-AuditJson -Path $folderJson -TargetUpn $upn -Operator $operator -FinalState $finalState -DryRun $DryRun | Out-Null
            Write-AuditHtml -OutputFolder $auditFolder -TargetUpn $upn -Operator $operator -FinalState $finalState -DryRun $DryRun | Out-Null
            if ($JsonOutPath -and ($JsonOutPath -ne $folderJson)) { Copy-Item -Path $folderJson -Destination $JsonOutPath -Force }
        }
    }

    if ($DryRun) {
        Write-Banner 'DRY RUN COMPLETE - NO CHANGES WERE MADE' 'Magenta'
        Write-Host "  Sample audit packet: $auditFolder" -ForegroundColor Magenta
        Write-Info 'Review AUDIT.md and audit.json to see what a real run produces.'
        Write-Info 'When ready, run a real offboarding (optionally with -WhatIf first).'
    } else {
        if (-not $spUrl) {
            Write-Banner 'UPLOAD TO SHAREPOINT' 'Yellow'
            Write-Info 'The audit packet was not uploaded to SharePoint.'
            Write-Info 'Please upload this folder to SharePoint for later review:'
            Write-Host "    $auditFolder" -ForegroundColor Yellow
        }
        Write-Banner 'COMPLETE' 'Green'
        Write-Host "  Audit folder: $auditFolder" -ForegroundColor Green
        if ($spUrl) { Write-Host "  SharePoint:   $spUrl" -ForegroundColor Green }
    }

    if (-not $Unattended -and $script:IsWindowsHost) {
        try { Start-Process explorer.exe $auditFolder } catch { }
    }

    if (-not $DryRun) { Disconnect-Services }
}

try {
    Main
} catch {
    Write-ErrMsg "FATAL: $_"
    Write-Host "  $($_.ScriptStackTrace)" -ForegroundColor Red
    Stop-TranscriptSafe
    Disconnect-Services
    if (-not $Unattended) { Read-Host 'Press ENTER to exit' }
    exit 1
}
