<#
.SYNOPSIS
    Shared service core for the REST API and MCP server.

.DESCRIPTION
    Dot-sourced by Start-RestApi.ps1 and Start-McpServer.ps1. Turns a small set
    of actions (preview, rehire, offboard, reverse) into calls to the existing
    PowerShell scripts and returns their audit.json as a normalized object.

    Safety model:
      - "preview" (dry run) and "rehire" (read-only) are always allowed.
      - "offboard" and "reverse" are destructive and are blocked unless the
        operator sets M365_OFFBOARDING_ALLOW_EXECUTE=1.
      - App-only credentials are read from the environment, never from callers.

    The script runner is injectable ($script:Runner) so the routing and gating
    can be unit tested without launching PowerShell or contacting Microsoft 365.

.NOTES
    MIT licensed. No warranty.
#>

$script:RepoRoot       = Split-Path -Parent $PSScriptRoot
$script:OffboardScript = Join-Path $script:RepoRoot 'Invoke-M365Offboarding.ps1'
$script:ReverseScript  = Join-Path $script:RepoRoot 'Invoke-M365OffboardingReversal.ps1'
$script:RehireScript   = Join-Path $script:RepoRoot 'Test-M365Rehire.ps1'

function Test-ExecuteEnabled {
    return ([string]$env:M365_OFFBOARDING_ALLOW_EXECUTE).ToLower() -in @('1', 'true', 'yes', 'on')
}

function Test-AppOnlyConfigured {
    return [bool]($env:M365_TENANT -and $env:M365_CLIENT_ID -and $env:M365_CERT_THUMBPRINT)
}

function Get-AppOnlyArgs {
    $a = @()
    if ($env:M365_TENANT)          { $a += @('-TenantId', $env:M365_TENANT) }
    if ($env:M365_CLIENT_ID)       { $a += @('-ClientId', $env:M365_CLIENT_ID) }
    if ($env:M365_CERT_THUMBPRINT) { $a += @('-CertificateThumbprint', $env:M365_CERT_THUMBPRINT) }
    if ($env:M365_ORG)             { $a += @('-Organization', $env:M365_ORG) }
    return $a
}

function Test-Upn {
    param([string]$Upn)
    return ($Upn -match '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
}

# Default runner: launch PowerShell with the script and return the parsed JSON
# it wrote to -JsonOutPath. Overridden in tests.
function Invoke-PwshScript {
    param([string]$Script, [string[]]$ScriptArgs, [string]$JsonOut)
    $exe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
    & $exe -NoProfile -ExecutionPolicy Bypass -File $Script @ScriptArgs *> $null
    if (Test-Path $JsonOut) { return (Get-Content $JsonOut -Raw | ConvertFrom-Json) }
    return $null
}
$script:Runner = ${function:Invoke-PwshScript}

function New-TempAuditRoot {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) 'm365-offboarding-service'
    if (-not (Test-Path $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
    return $root
}

function Invoke-OffboardingService {
    <#
        Action is one of preview|rehire|offboard|reverse.
        Arguments is a hashtable from the caller (userPrincipalName, etc.).
        Returns @{ ok; action; executed; result; error }.
    #>
    param(
        [ValidateSet('preview', 'rehire', 'offboard', 'reverse')][string]$Action,
        $Arguments = @{}   # hashtable (MCP) or PSCustomObject (REST JSON); dot access works for both
    )

    $upn = "$($Arguments.userPrincipalName)"
    if (-not (Test-Upn $upn)) {
        return @{ ok = $false; action = $Action; executed = $false; result = $null; error = 'A valid userPrincipalName is required.' }
    }

    $destructive = $Action -in @('offboard', 'reverse')
    if ($destructive -and -not (Test-ExecuteEnabled)) {
        return @{ ok = $false; action = $Action; executed = $false; result = $null
            error = "Execution is disabled. Set M365_OFFBOARDING_ALLOW_EXECUTE=1 to allow '$Action'. Use 'preview' to simulate safely." }
    }
    if ($destructive -and -not (Test-AppOnlyConfigured)) {
        return @{ ok = $false; action = $Action; executed = $false; result = $null
            error = 'App-only credentials are not configured (M365_TENANT, M365_CLIENT_ID, M365_CERT_THUMBPRINT).' }
    }

    $auditRoot = New-TempAuditRoot
    $jsonOut = Join-Path $auditRoot ("result_{0}.json" -f ([guid]::NewGuid().ToString('N')))

    switch ($Action) {
        'preview' {
            # Dry run: simulated, no sign-in, no changes.
            $a = @('-DryRun', '-Unattended', '-UserPrincipalName', $upn, '-AuditRoot', $auditRoot, '-JsonOutPath', $jsonOut)
            $script = $script:OffboardScript
        }
        'rehire' {
            $a = @('-UserPrincipalName', $upn, '-JsonOutPath', $jsonOut, '-Unattended')
            if (Test-AppOnlyConfigured) { $a += Get-AppOnlyArgs } else { $a += '-SkipTenantCheck' }
            if ($Arguments.sharePointSiteUrl) { $a += @('-SharePointSiteUrl', "$($Arguments.sharePointSiteUrl)") }
            $script = $script:RehireScript
        }
        'offboard' {
            $a = @('-Unattended', '-NoScreenshots', '-UserPrincipalName', $upn, '-AuditRoot', $auditRoot, '-JsonOutPath', $jsonOut)
            $a += Get-AppOnlyArgs
            if ($Arguments.steps)             { $a += @('-Steps', (($Arguments.steps) -join ',')) }
            if ($Arguments.forwardingAddress) { $a += @('-ForwardingAddress', "$($Arguments.forwardingAddress)") }
            if ($Arguments.delegateTo)        { $a += @('-DelegateTo', "$($Arguments.delegateTo)") }
            if ($Arguments.sharePointSiteUrl) { $a += @('-SharePointSiteUrl', "$($Arguments.sharePointSiteUrl)") }
            $script = $script:OffboardScript
        }
        'reverse' {
            $a = @('-Unattended', '-UserPrincipalName', $upn, '-AuditRoot', $auditRoot, '-JsonOutPath', $jsonOut)
            $a += Get-AppOnlyArgs
            if ($Arguments.licenseSkuId)         { $a += @('-LicenseSkuId', (($Arguments.licenseSkuId) -join ',')) }
            if ($Arguments.licenseSkuPartNumber) { $a += @('-LicenseSkuPartNumber', (($Arguments.licenseSkuPartNumber) -join ',')) }
            if ($Arguments.resetPassword)        { $a += '-ResetPassword' }
            $script = $script:ReverseScript
        }
    }

    try {
        $result = & $script:Runner -Script $script -ScriptArgs $a -JsonOut $jsonOut
    } catch {
        return @{ ok = $false; action = $Action; executed = $destructive; result = $null; error = "Script error: $_" }
    } finally {
        Remove-Item $jsonOut -Force -ErrorAction SilentlyContinue
    }

    if (-not $result) {
        return @{ ok = $false; action = $Action; executed = $destructive; result = $null; error = 'No result was produced by the script.' }
    }
    return @{ ok = $true; action = $Action; executed = $destructive; result = $result; error = $null }
}
