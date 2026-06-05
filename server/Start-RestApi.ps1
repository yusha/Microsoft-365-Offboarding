<#
.SYNOPSIS
    Minimal REST API in front of the Microsoft 365 offboarding tools.

.DESCRIPTION
    A dependency-free HTTP server (System.Net.HttpListener) that exposes the
    offboarding actions over JSON. It shells out to the existing PowerShell
    scripts and returns their audit.json.

    Endpoints:
      GET  /health      liveness and configuration summary (no auth)
      POST /preview     dry-run simulation of an offboarding (safe, no changes)
      POST /rehire      prior-offboarding / rehire check (read-only)
      POST /offboard    perform an offboarding   (requires execute flag)
      POST /reverse     reverse an offboarding    (requires execute flag)

    Security:
      - All endpoints except /health require  Authorization: Bearer <token>
        matching the M365_OFFBOARDING_API_TOKEN environment variable. The server
        refuses to start if that token is not set.
      - Destructive actions (offboard, reverse) also require
        M365_OFFBOARDING_ALLOW_EXECUTE=1 and app-only credentials in the
        environment. See server/README.md.
      - Binds to 127.0.0.1 by default. Put a real reverse proxy with TLS in
        front of it before exposing it on a network.

.PARAMETER Prefix
    HttpListener prefix. Default http://127.0.0.1:8770/.

.EXAMPLE
    $env:M365_OFFBOARDING_API_TOKEN = 'a-long-random-secret'
    ./server/Start-RestApi.ps1

.NOTES
    MIT licensed. No warranty.
#>

[CmdletBinding()]
param(
    [string]$Prefix = 'http://127.0.0.1:8770/'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'M365OffboardingService.ps1')

$script:ApiVersion = '1.0'

function Get-ApiResponse {
    # Pure routing/auth logic, returns @{ Status; Body }. Unit-testable.
    param(
        [string]$Method,
        [string]$Path,
        [string]$Body,
        [string]$AuthHeader,
        [string]$ExpectedToken
    )

    $Path = ($Path -replace '/+$', '')
    if ($Path -eq '') { $Path = '/' }

    if ($Method -eq 'GET' -and $Path -eq '/health') {
        return @{ Status = 200; Body = [ordered]@{
            status = 'ok'; service = 'M365 Offboarding API'; version = $script:ApiVersion
            executeEnabled = (Test-ExecuteEnabled); appOnlyConfigured = (Test-AppOnlyConfigured)
        } }
    }

    # Everything else requires the bearer token.
    $token = ''
    if ($AuthHeader -match '^(?i)Bearer\s+(.+)$') { $token = $Matches[1].Trim() }
    if (-not $ExpectedToken -or $token -ne $ExpectedToken) {
        return @{ Status = 401; Body = [ordered]@{ ok = $false; error = 'Unauthorized. Provide a valid Bearer token.' } }
    }

    $route = @{ '/preview' = 'preview'; '/rehire' = 'rehire'; '/offboard' = 'offboard'; '/reverse' = 'reverse' }
    if ($Method -ne 'POST' -or -not $route.ContainsKey($Path)) {
        return @{ Status = 404; Body = [ordered]@{ ok = $false; error = "No route for $Method $Path." } }
    }

    $args = @{}
    if ($Body) {
        try { $args = $Body | ConvertFrom-Json } catch {
            return @{ Status = 400; Body = [ordered]@{ ok = $false; error = 'Request body is not valid JSON.' } }
        }
    }

    $result = Invoke-OffboardingService -Action $route[$Path] -Arguments $args
    $status = if ($result.ok) { 200 } elseif ($result.error -match 'disabled|credentials') { 403 } elseif ($result.error -match 'required|valid') { 400 } else { 500 }
    return @{ Status = $status; Body = $result }
}

function Start-Api {
    param([string]$Prefix)

    $expected = $env:M365_OFFBOARDING_API_TOKEN
    if ([string]::IsNullOrWhiteSpace($expected)) {
        throw 'Set M365_OFFBOARDING_API_TOKEN to a strong secret before starting the API.'
    }
    if ($Prefix -notmatch '127\.0\.0\.1|localhost') {
        Write-Warning 'The API is binding to a non-localhost address. Front it with TLS and access controls.'
    }

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($Prefix)
    $listener.Start()
    Write-Host "M365 Offboarding API listening on $Prefix" -ForegroundColor Green
    Write-Host ("Execute enabled: {0}   App-only configured: {1}" -f (Test-ExecuteEnabled), (Test-AppOnlyConfigured)) -ForegroundColor Cyan
    Write-Host 'Press Ctrl+C to stop.' -ForegroundColor DarkGray

    try {
        while ($listener.IsListening) {
            $ctx = $listener.GetContext()
            $req = $ctx.Request
            $body = ''
            if ($req.HasEntityBody) {
                $reader = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
                $body = $reader.ReadToEnd(); $reader.Close()
            }
            $resp = Get-ApiResponse -Method $req.HttpMethod -Path $req.Url.AbsolutePath `
                -Body $body -AuthHeader $req.Headers['Authorization'] -ExpectedToken $expected

            $json = ($resp.Body | ConvertTo-Json -Depth 20)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $ctx.Response.StatusCode = $resp.Status
            $ctx.Response.ContentType = 'application/json'
            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $ctx.Response.OutputStream.Close()

            Write-Host ("{0} {1} -> {2}" -f $req.HttpMethod, $req.Url.AbsolutePath, $resp.Status) -ForegroundColor DarkGray
        }
    } finally {
        $listener.Stop()
    }
}

# Only start the listener when run directly (not when dot-sourced for tests).
if ($MyInvocation.InvocationName -ne '.') {
    Start-Api -Prefix $Prefix
}
