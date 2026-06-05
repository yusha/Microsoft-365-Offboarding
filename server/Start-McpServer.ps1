<#
.SYNOPSIS
    Model Context Protocol (MCP) server for the Microsoft 365 offboarding tools.

.DESCRIPTION
    A dependency-free MCP server that speaks JSON-RPC 2.0 over stdio (one JSON
    message per line). It lets an MCP client (for example Claude Desktop) call
    the offboarding tools. It shells out to the existing PowerShell scripts and
    returns their audit.json as the tool result.

    Tools exposed:
      preview_offboarding   dry-run simulation of an offboarding (safe)
      check_rehire          prior-offboarding / rehire check (read-only)
      offboard_user         perform an offboarding   (requires execute flag)
      reverse_offboarding   reverse an offboarding    (requires execute flag)

    Safety: offboard_user and reverse_offboarding are blocked unless
    M365_OFFBOARDING_ALLOW_EXECUTE=1 and app-only credentials are set in the
    environment. Keep destructive tools behind human approval in your client.

    Configure in an MCP client by launching:
      pwsh -NoProfile -File /path/to/server/Start-McpServer.ps1

.NOTES
    MIT licensed. No warranty.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'M365OffboardingService.ps1')

$script:McpServerName    = 'm365-offboarding'
$script:McpServerVersion = '1.0'
$script:McpProtocol      = '2025-06-18'

function Get-McpTools {
    @(
        [ordered]@{
            name = 'preview_offboarding'
            description = 'Simulate a Microsoft 365 user offboarding (dry run). Makes no changes and needs no sign-in. Returns a sample audit result describing every step.'
            inputSchema = [ordered]@{
                type = 'object'
                properties = [ordered]@{ userPrincipalName = [ordered]@{ type = 'string'; description = 'UPN to simulate, e.g. jdoe@contoso.com' } }
                required = @('userPrincipalName')
            }
        },
        [ordered]@{
            name = 'check_rehire'
            description = 'Check whether a person was offboarded before (rehire detection). Read-only. Returns a verdict and recommendation.'
            inputSchema = [ordered]@{
                type = 'object'
                properties = [ordered]@{
                    userPrincipalName = [ordered]@{ type = 'string'; description = 'UPN to check' }
                    sharePointSiteUrl = [ordered]@{ type = 'string'; description = 'Optional SharePoint site URL to scan for past audit packets' }
                }
                required = @('userPrincipalName')
            }
        },
        [ordered]@{
            name = 'offboard_user'
            description = 'Perform a Microsoft 365 user offboarding (destructive). Disabled unless the server operator has enabled execution. Returns the audit result.'
            inputSchema = [ordered]@{
                type = 'object'
                properties = [ordered]@{
                    userPrincipalName = [ordered]@{ type = 'string'; description = 'UPN to offboard' }
                    forwardingAddress = [ordered]@{ type = 'string'; description = 'Optional UPN to forward mail to' }
                    delegateTo        = [ordered]@{ type = 'string'; description = 'Optional UPN to grant Full Access and Send As' }
                    sharePointSiteUrl = [ordered]@{ type = 'string'; description = 'Optional SharePoint site URL to store the audit packet' }
                    steps             = [ordered]@{ type = 'array'; items = [ordered]@{ type = 'integer' }; description = 'Optional subset of step numbers (1-10)' }
                }
                required = @('userPrincipalName')
            }
        },
        [ordered]@{
            name = 'reverse_offboarding'
            description = 'Reverse a Microsoft 365 offboarding (destructive). Disabled unless the server operator has enabled execution. Returns the reversal audit result.'
            inputSchema = [ordered]@{
                type = 'object'
                properties = [ordered]@{
                    userPrincipalName    = [ordered]@{ type = 'string'; description = 'UPN to restore' }
                    licenseSkuPartNumber = [ordered]@{ type = 'array'; items = [ordered]@{ type = 'string' }; description = 'Optional license SKU part numbers to assign, e.g. SPE_E3' }
                    resetPassword        = [ordered]@{ type = 'boolean'; description = 'Reset the password so the user can sign in again' }
                }
                required = @('userPrincipalName')
            }
        }
    )
}

function New-McpResult { param($Id, $Result); return [ordered]@{ jsonrpc = '2.0'; id = $Id; result = $Result } }
function New-McpError  { param($Id, [int]$Code, [string]$Message); return [ordered]@{ jsonrpc = '2.0'; id = $Id; error = [ordered]@{ code = $Code; message = $Message } } }

function Invoke-McpToolCall {
    param([string]$Name, $Arguments)
    $map = @{ preview_offboarding = 'preview'; check_rehire = 'rehire'; offboard_user = 'offboard'; reverse_offboarding = 'reverse' }
    if (-not $map.ContainsKey($Name)) {
        return [ordered]@{ content = @([ordered]@{ type = 'text'; text = "Unknown tool: $Name" }); isError = $true }
    }
    $res = Invoke-OffboardingService -Action $map[$Name] -Arguments $Arguments
    $text = $res | ConvertTo-Json -Depth 20
    return [ordered]@{ content = @([ordered]@{ type = 'text'; text = $text }); isError = (-not $res.ok) }
}

function Invoke-McpMessage {
    # Handles one parsed JSON-RPC message. Returns a response object, or $null
    # for notifications (which get no response). Unit-testable.
    param($Message)

    $method = "$($Message.method)"
    $hasId = ($null -ne $Message.PSObject.Properties['id']) -and ($null -ne $Message.id)

    # Notifications (no id) are not answered.
    if (-not $hasId) { return $null }
    $id = $Message.id

    switch ($method) {
        'initialize' {
            $clientVersion = "$($Message.params.protocolVersion)"
            $version = if ($clientVersion) { $clientVersion } else { $script:McpProtocol }
            return New-McpResult $id ([ordered]@{
                protocolVersion = $version
                capabilities    = [ordered]@{ tools = [ordered]@{} }
                serverInfo      = [ordered]@{ name = $script:McpServerName; version = $script:McpServerVersion }
            })
        }
        'tools/list' { return New-McpResult $id ([ordered]@{ tools = (Get-McpTools) }) }
        'tools/call' {
            $name = "$($Message.params.name)"
            $arguments = $Message.params.arguments
            return New-McpResult $id (Invoke-McpToolCall -Name $name -Arguments $arguments)
        }
        'ping' { return New-McpResult $id ([ordered]@{}) }
        default { return New-McpError $id -32601 "Method not found: $method" }
    }
}

function Start-McpServer {
    [Console]::Error.WriteLine("m365-offboarding MCP server ready (execute=$([bool](Test-ExecuteEnabled)))")
    while ($true) {
        $line = [Console]::In.ReadLine()
        if ($null -eq $line) { break }           # EOF: client closed stdin
        $line = $line.Trim()
        if ($line -eq '') { continue }

        try { $msg = $line | ConvertFrom-Json } catch {
            [Console]::Out.WriteLine((New-McpError $null -32700 'Parse error' | ConvertTo-Json -Compress -Depth 20))
            continue
        }

        $resp = Invoke-McpMessage -Message $msg
        if ($null -ne $resp) {
            [Console]::Out.WriteLine(($resp | ConvertTo-Json -Compress -Depth 20))
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Start-McpServer
}
