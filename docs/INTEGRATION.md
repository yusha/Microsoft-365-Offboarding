# Integration guide

This tool was built so it can run unattended and be driven by other software: a scheduled task, a backend service behind a web portal, or an AI agent. This guide covers the app registration it needs, the `audit.json` contract it returns, and worked examples for PHP and for an AI agent.

## How automation works

In unattended mode the script:

- takes all inputs as parameters (no prompts),
- authenticates with an app registration and a certificate (no interactive sign-in),
- runs the requested steps,
- writes `audit.json` (and `AUDIT.md`), and
- sets a non-zero exit code if any step failed.

That means any language that can launch a process and read a file can integrate it. There is no long-running service to host; you invoke the script per offboarding and read the JSON it produces.

## App registration setup (one time)

1. In the Entra admin center, create an app registration.
2. Add these **application** Microsoft Graph permissions and grant admin consent:
   `User.ReadWrite.All`, `Directory.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`, `Application.ReadWrite.All`, `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All`.
3. For Exchange Online app-only access, register the app for Exchange management and assign it a role that can run the mailbox cmdlets (for example Exchange Recipient Administrator). See [App-only authentication for Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2).
4. Create or upload a certificate to the app registration, and install the matching certificate (with private key) on the machine that will run the script. Pass its thumbprint with `-CertificateThumbprint`.

App-only permissions are powerful. Scope them to exactly the list above, keep the certificate private key protected, and prefer running on a hardened, restricted host.

## Invoking unattended

```powershell
.\Invoke-M365Offboarding.ps1 -Unattended `
    -UserPrincipalName jdoe@contoso.com -AuditRoot C:\Audits -NoScreenshots `
    -TenantId contoso.onmicrosoft.com -ClientId <app-id> `
    -CertificateThumbprint <thumbprint> -Organization contoso.onmicrosoft.com `
    -JsonOutPath C:\Audits\jdoe.json
```

Exit code `0` means no step reported a failure. A non-zero exit code means at least one step failed; read `audit.json` to see which.

## The audit.json contract

```json
{
  "tool": "Invoke-M365Offboarding",
  "schemaVersion": "1.0",
  "targetUpn": "jdoe@contoso.com",
  "performedBy": "Offboarding App (app-id)",
  "offboardingDate": "2026-06-05",
  "startedUtc": "2026-06-05 18:23:11 UTC",
  "completedUtc": "2026-06-05 18:25:02 UTC",
  "steps": [
    {
      "step": 1,
      "timestampUtc": "2026-06-05 18:23:14 UTC",
      "action": "Reset password and revoked all sign-in sessions",
      "result": "Success",
      "screenshot": null,
      "details": "Password set to a random value (not retained)..."
    }
  ],
  "finalState": {
    "User principal name": "jdoe@contoso.com",
    "Account enabled": false,
    "Assigned licenses": "None",
    "Recipient type details": "SharedMailbox",
    "Mobile device partnerships": 0
  },
  "success": true
}
```

Field notes:

- `success` is `true` only when no step result begins with `FAILED`.
- Each `steps[].result` is one of `Success`, `Skipped`, `Completed with N failure(s)`, or `FAILED: <message>`.
- `step` `0` is the connection event, not one of the ten actions.
- `screenshot` is a filename relative to the audit folder, or `null` when screenshots were disabled.

Treat `audit.json` as the integration surface. The console output and `AUDIT.md` are for humans; the JSON is the stable contract.

## Example: PHP backend for a web portal

A portal endpoint that offboards a user and returns the structured result. Run this on a Windows host that has PowerShell, the modules, and the certificate installed. Validate and authorize the request in your application before calling this.

```php
<?php
// offboard.php  (call only from authenticated, authorized server-side code)

function offboardUser(string $upn): array {
    // Allowlist the UPN format. Never interpolate raw input into a command.
    if (!preg_match('/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$/', $upn)) {
        throw new InvalidArgumentException('Invalid UPN');
    }

    $auditRoot = 'C:\\Audits';
    $jsonOut   = $auditRoot . '\\' . preg_replace('/[^A-Za-z0-9]/', '_', $upn) . '.json';

    $args = [
        'powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', 'C:\\Tools\\Invoke-M365Offboarding.ps1',
        '-Unattended', '-NoScreenshots',
        '-UserPrincipalName', $upn,
        '-AuditRoot', $auditRoot,
        '-JsonOutPath', $jsonOut,
        '-TenantId', getenv('M365_TENANT'),
        '-ClientId', getenv('M365_CLIENT_ID'),
        '-CertificateThumbprint', getenv('M365_CERT_THUMBPRINT'),
        '-Organization', getenv('M365_ORG'),
    ];

    // proc_open with an argument array avoids shell injection.
    $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($args, $descriptors, $pipes);
    if (!is_resource($proc)) {
        throw new RuntimeException('Failed to start PowerShell');
    }
    stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]);
    foreach ($pipes as $p) { fclose($p); }
    $exitCode = proc_close($proc);

    if (!is_file($jsonOut)) {
        throw new RuntimeException("No audit.json produced (exit $exitCode)");
    }
    $result = json_decode(file_get_contents($jsonOut), true);
    $result['_exitCode'] = $exitCode;
    return $result;
}
```

Security notes for the portal path:

- Pass secrets (tenant, client id, thumbprint, organization) as environment variables or a secret store, never in the URL or page.
- Build the command as an argument array (`proc_open([...])`), not a concatenated string, so a malicious UPN cannot inject arguments.
- Enforce authentication, authorization, and an approval record in the application before calling `offboardUser`.
- Run the worker under a low-privilege OS account that only has access to the certificate.

## Example: AI agent tool

Because the tool takes structured inputs and returns structured JSON, it maps cleanly to an agent tool definition. The agent decides to call it; your executor runs the script and feeds `audit.json` back as the tool result.

Tool schema (JSON Schema style):

```json
{
  "name": "offboard_m365_user",
  "description": "Offboard a Microsoft 365 user: lock the account, clean up authorization, preserve the mailbox as shared, and apply a Conditional Access block. Returns a structured audit result.",
  "input_schema": {
    "type": "object",
    "properties": {
      "user_principal_name": { "type": "string", "description": "UPN of the account to offboard, e.g. jdoe@contoso.com" },
      "forwarding_address":  { "type": "string", "description": "Optional UPN to forward mail to" },
      "delegate_to":         { "type": "string", "description": "Optional UPN to grant Full Access and Send As" },
      "steps":               { "type": "array", "items": { "type": "integer", "minimum": 1, "maximum": 10 }, "description": "Optional subset of steps; omit to run all ten" }
    },
    "required": ["user_principal_name"]
  }
}
```

Executor responsibilities (keep these out of the model's control):

- Require a human approval or policy check before the call actually runs. Offboarding is destructive.
- Map the tool input to fixed script parameters; never let the model supply auth parameters or the audit root.
- Run the script unattended, then return the parsed `audit.json` as the tool result so the agent can report exactly which steps succeeded.
- On a non-zero exit code, return the failed steps from `audit.json` rather than a generic error, so the agent can explain what to retry.

A safe agent pattern is two tools: a read-only `preview_m365_offboarding` that runs the script with `-WhatIf` and returns the planned actions, and `offboard_m365_user` that performs them only after approval.

## Anthropic / Claude note

If you build the agent on the Claude API, define `offboard_m365_user` as a tool and let the model request it; your code executes the script and returns `audit.json` as the `tool_result`. Keep the destructive call behind human approval, and consider exposing the `-WhatIf` preview as a separate read-only tool so the model can plan before acting. For current tool-use details, see the Anthropic documentation.
