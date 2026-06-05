# Microsoft 365 Offboarding

A PowerShell tool that runs a complete, ordered Microsoft 365 user offboarding (decommissioning) against Microsoft Graph and Exchange Online, and produces an audit trail for every run.

It performs the ten steps below in a deliberate order, preserves the mailbox as a shared mailbox (no email or calendar data is lost), and writes an audit packet: optional per-step screenshots, a human-readable `AUDIT.md` timeline, and a machine-readable `audit.json`.

The tool runs interactively for a single admin at a keyboard, and unattended (app-only certificate auth, no prompts, JSON output) for automation: schedulers, AI agents, or a web portal. See [docs/INTEGRATION.md](docs/INTEGRATION.md).

> Not affiliated with or endorsed by Microsoft. Provided under the MIT license with no warranty. Test against a non-production account in your own tenant before using it for real.

## Why a fixed procedure

Most offboarding mistakes are not single dramatic errors. They are small omissions and ordering problems that each look harmless:

- A mailbox is converted to shared *after* the license is removed, which Microsoft does not allow, so the conversion silently fails or is skipped.
- A mobile device partnership is left in place, so a cached mail client keeps trying to refresh tokens for weeks and generates a stream of failed sign-in attempts.
- OAuth app grants and authentication methods are never reviewed, so third-party app access and MFA registrations outlive the account.
- No record is kept of what was done, so when someone asks "was this account actually secured?", answering it means a manual investigation instead of opening one file.

A fixed, ordered procedure with a built-in audit trail removes all four problems. Every step below links to Microsoft's own documentation so you can verify the reasoning rather than take it on trust.

## The ten steps

### Phase 1: Immediate lockout

**1. Reset the password and revoke all sign-in sessions.**
Resetting the password stops new interactive sign-ins. `Revoke-MgUserSignInSession` invalidates the refresh tokens that were already issued, so existing sessions cannot silently renew themselves. Microsoft documents this exact pair of actions as the emergency access-revocation sequence.
Reference: [Revoke user access in an emergency in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access)

**2. Block sign-in (disable the account).**
Setting `AccountEnabled` to `false` is Microsoft's first documented step for removing a former employee. It prevents the account from authenticating while leaving it intact so the mailbox can be preserved later.
References: [Remove a former employee, Step 1](https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/remove-former-employee) and [Revoke user access](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access)

**3. Remove ActiveSync mobile device partnerships.**
A phone or tablet that had the mailbox configured keeps an Exchange ActiveSync partnership. After the password is reset, that partnership keeps attempting to refresh its tokens, which produces repeated failed sign-in attempts and sign-in prompts on the former user's personal device. Removing the partnership with `Remove-MobileDevice` stops this. Microsoft calls this out as part of removing a former employee ("wipe and block a former employee's mobile device").
References: [Remove a former employee, Step 3](https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/remove-former-employee) and [Remove-MobileDevice](https://learn.microsoft.com/en-us/powershell/module/exchange/remove-mobiledevice)

### Phase 2: Authorization cleanup

**4. Remove registered authentication (MFA) methods.**
Enumerates the account's authentication methods and deletes each removable one (Microsoft Authenticator, phone, FIDO2 keys, Windows Hello for Business, email, software OATH, Temporary Access Pass). The password method cannot be removed and is left in place. This clears stale MFA registrations so they cannot be reused if the account is ever re-enabled.
Reference: [Microsoft Graph authentication methods API](https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethods-overview)

**5. Revoke OAuth app grants.**
Enumerates the user's delegated OAuth2 permission grants and revokes them with `Remove-MgOauth2PermissionGrant`. Without this, third-party and line-of-business apps the user had consented to can retain access tied to the account.
Reference: [Remove-MgOauth2PermissionGrant](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/remove-mgoauth2permissiongrant)

**6. Remove the user from groups and distribution lists.**
Removes cloud-managed group memberships so the account stops inheriting access and mail. Groups synchronized from on-premises Active Directory are detected and skipped, because they must be changed in on-premises AD, not in the cloud.
Reference: [Remove a former employee, Step 8 (remove from groups and admin roles)](https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/remove-former-employee)

### Phase 3: Mailbox transition and hardening

**7. Configure forwarding, auto-reply, or delegation (optional).**
If the work needs to continue, set SMTP forwarding and grant another user Full Access and Send As. This is optional and only runs when requested.
Reference: [Remove a former employee, Step 4 (forward email or convert to shared)](https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/remove-former-employee)

**8. Convert the user mailbox to a shared mailbox.**
This preserves all email and calendar data in a mailbox several people can access, and it must happen *before* the license is removed. Microsoft is explicit:

> "The user mailbox needs a license assigned to it before you convert it to a shared mailbox. Otherwise, you won't see the option to convert the mailbox. If you've removed the license, add it back so you can convert the mailbox. After converting the user mailbox to a shared mailbox, you can remove the license from the user's account."

A mailbox under 50 GB does not need a license as a shared mailbox. Do not delete the account: Microsoft requires it to remain as the anchor for the shared mailbox.
Reference: [Convert a user mailbox to a shared mailbox](https://learn.microsoft.com/en-us/microsoft-365/admin/email/convert-user-mailbox-to-shared-mailbox)

**9. Remove the Microsoft 365 licenses.**
Now safe, because step 8 already preserved the mailbox. `Set-MgUserLicense` removes every assigned SKU. The account stays in Entra ID, unlicensed, as the anchor for the shared mailbox.
References: [Remove a former employee, Step 6](https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/remove-former-employee) and [Remove licenses with PowerShell](https://learn.microsoft.com/en-us/microsoft-365/enterprise/remove-licenses-from-user-accounts-with-microsoft-365-powershell)

**10. Apply a Conditional Access block on the user principal.**
Defense in depth. The user is added to a security group ("Offboarded Users" by default) that a Conditional Access policy blocks from all sign-ins. Even if the account is mistakenly re-enabled later, Conditional Access rejects every authentication. On first run the tool creates the group and the policy; the policy is created in report-only mode so a tenant admin reviews and enables it.
Reference: [What is Conditional Access in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)

## Why this order

Two rules drive the sequence:

1. **Lock the account before touching anything else.** Phase 1 kills authentication first, so nothing can happen on the account while the rest of the cleanup runs.
2. **Convert the mailbox to shared before removing the license (step 8 before step 9).** Microsoft hides the conversion option once the license is gone. Doing these in the wrong order means either a failed conversion or having to re-add a license to fix it. The documentation quote in step 8 is the authority for this.

Step 10 is intentionally last and intentionally separate from disabling the account, so there is a policy-layer block that survives an accidental re-enable.

## Requirements

- PowerShell 5.1 or later on Windows, or PowerShell 7 or later on any platform. Screenshot capture and the folder picker are Windows-only and are skipped automatically elsewhere.
- The following modules, installed automatically on first run if missing:
  `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Users.Actions`, `Microsoft.Graph.Identity.SignIns`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.Groups`, `ExchangeOnlineManagement`.
- An account (interactive) or app registration (unattended) with these Microsoft Graph permissions, plus Exchange Online management rights:
  `User.ReadWrite.All`, `Directory.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`, `Application.ReadWrite.All`, `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All`. The optional SharePoint upload also needs `Sites.ReadWrite.All`, which the tool requests only when an upload may occur (a site URL was supplied, or you run interactively without `-SkipSharePointUpload`). If you never use the upload, that scope is never requested.

## Usage

### Interactive (single admin)

On Windows, double-click `Run-Offboarding.bat`, or run:

```powershell
.\Invoke-M365Offboarding.ps1
```

It prompts for the target user, the audit folder, signs you in through the browser (full MFA supported), and shows a menu. Choose `A` to run all ten steps in order, or pick individual steps.

Run a known user end to end without the menu:

```powershell
.\Invoke-M365Offboarding.ps1 -UserPrincipalName jdoe@contoso.com -AuditRoot C:\Audits -All
```

Preview without making changes (the script supports `-WhatIf`):

```powershell
.\Invoke-M365Offboarding.ps1 -UserPrincipalName jdoe@contoso.com -AuditRoot C:\Audits -All -WhatIf
```

### Unattended (automation)

App-only certificate auth, no prompts, JSON output. Suitable for a scheduled task, an AI agent tool call, or a backend service:

```powershell
.\Invoke-M365Offboarding.ps1 -Unattended `
    -UserPrincipalName jdoe@contoso.com -AuditRoot C:\Audits -NoScreenshots `
    -TenantId contoso.onmicrosoft.com -ClientId <app-id> `
    -CertificateThumbprint <thumbprint> -Organization contoso.onmicrosoft.com `
    -JsonOutPath C:\Audits\jdoe.json
```

See [docs/INTEGRATION.md](docs/INTEGRATION.md) for the app registration setup, the `audit.json` schema, and examples of calling the tool from PHP and from an AI agent.

## The audit packet

Each run produces a folder named `<user>_<yyyy-MM-dd>` containing:

```
jdoe_2026-06-05/
  step_01_password_reset_and_sessions_revoked_142315.png   (Windows only)
  ...
  step_10_conditional_access_applied_142740.png            (Windows only)
  AUDIT.md
  audit.json
```

`AUDIT.md` has the identification table, a UTC timeline of every action and result, detailed per-step notes, and a final-state confirmation (account enabled, recipient type, license count, mobile device count). `audit.json` carries the same data in a structured form for programmatic consumption.

## Storing the audit packet in SharePoint

The audit packet is meant to live in SharePoint for later review. After the run completes, the tool can upload the whole folder (screenshots, `AUDIT.md`, `audit.json`) to a SharePoint document library for you.

- **Linked:** pass `-SharePointSiteUrl https://contoso.sharepoint.com/sites/IT` (and optionally `-SharePointFolderPath "Offboarding Audits"`). The tool resolves the site's default document library, creates the per-user subfolder, and uploads every file. The resulting SharePoint link is printed and recorded in both `AUDIT.md` and `audit.json`. A local copy is also kept.
- **Interactive prompt:** if you do not pass a site URL, the tool asks whether to upload and, if you say yes, prompts for the site URL and folder.
- **Not linked:** if you decline, pass `-SkipSharePointUpload`, or the upload fails, the packet stays local and the tool tells you exactly which folder to upload to SharePoint manually.

Uploading uses the Microsoft Graph token already established at sign-in and needs the `Sites.ReadWrite.All` permission. That scope is requested at sign-in only when an upload may occur, so a run that never touches SharePoint never asks for it. If the permission is not consented, skip the upload and move the folder by hand. The offboarding itself never fails because of an upload problem; a failed upload only falls back to the manual-upload message.

## Parameters

| Parameter | Purpose |
|---|---|
| `-UserPrincipalName` | UPN of the account to offboard. |
| `-AuditRoot` | Parent folder for the audit packet. |
| `-Steps 1,2,3` | Run only these step numbers. |
| `-All` | Run all ten steps without the menu. |
| `-Unattended` | No prompts. Requires `-UserPrincipalName` and `-AuditRoot`. |
| `-NoScreenshots` | Skip screenshot capture. |
| `-ForwardingAddress` | Configure forwarding in step 7. |
| `-DelegateTo` | Grant Full Access and Send As in step 7. |
| `-SkipMailboxConversion` | Skip step 8 (for example a hard-delete workflow). |
| `-OffboardedGroupName` | Security group name for the CA block. Default "Offboarded Users". |
| `-BlockPolicyName` | Conditional Access policy name. |
| `-TenantId` / `-ClientId` / `-CertificateThumbprint` / `-Organization` | App-only auth for unattended runs. |
| `-JsonOutPath` | Explicit path for `audit.json`. |
| `-SharePointSiteUrl` | Upload the finished packet to this SharePoint site's document library. |
| `-SharePointFolderPath` | Destination folder in the library (default: library root). |
| `-SkipSharePointUpload` | Never upload and never prompt; keep the packet local. |
| `-WhatIf` | Preview every change without applying it. |

## Reversing an offboarding

If an account was offboarded by mistake, use the companion script `Invoke-M365OffboardingReversal.ps1`. It restores the reversible parts in the correct order (re-enable, lift the Conditional Access block, re-license, convert the mailbox back) and clearly reports what cannot be put back.

Recover the original licenses straight from the offboarding record and reset the password:

```powershell
.\Invoke-M365OffboardingReversal.ps1 -UserPrincipalName jdoe@contoso.com `
    -FromAuditJson C:\Audits\jdoe_2026-06-05\audit.json -ResetPassword
```

Or specify the license directly (by SKU part number or GUID), or run with no license argument to pick from a list interactively:

```powershell
.\Invoke-M365OffboardingReversal.ps1 -UserPrincipalName jdoe@contoso.com -LicenseSkuPartNumber SPE_E3 -ResetPassword
```

What it restores, in order:

1. Re-enable sign-in (`AccountEnabled = true`)
2. Remove the user from the "Offboarded Users" group (lifts the Conditional Access block)
3. Re-assign a Microsoft 365 license
4. Convert the shared mailbox back to a regular user mailbox (a regular mailbox needs a license, so this runs after re-licensing)
5. Reset the password (`-ResetPassword`) so the user can sign in again
6. Clear forwarding the offboarding set (use `-KeepForwarding` to leave it)
7. Optionally remove added Full Access / Send As delegations (`-RemoveDelegation`)

It runs interactively or unattended (app-only auth), supports `-WhatIf`, and writes its own reversal record (`REVERSAL_AUDIT.md` and `reversal-audit.json`). It needs the same kind of permissions as the offboarding tool, plus `Organization.Read.All` to read the tenant's license SKUs.

**Cannot be restored automatically:** removed authentication (MFA) methods, removed mobile device (ActiveSync) partnerships, and revoked OAuth grants. The script reports these so you can have the user re-register MFA, re-add their mailbox on devices, and re-consent to apps.

## Roadmap

- A dry-run / training mode that exercises every step against a dummy account.
- Rehire detection that warns when a display name was offboarded before.
- A thin REST wrapper and an AI-agent tool manifest built on the existing `audit.json` contract (see [docs/INTEGRATION.md](docs/INTEGRATION.md)).

## License

MIT. See [LICENSE](LICENSE).

## Contributing

Issues and pull requests are welcome. Useful contributions: support for additional authentication method types as Microsoft Graph adds them, packaging as a PowerShell module, and the roadmap items above.
