<div align="center">

# Microsoft 365 Offboarding

### A complete, ordered, audit-trailed Microsoft 365 user offboarding — in pure PowerShell.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207-5391FE.svg?logo=powershell&logoColor=white)](#requirements)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Cloud%20Shell-lightgrey.svg)](#-run-it-in-azure-cloud-shell)
[![Release](https://img.shields.io/github/v/release/yusha/Microsoft-365-Offboarding?color=blue)](https://github.com/yusha/Microsoft-365-Offboarding/releases)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#requirements)

**One command (or one double-click)** locks an account, cleans up its access, preserves the mailbox as a shared mailbox, and writes a tamper-evident audit packet, with every step backed by Microsoft's own documentation.

Developed by **[Yusha](https://yusha.ca)**

</div>

> [!NOTE]
> Not affiliated with or endorsed by Microsoft. Provided under the [MIT License](LICENSE) with no warranty, see the [Disclaimer](#-disclaimer). Always test against a non-production account in your own tenant first, double-click **`demo.bat`** for a safe, no-sign-in walkthrough.

---

## Contents

- [Highlights](#-highlights)
- [Quick start](#-quick-start)
- [What's included](#-whats-included)
- [The ten-step procedure](#-the-ten-step-procedure)
- [Usage](#-usage)
- [The audit packet](#-the-audit-packet)
- [Store the packet in SharePoint](#-store-the-packet-in-sharepoint)
- [Reverse an offboarding](#-reverse-an-offboarding)
- [Rehire detection](#-rehire-detection)
- [Run it in Azure Cloud Shell](#-run-it-in-azure-cloud-shell)
- [REST API and MCP server](#-rest-api-and-mcp-server)
- [Parameters](#-parameters)
- [Requirements](#requirements)
- [Disclaimer](#-disclaimer)
- [Roadmap and contributing](#-roadmap-and-contributing)

---

## ✨ Highlights

| | |
|---|---|
| **Ordered 10-step procedure** | A fixed sequence that locks, cleans, and hardens, in the order Microsoft's docs require. |
| **Mailbox preserved** | Converted to a shared mailbox before the license is removed, so no email or calendar data is lost. |
| **Audit packet every run** | Per-step screenshots, a human-readable `AUDIT.md`, and a machine-readable `audit.json`. |
| **Safe demo / training mode** | `demo.bat` and `-DryRun` walk every step with no sign-in and no changes. |
| **Reversal companion** | Undo a mistaken offboarding and get a clear report of what cannot be restored. |
| **Rehire detection** | Know before you re-hire: was this person offboarded before? Checks local, SharePoint, and live-tenant evidence. |
| **Runs anywhere** | Windows, Linux, and the Azure Portal's Cloud Shell, interactive or fully unattended (app-only auth). |
| **REST API and MCP server** | Drive it from a web portal, a scheduler, or an AI client such as Claude Desktop. |
| **Zero dependencies** | Pure PowerShell. The required Microsoft modules install themselves on first run. |

---

## 🚀 Quick start

**Just want to see what it does?** On Windows, double-click **`demo.bat`** (or run `.\Invoke-M365Offboarding.ps1 -DryRun`). It walks through all ten steps with **no sign-in, no modules, and no changes**, then writes a sample audit packet.

**Offboard a user (interactive):**

```powershell
.\Invoke-M365Offboarding.ps1
```

You will be prompted for the user and audit folder, signed in through the browser (MFA supported), and shown a menu, choose `A` to run all ten steps.

**Offboard a user end to end (no menu):**

```powershell
.\Invoke-M365Offboarding.ps1 -UserPrincipalName jdoe@contoso.com -AuditRoot C:\Audits -All
```

> [!TIP]
> Add `-WhatIf` to any real run to preview every change against the live account without applying it.

---

## 📦 What's included

| File | What it is |
|---|---|
| **`Invoke-M365Offboarding.ps1`** | The main tool: the 10-step offboarding, audit packet, dry-run mode, SharePoint upload. |
| **`Invoke-M365OffboardingReversal.ps1`** | Companion that safely reverses an offboarding. |
| **`Test-M365Rehire.ps1`** | Read-only rehire / prior-offboarding detection. |
| **`demo.bat`** | Double-click to run a safe dry-run demo. |
| **`Run-Offboarding.bat` / `Run-Reversal.bat` / `Run-RehireCheck.bat`** | Windows double-click launchers. |
| **`server/Start-RestApi.ps1`** | A JSON REST API in front of the tools. |
| **`server/Start-McpServer.ps1`** | A Model Context Protocol server for AI clients (Claude Desktop, etc.). |
| **`docs/INTEGRATION.md`** | App-registration setup, the `audit.json` schema, and PHP / AI-agent examples. |
| **`examples/`** | A working PHP wrapper and a sample `audit.json`. |

---

## 🔐 The ten-step procedure

Most offboarding mistakes are not dramatic, they are small omissions and ordering problems: a mailbox converted to shared *after* the license is removed (which Microsoft does not allow), a mobile partnership left behind that retries auth for weeks, OAuth grants and MFA methods never reviewed, and no record of what was actually done. A fixed, ordered procedure with a built-in audit trail removes all four.

| # | Phase | Step | Key cmdlet |
|:-:|---|---|---|
| 1 | **Immediate lockout** | Reset password and revoke all sign-in sessions | `Revoke-MgUserSignInSession` |
| 2 | | Block sign-in (disable the account) | `Update-MgUser -AccountEnabled:$false` |
| 3 | | Remove ActiveSync mobile device partnerships | `Remove-MobileDevice` |
| 4 | **Authorization cleanup** | Remove registered authentication (MFA) methods | `Remove-MgUserAuthentication*Method` |
| 5 | | Revoke OAuth app grants | `Remove-MgOauth2PermissionGrant` |
| 6 | | Remove from groups and distribution lists | `Remove-MgGroupMemberByRef` |
| 7 | **Mailbox transition & hardening** | Configure forwarding / delegation (optional) | `Set-Mailbox`, `Add-MailboxPermission` |
| 8 | | Convert the user mailbox to a shared mailbox | `Set-Mailbox -Type Shared` |
| 9 | | Remove Microsoft 365 licenses | `Set-MgUserLicense` |
| 10 | | Apply a Conditional Access block on the user principal | `New-MgIdentityConditionalAccessPolicy` |

**Why this order:** Phase 1 kills authentication first, so nothing can happen on the account while the rest runs. Step 8 must come before step 9 because Microsoft hides the "convert to shared" option once the license is removed. Step 10 is intentionally last and separate from disabling the account, so a policy-layer block survives an accidental re-enable.

<details>
<summary><strong>Full rationale and Microsoft documentation for each step</strong></summary>

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

</details>

---

## 🖥️ Usage

### Interactive (single admin)

Double-click `Run-Offboarding.bat`, or run `.\Invoke-M365Offboarding.ps1`. It prompts for the target user and audit folder, signs you in (MFA supported), and shows a menu.

### Training / dry-run mode

To learn or demonstrate the tool with **no risk**, double-click **`demo.bat`** or run `-DryRun`. It walks through all ten steps, narrates exactly what each one would do and which cmdlets it uses, and writes a clearly marked sample audit packet, but never signs in, never touches the tenant, and makes no change. It needs no admin account and works offline on any platform.

```powershell
.\Invoke-M365Offboarding.ps1 -DryRun
```

The sample `audit.json` is tagged `"dryRun": true`, and `AUDIT.md` is headed as a training run. Dry-run records are ignored by the rehire check and the re-run guard, so practising never affects real detection. (Difference from `-WhatIf`: `-WhatIf` makes a real connection and reads real data for a specific account but applies no changes; `-DryRun` is fully simulated with no sign-in or account.)

### Unattended (automation)

App-only certificate auth, no prompts, JSON output, suitable for a scheduled task, an AI agent tool call, or a backend service:

```powershell
.\Invoke-M365Offboarding.ps1 -Unattended `
    -UserPrincipalName jdoe@contoso.com -AuditRoot C:\Audits -NoScreenshots `
    -TenantId contoso.onmicrosoft.com -ClientId <app-id> `
    -CertificateThumbprint <thumbprint> -Organization contoso.onmicrosoft.com `
    -JsonOutPath C:\Audits\jdoe.json
```

See [docs/INTEGRATION.md](docs/INTEGRATION.md) for the app registration setup and the `audit.json` schema.

---

## 📁 The audit packet

Each run produces a folder named `<user>_<yyyy-MM-dd>` containing:

```
jdoe_2026-06-05/
  step_01_password_reset_and_sessions_revoked_142315.png   (when screenshots are available)
  ...
  step_10_conditional_access_applied_142740.png            (when screenshots are available)
  transcript.txt                                           (instead of screenshots on a headless host)
  AUDIT.md                                                 (human-readable)
  audit.html                                               (beautiful self-contained report, double-click to view)
  audit.json                                               (machine-readable)
```

Three views of the same record:

- **`audit.html`** — a styled, self-contained HTML report with inline CSS and no external dependencies. Double-click it to view the whole packet offline in any browser: the identification and timeline (with colour-coded result badges), a screenshot gallery, the per-step notes, and the final state. Keep the folder together so the screenshots display.
- **`AUDIT.md`** — the same content in Markdown: identification, a UTC timeline, per-step notes, and a final-state confirmation (account enabled, recipient type, license count, mobile device count).
- **`audit.json`** — the same data in a structured form for programmatic consumption.

---

## ☁️ Store the packet in SharePoint

The audit packet is meant to live in SharePoint for later review. After a run, the tool can upload the whole folder for you.

- **Linked:** pass `-SharePointSiteUrl https://contoso.sharepoint.com/sites/IT` (and optionally `-SharePointFolderPath "Offboarding Audits"`). The tool resolves the site's default document library, creates the per-user subfolder, uploads every file, and records the resulting link in `AUDIT.md` and `audit.json`. A local copy is kept too.
- **Interactive prompt:** without a site URL, the tool asks whether to upload and prompts for the site and folder.
- **Not linked:** if you decline, pass `-SkipSharePointUpload`, or the upload fails, the packet stays local and the tool tells you exactly which folder to upload by hand.

Uploading needs `Sites.ReadWrite.All`, requested only when an upload may actually occur. A failed upload never fails the offboarding, it just falls back to the manual-upload message.

---

## ↩️ Reverse an offboarding

If an account was offboarded by mistake, use `Invoke-M365OffboardingReversal.ps1`. It restores the reversible parts in the correct order and clearly reports what cannot be put back.

```powershell
# Recover the original licenses from the offboarding record and reset the password:
.\Invoke-M365OffboardingReversal.ps1 -UserPrincipalName jdoe@contoso.com `
    -FromAuditJson C:\Audits\jdoe_2026-06-05\audit.json -ResetPassword

# Or specify the license directly (or omit it to pick from a list):
.\Invoke-M365OffboardingReversal.ps1 -UserPrincipalName jdoe@contoso.com -LicenseSkuPartNumber SPE_E3 -ResetPassword
```

**Restores, in order:** re-enable sign-in → remove from the "Offboarded Users" group (lifts the CA block) → re-assign a license → convert the shared mailbox back to a regular mailbox (after re-licensing, because a regular mailbox needs a license) → reset the password → clear forwarding → optionally remove added delegations.

> [!WARNING]
> **Cannot be restored automatically:** removed authentication (MFA) methods, removed mobile device partnerships, and revoked OAuth grants. The script reports these so the user can re-register MFA, re-add their mailbox on devices, and re-consent to apps.

It runs interactively or unattended, supports `-WhatIf`, writes its own `REVERSAL_AUDIT.md` / `reversal-audit.json`, and needs `Organization.Read.All` in addition to the offboarding permissions (to read license SKUs).

---

## 🔁 Rehire detection

Before onboarding a returning employee (or re-running an offboarding), check whether the person was offboarded before with `Test-M365Rehire.ps1`. It is **read-only**.

```powershell
.\Test-M365Rehire.ps1 -UserPrincipalName jdoe@contoso.com -AuditRoot C:\Audits
.\Test-M365Rehire.ps1 -DisplayName "Jane Doe" -AuditRoot C:\Audits -SkipTenantCheck
.\Test-M365Rehire.ps1 -UserPrincipalName jdoe@contoso.com -SharePointSiteUrl https://contoso.sharepoint.com/sites/IT
```

It draws on up to three sources and prints a verdict:

- **Local audit history** — scans an audit root for past `audit.json` records (by UPN or display name).
- **SharePoint audit history** — when `-SharePointSiteUrl` is given, scans the document library directly over Graph (no local sync). The durable place to keep packets when technicians' machines are disposable.
- **Live tenant** — finds matching accounts and flags those that look offboarded (disabled, unlicensed, in the "Offboarded Users" group, or backed by a shared mailbox). This survives even when every local file and the script itself are deleted.

| Verdict | Meaning |
|---|---|
| `RehireLikely` | A previously offboarded account still exists. Restore it with the reversal script instead of creating a new one. |
| `PriorRecordOnly` | A past record exists but no matching account (it may have been deleted, restorable for 30 days). |
| `AccountAlreadyExists` | A matching active account exists that does not look offboarded. |
| `NoEvidence` | Nothing found; treat as a new hire. |

The offboarding tool also runs a lightweight version of this automatically: it warns before offboarding a user who already has a record in the chosen audit root.

---

## ☁️ Run it in Azure Cloud Shell

A Global Administrator can run the tool straight from the Azure Portal's Cloud Shell (the `>_` icon), no local machine needed. Pick **PowerShell**, then:

```powershell
git clone https://github.com/yusha/Microsoft-365-Offboarding
cd Microsoft-365-Offboarding
./Invoke-M365Offboarding.ps1 -UserPrincipalName jdoe@contoso.com -AuditRoot ~/clouddrive/audits -All `
    -SharePointSiteUrl https://contoso.sharepoint.com/sites/IT
```

- **Sign-in** uses device-code flow (no browser pop-up): enter the code at `microsoft.com/devicelogin`.
- **Modules** install once and persist in your Cloud Shell profile.
- **Screenshots** are not possible (headless, no desktop); the tool says so and records a `transcript.txt` instead. Use `-SharePointSiteUrl` so the packet leaves the session immediately.

On a **Linux desktop** (X11/Wayland) screenshots *are* supported via `grim`/`scrot`/`gnome-screenshot`/`import`, and the tool offers to install one if none is present. For fully hands-off runs, see the **Azure Automation runbook** note in [docs/INTEGRATION.md](docs/INTEGRATION.md).

---

## 🌐 REST API and MCP server

The [`server/`](server) folder ships two dependency-free PowerShell servers built on the `audit.json` contract, so you can drive the tools from a web portal, a scheduler, or an AI client.

**REST API** — `server/Start-RestApi.ps1` (System.Net.HttpListener):

```bash
curl -X POST http://127.0.0.1:8770/preview \
  -H 'Authorization: Bearer <token>' -d '{"userPrincipalName":"jdoe@contoso.com"}'
```

Routes: `GET /health`, `POST /preview`, `POST /rehire`, `POST /offboard`, `POST /reverse`. Bearer-token auth on every route except `/health`.

**MCP server** — `server/Start-McpServer.ps1` speaks Model Context Protocol over stdio, ready for **Claude Desktop** or another MCP client. Tools: `preview_offboarding`, `check_rehire`, `offboard_user`, `reverse_offboarding`.

> [!IMPORTANT]
> Both keep `preview` (dry-run) and `rehire` (read-only) always available, while the destructive `offboard` and `reverse` are **disabled unless** the operator sets `M365_OFFBOARDING_ALLOW_EXECUTE=1` and provides app-only credentials. Credentials never come from callers. See [server/README.md](server/README.md) for setup, the Claude Desktop config, and the full security model.

---

## ⚙️ Parameters

<details>
<summary><strong>Offboarding tool parameters</strong></summary>

| Parameter | Purpose |
|---|---|
| `-UserPrincipalName` | UPN of the account to offboard. |
| `-AuditRoot` | Parent folder for the audit packet. |
| `-Steps 1,2,3` | Run only these step numbers. |
| `-All` | Run all ten steps without the menu. |
| `-DryRun` | Training mode: simulate all steps, no sign-in, no changes. |
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

</details>

---

## Requirements

<details>
<summary><strong>PowerShell, modules, and permissions</strong></summary>

- **PowerShell** 5.1+ on Windows, or 7+ on any platform. The folder picker is Windows-only (a path prompt is used elsewhere). Screenshots are captured on Windows and on a Linux desktop with a capture tool; on a headless host such as Cloud Shell they are replaced by a `transcript.txt`.
- **Modules** (installed automatically on first run if missing): `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Users.Actions`, `Microsoft.Graph.Identity.SignIns`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.Groups`, `ExchangeOnlineManagement`.
- **Permissions** (an admin account interactively, or an app registration unattended), plus Exchange Online management rights: `User.ReadWrite.All`, `Directory.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`, `Application.ReadWrite.All`, `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All`. The optional SharePoint upload also needs `Sites.ReadWrite.All`, requested only when an upload may occur. The reversal script additionally needs `Organization.Read.All`.

</details>

---

## ⚠️ Disclaimer

<div align="center">

[![Use at your own risk](https://img.shields.io/badge/%E2%9A%A0%20USE%20AT%20YOUR%20OWN%20RISK-NO%20WARRANTY%20%C2%B7%20NO%20LIABILITY-F4C20D?style=for-the-badge&labelColor=B8860B)](#-disclaimer)

</div>

> The binding legal terms for this software are in the **[MIT License](LICENSE)**, which is the governing legal instrument. The disclaimer below restates and expands on its no-warranty and no-liability provisions in plain language; it supplements, and does not replace, that license.

**No warranty.** This software is provided free of charge, **"AS IS"** and **"AS AVAILABLE"**, without warranty of any kind, whether express, implied, or statutory, including but not limited to the implied warranties of merchantability, fitness for a particular purpose, title, and non-infringement. The author does not warrant that the software is error-free or secure, that it will operate without interruption, or that it will meet your requirements or produce any particular result.

**Powerful, irreversible actions.** This tool performs administrative operations against a live Microsoft 365 tenant, including disabling accounts, revoking sessions, removing authentication methods, revoking app grants, removing licenses, converting mailboxes, and applying Conditional Access policies. **Some of these actions cannot be undone.** You are solely responsible for understanding what the tool does and for any and all consequences of running it.

**Limitation of liability.** To the maximum extent permitted by applicable law, in no event shall the author or any contributor be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, including without limitation any direct, indirect, incidental, special, consequential, exemplary, or punitive damages, loss of data, loss of profits, business interruption, account lockout, or service disruption, arising from or in connection with the software or the use of (or inability to use) the software, even if advised of the possibility of such damages. **By downloading, running, or using this software you agree that you will not hold, and cannot legally hold, the author or contributors responsible or liable for any such outcome.**

**Your responsibilities.** You are responsible for: obtaining proper authorization before offboarding any account; testing against a non-production account in your own tenant first (use `demo.bat` / `-DryRun`); maintaining adequate backups; and complying with all applicable laws, regulations, contractual obligations, and organizational policies. This software is **not legal, security, compliance, or other professional advice**, and using it does not guarantee compliance with any standard or regulation.

**Acknowledgement.** By downloading, running, or otherwise using this software, you acknowledge that you have read, understood, and agree to this disclaimer and to the terms of the [MIT License](LICENSE).

## 🗺️ Roadmap and contributing

The planned feature set is complete. Issues and pull requests are welcome, useful contributions include support for additional authentication-method types as Microsoft Graph adds them, packaging as a PowerShell module, and a CI workflow.

## 👤 Credits

Designed and developed by **[Yusha](https://yusha.ca)**.

## License

[MIT](LICENSE). Copyright (c) 2026 [Yusha](https://yusha.ca).
