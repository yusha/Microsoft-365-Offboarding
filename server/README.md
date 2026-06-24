# REST API and MCP server

Two dependency-free PowerShell servers that put the offboarding tools behind an interface:

- `Start-RestApi.ps1` — a small HTTP/JSON REST API (`System.Net.HttpListener`).
- `Start-McpServer.ps1` — a Model Context Protocol (MCP) server over stdio, so an AI client (for example Claude Desktop) can call the tools.

Both share `M365OffboardingService.ps1`, which shells out to the existing scripts and returns their `audit.json`. No extra runtime is required, just PowerShell.

Developed by **[Yusha](https://yusha.ca)**.

## Actions

| Action | Tool / route | Effect | Gated |
|---|---|---|---|
| Preview | `preview_offboarding` / `POST /preview` | Dry-run simulation, no sign-in, no changes | No |
| Rehire check | `check_rehire` / `POST /rehire` | Read-only prior-offboarding detection | No |
| Offboard | `offboard_user` / `POST /offboard` | Performs the offboarding | Yes |
| Reverse | `reverse_offboarding` / `POST /reverse` | Reverses an offboarding | Yes |

## Safety model

- **Destructive actions are disabled by default.** `offboard` and `reverse` return an error unless the operator sets `M365_OFFBOARDING_ALLOW_EXECUTE=1`. `preview` and `rehire` always work.
- **Credentials come from the environment, never from callers.** App-only auth uses `M365_TENANT`, `M365_CLIENT_ID`, `M365_CERT_THUMBPRINT`, `M365_ORG`. Destructive actions also require these to be set.
- **The REST API requires a bearer token** (`M365_OFFBOARDING_API_TOKEN`) on every route except `/health`, and refuses to start without one. It binds to `127.0.0.1` by default; put TLS and access controls in front before exposing it.
- **Keep destructive tools behind human approval in your MCP client.** A good pattern is to let the model call `preview_offboarding` and `check_rehire` freely, and require explicit human confirmation before `offboard_user`.

## Environment variables

| Variable | Purpose |
|---|---|
| `M365_OFFBOARDING_API_TOKEN` | Bearer token for the REST API (required to start it). |
| `M365_OFFBOARDING_ALLOW_EXECUTE` | `1` to allow destructive actions. Default off. |
| `M365_TENANT` / `M365_CLIENT_ID` / `M365_CERT_THUMBPRINT` / `M365_ORG` | App-only credentials for real (non-preview) runs. |

## REST API

```powershell
$env:M365_OFFBOARDING_API_TOKEN = 'a-long-random-secret'
# Optional, to allow real offboarding:
$env:M365_OFFBOARDING_ALLOW_EXECUTE = '1'
$env:M365_TENANT = 'contoso.onmicrosoft.com'
$env:M365_CLIENT_ID = '<app-id>'
$env:M365_CERT_THUMBPRINT = '<thumbprint>'
$env:M365_ORG = 'contoso.onmicrosoft.com'

./server/Start-RestApi.ps1            # listens on http://127.0.0.1:8770/
```

Calls:

```bash
curl http://127.0.0.1:8770/health

curl -X POST http://127.0.0.1:8770/preview \
  -H 'Authorization: Bearer a-long-random-secret' \
  -H 'Content-Type: application/json' \
  -d '{"userPrincipalName":"jdoe@contoso.com"}'

curl -X POST http://127.0.0.1:8770/offboard \
  -H 'Authorization: Bearer a-long-random-secret' \
  -d '{"userPrincipalName":"jdoe@contoso.com","sharePointSiteUrl":"https://contoso.sharepoint.com/sites/IT"}'
```

Every response is the action's `audit.json` wrapped as `{ ok, action, executed, result, error }`. Status codes: `200` ok, `400` bad input, `401` missing/invalid token, `403` execution disabled or no credentials, `404` unknown route.

## MCP server

Run it directly for a quick check (it speaks JSON-RPC 2.0 on stdio):

```powershell
./server/Start-McpServer.ps1
```

Configure it in an MCP client. For Claude Desktop, add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "m365-offboarding": {
      "command": "pwsh",
      "args": ["-NoProfile", "-File", "C:\\Tools\\Microsoft-365-Offboarding\\server\\Start-McpServer.ps1"],
      "env": {
        "M365_TENANT": "contoso.onmicrosoft.com",
        "M365_CLIENT_ID": "<app-id>",
        "M365_CERT_THUMBPRINT": "<thumbprint>",
        "M365_ORG": "contoso.onmicrosoft.com",
        "M365_OFFBOARDING_ALLOW_EXECUTE": "0"
      }
    }
  }
}
```

With `M365_OFFBOARDING_ALLOW_EXECUTE` left at `0`, the agent can `preview_offboarding` and `check_rehire` but `offboard_user` / `reverse_offboarding` return a "disabled" message. Flip it to `1` only when you intend the agent (with human approval) to make real changes. The required Graph/Exchange application permissions are listed in [../docs/INTEGRATION.md](../docs/INTEGRATION.md).

## Tests

The routing, auth, gating, and MCP protocol handling are covered by unit tests with a mocked script runner (no sign-in, no HTTP). The functions are dot-source friendly: the servers only start their loop when run directly, so `. ./server/Start-RestApi.ps1` exposes `Get-ApiResponse` and `. ./server/Start-McpServer.ps1` exposes `Invoke-McpMessage` for testing.
