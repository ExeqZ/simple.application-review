# Application Review — M365 Enterprise Apps & Managed Identities

PowerShell solution for reviewing all enterprise applications and managed identities in Microsoft 365 / Entra ID tenants. Built for **service providers managing multiple customers**.

For each application and managed identity the tool reports:
- Every application and delegated permission granted
- **Internal risk level** (Critical / High / Medium / Low / None) based on abuse potential
- **Microsoft Defender for Cloud Apps (MDCA) permission level** (High / Medium / Low) — the same classification visible in the Defender portal under *OAuth Apps*
- **Sign-in activity** — last interactive, non-interactive, and service principal sign-in timestamp (from `signInActivity` on the SP object, no P1 licence required)
- **Detailed sign-in counts** per type for a configurable lookback window (requires Entra ID P1/P2 + `AuditLog.Read.All`)
- **Inactivity flag** — apps with no sign-in beyond a configurable threshold

Output formats: **HTML** (self-contained, filterable), **CSV**, and optional **JSON**.

---

## Prerequisites

| Requirement | Version |
|---|---|
| PowerShell | 7.2 or later (Windows PowerShell 5.1 also works) |

No external PowerShell modules are required. Everything uses native `Invoke-RestMethod`.

---

## App Registration Setup

Register **one app per tenant** (or one multi-tenant app with admin consent in each customer tenant).

### Required Application Permissions

| Permission | Purpose | Licence |
|---|---|---|
| `Application.Read.All` | Enumerate service principals | No P licence needed |
| `Directory.Read.All` | Resolve SP metadata | No P licence needed |
| `AuditLog.Read.All` | Detailed sign-in log queries (30-day retention) | Entra ID P1 or P2 |

> Without `AuditLog.Read.All` (or without a P1/P2 licence), use `-SkipDetailedSignInLogs`. The `signInActivity` property (last-seen timestamps) is available without P1/P2.

### Log Analytics (optional — for extended history up to 365+ days)

To query sign-in history beyond the Graph audit log retention window:

1. In **Entra ID → Diagnostic Settings**, stream the following log categories to a Log Analytics workspace:
   - `SigninLogs`
   - `NonInteractiveUserSignInLogs`
   - `ServicePrincipalSignInLogs`
   - `ManagedIdentitySignInLogs`
2. Grant the app registration the **Log Analytics Reader** Azure RBAC role on the workspace (Workspace → Access Control → Add role assignment).
3. No additional app permission in Entra is needed — the token uses a different OAuth scope (`https://api.loganalytics.io/.default`).

| Additional Permission | Where | Required for |
|---|---|---|
| `Log Analytics Reader` Azure RBAC | Workspace in Azure portal | Log Analytics queries |

### Authentication Methods (Recommended Order)

1. **Certificate** — Store in the Windows cert store or provide a PFX file. Most secure.
2. **Client Secret** — Store in a file with restricted permissions. Never hard-code it.

---

## Quick Start

### Single Tenant

```powershell
# Certificate (recommended)
.\Invoke-TenantReview.ps1 `
    -TenantId    'contoso.onmicrosoft.com' `
    -ClientId    'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
    -CertificateThumbprint 'AABBCCDDEEFF00112233445566778899AABBCCDD'

# Client secret file
.\Invoke-TenantReview.ps1 `
    -TenantId         'contoso.onmicrosoft.com' `
    -ClientId         'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
    -ClientSecretFile './secrets/contoso.secret'

# Fast mode (no P1 licence required)
.\.\Invoke-TenantReview.ps1 `
    -TenantId    'contoso.onmicrosoft.com' `
    -ClientId    'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
    -CertificateThumbprint 'AABB...' `
    -SkipDetailedSignInLogs

# Log Analytics mode — 365-day lookback (recommended for full history)
.\Invoke-TenantReview.ps1 `
    -TenantId                  'contoso.onmicrosoft.com' `
    -ClientId                  'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
    -CertificateThumbprint     'AABB...' `
    -LogAnalyticsWorkspaceId   'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
    -LogAnalyticsLookbackDays  365 `
    -InactivityThresholdDays   180
```

### Multiple Tenants (MSP Mode)

```powershell
# 1. Use the onboarding helper to set up a new customer (interactive, creates app + cert + config)
.\helpers\New-TenantSetup.ps1 `
    -TenantId            'contoso.onmicrosoft.com' `
    -CustomerShortName   'contoso' `
    -CustomerDisplayName 'Contoso Ltd'

# Then grant admin consent manually (see console output for direct link)

# 2. Run all enabled tenants
.\Invoke-MultiTenantReview.ps1

# 3. Run only tenants matching a filter
.\Invoke-MultiTenantReview.ps1 -TenantFilter 'Contoso' -ContinueOnError

# 4. Custom lookback window
.\Invoke-MultiTenantReview.ps1 -LookbackDays 60 -InactivityThresholdDays 120
```

---

## Configuration

### Tenant config files (`tenants/*.json`)

Each customer has its own JSON file in the `tenants/` folder. Files matching `*.json` are
**gitignored** — never commit them. Use `tenants/sample-customer.json.sample` as a starting point,
or run `helpers/New-TenantSetup.ps1` to generate one automatically.

```json
{
  "tenantId": "aaaaaaaa-0000-0000-0000-000000000001",
  "tenantName": "Customer A — Contoso Ltd",
  "enabled": true,
  "authMethod": "Certificate",
  "clientId": "bbbbbbbb-0000-0000-0000-000000000001",
  "certificateThumbprint": "AABBCCDDEEFF...",
  "settings": {
    "inactivityThresholdDays": 180,
    "signInLookbackDays": 30
  },
  "logAnalytics": {
    "enabled": true,
    "workspaceId": "cccccccc-0000-0000-0000-000000000001",
    "lookbackDays": 365
  }
}
```

| `authMethod` | Required fields |
|---|---|
| `Certificate` | `clientId` + `certificateThumbprint` **or** `certificatePath` (+ optional `certificatePasswordFile`) |
| `ClientSecret` | `clientId` + `clientSecretFile` (path to a file containing only the secret) |

### `config/sensitive-permissions.json`

Permission catalogue with two risk dimensions per entry:

| Field | Description |
|---|---|
| `riskLevel` | Internal assessment: `Critical` / `High` / `Medium` / `Low` |
| `defenderRiskLevel` | Microsoft Defender for Cloud Apps classification: `High` / `Medium` / `Low` |

Add or modify entries to match your organisation's risk appetite. Both dimensions are shown side-by-side in the HTML report.

---

## Output

Reports are written to `./reports/<TenantName>_<timestamp>/`.

| File | Description |
|---|---|
| `application-review.html` | Self-contained filterable HTML with colour-coded risk + Defender levels |
| `application-review.csv` | Flat CSV — suitable for Excel / Power BI |
| `application-review.json` | Raw JSON (with `-IncludeRawJson`) |

Multi-tenant runs also produce a `_summary/` folder with a cross-tenant aggregate HTML and CSV.

### Key Columns

| Column | Source |
|---|---|
| `OverallRiskLevel` | Highest internal `riskLevel` across all sensitive permissions |
| `OverallDefenderRiskLevel` | Highest `defenderRiskLevel` (MDCA) across all sensitive permissions |
| `DefenderHighPermissions` | Semicolon-delimited list of Defender-High permissions |
| `DefenderMediumPermissions` | Semicolon-delimited list of Defender-Medium permissions |
| `LastInteractiveSignIn` | From `signInActivity.lastSignInDateTime` on the SP object |
| `LastNonInteractiveSignIn` | From `signInActivity.lastNonInteractiveSignInDateTime` |
| `LastServicePrincipalSignIn` | From `signInActivity.lastServicePrincipalSignInDateTime` |
| `InteractiveSignInsInWindow` | Count from `/auditLogs/signIns` (P1 required) |
| `NonInteractiveSignInsInWindow` | Count from `/auditLogs/nonInteractiveSignIns` |
| `SpSignInsInWindow` | Count from `/auditLogs/servicePrincipalSignIns` |
| `DistinctInteractiveUsers` | Unique UPNs who signed in interactively in the window |
| `IsInactive` | `true` if `DaysSinceLastSignIn > InactivityThresholdDays` (default: **180 days**) |

### Sign-In Data Sources

| Mode | How to activate | Lookback | Licence |
|---|---|---|---|
| `signInActivity` (always on) | Automatic | Last timestamp only | None |
| Graph audit log | Default (no extra params) | ~30 days | Entra ID P1/P2 |
| Log Analytics | `-LogAnalyticsWorkspaceId` / `logAnalytics.enabled=true` | Up to 365+ days (workspace retention) | Entra ID P1/P2 + Log Analytics Reader RBAC |

---

## Project Structure

```
├── Invoke-TenantReview.ps1          # Single-tenant entry point
├── Invoke-MultiTenantReview.ps1     # Multi-tenant MSP runner
├── helpers/
│   └── New-TenantSetup.ps1          # Onboarding: creates app registration, cert, and config file
├── tenants/
│   ├── sample-customer.json.sample  # Template — copy to <customer>.json and fill in values
│   └── *.json                       # Per-customer config files (gitignored)
├── config/
│   └── sensitive-permissions.json   # Permission catalogue with Defender risk levels
├── modules/
│   ├── GraphAuth.psm1               # Auth (certificate JWT, client secret), throttle-aware Graph requests
│   ├── Applications.psm1            # Enumerate enterprise apps & managed identities
│   ├── Permissions.psm1             # App role assignments, delegated grants, risk analysis
│   ├── SignIns.psm1                 # Sign-in activity (SP object / Graph audit log / Log Analytics)
│   ├── LogAnalytics.psm1            # Bulk KQL queries against Azure Monitor Log Analytics
│   └── Reporting.psm1               # HTML, CSV, JSON output
├── reports/                         # Generated reports (gitignored)
└── secrets/                         # Credential files (gitignored)
```

---

## Security Notes

- `tenants/*.json`, `secrets/`, and `reports/` are **gitignored**.
- Secret files should have filesystem permissions restricted to the running service account.
- Certificate auth uses `EphemeralKeySet` — private key never touches disk.
- All Graph requests are read-only — no write operations are made to any tenant.

---

## Defender for Cloud Apps Risk Levels

`defenderRiskLevel` maps to the three permission severity levels in the Microsoft Defender for Cloud Apps portal (*Cloud Apps → OAuth Apps → Permission level*):

| Level | Typical permissions |
|---|---|
| **High** | Full mailbox read/write, send as any user, full directory write, file read/write, PIM management, MFA method management, Intune device management |
| **Medium** | Mailbox read, directory read, user/group read, Teams message read, SharePoint read/write, Conditional Access policy write |
| **Low** | Audit log read, usage reports, service health, basic org metadata |

Reference: [Manage OAuth app permissions — Microsoft Defender for Cloud Apps](https://learn.microsoft.com/en-us/defender-cloud-apps/manage-app-permissions)