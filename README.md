# Application Review — M365 Enterprise Apps & Managed Identities

PowerShell solution for reviewing all enterprise applications and managed identities in Microsoft 365 / Entra ID tenants. Built for **service providers managing multiple customers**.

For each application and managed identity the tool reports:
- Every application and delegated permission granted (full listing)
- **App Governance risk level** (High / Medium / Low) — the Microsoft Defender for Cloud Apps — App Governance classification
- **Risk score** as a numeric value (High=3, Medium=2, Low=1, None=0)
- **Overprivileged flag** — apps with high-risk permissions but minimal usage
- **Highly privileged flag** — apps with any High severity permissions
- **Consent type** — Admin consent vs. user consent, with count of user-consented principals
- **SCIM / Provisioning detection** — apps with synchronization jobs configured
- **Sign-in activity** — last interactive, non-interactive, and service principal sign-in timestamp
- **Detailed sign-in counts** per type for a configurable lookback window (requires Entra ID P1/P2 + `AuditLog.Read.All`)
- **Likely unused detection** — highlights apps that are inactive, have no sign-ins, and were created > 90 days ago (deletion candidates)
- **Direct link to Entra portal** for each application

Output formats: **HTML** (self-contained, filterable, sortable), **CSV**, and optional **JSON**.

---

## Getting Help

```powershell
# Show built-in help and usage examples
.\Invoke-TenantReview.ps1 -ShowHelp
.\Invoke-MultiTenantReview.ps1 -ShowHelp

# PowerShell built-in help (same content)
Get-Help .\Invoke-TenantReview.ps1 -Full
Get-Help .\Invoke-MultiTenantReview.ps1 -Full
```

---

## Prerequisites

| Requirement | Version |
|---|---|
| PowerShell | 7.2 or later (Windows PowerShell 5.1 also works) |

No external PowerShell modules are required. Everything uses native `Invoke-RestMethod`.

---

## App Registration Setup

Two models are supported:

| Model | Description | Best for |
|---|---|---|
| **Multi-tenant app** (recommended) | One app in your home tenant, admin-consented into each customer tenant | MSPs managing many tenants |
| **Per-tenant app** | Separate app registration in each customer tenant | Full isolation per customer |

### Multi-Tenant App (Recommended)

1. Register **one app** in your service provider tenant with "Accounts in any organizational directory" (multi-tenant)
2. Add the required permissions (below) and grant admin consent in your home tenant
3. For each customer, grant admin consent via:
   ```
   https://login.microsoftonline.com/{customer-tenant-id}/adminconsent?client_id={your-app-client-id}
   ```
4. Create `config/auth-defaults.json` (copy from `config/auth-defaults.json.sample`) with the shared `clientId` and certificate
5. Tenant config files (`tenants/*.json`) only need `tenantId`, `tenantName`, and `enabled` — auth is inherited from the global config

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
.\Invoke-TenantReview.ps1 `
    -TenantId    'contoso.onmicrosoft.com' `
    -ClientId    'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
    -CertificateThumbprint 'AABB...' `
    -SkipDetailedSignInLogs

# Log Analytics mode — 365-day lookback
.\Invoke-TenantReview.ps1 `
    -TenantId                  'contoso.onmicrosoft.com' `
    -ClientId                  'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
    -CertificateThumbprint     'AABB...' `
    -LogAnalyticsWorkspaceId   'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
    -LogAnalyticsLookbackDays  365 `
    -InactivityThresholdDays   180

# Debug mode — full transcript logging
.\Invoke-TenantReview.ps1 `
    -TenantId    'contoso.onmicrosoft.com' `
    -ClientId    'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
    -CertificateThumbprint 'AABB...' `
    -DebugLog
```

### Multiple Tenants (MSP Mode)

```powershell
# 1. Use the onboarding helper to set up a new customer
.\helpers\New-TenantSetup.ps1 `
    -TenantId            'contoso.onmicrosoft.com' `
    -CustomerShortName   'contoso' `
    -CustomerDisplayName 'Contoso Ltd'

# 2. Run all enabled tenants
.\Invoke-MultiTenantReview.ps1

# 3. Run only tenants matching a filter
.\Invoke-MultiTenantReview.ps1 -TenantFilter 'Contoso' -ContinueOnError

# 4. Debug mode
.\Invoke-MultiTenantReview.ps1 -DebugLog
```

---

## Configuration

### Global auth defaults (`config/auth-defaults.json`)

For multi-tenant app deployments, define authentication once in a global config file.
All tenant configs inherit these values unless they provide their own overrides.

Copy `config/auth-defaults.json.sample` → `config/auth-defaults.json` and fill in your values:

```json
{
  "authMethod": "Certificate",
  "clientId": "bbbbbbbb-0000-0000-0000-000000000001",
  "certificatePath": "./secrets/multi-tenant-app.pfx",
  "certificatePasswordFile": "./secrets/multi-tenant-app.pfx.pass"
}
```

When `config/auth-defaults.json` exists, tenant configs only need tenant-specific fields:

```json
{
  "tenantId": "aaaaaaaa-0000-0000-0000-000000000001",
  "tenantName": "Customer A — Contoso Ltd",
  "enabled": true
}
```

> **Precedence:** Per-tenant values always win. If a tenant config specifies `clientId` or `authMethod`, those override the global defaults.

### Tenant config files (`tenants/*.json`)

Each customer has its own JSON file in the `tenants/` folder. Files matching `*.json` are
**gitignored** — never commit them. Use `tenants/sample-customer.json.sample` as a starting point,
or run `helpers/New-TenantSetup.ps1` to generate one automatically.

Full per-tenant config (with auth override):

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
    "signInLookbackDays": 30,
    "signInBatchSize": 5
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

Permission catalogue with risk levels per entry:

| Field | Description |
|---|---|
| `riskLevel` | Legacy internal assessment (retained in JSON for reference) |
| `defenderRiskLevel` | **Primary risk indicator** — Microsoft Defender for Cloud Apps — App Governance classification: `High` / `Medium` / `Low` |

Add or modify entries to match your organisation's risk appetite. The `defenderRiskLevel` field is used throughout reports.

---

## Output

Reports are written to `./reports/<TenantName>_<timestamp>/`.

| File | Description |
|---|---|
| `application-review.html` | Self-contained filterable & sortable HTML report with direct Entra portal links |
| `application-review.csv` | Flat CSV — suitable for Excel / Power BI |
| `application-review.json` | Raw JSON (with `-IncludeRawJson`) |
| `debug-transcript_*.log` | Full debug transcript (with `-DebugLog`) |

Multi-tenant runs also produce a `_summary/` folder with a cross-tenant aggregate HTML and CSV.

### HTML Report Features

- **Filterable** by: Risk Level (High/Medium/Low), Inactive, Likely Unused, Overprivileged, Highly Privileged, SCIM, Admin Consent, User Consent
- **Sortable** by: all columns including sign-in counts (total, interactive, non-interactive, service principal), risk score, last sign-in date
- **Direct links** to each application in the Entra portal
- **Visual flags**: Likely Unused (yellow highlight), Overprivileged, Highly Privileged, SCIM badges
- **Consent indicators**: Admin vs. User consent with count of user-consented principals
- **Permission listing**: All permissions shown (not just sensitive), with delegated permissions marked `[D]`

### Key Columns

| Column | Description |
|---|---|
| `OverallRiskLevel` | Highest App Governance risk level across all permissions (High/Medium/Low/None) |
| `RiskScore` | Numeric risk score: High=3, Medium=2, Low=1, None=0 |
| `IsHighlyPrivileged` | `true` if the app has any High severity permissions |
| `IsOverprivileged` | `true` if highly privileged but with ≤5 sign-ins in the lookback window |
| `IsLikelyUnused` | `true` if inactive + no sign-ins + created > 90 days ago |
| `IsScimApp` | `true` if SCIM provisioning / synchronization jobs are configured |
| `ConsentType` | `Admin`, `User`, `Both`, or `None` |
| `UserConsentedCount` | Number of distinct users who granted consent (for user-consented apps) |
| `HighPermissions` | Semicolon-delimited list of High-risk permissions |
| `AllPermissions` | Semicolon-delimited list of all granted permissions |
| `EntraPortalLink` | Direct URL to the application in the Entra admin center |

### Sign-In Data Sources

| Mode | How to activate | Lookback | Licence |
|---|---|---|---|
| `signInActivity` (always on) | Automatic | Last timestamp only | None |
| Graph audit log | Default (no extra params) | ~30 days | Entra ID P1/P2 |
| Log Analytics | `-LogAnalyticsWorkspaceId` / `logAnalytics.enabled=true` | Up to 365+ days | Entra ID P1/P2 + Log Analytics Reader RBAC |

---

## Parameters

### `Invoke-TenantReview.ps1`

| Parameter | Description | Default |
|---|---|---|
| `-TenantId` | Azure AD tenant ID (GUID or domain) | *Required* |
| `-ClientId` | Application (client) ID | *Required* |
| `-CertificateThumbprint` | Certificate thumbprint from cert store | — |
| `-CertificatePath` | Path to PFX file | — |
| `-CertificatePasswordFile` | Path to PFX password file | — |
| `-ClientSecretFile` | Path to client secret file | — |
| `-ClientSecret` | Client secret (plain text, not recommended) | — |
| `-OutputFolder` | Report output folder | `./reports` |
| `-LookbackDays` | Graph audit log lookback window | `30` |
| `-InactivityThresholdDays` | Days without sign-in to flag as inactive | `180` |
| `-LogAnalyticsWorkspaceId` | Log Analytics workspace GUID | — |
| `-LogAnalyticsLookbackDays` | Log Analytics lookback window | `365` |
| `-IncludeFirstPartyMicrosoftApps` | Include Microsoft first-party apps | `$false` |
| `-IncludeDisabledApps` | Include disabled service principals | `$false` |
| `-ExcludeManagedIdentities` | Skip managed identities | `$false` |
| `-SkipDetailedSignInLogs` | Use `signInActivity` property only | `$false` |
| `-SignInBatchSize` | AppIds per Graph `$batch` HTTP call (1–20) | `5` |
| `-IncludeRawJson` | Also write a JSON report file | `$false` |
| `-DebugLog` | Enable debug transcript logging | `$false` |
| `-ShowHelp` | Show help manual and exit | `$false` |

### `Invoke-MultiTenantReview.ps1`

| Parameter | Description | Default |
|---|---|---|
| `-TenantsFolder` | Folder with tenant JSON config files | `./tenants` |
| `-OutputFolder` | Report output folder | `./reports` |
| `-TenantFilter` | Process only tenants matching this string | — |
| `-LookbackDays` | Override Graph audit log lookback window | config default |
| `-InactivityThresholdDays` | Override inactivity threshold | config default |
| `-LogAnalyticsLookbackDays` | Override Log Analytics lookback | config default |
| `-SkipDetailedSignInLogs` | Use `signInActivity` property only for all tenants | `$false` |
| `-SignInBatchSize` | Override appIds per Graph `$batch` HTTP call (1–20, 0 = use config) | `0` |
| `-IncludeRawJson` | Also write JSON per tenant | `$false` |
| `-ContinueOnError` | Continue on error for remaining tenants | `$false` |
| `-DebugLog` | Enable debug transcript logging | `$false` |
| `-ShowHelp` | Show help manual and exit | `$false` |

---

## Debugging

Use `-DebugLog` to enable a full PowerShell transcript that captures all console output, verbose messages, and step-by-step details:

```powershell
.\Invoke-TenantReview.ps1 -TenantId '...' -ClientId '...' -CertificateThumbprint '...' -DebugLog
```

The transcript is saved to `<report-folder>/debug-transcript_<timestamp>.log` and includes:
- All Graph API calls and responses (verbose level)
- Permission analysis details per application
- Sign-in data aggregation steps
- SCIM detection results
- Timing information for each step

---

## Project Structure

```
├── Invoke-TenantReview.ps1          # Single-tenant entry point
├── Invoke-MultiTenantReview.ps1     # Multi-tenant MSP runner
├── helpers/
│   ├── New-TenantSetup.ps1          # Onboarding: creates app registration, cert, and config file
│   └── Invoke-CertificateRotation.ps1  # Certificate renewal helper
├── tenants/
│   ├── sample-customer.json.sample  # Template — copy to <customer>.json and fill in values
│   └── *.json                       # Per-customer config files (gitignored)
├── config/
│   └── sensitive-permissions.json   # Permission catalogue with App Governance risk levels
├── modules/
│   ├── GraphAuth.psm1               # Auth (certificate JWT, client secret), throttle-aware Graph requests
│   ├── Applications.psm1            # Enumerate enterprise apps & managed identities, SCIM detection
│   ├── Permissions.psm1             # App role assignments, delegated grants, risk analysis, consent tracking
│   ├── SignIns.psm1                 # Sign-in activity (SP object / Graph audit log / Log Analytics)
│   ├── LogAnalytics.psm1            # Bulk KQL queries against Azure Monitor Log Analytics
│   └── Reporting.psm1               # HTML (filterable/sortable), CSV, JSON output
├── reports/                         # Generated reports (gitignored)
└── secrets/                         # Credential files (gitignored)
```

---

## Security Notes

- `tenants/*.json`, `secrets/`, and `reports/` are **gitignored**.
- Secret files should have filesystem permissions restricted to the running service account.
- Certificate auth uses `EphemeralKeySet` — private key never touches disk.
- All Graph requests are read-only — no write operations are made to any tenant.
- Debug transcripts may contain tenant metadata — treat them as sensitive.

---

## App Governance Risk Levels

Risk levels are sourced from the Microsoft Defender for Cloud Apps — **App Governance** classification:

| Level | Typical permissions |
|---|---|
| **High** | Full mailbox read/write, send as any user, full directory write, file read/write, PIM management, MFA method management, Intune device management |
| **Medium** | Mailbox read, directory read, user/group read, Teams message read, SharePoint read/write, Conditional Access policy write |
| **Low** | Audit log read, usage reports, service health, basic org metadata |

Reference: [App Governance — Microsoft Defender for Cloud Apps](https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-manage-app-governance)
