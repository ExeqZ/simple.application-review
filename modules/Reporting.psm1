<#
.SYNOPSIS
    Generates HTML, CSV, and JSON reports for the application review.

.DESCRIPTION
    Takes the combined result set (service principals + permissions + sign-in activity)
    and produces three report formats per tenant run.
    The HTML report is self-contained (no external CDN dependencies), sortable, and
    filterable. Risk levels follow the Microsoft Defender for Cloud Apps — App Governance
    classification (High / Medium / Low).
#>

function Export-ReviewReport {
    <#
    .SYNOPSIS
        Master export function — writes HTML, CSV, and JSON outputs to a timestamped folder.

    .PARAMETER Results
        Array of combined result objects as returned by Build-CombinedResult.

    .PARAMETER TenantName
        Display name of the tenant (used in report titles and file names).

    .PARAMETER TenantId
        Tenant GUID (included in report metadata).

    .PARAMETER OutputFolder
        Root folder for report output. A sub-folder per tenant/date is created automatically.

    .PARAMETER IncludeRawJson
        If set, also writes a raw JSON file containing the full result set.

    .EXAMPLE
        Export-ReviewReport -Results $combined -TenantName 'Contoso' -TenantId $tid -OutputFolder ./reports
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Results,

        [Parameter(Mandatory)]
        [string]$TenantName,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [switch]$IncludeRawJson
    )

    $timestamp  = Get-Date -Format 'yyyy-MM-dd_HH-mm'
    $safeName   = $TenantName -replace '[^\w\-]', '_'
    $reportDir  = Join-Path $OutputFolder "${safeName}_${timestamp}"

    if (-not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }

    Write-Host "  Writing reports to: $reportDir"

    # ── CSV ───────────────────────────────────────────────────────────────────
    $csvPath = Join-Path $reportDir 'application-review.csv'
    $Results | ForEach-Object { ConvertTo-FlatCsvRow $_ } |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV : $csvPath"

    # ── JSON ──────────────────────────────────────────────────────────────────
    if ($IncludeRawJson) {
        $jsonPath = Join-Path $reportDir 'application-review.json'
        $Results | ConvertTo-Json -Depth 15 | Set-Content -Path $jsonPath -Encoding UTF8
        Write-Host "  JSON: $jsonPath"
    }

    # ── HTML ──────────────────────────────────────────────────────────────────
    $htmlPath = Join-Path $reportDir 'application-review.html'
    $html = Build-HtmlReport -Results $Results -TenantName $TenantName -TenantId $TenantId
    $html | Set-Content -Path $htmlPath -Encoding UTF8
    Write-Host "  HTML: $htmlPath"

    return [PSCustomObject]@{
        ReportFolder = $reportDir
        HtmlPath     = $htmlPath
        CsvPath      = $csvPath
        JsonPath     = if ($IncludeRawJson) { $jsonPath } else { $null }
    }
}

function Build-CombinedResult {
    <#
    .SYNOPSIS
        Merges service principal, permission, sign-in activity, and SCIM data into a single object.

    .PARAMETER ServicePrincipal
        Service principal object from Get-AllApplications.

    .PARAMETER PermissionData
        Output of Get-ApplicationPermissions.

    .PARAMETER PermissionSummary
        Output of Get-PermissionSummary.

    .PARAMETER SignInActivity
        Output of Get-ApplicationSignInActivity.

    .PARAMETER IsScimApp
        Whether this app uses SCIM provisioning.

    .EXAMPLE
        $row = Build-CombinedResult -ServicePrincipal $sp -PermissionData $perms -PermissionSummary $summary -SignInActivity $sia
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$ServicePrincipal,
        [Parameter(Mandatory)] [object]$PermissionData,
        [Parameter(Mandatory)] [object]$PermissionSummary,
        [Parameter(Mandatory)] [object]$SignInActivity,
        [bool]$IsScimApp = $false,
        [object]$CredentialStatus = $null,
        [string[]]$Owners = @()
    )

    # Determine if app is likely unused and candidate for deletion:
    # Inactive + no sign-ins in window + created > 90 days ago
    $createdDate = $null
    if ($ServicePrincipal.createdDateTime) {
        try {
            if ($ServicePrincipal.createdDateTime -is [datetime]) {
                $createdDate = $ServicePrincipal.createdDateTime.ToUniversalTime()
            } else {
                $createdDate = [datetime]::Parse(
                    $ServicePrincipal.createdDateTime.ToString(),
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
                    [System.Globalization.DateTimeStyles]::AssumeUniversal
                )
            }
        } catch {}
    }
    $daysSinceCreated = if ($createdDate) {
        [int]((Get-Date).ToUniversalTime() - $createdDate).TotalDays
    } else { 999 }

    $isLikelyUnused = (
        $SignInActivity.IsInactive -and
        $SignInActivity.TotalSignInsInWindow -eq 0 -and
        $daysSinceCreated -gt 90
    )

    # Determine overprivileged: has high-risk permissions but very low/no usage
    $isOverprivileged = (
        $PermissionSummary.IsHighlyPrivileged -and
        $SignInActivity.TotalSignInsInWindow -le 5
    )

    return [PSCustomObject]@{
        # Identity
        ObjectId                      = $ServicePrincipal.id
        AppId                         = $ServicePrincipal.appId
        DisplayName                   = $ServicePrincipal.displayName
        PrincipalType                 = $ServicePrincipal._principalType
        AccountEnabled                = $ServicePrincipal.accountEnabled
        CreatedDateTime               = $ServicePrincipal.createdDateTime
        PublisherTenantId             = $ServicePrincipal.appOwnerOrganizationId
        AzureResourceId               = $ServicePrincipal.azureResourceId

        # Risk (App Governance levels: High/Medium/Low/None)
        OverallRiskLevel              = $PermissionSummary.OverallRiskLevel
        RiskScore                     = $PermissionSummary.RiskScore
        IsHighlyPrivileged            = $PermissionSummary.IsHighlyPrivileged
        IsOverprivileged              = $isOverprivileged
        TotalPermissions              = $PermissionSummary.TotalPermissions
        SensitivePermissionCount      = $PermissionSummary.SensitivePermissionCount
        HighPermissions               = ($PermissionSummary.HighPermissions -join '; ')
        MediumPermissions             = ($PermissionSummary.MediumPermissions -join '; ')
        LowPermissions                = ($PermissionSummary.LowPermissions -join '; ')

        # Consent
        ConsentType                   = $PermissionSummary.ConsentType
        UserConsentedCount            = $PermissionSummary.UserConsentedCount
        AdminConsented                = $PermissionSummary.AdminConsented

        # SCIM
        IsScimApp                     = $IsScimApp

        # Credentials
        HasExpiredSecrets             = if ($CredentialStatus) { $CredentialStatus.HasExpiredSecrets } else { $false }
        HasExpiredCerts               = if ($CredentialStatus) { $CredentialStatus.HasExpiredCerts } else { $false }
        HasExpiredCredentials          = if ($CredentialStatus) { $CredentialStatus.HasAnyExpired } else { $false }
        TotalCredentials              = if ($CredentialStatus) { $CredentialStatus.TotalCredentials } else { 0 }
        EarliestCredentialExpiry      = if ($CredentialStatus) { $CredentialStatus.EarliestExpiry } else { $null }
        _credentialDetails            = $CredentialStatus

        # Owners
        Owners                        = ($Owners -join '; ')
        OwnerCount                    = $Owners.Count

        # Likely unused / deletion candidate
        IsLikelyUnused                = $isLikelyUnused

        # Activity
        LastSeenOverall               = $SignInActivity.LastSeenOverall
        DaysSinceLastSignIn           = $SignInActivity.DaysSinceLastSignIn
        IsInactive                    = $SignInActivity.IsInactive
        LastInteractiveSignIn         = $SignInActivity.LastInteractiveSignIn
        LastNonInteractiveSignIn      = $SignInActivity.LastNonInteractiveSignIn
        LastServicePrincipalSignIn    = $SignInActivity.LastServicePrincipalSignIn
        TotalSignInsInWindow          = $SignInActivity.TotalSignInsInWindow
        InteractiveSignInsInWindow    = $SignInActivity.InteractiveSignInsInWindow
        NonInteractiveSignInsInWindow = $SignInActivity.NonInteractiveSignInsInWindow
        SpSignInsInWindow             = $SignInActivity.SpSignInsInWindow
        FailedSignInsInWindow         = $SignInActivity.FailedSignInsInWindow
        FailureRatePercent            = $SignInActivity.FailureRatePercent
        DistinctInteractiveUserCount  = $SignInActivity.DistinctInteractiveUserCount
        DistinctInteractiveUsers      = ($SignInActivity.DistinctInteractiveUsers -join '; ')
        DistinctSpCallerCount         = $SignInActivity.DistinctSpCallerCount
        AuditLogsQueried              = $SignInActivity.AuditLogsQueried

        # Full permission detail for JSON/HTML drill-down
        _appPermissions               = $PermissionData.ApplicationPermissions
        _delegatedPermissions         = $PermissionData.DelegatedPermissions
        _allPermissions               = $PermissionSummary.AllPermissions
    }
}

# ─── CSV helper ─────────────────────────────────────────────────────────────

function ConvertTo-FlatCsvRow {
    param([object]$Row)
    # Return a flat PSCustomObject (no nested arrays) suitable for Export-Csv
    [PSCustomObject][ordered]@{
        ObjectId                      = $Row.ObjectId
        AppId                         = $Row.AppId
        DisplayName                   = $Row.DisplayName
        PrincipalType                 = $Row.PrincipalType
        AccountEnabled                = $Row.AccountEnabled
        CreatedDateTime               = $Row.CreatedDateTime
        PublisherTenantId             = $Row.PublisherTenantId
        AzureResourceId               = $Row.AzureResourceId
        OverallRiskLevel              = $Row.OverallRiskLevel
        RiskScore                     = $Row.RiskScore
        IsHighlyPrivileged            = $Row.IsHighlyPrivileged
        IsOverprivileged              = $Row.IsOverprivileged
        TotalPermissions              = $Row.TotalPermissions
        SensitivePermissionCount      = $Row.SensitivePermissionCount
        HighPermissions               = $Row.HighPermissions
        MediumPermissions             = $Row.MediumPermissions
        LowPermissions                = $Row.LowPermissions
        AllPermissions                = if ($Row._allPermissions) { ($Row._allPermissions | ForEach-Object { "$($_.PermissionName) [$($_.PermissionType)]" }) -join '; ' } else { '' }
        ConsentType                   = $Row.ConsentType
        UserConsentedCount            = $Row.UserConsentedCount
        AdminConsented                = $Row.AdminConsented
        IsScimApp                     = $Row.IsScimApp
        HasExpiredCredentials          = $Row.HasExpiredCredentials
        TotalCredentials              = $Row.TotalCredentials
        EarliestCredentialExpiry      = if ($Row.EarliestCredentialExpiry) { $Row.EarliestCredentialExpiry.ToString('o') } else { '' }
        Owners                        = if ($Row.Owners) { $Row.Owners } else { '' }
        IsLikelyUnused                = $Row.IsLikelyUnused
        LastSeenOverall               = if ($Row.LastSeenOverall) { $Row.LastSeenOverall.ToString('o') } else { '' }
        DaysSinceLastSignIn           = $Row.DaysSinceLastSignIn
        IsInactive                    = $Row.IsInactive
        LastInteractiveSignIn         = if ($Row.LastInteractiveSignIn) { $Row.LastInteractiveSignIn.ToString('o') } else { '' }
        LastNonInteractiveSignIn      = if ($Row.LastNonInteractiveSignIn) { $Row.LastNonInteractiveSignIn.ToString('o') } else { '' }
        LastServicePrincipalSignIn    = if ($Row.LastServicePrincipalSignIn) { $Row.LastServicePrincipalSignIn.ToString('o') } else { '' }
        TotalSignInsInWindow          = $Row.TotalSignInsInWindow
        InteractiveSignInsInWindow    = $Row.InteractiveSignInsInWindow
        NonInteractiveSignInsInWindow = $Row.NonInteractiveSignInsInWindow
        SpSignInsInWindow             = $Row.SpSignInsInWindow
        FailedSignInsInWindow         = $Row.FailedSignInsInWindow
        FailureRatePercent            = $Row.FailureRatePercent
        DistinctInteractiveUserCount  = $Row.DistinctInteractiveUserCount
        DistinctInteractiveUsers      = if ($Row.DistinctInteractiveUsers) { $Row.DistinctInteractiveUsers } else { '' }
        DistinctSpCallerCount         = $Row.DistinctSpCallerCount
        EntraPortalLink               = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$($Row.ObjectId)/appId/$($Row.AppId)"
    }
}

# ─── HTML report builder ─────────────────────────────────────────────────────

function Build-HtmlReport {
    param(
        [object[]]$Results,
        [string]$TenantName,
        [string]$TenantId
    )

    $generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    $totalApps  = $Results.Count
    $eaCount    = @($Results | Where-Object { $_.PrincipalType -ne 'ManagedIdentity' }).Count
    $miCount    = @($Results | Where-Object { $_.PrincipalType -eq 'ManagedIdentity' }).Count
    $inactive   = @($Results | Where-Object { $_.IsInactive }).Count
    $high       = @($Results | Where-Object { $_.OverallRiskLevel -eq 'High'     }).Count
    $medium     = @($Results | Where-Object { $_.OverallRiskLevel -eq 'Medium'   }).Count
    $low        = @($Results | Where-Object { $_.OverallRiskLevel -eq 'Low'      }).Count
    $scimApps   = @($Results | Where-Object { $_.IsScimApp }).Count
    $likelyUnused = @($Results | Where-Object { $_.IsLikelyUnused }).Count
    $overpriv   = @($Results | Where-Object { $_.IsOverprivileged }).Count
    $highlyPriv = @($Results | Where-Object { $_.IsHighlyPrivileged }).Count
    $expiredCreds = @($Results | Where-Object { $_.HasExpiredCredentials }).Count

    $tableRows = ($Results | Sort-Object { @{'High'=0;'Medium'=1;'Low'=2;'None'=3}[$_.OverallRiskLevel] }, DisplayName | ForEach-Object {
        Build-HtmlTableRow $_ $TenantId
    }) -join "`n"

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Application Review — $([System.Net.WebUtility]::HtmlEncode($TenantName))</title>
<style>
  :root {
    --clr-high:     #b91c1c; --clr-high-bg:     #fef2f2;
    --clr-medium:   #b45309; --clr-medium-bg:   #fffbeb;
    --clr-low:      #166534; --clr-low-bg:       #f0fdf4;
    --clr-none:     #374151; --clr-none-bg:      #f9fafb;
    --clr-inactive: #6b7280;
    --clr-unused:   #7c2d12;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         font-size: 13px; color: #111827; background: #f3f4f6; }
  header { background: #1e3a5f; color: #fff; padding: 20px 32px; }
  header h1 { font-size: 1.4rem; font-weight: 600; }
  header p  { font-size: 0.8rem; opacity: 0.7; margin-top: 4px; }
  .summary { display: flex; flex-wrap: wrap; gap: 12px; padding: 20px 32px; }
  .card { background: #fff; border-radius: 8px; padding: 14px 20px; min-width: 140px;
          box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .card .num { font-size: 2rem; font-weight: 700; line-height: 1; }
  .card .lbl { font-size: 0.72rem; color: #6b7280; margin-top: 4px; }
  .card.high     .num { color: var(--clr-high);     }
  .card.medium   .num { color: var(--clr-medium);   }
  .card.low      .num { color: var(--clr-low);      }
  .card.inactive .num { color: var(--clr-inactive); }
  .card.unused   .num { color: var(--clr-unused);   }
  .section-title { padding: 0 32px 8px; font-size: 0.75rem; font-weight: 600;
                   color: #6b7280; text-transform: uppercase; letter-spacing: .05em; }
  .table-wrap { overflow-x: auto; padding: 0 32px 32px; }
  table { width: 100%; border-collapse: collapse; background: #fff;
          border-radius: 8px; overflow: hidden;
          box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  th { background: #1e3a5f; color: #fff; padding: 10px 12px;
       text-align: left; font-size: 0.72rem; font-weight: 600;
       text-transform: uppercase; letter-spacing: .04em; white-space: nowrap;
       cursor: pointer; user-select: none; position: relative; }
  th:hover { background: #2a4d78; }
  th .sort-icon { margin-left: 4px; font-size: 0.65rem; opacity: 0.5; }
  th.sorted-asc .sort-icon::after  { content: ' \25B2'; opacity: 1; }
  th.sorted-desc .sort-icon::after { content: ' \25BC'; opacity: 1; }
  td { padding: 9px 12px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f8fafc; }
  tr.row-unused { background: #fef3c7; }
  tr.row-unused:hover td { background: #fde68a; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px;
           font-size: 0.68rem; font-weight: 600; white-space: nowrap; }
  .badge-high     { color: var(--clr-high);     background: var(--clr-high-bg);     }
  .badge-medium   { color: var(--clr-medium);   background: var(--clr-medium-bg);   }
  .badge-low      { color: var(--clr-low);       background: var(--clr-low-bg);      }
  .badge-none     { color: var(--clr-none);     background: var(--clr-none-bg);     }
  .badge-scim     { color: #1e40af; background: #dbeafe; }
  .badge-unused   { color: #7c2d12; background: #ffedd5; }
  .badge-overpriv { color: #991b1b; background: #fee2e2; }
  .badge-highlyprivileged { color: #9a3412; background: #fff7ed; }
  .badge-consent-admin { color: #065f46; background: #d1fae5; }
  .badge-consent-user  { color: #92400e; background: #fef3c7; }
  .badge-expired       { color: #991b1b; background: #fee2e2; }
  .inactive-label { color: var(--clr-inactive); font-style: italic; }
  .perms-list { font-size: 0.7rem; color: #374151; }
  .perm-high     { color: var(--clr-high); font-weight: 600; }
  .perm-medium   { color: var(--clr-medium);   }
  .perm-low      { color: var(--clr-low);      }
  .perm-none     { color: #6b7280; }
  .days-num { font-weight: 600; }
  .days-inactive { color: var(--clr-inactive); }
  details summary { cursor: pointer; font-size: 0.72rem; color: #3b82f6; }
  details summary:hover { text-decoration: underline; }
  .filter-bar { padding: 0 32px 12px; display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
  .filter-group { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
  .filter-group-label { font-size: 0.68rem; font-weight: 600; color: #9ca3af; text-transform: uppercase; letter-spacing:.04em; margin-right: 2px; }
  .filter-btn { padding: 5px 14px; border-radius: 6px; border: 1px solid #d1d5db;
                background: #fff; cursor: pointer; font-size: 0.75rem; color: #374151; transition: all .12s; }
  .filter-btn:hover { border-color: #9ca3af; }
  .filter-btn.active { background: #1e3a5f; color: #fff; border-color: #1e3a5f; }
  .filter-sep { color: #e5e7eb; width: 1px; height: 24px; background: #e5e7eb; margin: 0 2px; align-self: center; }
  .filter-reset { padding: 5px 10px; border-radius: 6px; border: 1px dashed #d1d5db;
                  background: #f9fafb; cursor: pointer; font-size: 0.72rem; color: #6b7280; }
  .filter-reset:hover { background: #fee2e2; border-color: #fca5a5; color: #b91c1c; }
  .filter-count { font-size: 0.68rem; color: #6b7280; margin-left: 2px; }
  .app-link { color: #2563eb; text-decoration: none; font-size: 0.68rem; }
  .app-link:hover { text-decoration: underline; }
  @media print { .filter-bar { display: none; } }
</style>
</head>
<body>
<header>
  <h1>Enterprise Application &amp; Managed Identity Review</h1>
  <p>Tenant: $([System.Net.WebUtility]::HtmlEncode($TenantName)) &nbsp;|&nbsp; ID: $TenantId &nbsp;|&nbsp; Generated: $generated UTC</p>
  <p style="margin-top:4px;font-size:0.75rem;opacity:0.8">Risk levels: Microsoft Defender for Cloud Apps — App Governance classification</p>
</header>

<div class="summary">
  <div class="card"><div class="num">$totalApps</div><div class="lbl">Total Applications</div></div>
  <div class="card" style="border-left:4px solid #1e40af"><div class="num" style="color:#1e40af">$eaCount</div><div class="lbl">Enterprise Apps</div></div>
  <div class="card" style="border-left:4px solid #5b21b6"><div class="num" style="color:#5b21b6">$miCount</div><div class="lbl">Managed Identities</div></div>
  <div class="card high"><div class="num">$high</div><div class="lbl">High Risk</div></div>
  <div class="card medium"><div class="num">$medium</div><div class="lbl">Medium Risk</div></div>
  <div class="card low"><div class="num">$low</div><div class="lbl">Low Risk</div></div>
  <div class="card inactive"><div class="num">$inactive</div><div class="lbl">Inactive Apps</div></div>
  <div class="card unused"><div class="num">$likelyUnused</div><div class="lbl">Likely Unused</div></div>
  <div class="card" style="border-left:4px solid #991b1b"><div class="num" style="color:#991b1b">$overpriv</div><div class="lbl">Overprivileged</div></div>
  <div class="card" style="border-left:4px solid #9a3412"><div class="num" style="color:#9a3412">$highlyPriv</div><div class="lbl">Highly Privileged</div></div>
  <div class="card" style="border-left:4px solid #1e40af"><div class="num" style="color:#1e40af">$scimApps</div><div class="lbl">SCIM / Provisioning</div></div>
  <div class="card" style="border-left:4px solid #dc2626"><div class="num" style="color:#dc2626">$expiredCreds</div><div class="lbl">Expired Credentials</div></div>
</div>

<div class="filter-bar" id="filterBar">
  <div class="filter-group">
    <span class="filter-group-label">Type</span>
    <button class="filter-btn" data-filter="type" data-value="EA" onclick="toggleFilter(this)">Enterprise Apps</button>
    <button class="filter-btn" data-filter="type" data-value="MI" onclick="toggleFilter(this)">Managed Identities</button>
  </div>
  <div class="filter-sep"></div>
  <div class="filter-group">
    <span class="filter-group-label">Risk</span>
    <button class="filter-btn" data-filter="risk" data-value="High" onclick="toggleFilter(this)">High</button>
    <button class="filter-btn" data-filter="risk" data-value="Medium" onclick="toggleFilter(this)">Medium</button>
    <button class="filter-btn" data-filter="risk" data-value="Low" onclick="toggleFilter(this)">Low</button>
  </div>
  <div class="filter-sep"></div>
  <div class="filter-group">
    <span class="filter-group-label">Flags</span>
    <button class="filter-btn" data-filter="inactive" data-value="true" onclick="toggleFilter(this)">Inactive</button>
    <button class="filter-btn" data-filter="unused" data-value="true" onclick="toggleFilter(this)">Likely Unused</button>
    <button class="filter-btn" data-filter="overpriv" data-value="true" onclick="toggleFilter(this)">Overprivileged</button>
    <button class="filter-btn" data-filter="highlyprivileged" data-value="true" onclick="toggleFilter(this)">Highly Privileged</button>
    <button class="filter-btn" data-filter="scim" data-value="true" onclick="toggleFilter(this)">SCIM</button>
    <button class="filter-btn" data-filter="expired" data-value="true" onclick="toggleFilter(this)">Expired Credentials</button>
  </div>
  <div class="filter-sep"></div>
  <div class="filter-group">
    <span class="filter-group-label">Consent</span>
    <button class="filter-btn" data-filter="consent" data-value="Admin|Both" onclick="toggleFilter(this)">Admin Consent</button>
    <button class="filter-btn" data-filter="consent" data-value="User|Both" onclick="toggleFilter(this)">User Consent</button>
  </div>
  <div class="filter-sep"></div>
  <button class="filter-reset" onclick="resetFilters()">&#x2715; Clear filters</button>
  <span class="filter-count" id="filterCount"></span>
</div>

<p class="section-title">Application Details <span style="font-weight:400;text-transform:none">(click column headers to sort)</span></p>
<div class="table-wrap">
<table id="mainTable">
<thead>
<tr>
  <th data-sort="text" onclick="sortTable(0,this)">Application<span class="sort-icon"></span></th>
  <th data-sort="text" onclick="sortTable(1,this)">Type<span class="sort-icon"></span></th>
  <th data-sort="risk" onclick="sortTable(2,this)">Risk Level<span class="sort-icon"></span></th>
  <th data-sort="num" onclick="sortTable(3,this)">Score<span class="sort-icon"></span></th>
  <th>Flags</th>
  <th>Permissions</th>
  <th data-sort="text" onclick="sortTable(6,this)">Consent<span class="sort-icon"></span></th>
  <th data-sort="date" onclick="sortTable(7,this)">Last Sign-In<span class="sort-icon"></span></th>
  <th data-sort="num" onclick="sortTable(8,this)">Total<span class="sort-icon"></span></th>
  <th data-sort="num" onclick="sortTable(9,this)">&#128100;<span class="sort-icon"></span></th>
  <th data-sort="num" onclick="sortTable(10,this)">&#128274;<span class="sort-icon"></span></th>
  <th data-sort="num" onclick="sortTable(11,this)">&#9881;<span class="sort-icon"></span></th>
  <th data-sort="text" onclick="sortTable(12,this)">Status<span class="sort-icon"></span></th>
</tr>
</thead>
<tbody>
$tableRows
</tbody>
</table>
</div>

<script>
// activeFilters: map of filterKey -> Set of accepted values
// Within a group (same data-filter), buttons are OR-combined.
// Across groups, conditions are AND-combined.
const activeFilters = {};

function toggleFilter(btn) {
  const key = btn.dataset.filter;
  const val = btn.dataset.value;
  if (!activeFilters[key]) activeFilters[key] = new Set();
  if (btn.classList.contains('active')) {
    btn.classList.remove('active');
    activeFilters[key].delete(val);
    if (activeFilters[key].size === 0) delete activeFilters[key];
  } else {
    btn.classList.add('active');
    activeFilters[key].add(val);
  }
  applyFilters();
}

function resetFilters() {
  Object.keys(activeFilters).forEach(k => delete activeFilters[k]);
  document.querySelectorAll('.filter-btn.active').forEach(b => b.classList.remove('active'));
  applyFilters();
}

function applyFilters() {
  const keys = Object.keys(activeFilters);
  const rows = document.querySelectorAll('#mainTable tbody tr');
  let visible = 0;
  rows.forEach(r => {
    const show = keys.every(key => {
      const accepted = activeFilters[key];
      const cell = r.dataset[key] || '';
      // Each accepted value may be a pipe-separated pattern (e.g. "Admin|Both")
      return Array.from(accepted).some(pattern => pattern.split('|').some(v => v === cell));
    });
    r.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  const countEl = document.getElementById('filterCount');
  if (keys.length > 0) {
    countEl.textContent = visible + ' of ' + rows.length + ' shown';
  } else {
    countEl.textContent = '';
  }
}

function sortTable(colIdx, th) {
  const table = document.getElementById('mainTable');
  const tbody = table.querySelector('tbody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  const sortType = th.dataset.sort;

  // Determine sort direction
  const isAsc = th.classList.contains('sorted-asc');
  table.querySelectorAll('th').forEach(h => { h.classList.remove('sorted-asc','sorted-desc'); });
  th.classList.add(isAsc ? 'sorted-desc' : 'sorted-asc');
  const dir = isAsc ? -1 : 1;

  const riskOrder = {'High':0,'Medium':1,'Low':2,'None':3};

  rows.sort((a, b) => {
    let va = a.cells[colIdx].dataset.val || a.cells[colIdx].textContent.trim();
    let vb = b.cells[colIdx].dataset.val || b.cells[colIdx].textContent.trim();

    if (sortType === 'num') {
      va = parseFloat(va) || 0;
      vb = parseFloat(vb) || 0;
      return (va - vb) * dir;
    }
    if (sortType === 'risk') {
      va = riskOrder[va] !== undefined ? riskOrder[va] : 99;
      vb = riskOrder[vb] !== undefined ? riskOrder[vb] : 99;
      return (va - vb) * dir;
    }
    if (sortType === 'date') {
      va = va === '\u2014' ? '' : va;
      vb = vb === '\u2014' ? '' : vb;
      if (!va && !vb) return 0;
      if (!va) return 1 * dir;
      if (!vb) return -1 * dir;
      return (new Date(va) - new Date(vb)) * dir;
    }
    return va.localeCompare(vb) * dir;
  });

  rows.forEach(r => tbody.appendChild(r));
}

// Toggle show more / show less labels in permission details
document.addEventListener('toggle', function(e) {
  if (e.target.tagName === 'DETAILS') {
    var s = e.target.querySelector('summary');
    if (s && s.dataset.label) {
      s.textContent = e.target.open ? 'Show less' : s.dataset.label;
    }
  }
}, true);
</script>
</body>
</html>
"@
}

function Build-HtmlTableRow {
    param(
        [object]$Row,
        [string]$TenantId
    )

    $riskClass = switch ($Row.OverallRiskLevel) {
        'High'     { 'badge-high'   }
        'Medium'   { 'badge-medium' }
        'Low'      { 'badge-low'    }
        default    { 'badge-none'   }
    }

    # Flags column: SCIM, Overprivileged, Highly Privileged, Likely Unused
    $flagsHtml = @()
    if ($Row.IsLikelyUnused)      { $flagsHtml += "<span class='badge badge-unused' title='Inactive, no sign-ins, created &gt; 90 days ago'>Likely Unused</span>" }
    if ($Row.IsOverprivileged)    { $flagsHtml += "<span class='badge badge-overpriv' title='High-risk permissions with minimal usage'>Overprivileged</span>" }
    if ($Row.IsHighlyPrivileged -and -not $Row.IsOverprivileged) {
        $flagsHtml += "<span class='badge badge-highlyprivileged' title='Has High severity permissions'>Highly Privileged</span>"
    }
    if ($Row.IsScimApp)           { $flagsHtml += "<span class='badge badge-scim'>SCIM</span>" }
    if ($Row.HasExpiredSecrets)    { $flagsHtml += "<span class='badge badge-expired' title='One or more client secrets have expired'>Expired Secret</span>" }
    if ($Row.HasExpiredCerts)      { $flagsHtml += "<span class='badge badge-expired' title='One or more certificates have expired'>Expired Cert</span>" }
    $flagsCell = if ($flagsHtml.Count -gt 0) { $flagsHtml -join '<br>' } else { '<span style="color:#9ca3af">&mdash;</span>' }

    # Build permission list showing ALL permissions (not just sensitive)
    $permHtml = ''
    $allPerms = @()
    if ($Row._appPermissions)       { $allPerms += @($Row._appPermissions) }
    if ($Row._delegatedPermissions) { $allPerms += @($Row._delegatedPermissions) }

    if ($allPerms.Count -gt 0) {
        $permLines = $allPerms | Sort-Object { @{'High'=0;'Medium'=1;'Low'=2;'None'=3;'Unknown'=3}[$_.RiskLevel] } |
            ForEach-Object {
                $pClass = if ($_.IsSensitive) { "perm-$($_.RiskLevel.ToLower())" } else { 'perm-none' }
                $typeTag = if ($_.PermissionType -eq 'Delegated') { ' <span style="color:#9ca3af;font-size:0.6rem">[D]</span>' } else { '' }
                "<span class='$pClass'>$([System.Net.WebUtility]::HtmlEncode($_.PermissionName))$typeTag</span>"
            }
        $preview  = ($permLines | Select-Object -First 5) -join '<br>'
        $remaining = $allPerms.Count - 5
        if ($remaining -gt 0) {
            $restList = ($permLines | Select-Object -Skip 5) -join '<br>'
            $permHtml  = "<div class='perms-list'>$preview<br><details><summary data-label='+$remaining more'>+$remaining more</summary><div>$restList</div></details></div>"
        }
        else {
            $permHtml = "<div class='perms-list'>$preview</div>"
        }
    }
    else {
        $permHtml = '<span style="color:#9ca3af;font-size:0.7rem">No permissions</span>'
    }

    # Consent cell
    $consentHtml = switch ($Row.ConsentType) {
        'Admin' { "<span class='badge badge-consent-admin'>Admin</span>" }
        'User'  { "<span class='badge badge-consent-user'>User ($($Row.UserConsentedCount))</span>" }
        'Both'  { "<span class='badge badge-consent-admin'>Admin</span><br><span class='badge badge-consent-user'>User ($($Row.UserConsentedCount))</span>" }
        default { '<span style="color:#9ca3af">&mdash;</span>' }
    }

    # Sign-in cell
    $lastSeen = if ($Row.LastSeenOverall) { $Row.LastSeenOverall.ToString('yyyy-MM-dd') } else { '&mdash;' }
    $daysHtml = if ($null -ne $Row.DaysSinceLastSignIn) {
        $cls = if ($Row.IsInactive) { 'days-inactive' } else { '' }
        "<span class='days-num $cls'>$($Row.DaysSinceLastSignIn)d ago</span>"
    } else { '<span style="color:#9ca3af">No data</span>' }

    # Status badge
    $statusHtml = if ($Row.IsLikelyUnused) {
        "<span class='badge badge-unused'>Deletion candidate</span>"
    } elseif ($Row.IsInactive) {
        "<span class='inactive-label'>Inactive</span>"
    } else {
        "<span style='color:#166534;font-weight:600'>Active</span>"
    }

    $typeBadge = if ($Row.PrincipalType -eq 'ManagedIdentity') {
        "<span style='font-size:0.65rem;background:#ede9fe;color:#5b21b6;padding:2px 6px;border-radius:4px'>MI</span>"
    } else {
        "<span style='font-size:0.65rem;background:#dbeafe;color:#1e40af;padding:2px 6px;border-radius:4px'>EA</span>"
    }

    $name     = [System.Net.WebUtility]::HtmlEncode($Row.DisplayName)
    $appId    = [System.Net.WebUtility]::HtmlEncode($Row.AppId)
    $objId    = [System.Net.WebUtility]::HtmlEncode($Row.ObjectId)
    $isInact  = if ($Row.IsInactive) { 'true' } else { 'false' }
    $isUnused = if ($Row.IsLikelyUnused) { 'true' } else { 'false' }
    $isOverp  = if ($Row.IsOverprivileged) { 'true' } else { 'false' }
    $isHiPriv = if ($Row.IsHighlyPrivileged) { 'true' } else { 'false' }
    $isScim   = if ($Row.IsScimApp) { 'true' } else { 'false' }
    $isExpired = if ($Row.HasExpiredCredentials) { 'true' } else { 'false' }
    $typeKey  = if ($Row.PrincipalType -eq 'ManagedIdentity') { 'MI' } else { 'EA' }
    $rowClass = if ($Row.IsLikelyUnused) { 'row-unused' } else { '' }

    # Owner line for the application cell
    $ownerHtml = if ($Row.Owners) {
        "<br><span style='font-size:0.68rem;color:#6b7280'>Owner: $([System.Net.WebUtility]::HtmlEncode($Row.Owners))</span>"
    } else { '' }

    # Direct link to Entra portal
    $entraLink = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$objId/appId/$appId"

    return @"
<tr class="$rowClass" data-risk="$($Row.OverallRiskLevel)" data-inactive="$isInact" data-unused="$isUnused" data-overpriv="$isOverp" data-highlyprivileged="$isHiPriv" data-scim="$isScim" data-expired="$isExpired" data-consent="$($Row.ConsentType)" data-type="$typeKey">
  <td data-val="$name">
    <strong>$name</strong><br>
    <span style="font-size:0.68rem;color:#9ca3af">$appId</span>$ownerHtml<br>
    <a href="$entraLink" target="_blank" rel="noopener" class="app-link">Open in Entra &#8599;</a>
  </td>
  <td>$typeBadge</td>
  <td data-val="$($Row.OverallRiskLevel)"><span class="badge $riskClass">$($Row.OverallRiskLevel)</span></td>
  <td data-val="$($Row.RiskScore)" style="text-align:center;font-weight:600">$($Row.RiskScore)</td>
  <td>$flagsCell</td>
  <td>$permHtml</td>
  <td>$consentHtml</td>
  <td data-val="$lastSeen">$lastSeen<br>$daysHtml</td>
  <td data-val="$($Row.TotalSignInsInWindow)" style="text-align:center">$($Row.TotalSignInsInWindow)</td>
  <td data-val="$($Row.InteractiveSignInsInWindow)" style="text-align:center" title="Interactive sign-ins">$($Row.InteractiveSignInsInWindow)</td>
  <td data-val="$($Row.NonInteractiveSignInsInWindow)" style="text-align:center" title="Non-interactive sign-ins">$($Row.NonInteractiveSignInsInWindow)</td>
  <td data-val="$($Row.SpSignInsInWindow)" style="text-align:center" title="Service principal sign-ins">$($Row.SpSignInsInWindow)</td>
  <td data-val="$statusHtml">$statusHtml</td>
</tr>
"@
}

Export-ModuleMember -Function Export-ReviewReport, Build-CombinedResult
