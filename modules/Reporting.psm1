<#
.SYNOPSIS
    Generates HTML, CSV, and JSON reports for the application review.

.DESCRIPTION
    Takes the combined result set (service principals + permissions + sign-in activity)
    and produces three report formats per tenant run.
    The HTML report is self-contained (no external CDN dependencies) and colour-codes
    risk levels matching both the internal severity (Critical/High/Medium/Low) and
    the Microsoft Defender for Cloud Apps classification (High/Medium/Low).
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
        Merges service principal, permission, and sign-in activity data into a single object.

    .PARAMETER ServicePrincipal
        Service principal object from Get-AllApplications.

    .PARAMETER PermissionData
        Output of Get-ApplicationPermissions.

    .PARAMETER PermissionSummary
        Output of Get-PermissionSummary.

    .PARAMETER SignInActivity
        Output of Get-ApplicationSignInActivity.

    .EXAMPLE
        $row = Build-CombinedResult -ServicePrincipal $sp -PermissionData $perms -PermissionSummary $summary -SignInActivity $sia
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$ServicePrincipal,
        [Parameter(Mandatory)] [object]$PermissionData,
        [Parameter(Mandatory)] [object]$PermissionSummary,
        [Parameter(Mandatory)] [object]$SignInActivity
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

        # Risk
        OverallRiskLevel              = $PermissionSummary.OverallRiskLevel
        OverallDefenderRiskLevel      = $PermissionSummary.OverallDefenderRiskLevel
        TotalPermissions              = $PermissionSummary.TotalPermissions
        SensitivePermissionCount      = $PermissionSummary.SensitivePermissionCount
        CriticalPermissions           = ($PermissionSummary.CriticalPermissions -join '; ')
        HighPermissions               = ($PermissionSummary.HighPermissions -join '; ')
        MediumPermissions             = ($PermissionSummary.MediumPermissions -join '; ')
        DefenderHighPermissions       = ($PermissionSummary.DefenderHighPermissions -join '; ')
        DefenderMediumPermissions     = ($PermissionSummary.DefenderMediumPermissions -join '; ')
        DefenderLowPermissions        = ($PermissionSummary.DefenderLowPermissions -join '; ')

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
        OverallDefenderRiskLevel      = $Row.OverallDefenderRiskLevel
        TotalPermissions              = $Row.TotalPermissions
        SensitivePermissionCount      = $Row.SensitivePermissionCount
        CriticalPermissions           = $Row.CriticalPermissions
        HighPermissions               = $Row.HighPermissions
        MediumPermissions             = $Row.MediumPermissions
        DefenderHighPermissions       = $Row.DefenderHighPermissions
        DefenderMediumPermissions     = $Row.DefenderMediumPermissions
        DefenderLowPermissions        = $Row.DefenderLowPermissions
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
    }
}

# ─── HTML report builder ─────────────────────────────────────────────────────

function Build-HtmlReport {
    param(
        [object[]]$Results,
        [string]$TenantName,
        [string]$TenantId
    )

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm UTC'
    $totalApps = $Results.Count
    $inactive  = @($Results | Where-Object { $_.IsInactive }).Count
    $critical  = @($Results | Where-Object { $_.OverallRiskLevel -eq 'Critical' }).Count
    $high      = @($Results | Where-Object { $_.OverallRiskLevel -eq 'High'     }).Count
    $medium    = @($Results | Where-Object { $_.OverallRiskLevel -eq 'Medium'   }).Count

    $defHigh   = @($Results | Where-Object { $_.OverallDefenderRiskLevel -eq 'High'   }).Count
    $defMedium = @($Results | Where-Object { $_.OverallDefenderRiskLevel -eq 'Medium' }).Count
    $defLow    = @($Results | Where-Object { $_.OverallDefenderRiskLevel -eq 'Low'    }).Count

    $tableRows = ($Results | Sort-Object OverallRiskLevel, DisplayName | ForEach-Object {
        Build-HtmlTableRow $_
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
    --clr-critical: #b91c1c; --clr-critical-bg: #fef2f2;
    --clr-high:     #c2410c; --clr-high-bg:     #fff7ed;
    --clr-medium:   #b45309; --clr-medium-bg:   #fffbeb;
    --clr-low:      #166534; --clr-low-bg:       #f0fdf4;
    --clr-none:     #374151; --clr-none-bg:      #f9fafb;
    --clr-inactive: #6b7280;
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
  .card.critical .num { color: var(--clr-critical); }
  .card.high     .num { color: var(--clr-high);     }
  .card.medium   .num { color: var(--clr-medium);   }
  .card.inactive .num { color: var(--clr-inactive); }
  .section-title { padding: 0 32px 8px; font-size: 0.75rem; font-weight: 600;
                   color: #6b7280; text-transform: uppercase; letter-spacing: .05em; }
  .table-wrap { overflow-x: auto; padding: 0 32px 32px; }
  table { width: 100%; border-collapse: collapse; background: #fff;
          border-radius: 8px; overflow: hidden;
          box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  th { background: #1e3a5f; color: #fff; padding: 10px 12px;
       text-align: left; font-size: 0.72rem; font-weight: 600;
       text-transform: uppercase; letter-spacing: .04em; white-space: nowrap; }
  td { padding: 9px 12px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f8fafc; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px;
           font-size: 0.68rem; font-weight: 600; white-space: nowrap; }
  .badge-critical { color: var(--clr-critical); background: var(--clr-critical-bg); }
  .badge-high     { color: var(--clr-high);     background: var(--clr-high-bg);     }
  .badge-medium   { color: var(--clr-medium);   background: var(--clr-medium-bg);   }
  .badge-low      { color: var(--clr-low);       background: var(--clr-low-bg);      }
  .badge-none     { color: var(--clr-none);     background: var(--clr-none-bg);     }
  .inactive-label { color: var(--clr-inactive); font-style: italic; }
  .perms-list { font-size: 0.7rem; color: #374151; }
  .perm-critical { color: var(--clr-critical); font-weight: 600; }
  .perm-high     { color: var(--clr-high);     }
  .perm-medium   { color: var(--clr-medium);   }
  .perm-low      { color: var(--clr-low);      }
  .def-badge { display: inline-block; padding: 1px 6px; border-radius: 4px;
               font-size: 0.65rem; font-weight: 600; margin-left: 4px; }
  .def-high   { background: #fee2e2; color: #991b1b; }
  .def-medium { background: #fef3c7; color: #92400e; }
  .def-low    { background: #d1fae5; color: #065f46; }
  .days-num { font-weight: 600; }
  .days-inactive { color: var(--clr-inactive); }
  details summary { cursor: pointer; font-size: 0.72rem; color: #3b82f6; }
  details summary:hover { text-decoration: underline; }
  .filter-bar { padding: 0 32px 12px; display: flex; gap: 8px; flex-wrap: wrap; }
  .filter-btn { padding: 5px 14px; border-radius: 6px; border: 1px solid #d1d5db;
                background: #fff; cursor: pointer; font-size: 0.75rem; color: #374151; }
  .filter-btn.active { background: #1e3a5f; color: #fff; border-color: #1e3a5f; }
  @media print { .filter-bar { display: none; } }
</style>
</head>
<body>
<header>
  <h1>Enterprise Application &amp; Managed Identity Review</h1>
  <p>Tenant: $([System.Net.WebUtility]::HtmlEncode($TenantName)) &nbsp;|&nbsp; ID: $TenantId &nbsp;|&nbsp; Generated: $generated UTC</p>
</header>

<div class="summary">
  <div class="card"><div class="num">$totalApps</div><div class="lbl">Total Applications</div></div>
  <div class="card critical"><div class="num">$critical</div><div class="lbl">Critical Risk</div></div>
  <div class="card high"><div class="num">$high</div><div class="lbl">High Risk</div></div>
  <div class="card medium"><div class="num">$medium</div><div class="lbl">Medium Risk</div></div>
  <div class="card inactive"><div class="num">$inactive</div><div class="lbl">Inactive Apps</div></div>
  <div class="card" style="border-left:4px solid #991b1b"><div class="num" style="color:#991b1b">$defHigh</div><div class="lbl">Defender: High</div></div>
  <div class="card" style="border-left:4px solid #92400e"><div class="num" style="color:#92400e">$defMedium</div><div class="lbl">Defender: Medium</div></div>
  <div class="card" style="border-left:4px solid #065f46"><div class="num" style="color:#065f46">$defLow</div><div class="lbl">Defender: Low</div></div>
</div>

<div class="filter-bar">
  <button class="filter-btn active" onclick="filterRows('all',this)">All</button>
  <button class="filter-btn" onclick="filterRows('Critical',this)">Critical</button>
  <button class="filter-btn" onclick="filterRows('High',this)">High</button>
  <button class="filter-btn" onclick="filterRows('Medium',this)">Medium</button>
  <button class="filter-btn" onclick="filterRows('inactive',this)">Inactive</button>
</div>

<p class="section-title">Application Details</p>
<div class="table-wrap">
<table id="mainTable">
<thead>
<tr>
  <th>Application</th>
  <th>Type</th>
  <th>Risk Level</th>
  <th>Defender Level</th>
  <th>Permissions</th>
  <th>Last Sign-In</th>
  <th>Sign-Ins (window)</th>
  <th>Status</th>
</tr>
</thead>
<tbody>
$tableRows
</tbody>
</table>
</div>

<script>
function filterRows(level, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const rows = document.querySelectorAll('#mainTable tbody tr');
  rows.forEach(r => {
    if (level === 'all') { r.style.display = ''; return; }
    if (level === 'inactive') { r.style.display = r.dataset.inactive === 'true' ? '' : 'none'; return; }
    r.style.display = r.dataset.risk === level ? '' : 'none';
  });
}
</script>
</body>
</html>
"@
}

function Build-HtmlTableRow {
    param([object]$Row)

    $riskClass    = switch ($Row.OverallRiskLevel) {
        'Critical' { 'badge-critical' }
        'High'     { 'badge-high'     }
        'Medium'   { 'badge-medium'   }
        'Low'      { 'badge-low'      }
        default    { 'badge-none'     }
    }

    $defClass = switch ($Row.OverallDefenderRiskLevel) {
        'High'   { 'def-high'   }
        'Medium' { 'def-medium' }
        'Low'    { 'def-low'    }
        default  { ''          }
    }

    $defBadge = if ($defClass) {
        "<span class='def-badge $defClass'>$([System.Net.WebUtility]::HtmlEncode($Row.OverallDefenderRiskLevel))</span>"
    } else { '<span style="color:#9ca3af">—</span>' }

    # Build sensitive permission list for the cell
    $permHtml = ''
    $allSensitive = @()
    if ($Row._appPermissions) {
        $allSensitive += @($Row._appPermissions | Where-Object { $_.IsSensitive })
    }
    if ($Row._delegatedPermissions) {
        $allSensitive += @($Row._delegatedPermissions | Where-Object { $_.IsSensitive })
    }

    if ($allSensitive.Count -gt 0) {
        $permLines = $allSensitive | Sort-Object { @{'Critical'=0;'High'=1;'Medium'=2;'Low'=3}[$_.RiskLevel] } |
            ForEach-Object {
                $pClass = "perm-$($_.RiskLevel.ToLower())"
                $dClass = if ($_.DefenderRiskLevel -ne 'Unknown') { "def-badge def-$($_.DefenderRiskLevel.ToLower())" } else { '' }
                $dTag   = if ($dClass) { " <span class='$dClass'>D:$([System.Net.WebUtility]::HtmlEncode($_.DefenderRiskLevel))</span>" } else { '' }
                "<span class='$pClass'>$([System.Net.WebUtility]::HtmlEncode($_.PermissionName))</span>$dTag"
            }
        $preview  = ($permLines | Select-Object -First 3) -join '<br>'
        $remaining = $allSensitive.Count - 3
        if ($remaining -gt 0) {
            $fullList = $permLines -join '<br>'
            $permHtml  = "<div class='perms-list'>$preview<br><details><summary>+$remaining more</summary><div>$fullList</div></details></div>"
        }
        else {
            $permHtml = "<div class='perms-list'>$preview</div>"
        }
    }
    else {
        $permHtml = '<span style="color:#9ca3af;font-size:0.7rem">None flagged</span>'
    }

    # Sign-in cell
    $lastSeen = if ($Row.LastSeenOverall) { $Row.LastSeenOverall.ToString('yyyy-MM-dd') } else { '—' }
    $daysHtml = if ($null -ne $Row.DaysSinceLastSignIn) {
        $cls = if ($Row.IsInactive) { 'days-inactive' } else { '' }
        "<span class='days-num $cls'>$($Row.DaysSinceLastSignIn)d ago</span>"
    } else { '<span style="color:#9ca3af">No data</span>' }

    # Status badge
    $statusHtml = if ($Row.IsInactive) {
        "<span class='inactive-label'>Inactive</span>"
    } else {
        "<span style='color:#166534;font-weight:600'>Active</span>"
    }

    $typeBadge = if ($Row.PrincipalType -eq 'ManagedIdentity') {
        "<span style='font-size:0.65rem;background:#ede9fe;color:#5b21b6;padding:2px 6px;border-radius:4px'>MI</span>"
    } else {
        "<span style='font-size:0.65rem;background:#dbeafe;color:#1e40af;padding:2px 6px;border-radius:4px'>EA</span>"
    }

    $name    = [System.Net.WebUtility]::HtmlEncode($Row.DisplayName)
    $appId   = [System.Net.WebUtility]::HtmlEncode($Row.AppId)
    $isInact = if ($Row.IsInactive) { 'true' } else { 'false' }

    return @"
<tr data-risk="$($Row.OverallRiskLevel)" data-inactive="$isInact">
  <td>
    <strong>$name</strong><br>
    <span style="font-size:0.68rem;color:#9ca3af">$appId</span>
  </td>
  <td>$typeBadge</td>
  <td><span class="badge $riskClass">$($Row.OverallRiskLevel)</span></td>
  <td>$defBadge</td>
  <td>$permHtml</td>
  <td>$lastSeen<br>$daysHtml</td>
  <td style="text-align:center">
    <span title="Interactive">&#128100; $($Row.InteractiveSignInsInWindow)</span>&nbsp;
    <span title="Non-Interactive">&#128274; $($Row.NonInteractiveSignInsInWindow)</span>&nbsp;
    <span title="Service Principal">&#128736; $($Row.SpSignInsInWindow)</span>
  </td>
  <td>$statusHtml</td>
</tr>
"@
}

Export-ModuleMember -Function Export-ReviewReport, Build-CombinedResult
