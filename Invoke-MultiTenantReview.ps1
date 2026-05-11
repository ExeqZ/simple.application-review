<#
.SYNOPSIS
    Runs the enterprise application review across multiple M365 tenants (MSP / service provider use).

.DESCRIPTION
    Reads tenant configuration files from the ./tenants folder. Each file (*.json) represents
    one customer/tenant. Results are saved per-tenant in the output folder. An aggregated
    cross-tenant summary CSV and HTML are also produced.

    Create a new tenant config by copying tenants/sample-customer.json.sample to
    tenants/<customer-name>.json and filling in the values.

.PARAMETER TenantsFolder
    Path to the folder containing tenant JSON config files. Defaults to ./tenants.

.PARAMETER OutputFolder
    Root folder for all report output. Defaults to ./reports.

.PARAMETER TenantFilter
    Optional: process only tenants whose tenantName or tenantId matches this string (partial match).

.PARAMETER LookbackDays
    Override default Graph audit log lookback days from config. Ignored for tenants using Log Analytics.

.PARAMETER InactivityThresholdDays
    Override default inactivity threshold (days without sign-in). Defaults to 180 from config.

.PARAMETER SkipDetailedSignInLogs
    Skip audit log queries for all tenants (use signInActivity property only).

.PARAMETER IncludeRawJson
    Also write raw JSON per tenant.

.PARAMETER ContinueOnError
    If set, errors for one tenant are logged but processing continues for remaining tenants.
    Default: stop on first error.

.PARAMETER DebugLog
    Enables debug mode. Starts a PowerShell transcript that captures all console output,
    verbose messages, and detailed step-by-step logging to a file in the report folder.

.PARAMETER ShowHelp
    Displays a detailed help manual with usage examples and parameter descriptions, then exits.

.EXAMPLE
    # Run all enabled tenants from default tenants folder
    .\Invoke-MultiTenantReview.ps1

.EXAMPLE
    # Only process tenants matching 'Contoso'
    .\Invoke-MultiTenantReview.ps1 -TenantFilter 'Contoso' -ContinueOnError

.EXAMPLE
    # Use a custom tenants folder
    .\Invoke-MultiTenantReview.ps1 -TenantsFolder 'D:\configs\tenants'

.NOTES
    Add a JSON file per customer to the ./tenants folder.
    Copy tenants/sample-customer.json.sample as a starting point.
#>
[CmdletBinding()]
param(
    [string]$TenantsFolder            = './tenants',
    [string]$OutputFolder             = './reports',
    [string]$TenantFilter             = '',
    [int]   $LookbackDays             = 0,    # 0 = use config default
    [int]   $InactivityThresholdDays  = 0,    # 0 = use config default
    [int]   $LogAnalyticsLookbackDays = 0,    # 0 = use per-tenant config (default 365)
    [switch]$SkipDetailedSignInLogs,

    # Number of appIds per Graph $batch HTTP call for sign-in log queries (1–20, 0 = use config)
    [int]$SignInBatchSize = 0,

    [switch]$IncludeRawJson,
    [switch]$ContinueOnError,
    [switch]$DebugLog,
    [switch]$ShowHelp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = if ($ContinueOnError) { 'Continue' } else { 'Stop' }

# ── Show help and exit ────────────────────────────────────────────────────────
if ($ShowHelp) {
    Write-Host @"

  ╔══════════════════════════════════════════════════════════════════════╗
  ║      Invoke-MultiTenantReview.ps1 — Multi-Tenant Application Review ║
  ╚══════════════════════════════════════════════════════════════════════╝

  DESCRIPTION
    Runs the enterprise application review across multiple M365 tenants.
    Reads tenant JSON config files from the tenants folder, processes each
    one, and produces per-tenant reports plus a cross-tenant aggregate summary.

  USAGE
    .\Invoke-MultiTenantReview.ps1 [options]

  OPTIONS
    -TenantsFolder <path>                 Folder with tenant config files (default: ./tenants)
    -OutputFolder <path>                  Report output folder (default: ./reports)
    -TenantFilter <string>                Process only matching tenants (partial match on name/id)
    -LookbackDays <n>                     Override Graph audit log lookback (0 = use config)
    -InactivityThresholdDays <n>          Override inactivity threshold (0 = use config)
    -LogAnalyticsLookbackDays <n>         Override LA lookback (0 = use config)
    -SkipDetailedSignInLogs               No audit log queries for all tenants
    -SignInBatchSize <n>                   Override appIds per Graph `$batch call (1-20, 0=config)
    -IncludeRawJson                       Also write JSON per tenant
    -ContinueOnError                      Continue on error for remaining tenants
    -DebugLog                             Full transcript logging to report folder
    -ShowHelp                             Show this help and exit

  TENANT CONFIG
    Each JSON file in the tenants folder represents one customer.
    Copy tenants/sample-customer.json.sample to <customer>.json and fill in values.
    Use helpers/New-TenantSetup.ps1 to create a new config automatically.

  EXAMPLES
    # Run all enabled tenants
    .\Invoke-MultiTenantReview.ps1

    # Run only tenants matching 'Contoso'
    .\Invoke-MultiTenantReview.ps1 -TenantFilter 'Contoso' -ContinueOnError

    # Debug mode
    .\Invoke-MultiTenantReview.ps1 -DebugLog

  OUTPUT
    reports/<TenantName>_<timestamp>/     Per-tenant HTML/CSV reports
    reports/_summary/                     Cross-tenant aggregate summary (HTML + CSV)
    reports/debug-transcript_*.log        Debug log (with -DebugLog)

"@ -ForegroundColor Cyan
    return
}

# ── Debug / transcript mode ───────────────────────────────────────────────────
$script:DebugTranscriptPath = $null
if ($DebugLog) {
    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }
    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $script:DebugTranscriptPath = Join-Path $OutputFolder "debug-transcript_$timestamp.log"
    Start-Transcript -Path $script:DebugTranscriptPath -Append
    $VerbosePreference = 'Continue'
    Write-Host "[DEBUG] Transcript started: $($script:DebugTranscriptPath)" -ForegroundColor Magenta
    Write-Host "[DEBUG] PowerShell $($PSVersionTable.PSVersion) on $([Environment]::OSVersion.VersionString)" -ForegroundColor Magenta
    Write-Host "[DEBUG] Parameters: $($PSBoundParameters | ConvertTo-Json -Compress -Depth 2)" -ForegroundColor Magenta
}

# ── Load config from tenants folder ──────────────────────────────────────────
if (-not (Test-Path $TenantsFolder)) {
    throw "Tenants folder not found: $TenantsFolder`nCreate the folder and add a JSON config file per customer. Use tenants/sample-customer.json.sample as a template."
}

$tenantFiles = @(Get-ChildItem -Path $TenantsFolder -Filter '*.json' -File | Sort-Object Name)
if ($tenantFiles.Count -eq 0) {
    throw "No .json files found in $TenantsFolder. Copy tenants/sample-customer.json.sample to a .json file and fill in your values."
}

# Global defaults — can be overridden per-tenant via a settings block
$globalDefaults = @{
    inactivityThresholdDays         = 180
    signInLookbackDays              = 30
    signInBatchSize                 = 5
    includeDisabledApps             = $false
    includeManagedIdentities        = $true
    includeFirstPartyMicrosoftApps  = $false
}

# ── Load global auth defaults (multi-tenant app support) ─────────────────────
$authDefaultsPath = Join-Path $PSScriptRoot 'config' 'auth-defaults.json'
$globalAuth = $null
if (Test-Path $authDefaultsPath) {
    try {
        $globalAuth = Get-Content $authDefaultsPath -Raw | ConvertFrom-Json
        Write-Verbose "Loaded global auth defaults from $authDefaultsPath (clientId: $($globalAuth.clientId))"
    }
    catch {
        Write-Warning "Failed to parse config/auth-defaults.json: $_"
    }
}

# Load all tenant objects
$allTenantConfigs = foreach ($file in $tenantFiles) {
    try {
        $t = Get-Content $file.FullName -Raw | ConvertFrom-Json
        # Attach source file path for diagnostics
        $t | Add-Member -NotePropertyName '_sourceFile' -NotePropertyValue $file.FullName -Force

        # Merge global auth defaults into tenant config where fields are missing
        if ($globalAuth) {
            $authFields = @('authMethod', 'clientId', 'certificateThumbprint', 'certificatePath', 'certificatePasswordFile', 'clientSecretFile')
            foreach ($field in $authFields) {
                if ((-not $t.PSObject.Properties[$field] -or [string]::IsNullOrWhiteSpace($t.$field)) `
                    -and $globalAuth.PSObject.Properties[$field] -and -not [string]::IsNullOrWhiteSpace($globalAuth.$field)) {
                    $t | Add-Member -NotePropertyName $field -NotePropertyValue $globalAuth.$field -Force
                }
            }
        }

        $t
    }
    catch {
        Write-Warning "Skipping $($file.Name): failed to parse JSON — $_"
    }
}

$tenants = @($allTenantConfigs | Where-Object { $_.enabled -eq $true })

if ($TenantFilter) {
    $tenants = @($tenants | Where-Object {
        $_.tenantName -like "*$TenantFilter*" -or $_.tenantId -like "*$TenantFilter*"
    })
}

if ($tenants.Count -eq 0) {
    Write-Warning "No enabled tenants found in $TenantsFolder (filter: '$TenantFilter')."
    return
}

# Resolve global fallback lookback/inactivity (can be overridden per-tenant below)
$globalLookback  = if ($LookbackDays            -gt 0) { $LookbackDays }           else { $globalDefaults.signInLookbackDays }
$globalInactive  = if ($InactivityThresholdDays -gt 0) { $InactivityThresholdDays } else { $globalDefaults.inactivityThresholdDays }

Write-Host "`n=== Multi-Tenant Application Review ===" -ForegroundColor Cyan
Write-Host "  Tenants folder : $TenantsFolder"
Write-Host "  Tenant files   : $($tenantFiles.Count) found, $($tenants.Count) enabled"
if ($globalAuth) {
    Write-Host "  Global auth    : clientId=$($globalAuth.clientId) ($($globalAuth.authMethod))" -ForegroundColor Gray
}
Write-Host "  Lookback       : $globalLookback days (default)"
Write-Host "  Inactivity     : $globalInactive days (default)"
Write-Host "  Output         : $OutputFolder`n"

# ── Helper: multi-tenant HTML summary ────────────────────────────────────────
# Defined here (before use) so PowerShell can resolve it during execution.
function Build-MultiTenantSummaryHtml {
    param([object[]]$Summaries)

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm UTC'
    $rows = ($Summaries | ForEach-Object {
        $statusColor = if ($_.Status -eq 'Success') { '#166534' } else { '#991b1b' }
        $highCls = if ($_.HighRisk    -gt 0) { 'color:#b91c1c;font-weight:700' } else { '' }
        $medCls  = if ($_.MediumRisk  -gt 0) { 'color:#b45309;font-weight:600' } else { '' }
        $tenantNameHtml = [System.Net.WebUtility]::HtmlEncode($_.TenantName)
        @"
<tr>
  <td><strong>$tenantNameHtml</strong><br><span style='font-size:0.68rem;color:#9ca3af'>$($_.TenantId)</span></td>
  <td style='text-align:center'>$($_.TotalApps)</td>
  <td style='text-align:center;$highCls'>$($_.HighRisk)</td>
  <td style='text-align:center;$medCls'>$($_.MediumRisk)</td>
  <td style='text-align:center'>$($_.LowRisk)</td>
  <td style='text-align:center;$(if($_.LikelyUnused -gt 0){"color:#7c2d12;font-weight:700"})'>$($_.LikelyUnused)</td>
  <td style='text-align:center;$(if($_.Overprivileged -gt 0){"color:#991b1b;font-weight:700"})'>$($_.Overprivileged)</td>
  <td style='text-align:center;$(if($_.InactiveApps -gt 0){"color:#6b7280"})'>$($_.InactiveApps)</td>
  <td style='text-align:center'>$($_.ScimApps)</td>
  <td>$($_.ProcessedAt)</td>
  <td style='color:$statusColor;font-weight:600'>$($_.Status)</td>
</tr>
"@
    }) -join "`n"

    return @"
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Multi-Tenant Application Review Summary</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px;background:#f3f4f6;color:#111827;margin:0;padding:0}
header{background:#1e3a5f;color:#fff;padding:18px 28px}
header h1{font-size:1.3rem;font-weight:600}
header p{font-size:.78rem;opacity:.7;margin-top:3px}
.wrap{padding:24px 28px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
th{background:#1e3a5f;color:#fff;padding:9px 12px;text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em}
td{padding:8px 12px;border-bottom:1px solid #e5e7eb;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8fafc}
</style></head><body>
<header><h1>Multi-Tenant Application Review — Summary</h1><p>Generated: $generated</p></header>
<div class="wrap">
<table>
<thead><tr>
  <th>Tenant</th><th>Apps</th><th>High</th><th>Medium</th><th>Low</th>
  <th>Likely Unused</th><th>Overprivileged</th><th>Inactive</th><th>SCIM</th><th>Run At</th><th>Status</th>
</tr></thead>
<tbody>$rows</tbody>
</table>
</div></body></html>
"@
}

# ── Import modules ────────────────────────────────────────────────────────────
$moduleRoot = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $moduleRoot 'GraphAuth.psm1')    -Force
Import-Module (Join-Path $moduleRoot 'Applications.psm1') -Force
Import-Module (Join-Path $moduleRoot 'Permissions.psm1')  -Force
Import-Module (Join-Path $moduleRoot 'SignIns.psm1')      -Force
Import-Module (Join-Path $moduleRoot 'LogAnalytics.psm1') -Force
Import-Module (Join-Path $moduleRoot 'Reporting.psm1')    -Force

$allTenantSummaries = [System.Collections.Generic.List[object]]::new()
$tenantIndex        = 0
$errors             = [System.Collections.Generic.List[object]]::new()

foreach ($tenant in $tenants) {
    $tenantIndex++
    $tenantLabel = "$($tenant.tenantName) ($($tenant.tenantId))"
    Write-Host "[$tenantIndex/$($tenants.Count)] Processing: $tenantLabel" -ForegroundColor Cyan

    # Per-tenant settings override (falls back to global defaults)
    $ts              = $tenant.settings
    $effectiveLookback = if ($LookbackDays -gt 0) { $LookbackDays }
                         elseif ($ts -and $ts.signInLookbackDays)   { [int]$ts.signInLookbackDays }
                         else                                        { $globalDefaults.signInLookbackDays }
    $effectiveInactive = if ($InactivityThresholdDays -gt 0) { $InactivityThresholdDays }
                         elseif ($ts -and $ts.PSObject.Properties['inactivityThresholdDays']) { [int]$ts.inactivityThresholdDays }
                         else                                                                  { $globalDefaults.inactivityThresholdDays }

    $tenantStartTime = Get-Date

    try {
        # ── Authenticate ──────────────────────────────────────────────────────
        $accessToken = Get-GraphAccessTokenFromConfig -TenantConfig $tenant
        Write-Host "  Authenticated." -ForegroundColor Green

        # ── Resolve tenant name ───────────────────────────────────────────────
        try {
            $orgInfo    = Invoke-GraphRequest -AccessToken $accessToken `
                -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName,id'
            $tenantName = $orgInfo[0].displayName ?? $tenant.tenantName
            $tenantGuid = $orgInfo[0].id ?? $tenant.tenantId
        }
        catch {
            $tenantName = $tenant.tenantName
            $tenantGuid = $tenant.tenantId
        }

        # ── Enumerate ─────────────────────────────────────────────────────────
        Clear-ServicePrincipalCache
        $spParams = @{
            AccessToken                = $accessToken
            IncludeFirstPartyMicrosoft = if ($ts -and $ts.PSObject.Properties['includeFirstPartyMicrosoftApps']) { [bool]$ts.includeFirstPartyMicrosoftApps } else { $globalDefaults.includeFirstPartyMicrosoftApps }
            IncludeDisabled            = if ($ts -and $ts.PSObject.Properties['includeDisabledApps'])            { [bool]$ts.includeDisabledApps            } else { $globalDefaults.includeDisabledApps }
            IncludeManagedIdentities   = if ($ts -and $ts.PSObject.Properties['includeManagedIdentities'])       { [bool]$ts.includeManagedIdentities       } else { $globalDefaults.includeManagedIdentities }
        }
        $servicePrincipals = Get-AllApplications @spParams
        Write-Host "  Found $($servicePrincipals.Count) principals."

        # ── Permissions ───────────────────────────────────────────────────────
        $permResults = [System.Collections.Generic.List[object]]::new()
        $total       = $servicePrincipals.Count
        $i           = 0
        foreach ($sp in $servicePrincipals) {
            $i++
            Write-Progress -Id 1 -Activity "[$tenantIndex] Permissions" `
                -Status "$i/$total — $($sp.displayName)" `
                -PercentComplete (($i / $total) * 100)

            $pd  = Get-ApplicationPermissions -AccessToken $accessToken -ServicePrincipalId $sp.id
            $ps  = Get-PermissionSummary -PermissionData $pd
            $permResults.Add([PSCustomObject]@{ ServicePrincipal = $sp; PermissionData = $pd; PermissionSummary = $ps })
        }
        Write-Progress -Id 1 -Activity "[$tenantIndex] Permissions" -Completed

        # ── Sign-in activity ──────────────────────────────────────────────────
        # Build a token refresh scriptblock scoped to this tenant's config
        $currentTenant = $tenant
        $tenantTokenRefreshScript = {
            return Get-GraphAccessTokenFromConfig -TenantConfig $currentTenant
        }.GetNewClosure()

        $signInParams = @{
            AccessToken             = $accessToken
            ServicePrincipals       = $servicePrincipals
            InactivityThresholdDays = $effectiveInactive
            TokenRefreshScript       = $tenantTokenRefreshScript
            SignInBatchSize          = if ($SignInBatchSize -gt 0) { $SignInBatchSize }
                                       elseif ($ts -and $ts.PSObject.Properties['signInBatchSize']) { [int]$ts.signInBatchSize }
                                       else { $globalDefaults.signInBatchSize }
        }

        # Check whether this tenant has Log Analytics configured
        $laConfig = $tenant.logAnalytics
        $laEnabled = $laConfig -and $laConfig.enabled -eq $true -and $laConfig.workspaceId

        if ($laEnabled) {
            $effectiveLaLookback = if ($LogAnalyticsLookbackDays -gt 0) { $LogAnalyticsLookbackDays }
                                   elseif ($laConfig.lookbackDays)        { [int]$laConfig.lookbackDays }
                                   else                                   { 365 }
            Write-Host "  Acquiring Log Analytics token (lookback: ${effectiveLaLookback}d)..." -ForegroundColor Gray
            try {
                $laToken  = Get-LogAnalyticsAccessToken -TenantConfig $tenant

                $laCheck = Test-LogAnalyticsConnectivity -AccessToken $laToken -WorkspaceId $laConfig.workspaceId
                if (-not $laCheck.Connected) {
                    Write-Warning "  LA connectivity failed: $($laCheck.ErrorMessage). Falling back to Graph audit log."
                    $signInParams['LookbackDays']     = $effectiveLookback
                    $signInParams['SkipDetailedLogs'] = $SkipDetailedSignInLogs
                }
                else {
                    if ($laCheck.TablesMissing.Count -gt 0) {
                        Write-Warning "  LA tables not streamed (configure Diagnostic Settings): $($laCheck.TablesMissing -join ', ')"
                    }
                    $signInParams['LogAnalyticsConfig'] = @{
                        AccessToken  = $laToken
                        WorkspaceId  = $laConfig.workspaceId
                        LookbackDays = $effectiveLaLookback
                    }
                    Write-Host "  Log Analytics ready — workspace $($laConfig.workspaceId)" -ForegroundColor Green
                }
            }
            catch {
                Write-Warning "  Failed to acquire LA token: $_. Falling back to Graph audit log."
                $signInParams['LookbackDays']     = $effectiveLookback
                $signInParams['SkipDetailedLogs'] = $SkipDetailedSignInLogs
            }
        }
        else {
            $signInParams['LookbackDays']     = $effectiveLookback
            $signInParams['SkipDetailedLogs'] = $SkipDetailedSignInLogs
        }

        $signInResults = Get-BulkSignInActivity @signInParams

        # ── SCIM detection ────────────────────────────────────────────────────
        $scimStatus = Get-BulkScimStatus -AccessToken $accessToken -ServicePrincipals $servicePrincipals

        # ── Combine ───────────────────────────────────────────────────────────
        $signInLookup = @{}
        foreach ($sia in $signInResults) { $signInLookup[$sia.ServicePrincipalId] = $sia }

        $combined = foreach ($pr in $permResults) {
            $sia = $signInLookup[$pr.ServicePrincipal.id]
            if (-not $sia) {
                $sia = [PSCustomObject]@{
                    ServicePrincipalId = $pr.ServicePrincipal.id
                    LastSeenOverall = $null; DaysSinceLastSignIn = $null; IsInactive = $true
                    LastInteractiveSignIn = $null; LastNonInteractiveSignIn = $null
                    LastServicePrincipalSignIn = $null; TotalSignInsInWindow = 0
                    InteractiveSignInsInWindow = 0; NonInteractiveSignInsInWindow = 0
                    SpSignInsInWindow = 0; FailedSignInsInWindow = 0; FailureRatePercent = 0
                    DistinctInteractiveUsers = @(); DistinctInteractiveUserCount = 0
                    DistinctSpCallers = @(); DistinctSpCallerCount = 0; AuditLogsQueried = $false
                }
            }
            $isScim = if ($scimStatus.ContainsKey($pr.ServicePrincipal.id)) { $scimStatus[$pr.ServicePrincipal.id] } else { $false }
            Build-CombinedResult `
                -ServicePrincipal  $pr.ServicePrincipal `
                -PermissionData    $pr.PermissionData `
                -PermissionSummary $pr.PermissionSummary `
                -SignInActivity     $sia `
                -IsScimApp          $isScim
        }

        # ── Report ────────────────────────────────────────────────────────────
        $reportResult = Export-ReviewReport `
            -Results       $combined `
            -TenantName    $tenantName `
            -TenantId      $tenantGuid `
            -OutputFolder  $OutputFolder `
            -IncludeRawJson:$IncludeRawJson

        # ── Per-tenant summary row ─────────────────────────────────────────────
        $elapsedSec = [int]((Get-Date) - $tenantStartTime).TotalSeconds

        $allTenantSummaries.Add([PSCustomObject]@{
            TenantName             = $tenantName
            TenantId               = $tenantGuid
            TotalApps              = @($combined).Count
            HighRisk               = @($combined | Where-Object { $_.OverallRiskLevel -eq 'High'     }).Count
            MediumRisk             = @($combined | Where-Object { $_.OverallRiskLevel -eq 'Medium'   }).Count
            LowRisk                = @($combined | Where-Object { $_.OverallRiskLevel -eq 'Low'      }).Count
            InactiveApps           = @($combined | Where-Object { $_.IsInactive }).Count
            LikelyUnused           = @($combined | Where-Object { $_.IsLikelyUnused }).Count
            Overprivileged         = @($combined | Where-Object { $_.IsOverprivileged }).Count
            ScimApps               = @($combined | Where-Object { $_.IsScimApp }).Count
            ProcessedAt            = (Get-Date -Format 'yyyy-MM-dd HH:mm')
            ElapsedSeconds         = $elapsedSec
            Status                 = 'Success'
            ReportFolder           = $reportResult.ReportFolder
        })

        Write-Host "  Done in ${elapsedSec}s — reports at $($reportResult.ReportFolder)`n" -ForegroundColor Green
    }
    catch {
        $errors.Add([PSCustomObject]@{ TenantName = $tenant.tenantName; TenantId = $tenant.tenantId; Error = $_.ToString() })
        $allTenantSummaries.Add([PSCustomObject]@{
            TenantName = $tenant.tenantName; TenantId = $tenant.tenantId
            Status = 'Failed'; ErrorMessage = $_.ToString()
            TotalApps = 0; HighRisk = 0; MediumRisk = 0; LowRisk = 0
            InactiveApps = 0; LikelyUnused = 0; Overprivileged = 0; ScimApps = 0
            ProcessedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm'); ElapsedSeconds = 0
            ReportFolder = ''
        })
        Write-Warning "ERROR for $($tenant.tenantName): $_"
        if (-not $ContinueOnError) { break }
    }
}

# ── Aggregate summary report ──────────────────────────────────────────────────
if ($allTenantSummaries.Count -gt 0) {
    $summaryDir = Join-Path $OutputFolder '_summary'
    if (-not (Test-Path $summaryDir)) { New-Item -ItemType Directory -Path $summaryDir -Force | Out-Null }

    $timestamp   = Get-Date -Format 'yyyy-MM-dd_HH-mm'
    $summaryCsv  = Join-Path $summaryDir "multi-tenant-summary_$timestamp.csv"
    $allTenantSummaries | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8

    # HTML summary
    $summaryHtml = Build-MultiTenantSummaryHtml -Summaries $allTenantSummaries
    $summaryHtmlPath = Join-Path $summaryDir "multi-tenant-summary_$timestamp.html"
    $summaryHtml | Set-Content -Path $summaryHtmlPath -Encoding UTF8

    Write-Host "`n=== Multi-Tenant Summary ===" -ForegroundColor Cyan
    $allTenantSummaries | Format-Table TenantName, TotalApps, HighRisk, MediumRisk,
        LikelyUnused, Overprivileged, InactiveApps, Status -AutoSize
    Write-Host "  Aggregate CSV : $summaryCsv"
    Write-Host "  Aggregate HTML: $summaryHtmlPath"
}

if ($errors.Count -gt 0) {
    Write-Warning "`n$($errors.Count) tenant(s) failed:"
    $errors | ForEach-Object { Write-Warning "  $($_.TenantName): $($_.Error)" }
}

if ($DebugLog) {
    Write-Verbose "[DEBUG] Multi-tenant review completed at $(Get-Date -Format 'o')"
    Stop-Transcript -ErrorAction SilentlyContinue
}
