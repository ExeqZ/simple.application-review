<#
.SYNOPSIS
    Retrieves sign-in activity for enterprise applications and managed identities.

.DESCRIPTION
    Two data sources are combined:
      1. signInActivity on the service principal object (beta endpoint) — last interactive,
         non-interactive, and service principal sign-in timestamps. No P1/P2 licence required
         for this property itself.
      2. Sign-in logs via /auditLogs/signIns (interactive) and /auditLogs/nonInteractiveSignIns
         and /auditLogs/servicePrincipalSignIns — requires Entra ID P1 or P2 and
         AuditLog.Read.All permission.

    The module gracefully falls back to signInActivity-only mode when the audit log
    endpoints return 403 (insufficient licence or permission).
#>

function Get-ApplicationSignInActivity {
    <#
    .SYNOPSIS
        Returns sign-in activity for a single service principal.

    .PARAMETER AccessToken
        Bearer access token with AuditLog.Read.All (or at minimum Directory.Read.All).

    .PARAMETER ServicePrincipal
        Service principal object as returned by Get-AllApplications / Get-EnterpriseApplications.

    .PARAMETER LookbackDays
        How many days back to query sign-in logs. Defaults to 30.

    .PARAMETER InactivityThresholdDays
        Number of days without a sign-in before the app is considered inactive. Defaults to 90.

    .PARAMETER SkipDetailedLogs
        If set, only uses signInActivity on the SP object (no audit log queries).
        Use this if the tenant does not have Entra ID P1/P2 or AuditLog.Read.All.

    .EXAMPLE
        $activity = Get-ApplicationSignInActivity -AccessToken $token -ServicePrincipal $sp
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [object]$ServicePrincipal,

        [int]$LookbackDays = 30,
        [int]$InactivityThresholdDays = 180,
        [switch]$SkipDetailedLogs
    )

    $spId   = $ServicePrincipal.id
    $appId  = $ServicePrincipal.appId
    $spName = $ServicePrincipal.displayName

    # ── Source 1: signInActivity on the SP object (from beta endpoint) ────────
    # Already fetched when enumerating — no extra API call needed.
    $sia = $ServicePrincipal.signInActivity

    $lastInteractive     = Parse-NullableDate $sia.lastSignInDateTime
    $lastNonInteractive  = Parse-NullableDate $sia.lastNonInteractiveSignInDateTime
    $lastServicePrincipal = Parse-NullableDate $sia.lastServicePrincipalSignInDateTime

    # Most recent sign-in across all types from the SP object
    $lastSeenViaSp = ($lastInteractive, $lastNonInteractive, $lastServicePrincipal |
        Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1)

    # ── Source 2: Audit log queries (optional, requires P1/P2 + AuditLog.Read.All) ──
    $interactiveLogs      = @()
    $nonInteractiveLogs   = @()
    $spSignInLogs         = @()
    $auditLogsAvailable   = $false

    if (-not $SkipDetailedLogs) {
        $since = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')

        $interactiveLogs    = Get-InteractiveSignIns    -AccessToken $AccessToken -AppId $appId -Since $since
        $nonInteractiveLogs = Get-NonInteractiveSignIns -AccessToken $AccessToken -AppId $appId -Since $since
        $spSignInLogs       = Get-ServicePrincipalSignIns -AccessToken $AccessToken -ServicePrincipalId $spId -Since $since

        $auditLogsAvailable = $true
    }

    # ── Aggregate ─────────────────────────────────────────────────────────────
    $allLogDates = @(
        $interactiveLogs    | Select-Object -ExpandProperty createdDateTime | ForEach-Object { Parse-NullableDate $_ }
        $nonInteractiveLogs | Select-Object -ExpandProperty createdDateTime | ForEach-Object { Parse-NullableDate $_ }
        $spSignInLogs       | Select-Object -ExpandProperty createdDateTime | ForEach-Object { Parse-NullableDate $_ }
    ) | Where-Object { $_ }

    $lastSeenViaLogs = $allLogDates | Sort-Object -Descending | Select-Object -First 1

    # Best available last-seen date
    $lastSeenOverall = ($lastSeenViaSp, $lastSeenViaLogs | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1)

    $daysSinceLastSeen = $null
    $isInactive        = $null
    if ($lastSeenOverall) {
        $daysSinceLastSeen = [int]((Get-Date).ToUniversalTime() - $lastSeenOverall).TotalDays
        $isInactive        = $daysSinceLastSeen -gt $InactivityThresholdDays
    }
    else {
        # No sign-in found at all — treat as inactive (never used or data not available)
        $isInactive = $true
    }

    # Unique users who signed in interactively in the lookback window
    $distinctInteractiveUsers = @($interactiveLogs |
        Where-Object { $_.userPrincipalName } |
        Select-Object -ExpandProperty userPrincipalName -Unique)

    # Unique service principal/managed identity sign-ins in the lookback window
    $distinctSpSignIns = @($spSignInLogs |
        Where-Object { $_.servicePrincipalName } |
        Select-Object -ExpandProperty servicePrincipalName -Unique)

    # Failure rate in the lookback window
    $totalSignIns    = $interactiveLogs.Count + $nonInteractiveLogs.Count + $spSignInLogs.Count
    $failedSignIns   = @(
        $interactiveLogs    | Where-Object { $_.status.errorCode -ne 0 }
        $nonInteractiveLogs | Where-Object { $_.status.errorCode -ne 0 }
        $spSignInLogs       | Where-Object { $_.status.errorCode -ne 0 }
    ).Count
    $failureRate = if ($totalSignIns -gt 0) { [math]::Round(($failedSignIns / $totalSignIns) * 100, 1) } else { 0 }

    return [PSCustomObject]@{
        ServicePrincipalId            = $spId
        DisplayName                   = $spName

        # Timestamps from SP signInActivity property
        LastInteractiveSignIn         = $lastInteractive
        LastNonInteractiveSignIn      = $lastNonInteractive
        LastServicePrincipalSignIn    = $lastServicePrincipal

        # Best available last-seen date
        LastSeenOverall               = $lastSeenOverall
        DaysSinceLastSignIn           = $daysSinceLastSeen
        IsInactive                    = $isInactive
        InactivityThresholdDays       = $InactivityThresholdDays

        # Counts from audit log (only meaningful when SkipDetailedLogs is not set)
        AuditLogsQueried              = $auditLogsAvailable
        LookbackDays                  = $LookbackDays
        TotalSignInsInWindow          = $totalSignIns
        InteractiveSignInsInWindow    = $interactiveLogs.Count
        NonInteractiveSignInsInWindow = $nonInteractiveLogs.Count
        SpSignInsInWindow             = $spSignInLogs.Count
        FailedSignInsInWindow         = $failedSignIns
        FailureRatePercent            = $failureRate

        # Who used this app
        DistinctInteractiveUsers      = $distinctInteractiveUsers
        DistinctInteractiveUserCount  = $distinctInteractiveUsers.Count
        DistinctSpCallers             = $distinctSpSignIns
        DistinctSpCallerCount         = $distinctSpSignIns.Count
    }
}

function Get-InteractiveSignIns {
    <#
    .SYNOPSIS
        Retrieves interactive user sign-ins for an application from the audit log.
    #>
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$AppId,
        [string]$Since
    )

    $select = 'createdDateTime,userPrincipalName,userId,status,ipAddress,location,clientAppUsed,conditionalAccessStatus,riskLevelDuringSignIn'
    $filter = "appId eq '$AppId' and createdDateTime ge $Since"
    $uri    = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$select=$select&`$top=999"

    return Invoke-GraphRequestSafe -AccessToken $AccessToken -Uri $uri -Context "interactive sign-ins for app $AppId"
}

function Get-NonInteractiveSignIns {
    <#
    .SYNOPSIS
        Retrieves non-interactive user sign-ins for an application from the audit log.
    #>
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$AppId,
        [string]$Since
    )

    $select = 'createdDateTime,userPrincipalName,userId,status,ipAddress,clientAppUsed'
    $filter = "appId eq '$AppId' and createdDateTime ge $Since"
    $uri    = "https://graph.microsoft.com/v1.0/auditLogs/nonInteractiveSignIns?`$filter=$filter&`$select=$select&`$top=999"

    return Invoke-GraphRequestSafe -AccessToken $AccessToken -Uri $uri -Context "non-interactive sign-ins for app $AppId"
}

function Get-ServicePrincipalSignIns {
    <#
    .SYNOPSIS
        Retrieves service principal (app-to-app / managed identity) sign-ins.
    #>
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$ServicePrincipalId,
        [string]$Since
    )

    $select = 'createdDateTime,servicePrincipalName,servicePrincipalId,status,ipAddress,resourceDisplayName,resourceId'
    $filter = "servicePrincipalId eq '$ServicePrincipalId' and createdDateTime ge $Since"
    $uri    = "https://graph.microsoft.com/v1.0/auditLogs/servicePrincipalSignIns?`$filter=$filter&`$select=$select&`$top=999"

    return Invoke-GraphRequestSafe -AccessToken $AccessToken -Uri $uri -Context "SP sign-ins for $ServicePrincipalId"
}

function Get-BulkSignInActivity {
    <#
    .SYNOPSIS
        Retrieves sign-in activity for a list of service principals efficiently.

    .DESCRIPTION
        Two execution modes:

        1. Log Analytics mode (preferred for long lookback periods):
           Pass -LogAnalyticsConfig with AccessToken, WorkspaceId, and LookbackDays.
           Issues bulk KQL queries covering up to 365+ days and merges results with the
           signInActivity property already present on each SP object.

        2. Graph audit log mode (default, max ~30 days reliable retention):
           Queries /auditLogs/signIns et al. per service principal. Requires Entra ID P1/P2
           and AuditLog.Read.All. Use -SkipDetailedLogs to skip audit log queries entirely
           and only use the signInActivity property timestamps.

    .PARAMETER AccessToken
        Graph API bearer token.

    .PARAMETER ServicePrincipals
        Array of service principal objects (must include signInActivity — use beta endpoint).

    .PARAMETER LookbackDays
        Lookback window for Graph audit log queries. Defaults to 30.
        Ignored when LogAnalyticsConfig is provided (use LogAnalyticsConfig.LookbackDays instead).

    .PARAMETER InactivityThresholdDays
        Days without any sign-in to mark an app inactive. Defaults to 180.

    .PARAMETER SkipDetailedLogs
        Only use signInActivity on the SP object (no audit log API calls). Fastest mode.
        Ignored when LogAnalyticsConfig is provided.

    .PARAMETER LogAnalyticsConfig
        Hashtable enabling Log Analytics mode. Required keys:
          AccessToken  — LA-scoped bearer token (scope: https://api.loganalytics.io/.default)
          WorkspaceId  — Log Analytics workspace GUID
          LookbackDays — How many days to query (e.g. 365)

    .EXAMPLE
        # Graph audit log mode
        $activity = Get-BulkSignInActivity -AccessToken $token -ServicePrincipals $apps

    .EXAMPLE
        # Log Analytics mode (365-day lookback)
        $laToken   = Get-LogAnalyticsAccessToken -TenantConfig $tenant
        $activity  = Get-BulkSignInActivity -AccessToken $token -ServicePrincipals $apps `
            -InactivityThresholdDays 180 `
            -LogAnalyticsConfig @{
                AccessToken  = $laToken
                WorkspaceId  = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
                LookbackDays = 365
            }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [object[]]$ServicePrincipals,

        [int]$LookbackDays            = 30,
        [int]$InactivityThresholdDays = 180,
        [switch]$SkipDetailedLogs,

        # When provided, switches to Log Analytics bulk-query mode.
        [hashtable]$LogAnalyticsConfig = $null
    )

    # ── Log Analytics mode ────────────────────────────────────────────────────
    if ($LogAnalyticsConfig) {
        $requiredKeys = @('AccessToken', 'WorkspaceId', 'LookbackDays')
        foreach ($key in $requiredKeys) {
            if (-not $LogAnalyticsConfig.ContainsKey($key)) {
                throw "LogAnalyticsConfig is missing required key: '$key'"
            }
        }

        Write-Host "  Using Log Analytics workspace $($LogAnalyticsConfig.WorkspaceId) — lookback $($LogAnalyticsConfig.LookbackDays) days" -ForegroundColor Cyan

        return Get-BulkSignInActivityFromLogAnalytics `
            -AccessToken             $LogAnalyticsConfig.AccessToken `
            -WorkspaceId             $LogAnalyticsConfig.WorkspaceId `
            -ServicePrincipals       $ServicePrincipals `
            -LookbackDays            $LogAnalyticsConfig.LookbackDays `
            -InactivityThresholdDays $InactivityThresholdDays
    }

    # ── Graph audit log mode (per-SP) ─────────────────────────────────────────
    $results   = [System.Collections.Generic.List[object]]::new()
    $total     = $ServicePrincipals.Count
    $processed = 0

    foreach ($sp in $ServicePrincipals) {
        $processed++
        Write-Progress -Activity 'Retrieving sign-in activity' `
            -Status "$processed / $total — $($sp.displayName)" `
            -PercentComplete (($processed / $total) * 100)

        $activity = Get-ApplicationSignInActivity `
            -AccessToken             $AccessToken `
            -ServicePrincipal        $sp `
            -LookbackDays            $LookbackDays `
            -InactivityThresholdDays $InactivityThresholdDays `
            -SkipDetailedLogs:       $SkipDetailedLogs

        $results.Add($activity)
    }

    Write-Progress -Activity 'Retrieving sign-in activity' -Completed
    return $results
}

# ─── Internal helpers ────────────────────────────────────────────────────────

function Invoke-GraphRequestSafe {
    <#
    .SYNOPSIS
        Wraps Invoke-GraphRequest and returns an empty array on 403/404 instead of throwing.
        Used for audit log endpoints that may not be licensed or consented.
    #>
    param(
        [string]$AccessToken,
        [string]$Uri,
        [string]$Context
    )
    try {
        return @(Invoke-GraphRequest -AccessToken $AccessToken -Uri $Uri -All)
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -in 403, 404) {
            Write-Verbose "Audit log not available for $Context (HTTP $statusCode — licence or permission missing). Skipping."
            return @()
        }
        Write-Warning "Error querying $Context`: $_"
        return @()
    }
}

function Parse-NullableDate {
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { return [datetime]::Parse($Value, $null, [System.Globalization.DateTimeStyles]::RoundtripKind) }
    catch { return $null }
}

Export-ModuleMember -Function Get-ApplicationSignInActivity, Get-BulkSignInActivity,
    Get-InteractiveSignIns, Get-NonInteractiveSignIns, Get-ServicePrincipalSignIns
