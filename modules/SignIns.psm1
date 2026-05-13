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
    $filter = "appId eq '$AppId' and createdDateTime ge $Since and signInEventTypes/any(t: t eq 'nonInteractiveUser')"
    $uri    = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$([Uri]::EscapeDataString($filter))&`$select=$select&`$top=999&`$count=true"

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
    $filter = "servicePrincipalId eq '$ServicePrincipalId' and createdDateTime ge $Since and signInEventTypes/any(t: t eq 'servicePrincipal')"
    $uri    = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$([Uri]::EscapeDataString($filter))&`$select=$select&`$top=999&`$count=true"

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

    .PARAMETER SignInBatchSize
        Number of appIds to bundle per Graph $batch HTTP call (max 20, default 5).
        Smaller values are more reliable; larger values reduce total HTTP requests.

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

        # Number of appIds per Graph $batch HTTP call (1–20). Default 5.
        [ValidateRange(1, 20)]
        [int]$SignInBatchSize = 5,

        # Optional scriptblock that returns a fresh access token when invoked.
        # Passed through to Invoke-BatchedSignInQuery for proactive token renewal.
        [scriptblock]$TokenRefreshScript = $null,

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

    # ── Graph audit log mode (JSON $batch with simple per-appId filters) ────────
    # Uses Graph $batch API to bundle individual per-appId queries (up to BatchSize per
    # HTTP call). Each sub-request has a simple OData filter — no OR combinations, no
    # complex lambda expressions that trigger "Unsupported Query" errors.
    # Interactive sign-ins use the stable v1.0 endpoint; non-interactive and SP sign-ins
    # use dedicated /beta/reports endpoints when available.
    $allAppIds  = @($ServicePrincipals | Select-Object -ExpandProperty appId)

    $interactiveMap    = @{}
    $nonInteractiveMap = @{}
    $spSignInMap       = @{}

    if (-not $SkipDetailedLogs) {
        $since = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        Write-Host ("  Querying audit logs: {0} service principals via Graph `$batch (batch size: {1})..." -f
            $allAppIds.Count, $SignInBatchSize) -ForegroundColor Gray

        # Interactive user sign-ins — v1.0 endpoint (returns interactive by default, no signInEventTypes lambda needed)
        $batchQueryParams = @{
            AccessToken        = $AccessToken
            AppIds             = $allAppIds
            Since              = $since
            BatchSize          = $SignInBatchSize
        }
        if ($TokenRefreshScript) { $batchQueryParams['TokenRefreshScript'] = $TokenRefreshScript }

        $interactiveMap = Invoke-BatchedSignInQuery @batchQueryParams -SignInType 'interactive'

        # Pick up a potentially refreshed token from the last batch run
        if ($TokenRefreshScript -and (Test-TokenExpiringSoon -AccessToken $AccessToken)) {
            $AccessToken = & $TokenRefreshScript
            $batchQueryParams['AccessToken'] = $AccessToken
        }

        # Non-interactive user sign-ins — beta endpoint with signInEventTypes filter
        $batchQueryParams['AccessToken'] = $AccessToken
        $nonInteractiveMap = Invoke-BatchedSignInQuery @batchQueryParams -SignInType 'nonInteractiveUser'

        # Service principal / managed identity sign-ins — beta endpoint with signInEventTypes filter
        if ($TokenRefreshScript -and (Test-TokenExpiringSoon -AccessToken $AccessToken)) {
            $AccessToken = & $TokenRefreshScript
            $batchQueryParams['AccessToken'] = $AccessToken
        }
        $spSignInMap = Invoke-BatchedSignInQuery @batchQueryParams -SignInType 'servicePrincipal'
    }

    # ── Aggregate per SP from the bulk lookup maps ─────────────────────────────
    $results = [System.Collections.Generic.List[object]]::new()
    $total   = $ServicePrincipals.Count
    $idx     = 0

    foreach ($sp in $ServicePrincipals) {
        $idx++
        Write-Progress -Activity 'Aggregating sign-in activity' `
            -Status "$idx / $total — $($sp.displayName)" `
            -PercentComplete (($idx / $total) * 100)

        # Source 1: signInActivity timestamps already on the SP object (no extra API call)
        $sia                  = $sp.signInActivity
        $lastInteractive      = Parse-NullableDate $sia.lastSignInDateTime
        $lastNonInteractive   = Parse-NullableDate $sia.lastNonInteractiveSignInDateTime
        $lastServicePrincipal = Parse-NullableDate $sia.lastServicePrincipalSignInDateTime
        $lastSeenViaSp        = ($lastInteractive, $lastNonInteractive, $lastServicePrincipal |
                                 Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1)

        # Source 2: audit log records from the bulk maps
        if ($SkipDetailedLogs) {
            $interactiveLogs    = @()
            $nonInteractiveLogs = @()
            $spSignInLogs       = @()
            $auditLogsAvailable = $false
        }
        else {
            $interactiveLogs    = @($interactiveMap[$sp.appId])
            $nonInteractiveLogs = @($nonInteractiveMap[$sp.appId])
            $spSignInLogs       = @($spSignInMap[$sp.appId])
            $auditLogsAvailable = $true
        }

        $allLogDates = @(
            $interactiveLogs    | Select-Object -ExpandProperty createdDateTime | ForEach-Object { Parse-NullableDate $_ }
            $nonInteractiveLogs | Select-Object -ExpandProperty createdDateTime | ForEach-Object { Parse-NullableDate $_ }
            $spSignInLogs       | Select-Object -ExpandProperty createdDateTime | ForEach-Object { Parse-NullableDate $_ }
        ) | Where-Object { $_ }

        $lastSeenViaLogs = $allLogDates | Sort-Object -Descending | Select-Object -First 1
        $lastSeenOverall = ($lastSeenViaSp, $lastSeenViaLogs |
                            Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1)

        $daysSinceLastSeen = $null
        $isInactive        = $null
        if ($lastSeenOverall) {
            $daysSinceLastSeen = [int]((Get-Date).ToUniversalTime() - $lastSeenOverall).TotalDays
            $isInactive        = $daysSinceLastSeen -gt $InactivityThresholdDays
        }
        else {
            $isInactive = $true
        }

        $distinctInteractiveUsers = @($interactiveLogs |
            Where-Object { $_.userPrincipalName } |
            Select-Object -ExpandProperty userPrincipalName -Unique)

        $distinctSpSignIns = @($spSignInLogs |
            Where-Object { $_.servicePrincipalName } |
            Select-Object -ExpandProperty servicePrincipalName -Unique)

        $totalSignIns  = $interactiveLogs.Count + $nonInteractiveLogs.Count + $spSignInLogs.Count
        $failedSignIns = @(
            $interactiveLogs    | Where-Object { $_.status.errorCode -ne 0 }
            $nonInteractiveLogs | Where-Object { $_.status.errorCode -ne 0 }
            $spSignInLogs       | Where-Object { $_.status.errorCode -ne 0 }
        ).Count
        $failureRate = if ($totalSignIns -gt 0) { [math]::Round(($failedSignIns / $totalSignIns) * 100, 1) } else { 0 }

        $results.Add([PSCustomObject]@{
            ServicePrincipalId            = $sp.id
            DisplayName                   = $sp.displayName
            LastInteractiveSignIn         = $lastInteractive
            LastNonInteractiveSignIn      = $lastNonInteractive
            LastServicePrincipalSignIn    = $lastServicePrincipal
            LastSeenOverall               = $lastSeenOverall
            DaysSinceLastSignIn           = $daysSinceLastSeen
            IsInactive                    = $isInactive
            InactivityThresholdDays       = $InactivityThresholdDays
            AuditLogsQueried              = $auditLogsAvailable
            LookbackDays                  = $LookbackDays
            TotalSignInsInWindow          = $totalSignIns
            InteractiveSignInsInWindow    = $interactiveLogs.Count
            NonInteractiveSignInsInWindow = $nonInteractiveLogs.Count
            SpSignInsInWindow             = $spSignInLogs.Count
            FailedSignInsInWindow         = $failedSignIns
            FailureRatePercent            = $failureRate
            DistinctInteractiveUsers      = $distinctInteractiveUsers
            DistinctInteractiveUserCount  = $distinctInteractiveUsers.Count
            DistinctSpCallers             = $distinctSpSignIns
            DistinctSpCallerCount         = $distinctSpSignIns.Count
        })
    }

    Write-Progress -Activity 'Aggregating sign-in activity' -Completed
    return $results
}

# ─── Internal helpers ────────────────────────────────────────────────────────
function Invoke-BatchedSignInQuery {
    <#
    .SYNOPSIS
        Uses the Graph JSON $batch API to query sign-in logs for multiple appIds efficiently.
        Each appId gets its own simple OData filter — no OR combinations or complex lambda
        expressions. Sub-requests are bundled into $batch HTTP calls (up to BatchSize per call).

    .DESCRIPTION
        Strategy per sign-in type:
          - interactive:       /v1.0/auditLogs/signIns  (returns interactive by default)
          - nonInteractiveUser: /beta/auditLogs/signIns + signInEventTypes/any() lambda
          - servicePrincipal:  /beta/auditLogs/signIns + signInEventTypes/any() lambda

        Because each sub-request in the $batch is independent, a lambda failure for one appId
        does not affect the others. Failed sub-requests are logged and the appId is skipped
        gracefully.

    .PARAMETER AppIds
        Array of application (client) IDs to query.

    .PARAMETER SignInType
        One of: 'interactive', 'nonInteractiveUser', 'servicePrincipal'.

    .PARAMETER BatchSize
        How many sub-requests per $batch HTTP call (1–20). Defaults to 5.

    .OUTPUTS
        Hashtable mapping each appId to a list of sign-in records.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string[]]$AppIds,

        [Parameter(Mandatory)]
        [string]$Since,

        [Parameter(Mandatory)]
        [ValidateSet('interactive', 'nonInteractiveUser', 'servicePrincipal')]
        [string]$SignInType,

        [ValidateRange(1, 20)]
        [int]$BatchSize = 5,

        # Optional scriptblock that returns a fresh access token when invoked.
        # Called proactively before each batch when the current token is near expiry.
        [scriptblock]$TokenRefreshScript = $null
    )

    # Pre-populate result map so callers always get a list per appId
    $resultMap = @{}
    foreach ($id in $AppIds) { $resultMap[$id] = [System.Collections.Generic.List[object]]::new() }

    # Build the $select and URL pattern per sign-in type
    # Note: OData filters require single-quoted string values. Use [char]39 to embed
    # literal single quotes inside PowerShell double-quoted strings.
    # Sub-request URLs are relative to the $batch endpoint version — do NOT include
    # /v1.0/ or /beta/ in the URL. Instead, set the batch endpoint version appropriately.
    $q = [char]39   # single-quote character for OData filter values
    $batchVersion = 'v1.0'   # default; overridden for beta endpoints below
    switch ($SignInType) {
        'interactive' {
            $selectFields = 'appId,createdDateTime,userPrincipalName,userId,status,ipAddress,location,clientAppUsed,conditionalAccessStatus,riskLevelDuringSignIn'
            # v1.0 /auditLogs/signIns returns interactive sign-ins by default — no lambda filter needed
            $batchVersion = 'v1.0'
            $buildUrl = {
                param($appId)
                $f = [Uri]::EscapeDataString("appId eq ${q}${appId}${q} and createdDateTime ge $Since")
                return "/auditLogs/signIns?`$filter=$f&`$select=$selectFields&`$top=999"
            }
        }
        'nonInteractiveUser' {
            $selectFields = 'appId,createdDateTime,userPrincipalName,userId,status,ipAddress,clientAppUsed'
            $batchVersion = 'beta'
            $buildUrl = {
                param($appId)
                $f = [Uri]::EscapeDataString("appId eq ${q}${appId}${q} and createdDateTime ge $Since and signInEventTypes/any(t: t eq ${q}nonInteractiveUser${q})")
                return "/auditLogs/signIns?`$filter=$f&`$select=$selectFields&`$top=999&`$count=true"
            }
        }
        'servicePrincipal' {
            $selectFields = 'appId,createdDateTime,servicePrincipalName,status,ipAddress,resourceDisplayName,resourceId'
            $batchVersion = 'beta'
            $buildUrl = {
                param($appId)
                $f = [Uri]::EscapeDataString("appId eq ${q}${appId}${q} and createdDateTime ge $Since and signInEventTypes/any(t: t eq ${q}servicePrincipal${q})")
                return "/auditLogs/signIns?`$filter=$f&`$select=$selectFields&`$top=999&`$count=true"
            }
        }
    }

    $totalBatches = [math]::Ceiling($AppIds.Count / $BatchSize)
    Write-Verbose "  $SignInType sign-ins: $($AppIds.Count) appIds in $totalBatches batch(es) (batch size $BatchSize)"

    for ($i = 0; $i -lt $AppIds.Count; $i += $BatchSize) {
        $batch    = $AppIds[$i .. [math]::Min($i + $BatchSize - 1, $AppIds.Count - 1)]
        $batchNum = [math]::Floor($i / $BatchSize) + 1

        # Proactively refresh token before it expires (5-minute margin)
        if ($TokenRefreshScript -and (Test-TokenExpiringSoon -AccessToken $AccessToken)) {
            Write-Verbose "Access token expiring soon — refreshing before $SignInType batch ${batchNum}/${totalBatches}..."
            $AccessToken = & $TokenRefreshScript
            Write-Verbose "Token refreshed successfully."
        }

        # Build the sub-requests for this batch
        $subRequests = @()
        foreach ($appId in $batch) {
            $url = & $buildUrl $appId
            $subRequests += @{
                id      = $appId
                method  = 'GET'
                url     = $url
                headers = @{ ConsistencyLevel = 'eventual' }
            }
        }

        try {
            $responses = Invoke-GraphBatchRequest -AccessToken $AccessToken -Requests $subRequests -BatchEndpointVersion $batchVersion
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            if ($statusCode -in 403, 404) {
                Write-Verbose "Audit log batch not available for $SignInType batch $batchNum (HTTP $statusCode). Skipping."
                continue
            }
            Write-Warning "Graph `$batch call failed for $SignInType batch ${batchNum}/${totalBatches}: $_"
            continue
        }

        # Process each sub-response individually
        foreach ($resp in $responses) {
            $appId = $resp.id

            if ($resp.status -ge 200 -and $resp.status -lt 300) {
                # Success — extract records from the response body
                $records = @()
                if ($resp.body -and $resp.body.value) {
                    $records = @($resp.body.value)
                }
                foreach ($record in $records) {
                    $key = $record.appId
                    if ($key -and $resultMap.ContainsKey($key)) {
                        $resultMap[$key].Add($record)
                    }
                }
                # Note: $batch does not support @odata.nextLink pagination within sub-requests.
                # The $top=999 limit is sufficient for the lookback windows used here (30 days).
                # For apps with >999 sign-ins in the window, the signInActivity timestamps and
                # counts are still directionally accurate.
            }
            elseif ($resp.status -in 403, 404) {
                Write-Verbose "Audit log not available for $SignInType appId $appId (HTTP $($resp.status)). Skipping."
            }
            else {
                $errMsg = ''
                if ($resp.body -and $resp.body.error) {
                    $errMsg = $resp.body.error.message
                }
                Write-Verbose "Sub-request failed for $SignInType appId $appId (HTTP $($resp.status)): $errMsg"
            }
        }
    }

    return $resultMap
}
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
    if ($null -eq $Value) { return $null }
    # If already a DateTime, normalise to UTC and return directly
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return $Value
    }
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        # Use InvariantCulture to avoid locale-dependent parsing (e.g. dd/MM vs MM/dd)
        return [datetime]::Parse(
            $Value.ToString(),
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
            [System.Globalization.DateTimeStyles]::AssumeUniversal
        )
    }
    catch { return $null }
}

Export-ModuleMember -Function Get-ApplicationSignInActivity, Get-BulkSignInActivity,
    Get-InteractiveSignIns, Get-NonInteractiveSignIns, Get-ServicePrincipalSignIns
