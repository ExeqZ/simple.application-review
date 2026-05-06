<#
.SYNOPSIS
    Queries Azure Monitor Log Analytics for Entra ID sign-in logs.

.DESCRIPTION
    Provides bulk KQL-based sign-in activity retrieval from a Log Analytics workspace
    that has Entra ID Diagnostic Settings configured to stream sign-in logs.

    Supports lookback periods far beyond the Graph API audit log retention limit
    (e.g. 365 days or longer, depending on workspace retention configuration).

    Required tables in the workspace (configured via Entra Diagnostic Settings):
      - SigninLogs                        — interactive user sign-ins
      - AADNonInteractiveUserSignInLogs   — non-interactive user sign-ins
      - AADServicePrincipalSignInLogs     — service principal / app-to-app sign-ins
      - AADManagedIdentitySignInLogs      — managed identity sign-ins

    Required RBAC on the workspace: 'Log Analytics Reader' for the app registration.
    Token scope: https://api.loganalytics.io/.default  (use Get-LogAnalyticsAccessToken)

.NOTES
    The app registration used for Graph API can be reused for Log Analytics as long as
    it has been granted the 'Log Analytics Reader' Azure RBAC role on the workspace.
#>

function Invoke-LogAnalyticsQuery {
    <#
    .SYNOPSIS
        Executes a KQL query against an Azure Monitor Log Analytics workspace.

    .PARAMETER AccessToken
        Bearer access token with scope https://api.loganalytics.io/.default.

    .PARAMETER WorkspaceId
        The Log Analytics workspace ID (GUID from Azure portal → workspace → Overview).

    .PARAMETER Query
        KQL query string.

    .PARAMETER TimeoutSeconds
        HTTP request timeout. Defaults to 120 seconds (KQL queries can be slow on large datasets).

    .EXAMPLE
        $result = Invoke-LogAnalyticsQuery -AccessToken $laToken -WorkspaceId $wsId `
            -Query 'SigninLogs | limit 5'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$WorkspaceId,

        [Parameter(Mandatory)]
        [string]$Query,

        [int]$TimeoutSeconds = 180
    )

    $uri     = "https://api.loganalytics.io/v1/workspaces/$WorkspaceId/query"
    $headers = @{
        'Authorization' = "Bearer $AccessToken"
        'Content-Type'  = 'application/json'
        'Prefer'        = 'response-v1=true'  # consistent column metadata format
    }
    $body = @{ query = $Query } | ConvertTo-Json -Compress

    $response = Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -Body $body `
        -TimeoutSec $TimeoutSeconds -ErrorAction Stop

    return $response
}

function Get-BulkSignInActivityFromLogAnalytics {
    <#
    .SYNOPSIS
        Retrieves aggregated sign-in activity for all provided service principals from Log Analytics.

    .DESCRIPTION
        Issues up to four bulk KQL queries (one per sign-in table) and returns a list of
        activity objects compatible with the output of Get-BulkSignInActivity in SignIns.psm1.
        Timestamps from the SP object's signInActivity property are merged with LA results
        so that the most recent sign-in across both sources is always reflected.

    .PARAMETER AccessToken
        Log Analytics bearer token (scope: https://api.loganalytics.io/.default).

    .PARAMETER WorkspaceId
        Log Analytics workspace GUID.

    .PARAMETER ServicePrincipals
        Array of service principal objects as returned by Get-AllApplications.
        Must include the signInActivity property (fetched via the beta endpoint).

    .PARAMETER LookbackDays
        How many days of sign-in history to query. Defaults to 365.

    .PARAMETER InactivityThresholdDays
        Days without any sign-in to consider the app inactive. Defaults to 180.

    .PARAMETER BatchSize
        Number of app/SP IDs to include per KQL query. Reduce if you hit query limits.
        Defaults to 200.

    .EXAMPLE
        $activity = Get-BulkSignInActivityFromLogAnalytics `
            -AccessToken $laToken -WorkspaceId $wsId -ServicePrincipals $sps -LookbackDays 365
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$WorkspaceId,

        [Parameter(Mandatory)]
        [object[]]$ServicePrincipals,

        [int]$LookbackDays           = 365,
        [int]$InactivityThresholdDays = 180,
        [int]$BatchSize              = 200
    )

    Write-Verbose "Log Analytics: querying $($ServicePrincipals.Count) service principals, lookback ${LookbackDays}d"

    # Separate types for table-specific queries
    $enterpriseApps = @($ServicePrincipals | Where-Object { $_._principalType -eq 'EnterpriseApplication' })
    $managedIds     = @($ServicePrincipals | Where-Object { $_._principalType -eq 'ManagedIdentity'       })

    # Build AppId → SP object ID mapping
    $appIdToSpId = @{}
    foreach ($sp in $ServicePrincipals) { $appIdToSpId[$sp.appId] = $sp.id }

    # ── Per-SP accumulators ───────────────────────────────────────────────────
    $spData = @{}
    foreach ($sp in $ServicePrincipals) {
        $spData[$sp.id] = @{
            InteractiveCount     = 0
            FailedInteractive    = 0
            LastInteractive      = $null
            NonInteractiveCount  = 0
            FailedNonInteractive = 0
            LastNonInteractive   = $null
            SpCount              = 0
            FailedSp             = 0
            LastSp               = $null
            MiCount              = 0
            FailedMi             = 0
            LastMi               = $null
            DistinctUsers        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            DistinctCallers      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
    }

    # ── Single efficient KQL query per batch using join pattern ────────────────
    # Instead of 4 separate queries per table, issue 1 query per batch that
    # joins all 4 sign-in tables against a datatable of AppIds.
    $allAppIds = @($ServicePrincipals | Select-Object -ExpandProperty appId)
    $totalBatches = [math]::Ceiling($allAppIds.Count / $BatchSize)
    Write-Host ("  Log Analytics: querying {0} apps in {1} batch(es) using join pattern..." -f
        $allAppIds.Count, $totalBatches) -ForegroundColor Gray

    for ($i = 0; $i -lt $allAppIds.Count; $i += $BatchSize) {
        $batch    = $allAppIds[$i..([math]::Min($i + $BatchSize - 1, $allAppIds.Count - 1))]
        $batchNum = [math]::Floor($i / $BatchSize) + 1
        Write-Progress -Id 2 -Activity 'Log Analytics' `
            -Status "Batch $batchNum / $totalBatches" `
            -PercentComplete (($batchNum / $totalBatches) * 100)

        # Build the datatable entries for this batch
        $datatableRows = ($batch | ForEach-Object { "`"$_`"" }) -join ",`n    "

        $query = @"
let lookback = ${LookbackDays}d;
let AppIds = datatable(AppId: string)
[
    $datatableRows
];
AppIds
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | summarize
        SignInCount     = count(),
        FailedSignIns  = countif(ResultType != "0"),
        LastSignIn     = max(TimeGenerated),
        UniqueUsers    = make_set(UserPrincipalName, 500)
      by AppId
) on AppId
| join kind=leftouter (
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(lookback)
    | summarize
        NonInteractiveCount  = count(),
        FailedNonInteractive = countif(ResultType != "0"),
        LastNonInteractive   = max(TimeGenerated)
      by AppId
) on AppId
| join kind=leftouter (
    AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(lookback)
    | summarize
        SPSignInCount  = count(),
        FailedSP       = countif(ResultType != "0"),
        LastSPSignIn   = max(TimeGenerated),
        CallerNames    = make_set(ServicePrincipalName, 200)
      by AppId
) on AppId
| join kind=leftouter (
    AADManagedIdentitySignInLogs
    | where TimeGenerated > ago(lookback)
    | summarize
        MISignInCount  = count(),
        FailedMI       = countif(ResultType != "0"),
        LastMISignIn   = max(TimeGenerated)
      by AppId
) on AppId
| project
    AppId = AppId,
    SignInCount              = coalesce(SignInCount, 0),
    FailedSignIns           = coalesce(FailedSignIns, 0),
    LastSignIn,
    UniqueUsers,
    NonInteractiveCount     = coalesce(NonInteractiveCount, 0),
    FailedNonInteractive    = coalesce(FailedNonInteractive, 0),
    LastNonInteractive,
    SPSignInCount           = coalesce(SPSignInCount, 0),
    FailedSP                = coalesce(FailedSP, 0),
    LastSPSignIn,
    CallerNames,
    MISignInCount           = coalesce(MISignInCount, 0),
    FailedMI                = coalesce(FailedMI, 0),
    LastMISignIn
"@
        $rows = Invoke-LogAnalyticsQuerySafe -AccessToken $AccessToken -WorkspaceId $WorkspaceId `
            -Query $query -TableDescription "bulk join batch $batchNum"

        foreach ($row in $rows) {
            $spId = $appIdToSpId[$row.AppId]
            if (-not $spId -or -not $spData.ContainsKey($spId)) { continue }

            # Interactive
            $spData[$spId].InteractiveCount  += [int]($row.SignInCount ?? 0)
            $spData[$spId].FailedInteractive += [int]($row.FailedSignIns ?? 0)
            $d = ConvertFrom-LADate $row.LastSignIn
            if ($d -and (-not $spData[$spId].LastInteractive -or $d -gt $spData[$spId].LastInteractive)) {
                $spData[$spId].LastInteractive = $d
            }
            $users = Expand-LADynamic $row.UniqueUsers
            foreach ($u in $users) { if ($u) { $spData[$spId].DistinctUsers.Add($u) | Out-Null } }

            # Non-interactive
            $spData[$spId].NonInteractiveCount   += [int]($row.NonInteractiveCount ?? 0)
            $spData[$spId].FailedNonInteractive  += [int]($row.FailedNonInteractive ?? 0)
            $d = ConvertFrom-LADate $row.LastNonInteractive
            if ($d -and (-not $spData[$spId].LastNonInteractive -or $d -gt $spData[$spId].LastNonInteractive)) {
                $spData[$spId].LastNonInteractive = $d
            }

            # Service principal
            $spData[$spId].SpCount  += [int]($row.SPSignInCount ?? 0)
            $spData[$spId].FailedSp += [int]($row.FailedSP ?? 0)
            $d = ConvertFrom-LADate $row.LastSPSignIn
            if ($d -and (-not $spData[$spId].LastSp -or $d -gt $spData[$spId].LastSp)) {
                $spData[$spId].LastSp = $d
            }
            $callers = Expand-LADynamic $row.CallerNames
            foreach ($c in $callers) { if ($c) { $spData[$spId].DistinctCallers.Add($c) | Out-Null } }

            # Managed identity (add to SP counts to avoid double-counting if both tables overlap)
            $miCount = [int]($row.MISignInCount ?? 0)
            if ($miCount -gt 0 -and $spData[$spId].SpCount -eq 0) {
                $spData[$spId].SpCount  += $miCount
                $spData[$spId].FailedSp += [int]($row.FailedMI ?? 0)
            }
            $d = ConvertFrom-LADate $row.LastMISignIn
            if ($d -and (-not $spData[$spId].LastSp -or $d -gt $spData[$spId].LastSp)) {
                $spData[$spId].LastSp = $d
            }
        }
    }

    Write-Progress -Id 2 -Activity 'Log Analytics' -Completed

    # ── Build result objects ──────────────────────────────────────────────────
    $results = foreach ($sp in $ServicePrincipals) {
        $d = $spData[$sp.id]

        # Merge LA dates with signInActivity timestamps on the SP object (prefer most recent)
        $sia = $sp.signInActivity
        $siaInteractive    = ConvertFrom-LADate $sia.lastSignInDateTime
        $siaNonInteractive = ConvertFrom-LADate $sia.lastNonInteractiveSignInDateTime
        $siaSP             = ConvertFrom-LADate $sia.lastServicePrincipalSignInDateTime

        $lastInteractive    = @($d.LastInteractive, $siaInteractive)     | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
        $lastNonInteractive = @($d.LastNonInteractive, $siaNonInteractive) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
        $lastSP             = @($d.LastSp, $siaSP)                       | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1

        $lastSeenOverall = @($lastInteractive, $lastNonInteractive, $lastSP) |
            Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1

        $daysSinceLast = $null
        $isInactive    = $true
        if ($lastSeenOverall) {
            $daysSinceLast = [int]((Get-Date).ToUniversalTime() - $lastSeenOverall).TotalDays
            $isInactive    = $daysSinceLast -gt $InactivityThresholdDays
        }

        $totalSignIns = $d.InteractiveCount + $d.NonInteractiveCount + $d.SpCount
        $totalFailed  = $d.FailedInteractive + $d.FailedNonInteractive + $d.FailedSp
        $failureRate  = if ($totalSignIns -gt 0) { [math]::Round(($totalFailed / $totalSignIns) * 100, 1) } else { 0 }

        $distinctUsers   = @($d.DistinctUsers)
        $distinctCallers = @($d.DistinctCallers)

        [PSCustomObject]@{
            ServicePrincipalId            = $sp.id
            DisplayName                   = $sp.displayName
            LastInteractiveSignIn         = $lastInteractive
            LastNonInteractiveSignIn      = $lastNonInteractive
            LastServicePrincipalSignIn    = $lastSP
            LastSeenOverall               = $lastSeenOverall
            DaysSinceLastSignIn           = $daysSinceLast
            IsInactive                    = $isInactive
            InactivityThresholdDays       = $InactivityThresholdDays
            AuditLogsQueried              = $true
            DataSource                    = 'LogAnalytics'
            LookbackDays                  = $LookbackDays
            TotalSignInsInWindow          = $totalSignIns
            InteractiveSignInsInWindow    = $d.InteractiveCount
            NonInteractiveSignInsInWindow = $d.NonInteractiveCount
            SpSignInsInWindow             = $d.SpCount
            FailedSignInsInWindow         = $totalFailed
            FailureRatePercent            = $failureRate
            DistinctInteractiveUsers      = $distinctUsers
            DistinctInteractiveUserCount  = $distinctUsers.Count
            DistinctSpCallers             = $distinctCallers
            DistinctSpCallerCount         = $distinctCallers.Count
        }
    }

    return $results
}

function Test-LogAnalyticsConnectivity {
    <#
    .SYNOPSIS
        Verifies that the workspace is reachable and sign-in log tables are present.

    .OUTPUTS
        PSCustomObject with fields: Connected, TablesFound (array), TablesWarning (array), ErrorMessage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$AccessToken,
        [Parameter(Mandatory)] [string]$WorkspaceId
    )

    $expectedTables = @(
        'SigninLogs',
        'AADNonInteractiveUserSignInLogs',
        'AADServicePrincipalSignInLogs',
        'AADManagedIdentitySignInLogs'
    )

    $query = @"
let tables = dynamic(["SigninLogs","AADNonInteractiveUserSignInLogs","AADServicePrincipalSignInLogs","AADManagedIdentitySignInLogs"]);
union isfuzzy=true
    (SigninLogs                      | summarize LastRecord = max(TimeGenerated), Rows = count() | extend TableName = "SigninLogs"),
    (AADNonInteractiveUserSignInLogs | summarize LastRecord = max(TimeGenerated), Rows = count() | extend TableName = "AADNonInteractiveUserSignInLogs"),
    (AADServicePrincipalSignInLogs   | summarize LastRecord = max(TimeGenerated), Rows = count() | extend TableName = "AADServicePrincipalSignInLogs"),
    (AADManagedIdentitySignInLogs    | summarize LastRecord = max(TimeGenerated), Rows = count() | extend TableName = "AADManagedIdentitySignInLogs")
| project TableName, LastRecord, Rows
"@

    try {
        $response = Invoke-LogAnalyticsQuery -AccessToken $AccessToken -WorkspaceId $WorkspaceId -Query $query
        $rows      = ConvertFrom-LogAnalyticsTable -Response $response

        $found    = @($rows | Select-Object -ExpandProperty TableName)
        $missing  = @($expectedTables | Where-Object { $_ -notin $found })

        return [PSCustomObject]@{
            Connected     = $true
            TablesFound   = $found
            TablesMissing = $missing
            TableDetail   = $rows
            ErrorMessage  = ''
        }
    }
    catch {
        return [PSCustomObject]@{
            Connected     = $false
            TablesFound   = @()
            TablesMissing = $expectedTables
            TableDetail   = @()
            ErrorMessage  = $_.ToString()
        }
    }
}

# ─── Internal helpers ────────────────────────────────────────────────────────

function Invoke-LogAnalyticsQuerySafe {
    <#
    .SYNOPSIS
        Wraps Invoke-LogAnalyticsQuery; on a 400/404 (table not found), returns empty results
        with a warning rather than throwing — graceful degradation when tables are not configured.
    #>
    param(
        [string]$AccessToken,
        [string]$WorkspaceId,
        [string]$Query,
        [string]$TableDescription = 'table'
    )

    try {
        $response = Invoke-LogAnalyticsQuery -AccessToken $AccessToken -WorkspaceId $WorkspaceId -Query $Query
        return ConvertFrom-LogAnalyticsTable -Response $response
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        # 400 Bad Request = table doesn't exist in this workspace (not configured in Diagnostic Settings)
        if ($statusCode -in 400, 404) {
            Write-Verbose "Log Analytics table not available for $TableDescription (HTTP $statusCode). Table may not be streamed to this workspace."
            return @()
        }
        Write-Warning "Log Analytics query failed for $TableDescription (HTTP $statusCode): $_"
        return @()
    }
}

function ConvertFrom-LogAnalyticsTable {
    <#
    .SYNOPSIS
        Converts the tabular response from the Log Analytics REST API into an array of PSCustomObjects.
    #>
    param([object]$Response)

    if (-not $Response -or -not $Response.tables -or $Response.tables.Count -eq 0) { return @() }

    $table   = $Response.tables[0]
    $columns = @($table.columns | Select-Object -ExpandProperty name)

    foreach ($row in $table.rows) {
        $obj = [ordered]@{}
        for ($i = 0; $i -lt $columns.Count; $i++) {
            $obj[$columns[$i]] = $row[$i]
        }
        [PSCustomObject]$obj
    }
}

function ConvertFrom-LADate {
    <#
    .SYNOPSIS
        Parses a Log Analytics datetime string or null into a [datetime] or $null.
    #>
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        return [datetime]::Parse($Value, $null, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    }
    catch { return $null }
}

function Expand-LADynamic {
    <#
    .SYNOPSIS
        Normalises a Log Analytics 'dynamic' column value into a PowerShell array.
        LA returns dynamic columns as either a nested array (already parsed by Invoke-RestMethod)
        or as a JSON string when the column is part of a make_set() result.
    #>
    param([object]$Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return @($Value) }
    if ($Value -is [string]) {
        try { return @($Value | ConvertFrom-Json) }
        catch { return @() }
    }
    return @()
}

Export-ModuleMember -Function Get-BulkSignInActivityFromLogAnalytics, Test-LogAnalyticsConnectivity, Invoke-LogAnalyticsQuery
