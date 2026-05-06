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

    # Build AppId → SP object ID mapping (interactive/non-interactive logs are keyed by AppId)
    $appIdToSpId = @{}
    foreach ($sp in $enterpriseApps) { $appIdToSpId[$sp.appId] = $sp.id }

    # ── Per-SP accumulators ───────────────────────────────────────────────────
    $spData = @{}
    foreach ($sp in $ServicePrincipals) {
        $spData[$sp.id] = @{
            InteractiveCount    = 0
            FailedInteractive   = 0
            LastInteractive     = $null
            NonInteractiveCount = 0
            FailedNonInteractive = 0
            LastNonInteractive  = $null
            SpCount             = 0
            FailedSp            = 0
            LastSp              = $null
            DistinctUsers       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            DistinctCallers     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
    }

    # ── 1. Interactive sign-ins (SigninLogs, filtered by AppId) ──────────────
    if ($enterpriseApps.Count -gt 0) {
        $allAppIds = @($enterpriseApps | Select-Object -ExpandProperty appId)
        Write-Progress -Id 2 -Activity 'Log Analytics' -Status 'Querying SigninLogs (interactive)...' -PercentComplete 10

        for ($i = 0; $i -lt $allAppIds.Count; $i += $BatchSize) {
            $batch  = $allAppIds[$i..([math]::Min($i + $BatchSize - 1, $allAppIds.Count - 1))]
            $idsArr = ($batch | ForEach-Object { "`"$_`"" }) -join ','

            $query = @"
let lookback = ${LookbackDays}d;
let appIds = dynamic([$idsArr]);
SigninLogs
| where TimeGenerated > ago(lookback)
| where AppId in (appIds)
| summarize
    TotalCount  = count(),
    FailedCount = countif(ResultType != "0"),
    LastSignIn  = max(TimeGenerated),
    UniqueUsers = make_set(UserPrincipalName, 500)
  by AppId
"@
            $rows = Invoke-LogAnalyticsQuerySafe -AccessToken $AccessToken -WorkspaceId $WorkspaceId `
                -Query $query -TableDescription 'SigninLogs'

            foreach ($row in $rows) {
                $spId = $appIdToSpId[$row.AppId]
                if (-not $spId -or -not $spData.ContainsKey($spId)) { continue }

                $spData[$spId].InteractiveCount  += [int]($row.TotalCount ?? 0)
                $spData[$spId].FailedInteractive += [int]($row.FailedCount ?? 0)

                $d = ConvertFrom-LADate $row.LastSignIn
                if ($d -and (-not $spData[$spId].LastInteractive -or $d -gt $spData[$spId].LastInteractive)) {
                    $spData[$spId].LastInteractive = $d
                }

                # UniqueUsers is a dynamic column — may be a string (JSON) or already an array
                $users = Expand-LADynamic $row.UniqueUsers
                foreach ($u in $users) { if ($u) { $spData[$spId].DistinctUsers.Add($u) | Out-Null } }
            }
        }
    }

    # ── 2. Non-interactive sign-ins (AADNonInteractiveUserSignInLogs) ─────────
    if ($enterpriseApps.Count -gt 0) {
        $allAppIds = @($enterpriseApps | Select-Object -ExpandProperty appId)
        Write-Progress -Id 2 -Activity 'Log Analytics' -Status 'Querying AADNonInteractiveUserSignInLogs...' -PercentComplete 35

        for ($i = 0; $i -lt $allAppIds.Count; $i += $BatchSize) {
            $batch  = $allAppIds[$i..([math]::Min($i + $BatchSize - 1, $allAppIds.Count - 1))]
            $idsArr = ($batch | ForEach-Object { "`"$_`"" }) -join ','

            $query = @"
let lookback = ${LookbackDays}d;
let appIds = dynamic([$idsArr]);
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where AppId in (appIds)
| summarize
    TotalCount  = count(),
    FailedCount = countif(ResultType != "0"),
    LastSignIn  = max(TimeGenerated)
  by AppId
"@
            $rows = Invoke-LogAnalyticsQuerySafe -AccessToken $AccessToken -WorkspaceId $WorkspaceId `
                -Query $query -TableDescription 'AADNonInteractiveUserSignInLogs'

            foreach ($row in $rows) {
                $spId = $appIdToSpId[$row.AppId]
                if (-not $spId -or -not $spData.ContainsKey($spId)) { continue }

                $spData[$spId].NonInteractiveCount   += [int]($row.TotalCount ?? 0)
                $spData[$spId].FailedNonInteractive  += [int]($row.FailedCount ?? 0)

                $d = ConvertFrom-LADate $row.LastSignIn
                if ($d -and (-not $spData[$spId].LastNonInteractive -or $d -gt $spData[$spId].LastNonInteractive)) {
                    $spData[$spId].LastNonInteractive = $d
                }
            }
        }
    }

    # ── 3. Service principal sign-ins (AADServicePrincipalSignInLogs) ─────────
    $allSpIds = @($ServicePrincipals | Select-Object -ExpandProperty id)
    Write-Progress -Id 2 -Activity 'Log Analytics' -Status 'Querying AADServicePrincipalSignInLogs...' -PercentComplete 60

    for ($i = 0; $i -lt $allSpIds.Count; $i += $BatchSize) {
        $batch  = $allSpIds[$i..([math]::Min($i + $BatchSize - 1, $allSpIds.Count - 1))]
        $idsArr = ($batch | ForEach-Object { "`"$_`"" }) -join ','

        $query = @"
let lookback = ${LookbackDays}d;
let spIds = dynamic([$idsArr]);
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(lookback)
| where ServicePrincipalId in (spIds)
| summarize
    TotalCount   = count(),
    FailedCount  = countif(ResultType != "0"),
    LastSignIn   = max(TimeGenerated),
    CallerNames  = make_set(ServicePrincipalName, 200)
  by ServicePrincipalId
"@
        $rows = Invoke-LogAnalyticsQuerySafe -AccessToken $AccessToken -WorkspaceId $WorkspaceId `
            -Query $query -TableDescription 'AADServicePrincipalSignInLogs'

        foreach ($row in $rows) {
            if (-not $spData.ContainsKey($row.ServicePrincipalId)) { continue }
            $spId = $row.ServicePrincipalId

            $spData[$spId].SpCount  += [int]($row.TotalCount ?? 0)
            $spData[$spId].FailedSp += [int]($row.FailedCount ?? 0)

            $d = ConvertFrom-LADate $row.LastSignIn
            if ($d -and (-not $spData[$spId].LastSp -or $d -gt $spData[$spId].LastSp)) {
                $spData[$spId].LastSp = $d
            }

            $callers = Expand-LADynamic $row.CallerNames
            foreach ($c in $callers) { if ($c) { $spData[$spId].DistinctCallers.Add($c) | Out-Null } }
        }
    }

    # ── 4. Managed identity sign-ins (AADManagedIdentitySignInLogs) ───────────
    if ($managedIds.Count -gt 0) {
        $allMiIds = @($managedIds | Select-Object -ExpandProperty id)
        Write-Progress -Id 2 -Activity 'Log Analytics' -Status 'Querying AADManagedIdentitySignInLogs...' -PercentComplete 80

        for ($i = 0; $i -lt $allMiIds.Count; $i += $BatchSize) {
            $batch  = $allMiIds[$i..([math]::Min($i + $BatchSize - 1, $allMiIds.Count - 1))]
            $idsArr = ($batch | ForEach-Object { "`"$_`"" }) -join ','

            $query = @"
let lookback = ${LookbackDays}d;
let spIds = dynamic([$idsArr]);
AADManagedIdentitySignInLogs
| where TimeGenerated > ago(lookback)
| where ServicePrincipalId in (spIds)
| summarize
    TotalCount  = count(),
    FailedCount = countif(ResultType != "0"),
    LastSignIn  = max(TimeGenerated),
    Resources   = make_set(ResourceDisplayName, 100)
  by ServicePrincipalId
"@
            $rows = Invoke-LogAnalyticsQuerySafe -AccessToken $AccessToken -WorkspaceId $WorkspaceId `
                -Query $query -TableDescription 'AADManagedIdentitySignInLogs'

            foreach ($row in $rows) {
                if (-not $spData.ContainsKey($row.ServicePrincipalId)) { continue }
                $spId = $row.ServicePrincipalId

                # MI sign-ins appear in both AADServicePrincipalSignInLogs and AADManagedIdentitySignInLogs.
                # Only add MI-table counts when the SP-table returned nothing to avoid double-counting.
                if ($spData[$spId].SpCount -eq 0) {
                    $spData[$spId].SpCount  += [int]($row.TotalCount ?? 0)
                    $spData[$spId].FailedSp += [int]($row.FailedCount ?? 0)
                }

                $d = ConvertFrom-LADate $row.LastSignIn
                if ($d -and (-not $spData[$spId].LastSp -or $d -gt $spData[$spId].LastSp)) {
                    $spData[$spId].LastSp = $d
                }

                $resources = Expand-LADynamic $row.Resources
                foreach ($r in $resources) { if ($r) { $spData[$spId].DistinctCallers.Add($r) | Out-Null } }
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
