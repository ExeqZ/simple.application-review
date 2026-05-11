<#
.SYNOPSIS
    Reviews all enterprise applications and managed identities in a single M365 tenant.

.DESCRIPTION
    Authenticates to Microsoft Graph, enumerates all enterprise applications and managed
    identities, analyses their permissions against the sensitive-permissions list (including
    Microsoft Defender for Cloud Apps risk levels), checks sign-in activity, and produces
    HTML, CSV, and optionally JSON reports.

.PARAMETER TenantId
    Azure AD tenant ID (GUID or verified domain).

.PARAMETER ClientId
    Application (client) ID.

.PARAMETER ClientSecret
    Client secret as plain text. Not recommended for production — use -ClientSecretFile or certificate.

.PARAMETER ClientSecretFile
    Path to a file containing the client secret (single line).

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in the local Windows certificate store.

.PARAMETER CertificatePath
    Path to a PFX file.

.PARAMETER CertificatePasswordFile
    Path to a file containing the PFX password.

.PARAMETER OutputFolder
    Folder to write reports to. Defaults to ./reports.

.PARAMETER LookbackDays
    How many days of Graph audit log sign-in history to examine. Defaults to 30.
    Ignored when -LogAnalyticsWorkspaceId is provided.

.PARAMETER InactivityThresholdDays
    Days without any sign-in before marking an app inactive. Defaults to 180.

.PARAMETER LogAnalyticsWorkspaceId
    Azure Monitor Log Analytics workspace GUID. When provided, sign-in activity is queried
    from Log Analytics instead of the Graph audit log endpoint, enabling lookback periods
    up to 365+ days. The app registration must have the 'Log Analytics Reader' Azure RBAC
    role on this workspace.

.PARAMETER LogAnalyticsLookbackDays
    How many days to query from Log Analytics. Defaults to 365. Only used when
    -LogAnalyticsWorkspaceId is set.

.PARAMETER IncludeFirstPartyMicrosoftApps
    Include Microsoft-owned first-party apps (noisy, off by default).

.PARAMETER IncludeDisabledApps
    Include disabled service principals.

.PARAMETER ExcludeManagedIdentities
    Skip managed identities.

.PARAMETER SkipDetailedSignInLogs
    Only use the signInActivity property on the SP object. Faster; requires no Entra ID P1/P2
    or AuditLog.Read.All, but provides less detail (no per-user breakdown).

.PARAMETER SignInBatchSize
    Number of appIds to bundle per Graph $batch HTTP call for sign-in log queries.
    Valid range: 1–20. Smaller values are more reliable with complex tenants;
    larger values reduce total HTTP requests. Defaults to 5.

.PARAMETER IncludeRawJson
    Also write a raw JSON file containing the full result set.

.PARAMETER NoEnterpriseAuth
    Skips enterprise app authentication entirely. The script will use an existing
    Azure PowerShell session instead (Az.Accounts module). You must run
    Connect-AzAccount before invoking this script.

    Required manual steps before running with -NoEnterpriseAuth:
      1. Install the Az.Accounts module:  Install-Module Az.Accounts -Scope CurrentUser
      2. Sign in interactively:           Connect-AzAccount -TenantId '<your-tenant-id>'
      3. Ensure your user account has at least the Global Reader (or equivalent) Entra ID
         directory role so that the delegated permissions Application.Read.All,
         Directory.Read.All, and AuditLog.Read.All are effective.

    When -NoEnterpriseAuth is used, -ClientId is not required. -TenantId is optional;
    if omitted, the tenant is detected from the active Az session.

.PARAMETER DebugLog
    Enables debug mode. Starts a PowerShell transcript that captures all console output,
    verbose messages, and detailed step-by-step logging to a file in the report folder.
    Also sets $VerbosePreference to 'Continue' so all Write-Verbose messages are visible.

.PARAMETER ShowHelp
    Displays a detailed help manual with usage examples and parameter descriptions, then exits.

.EXAMPLE
    # Certificate (recommended)
    .\Invoke-TenantReview.ps1 -TenantId 'contoso.onmicrosoft.com' -ClientId 'xxxxxxxx' `
        -CertificateThumbprint 'AABBCC...' -OutputFolder ./reports

.EXAMPLE
    # Secret file
    .\Invoke-TenantReview.ps1 -TenantId 'contoso.onmicrosoft.com' -ClientId 'xxxxxxxx' `
        -ClientSecretFile ./secrets/contoso.secret

.EXAMPLE
    # Debug mode with full transcript
    .\Invoke-TenantReview.ps1 -TenantId 'contoso.onmicrosoft.com' -ClientId 'xxxxxxxx' `
        -CertificateThumbprint 'AABB...' -DebugLog

.EXAMPLE
    # No enterprise app — use existing Az session
    Connect-AzAccount -TenantId 'contoso.onmicrosoft.com'
    .\Invoke-TenantReview.ps1 -NoEnterpriseAuth

.EXAMPLE
    # No enterprise app — explicit tenant ID
    Connect-AzAccount -TenantId 'contoso.onmicrosoft.com'
    .\Invoke-TenantReview.ps1 -NoEnterpriseAuth -TenantId 'contoso.onmicrosoft.com'

.NOTES
    Required app permissions: Application.Read.All, Directory.Read.All, AuditLog.Read.All
    (AuditLog.Read.All can be omitted with -SkipDetailedSignInLogs)
#>
[CmdletBinding(DefaultParameterSetName = 'Help')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Secret')]
    [Parameter(Mandatory, ParameterSetName = 'SecretFile')]
    [Parameter(Mandatory, ParameterSetName = 'CertThumbprint')]
    [Parameter(Mandatory, ParameterSetName = 'CertFile')]
    [Parameter(ParameterSetName = 'NoEnterpriseAuth')]
    [string]$TenantId,

    [Parameter(Mandatory, ParameterSetName = 'Secret')]
    [Parameter(Mandatory, ParameterSetName = 'SecretFile')]
    [Parameter(Mandatory, ParameterSetName = 'CertThumbprint')]
    [Parameter(Mandatory, ParameterSetName = 'CertFile')]
    [string]$ClientId,

    [Parameter(Mandatory, ParameterSetName = 'Secret')]
    [string]$ClientSecret,

    [Parameter(Mandatory, ParameterSetName = 'SecretFile')]
    [string]$ClientSecretFile,

    [Parameter(Mandatory, ParameterSetName = 'CertThumbprint')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = 'CertFile')]
    [string]$CertificatePath,

    [Parameter(ParameterSetName = 'CertFile')]
    [string]$CertificatePasswordFile,

    [string]$OutputFolder = './reports',

    [int]$LookbackDays            = 30,
    [int]$InactivityThresholdDays = 180,

    # Log Analytics — enables long-period sign-in history (e.g. 365 days)
    [string]$LogAnalyticsWorkspaceId  = '',
    [int]   $LogAnalyticsLookbackDays = 365,

    [switch]$IncludeFirstPartyMicrosoftApps,
    [switch]$IncludeDisabledApps,
    [switch]$ExcludeManagedIdentities,
    [switch]$SkipDetailedSignInLogs,

    # Number of appIds per Graph $batch HTTP call for sign-in log queries (1–20)
    [ValidateRange(1, 20)]
    [int]$SignInBatchSize = 5,

    [switch]$IncludeRawJson,
    [switch]$DebugLog,

    [Parameter(Mandatory, ParameterSetName = 'NoEnterpriseAuth')]
    [switch]$NoEnterpriseAuth,

    [switch]$ShowHelp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Show help and exit ────────────────────────────────────────────────────────
if ($ShowHelp) {
    Write-Host @"

  ╔══════════════════════════════════════════════════════════════════════╗
  ║          Invoke-TenantReview.ps1 — Application Review Tool         ║
  ╚══════════════════════════════════════════════════════════════════════╝

  DESCRIPTION
    Reviews all enterprise applications and managed identities in a single
    M365 / Entra ID tenant. Analyses permissions against the App Governance
    risk classification, checks sign-in activity, detects SCIM provisioning,
    and identifies overprivileged or likely unused applications.

  USAGE
    .\Invoke-TenantReview.ps1 -TenantId <id> -ClientId <id> <auth-params> [options]

  AUTHENTICATION (pick one)
    -CertificateThumbprint <thumb>        Certificate from local store (recommended)
    -CertificatePath <pfx> [-CertificatePasswordFile <file>]   PFX file
    -ClientSecretFile <file>              File containing client secret
    -ClientSecret <string>                Plain text secret (not recommended)
    -NoEnterpriseAuth                     Use existing Az PowerShell session (no app needed)

  OPTIONS
    -OutputFolder <path>                  Report output folder (default: ./reports)
    -LookbackDays <n>                     Graph audit log lookback (default: 30)
    -InactivityThresholdDays <n>          Days to flag inactive (default: 180)
    -LogAnalyticsWorkspaceId <guid>       Enable Log Analytics mode
    -LogAnalyticsLookbackDays <n>         LA lookback (default: 365)
    -IncludeFirstPartyMicrosoftApps       Include Microsoft first-party apps
    -IncludeDisabledApps                  Include disabled service principals
    -ExcludeManagedIdentities             Skip managed identities
    -SkipDetailedSignInLogs               No audit log queries (fast, no P1 needed)
    -SignInBatchSize <n>                   AppIds per Graph `$batch call (1-20, default: 5)
    -IncludeRawJson                       Also write JSON report
    -NoEnterpriseAuth                     Use existing Az session (no enterprise app)
    -DebugLog                             Full transcript logging to report folder
    -ShowHelp                             Show this help and exit

  EXAMPLES
    # Certificate auth
    .\Invoke-TenantReview.ps1 -TenantId contoso.onmicrosoft.com ``
        -ClientId xxxxxxxx -CertificateThumbprint AABB...

    # Client secret file
    .\Invoke-TenantReview.ps1 -TenantId contoso.onmicrosoft.com ``
        -ClientId xxxxxxxx -ClientSecretFile ./secrets/contoso.secret

    # No enterprise app — use existing Az session
    Connect-AzAccount -TenantId contoso.onmicrosoft.com
    .\Invoke-TenantReview.ps1 -NoEnterpriseAuth

    # Debug mode
    .\Invoke-TenantReview.ps1 -TenantId contoso.onmicrosoft.com ``
        -ClientId xxxxxxxx -CertificateThumbprint AABB... -DebugLog

  REQUIRED APP PERMISSIONS (enterprise app mode)
    Application.Read.All     Enumerate service principals
    Directory.Read.All       Resolve SP metadata
    AuditLog.Read.All        Detailed sign-in logs (optional, skip with -SkipDetailedSignInLogs)

  MANUAL AUTH PREREQUISITES (-NoEnterpriseAuth)
    1. Install-Module Az.Accounts -Scope CurrentUser
    2. Connect-AzAccount -TenantId '<your-tenant-id>'
    3. Your user account must have the Global Reader (or equivalent) Entra ID role
       so that delegated Application.Read.All, Directory.Read.All, and
       AuditLog.Read.All permissions are effective.

  OUTPUT
    reports/<TenantName>_<timestamp>/application-review.html   Filterable & sortable HTML
    reports/<TenantName>_<timestamp>/application-review.csv    Flat CSV for Excel / Power BI
    reports/<TenantName>_<timestamp>/application-review.json   Full JSON (with -IncludeRawJson)
    reports/<TenantName>_<timestamp>/debug-transcript_*.log    Debug log (with -DebugLog)

"@ -ForegroundColor Cyan
    return
}

# ── Validate required params when not using -ShowHelp ─────────────────────────
if (-not $NoEnterpriseAuth -and (-not $TenantId -or -not $ClientId)) {
    Write-Host "ERROR: -TenantId and -ClientId are required. Use -ShowHelp to see usage." -ForegroundColor Red
    return
}

# ── Debug / transcript mode ───────────────────────────────────────────────────
$script:DebugTranscriptPath = $null
if ($DebugLog) {
    # Ensure output folder exists before starting transcript
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

# ── Resolve module path ───────────────────────────────────────────────────────
$moduleRoot = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $moduleRoot 'GraphAuth.psm1')      -Force
Import-Module (Join-Path $moduleRoot 'Applications.psm1')   -Force
Import-Module (Join-Path $moduleRoot 'Permissions.psm1')    -Force
Import-Module (Join-Path $moduleRoot 'SignIns.psm1')        -Force
Import-Module (Join-Path $moduleRoot 'LogAnalytics.psm1')   -Force
Import-Module (Join-Path $moduleRoot 'Reporting.psm1')      -Force

Write-Host "`n=== Application Review — Tenant: $($TenantId ?? '(detecting from session)') ===" -ForegroundColor Cyan

if ($DebugLog) { Write-Verbose "[DEBUG] Starting review for tenant: $TenantId at $(Get-Date -Format 'o')" }

# ── Authenticate ──────────────────────────────────────────────────────────────
Write-Host "`n[1/6] Authenticating..." -ForegroundColor Yellow
if ($DebugLog) { Write-Verbose "[DEBUG] Auth method: $($PSCmdlet.ParameterSetName)" }

if ($NoEnterpriseAuth) {
    # ── Manual auth via Az.Accounts ────────────────────────────────────────────
    Write-Host "  Using existing Az PowerShell session (no enterprise app)..." -ForegroundColor Gray
    if (-not (Get-Command 'Get-AzAccessToken' -ErrorAction SilentlyContinue)) {
        throw "Az.Accounts module not found. Install it with: Install-Module Az.Accounts -Scope CurrentUser"
    }
    $azContext = Get-AzContext
    if (-not $azContext) {
        throw "No active Az session. Run 'Connect-AzAccount -TenantId <your-tenant-id>' first."
    }
    if (-not $TenantId) {
        $TenantId = $azContext.Tenant.Id
        Write-Host "  Detected tenant from Az session: $TenantId" -ForegroundColor Gray
    }
    $tokenResult = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -ErrorAction Stop
    # Az.Accounts >=2.13 returns Token as SecureString; older versions return plain text
    if ($tokenResult.Token -is [securestring]) {
        $accessToken = ConvertFrom-SecureString $tokenResult.Token -AsPlainText
    } else {
        $accessToken = $tokenResult.Token
    }
    Write-Host "  Authentication successful (Az session — $($azContext.Account.Id))." -ForegroundColor Green
    if ($DebugLog) { Write-Verbose "[DEBUG] Access token acquired from Az session for account $($azContext.Account.Id)" }
}
else {
    # ── Enterprise app authentication ─────────────────────────────────────────
    $tokenParams = @{ TenantId = $TenantId; ClientId = $ClientId }

    switch ($PSCmdlet.ParameterSetName) {
        'Secret' {
            $tokenParams['ClientSecret'] = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
            $ClientSecret = $null  # clear plain text immediately
        }
        'SecretFile' {
            if (-not (Test-Path $ClientSecretFile)) {
                throw "Secret file not found: $ClientSecretFile"
            }
            $secretPlain = (Get-Content $ClientSecretFile -Raw).Trim()
            $tokenParams['ClientSecret'] = ConvertTo-SecureString $secretPlain -AsPlainText -Force
            $secretPlain = $null
        }
        'CertThumbprint' {
            $tokenParams['CertificateThumbprint'] = $CertificateThumbprint
        }
        'CertFile' {
            $tokenParams['CertificatePath'] = $CertificatePath
            if ($CertificatePasswordFile -and (Test-Path $CertificatePasswordFile)) {
                $passPlain = (Get-Content $CertificatePasswordFile -Raw).Trim()
                $tokenParams['CertificatePassword'] = ConvertTo-SecureString $passPlain -AsPlainText -Force
                $passPlain = $null
            }
        }
    }

    $accessToken = Get-GraphAccessToken @tokenParams
    Write-Host "  Authentication successful." -ForegroundColor Green
    if ($DebugLog) { Write-Verbose "[DEBUG] Access token acquired successfully" }
}

# ── Resolve tenant display name ───────────────────────────────────────────────
try {
    $orgInfo    = Invoke-GraphRequest -AccessToken $accessToken `
        -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName,id,verifiedDomains'
    $tenantName = $orgInfo[0].displayName ?? $TenantId
    $tenantGuid = $orgInfo[0].id
}
catch {
    Write-Warning "Could not resolve tenant display name: $_"
    $tenantName = $TenantId
    $tenantGuid = $TenantId
}

Write-Host "  Tenant: $tenantName ($tenantGuid)"

# ── Build token refresh scriptblock ───────────────────────────────────────────
# Used by batch operations to proactively renew the token before it expires.
if ($NoEnterpriseAuth) {
    $tokenRefreshScript = {
        $result = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -ErrorAction Stop
        if ($result.Token -is [securestring]) {
            return ConvertFrom-SecureString $result.Token -AsPlainText
        }
        return $result.Token
    }
}
else {
    # Capture credential parameters in a closure so the scriptblock can re-acquire tokens
    $refreshTokenParams = @{ TenantId = $TenantId; ClientId = $ClientId }
    switch ($PSCmdlet.ParameterSetName) {
        'Secret' {
            # Re-read is not possible (cleared), but original $tokenParams still holds the SecureString
            $refreshTokenParams['ClientSecret'] = $tokenParams['ClientSecret']
        }
        'SecretFile' {
            $refreshTokenParams['ClientSecretFile'] = $ClientSecretFile
        }
        'CertThumbprint' {
            $refreshTokenParams['CertificateThumbprint'] = $CertificateThumbprint
        }
        'CertFile' {
            $refreshTokenParams['CertificatePath'] = $CertificatePath
            if ($CertificatePasswordFile) {
                $refreshTokenParams['CertificatePasswordFile'] = $CertificatePasswordFile
            }
        }
    }
    $tokenRefreshScript = {
        $p = @{ TenantId = $refreshTokenParams.TenantId; ClientId = $refreshTokenParams.ClientId }
        if ($refreshTokenParams.ContainsKey('ClientSecret')) {
            $p['ClientSecret'] = $refreshTokenParams['ClientSecret']
        }
        elseif ($refreshTokenParams.ContainsKey('ClientSecretFile')) {
            $secretPlain = (Get-Content $refreshTokenParams['ClientSecretFile'] -Raw).Trim()
            $p['ClientSecret'] = ConvertTo-SecureString $secretPlain -AsPlainText -Force
            $secretPlain = $null
        }
        elseif ($refreshTokenParams.ContainsKey('CertificateThumbprint')) {
            $p['CertificateThumbprint'] = $refreshTokenParams['CertificateThumbprint']
        }
        elseif ($refreshTokenParams.ContainsKey('CertificatePath')) {
            $p['CertificatePath'] = $refreshTokenParams['CertificatePath']
            if ($refreshTokenParams.ContainsKey('CertificatePasswordFile') -and
                (Test-Path $refreshTokenParams['CertificatePasswordFile'])) {
                $passPlain = (Get-Content $refreshTokenParams['CertificatePasswordFile'] -Raw).Trim()
                $p['CertificatePassword'] = ConvertTo-SecureString $passPlain -AsPlainText -Force
                $passPlain = $null
            }
        }
        return Get-GraphAccessToken @p
    }.GetNewClosure()
}

# ── Enumerate applications ────────────────────────────────────────────────────
Write-Host "`n[2/6] Enumerating applications..." -ForegroundColor Yellow
Clear-ServicePrincipalCache

$appParams = @{
    AccessToken                = $accessToken
    IncludeFirstPartyMicrosoft = $IncludeFirstPartyMicrosoftApps
    IncludeDisabled            = $IncludeDisabledApps
    IncludeManagedIdentities   = (-not $ExcludeManagedIdentities)
}
$servicePrincipals = Get-AllApplications @appParams
Write-Host "  Found $($servicePrincipals.Count) service principals to review." -ForegroundColor Green
if ($DebugLog) { Write-Verbose "[DEBUG] Service principal count: $($servicePrincipals.Count), Filters: IncludeFirstParty=$IncludeFirstPartyMicrosoftApps IncludeDisabled=$IncludeDisabledApps ExcludeMI=$ExcludeManagedIdentities" }

# ── Analyse permissions ───────────────────────────────────────────────────────
Write-Host "`n[3/6] Analysing permissions..." -ForegroundColor Yellow

$permissionResults = [System.Collections.Generic.List[object]]::new()
$total             = $servicePrincipals.Count
$i                 = 0

foreach ($sp in $servicePrincipals) {
    $i++
    Write-Progress -Activity 'Analysing permissions' `
        -Status "$i / $total — $($sp.displayName)" `
        -PercentComplete (($i / $total) * 100)

    $permData    = Get-ApplicationPermissions -AccessToken $accessToken -ServicePrincipalId $sp.id -AppId $sp.appId
    $permSummary = Get-PermissionSummary -PermissionData $permData

    $permissionResults.Add([PSCustomObject]@{
        ServicePrincipal = $sp
        PermissionData   = $permData
        PermissionSummary = $permSummary
    })
}
Write-Progress -Activity 'Analysing permissions' -Completed
Write-Host "  Permissions analysed." -ForegroundColor Green
if ($DebugLog) { Write-Verbose "[DEBUG] Permissions analysed for $($permissionResults.Count) apps" }

# ── Sign-in activity ──────────────────────────────────────────────────────────
Write-Host "`n[4/6] Retrieving sign-in activity..." -ForegroundColor Yellow

$signInParams = @{
    AccessToken             = $accessToken
    ServicePrincipals       = $servicePrincipals
    InactivityThresholdDays = $InactivityThresholdDays
    SignInBatchSize          = $SignInBatchSize
    TokenRefreshScript       = $tokenRefreshScript
}

if ($LogAnalyticsWorkspaceId) {
    # ── Log Analytics mode ────────────────────────────────────────────────────
    Write-Host "  Acquiring Log Analytics token..." -ForegroundColor Gray
    try {
        if ($NoEnterpriseAuth) {
            # Get Log Analytics token from existing Az session
            $laTokenResult = Get-AzAccessToken -ResourceUrl 'https://api.loganalytics.io' -ErrorAction Stop
            if ($laTokenResult.Token -is [securestring]) {
                $laToken = ConvertFrom-SecureString $laTokenResult.Token -AsPlainText
            } else {
                $laToken = $laTokenResult.Token
            }
        }
        else {
            $laToken = Get-LogAnalyticsAccessToken -TenantId $tenantGuid -ClientId $ClientId
            # Reuse credential params already resolved above by passing through the same param set
            # (certificate or secret) — reconstruct from PSBoundParameters
            $credParams = @{ TenantId = $tenantGuid; ClientId = $ClientId }
            switch ($PSCmdlet.ParameterSetName) {
                'Secret'         { $credParams['ClientSecret']          = ConvertTo-SecureString $ClientSecret -AsPlainText -Force }
                'SecretFile'     {
                    $credParams['ClientSecret'] = ConvertTo-SecureString `
                        ((Get-Content $ClientSecretFile -Raw).Trim()) -AsPlainText -Force
                }
                'CertThumbprint' { $credParams['CertificateThumbprint'] = $CertificateThumbprint }
                'CertFile'       {
                    $credParams['CertificatePath'] = $CertificatePath
                    if ($CertificatePasswordFile -and (Test-Path $CertificatePasswordFile)) {
                        $credParams['CertificatePassword'] = ConvertTo-SecureString `
                            ((Get-Content $CertificatePasswordFile -Raw).Trim()) -AsPlainText -Force
                    }
                }
            }
            $laToken = Get-GraphAccessToken @credParams -Scope 'https://api.loganalytics.io/.default'
        }

        # Optional connectivity check
        Write-Host "  Verifying Log Analytics workspace connectivity..." -ForegroundColor Gray
        $laCheck = Test-LogAnalyticsConnectivity -AccessToken $laToken -WorkspaceId $LogAnalyticsWorkspaceId
        if (-not $laCheck.Connected) {
            Write-Warning "Log Analytics connectivity check failed: $($laCheck.ErrorMessage). Falling back to Graph audit log."
        }
        else {
            if ($laCheck.TablesMissing.Count -gt 0) {
                Write-Warning "Log Analytics: the following tables are not available in this workspace (configure Diagnostic Settings): $($laCheck.TablesMissing -join ', ')"
            }
            $signInParams['LogAnalyticsConfig'] = @{
                AccessToken  = $laToken
                WorkspaceId  = $LogAnalyticsWorkspaceId
                LookbackDays = $LogAnalyticsLookbackDays
            }
            Write-Host "  Log Analytics ready. Lookback: $LogAnalyticsLookbackDays days." -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Failed to acquire Log Analytics token: $_. Falling back to Graph audit log."
        $signInParams['LookbackDays']    = $LookbackDays
        $signInParams['SkipDetailedLogs'] = $SkipDetailedSignInLogs
    }
}
else {
    # ── Graph audit log mode ──────────────────────────────────────────────────
    $signInParams['LookbackDays']     = $LookbackDays
    $signInParams['SkipDetailedLogs'] = $SkipDetailedSignInLogs
    if ($SkipDetailedSignInLogs) {
        Write-Host "  (SkipDetailedSignInLogs — using signInActivity property only)" -ForegroundColor Gray
    }
}

$signInResults = Get-BulkSignInActivity @signInParams

Write-Host "  Sign-in activity retrieved." -ForegroundColor Green
if ($DebugLog) { Write-Verbose "[DEBUG] Sign-in results: $($signInResults.Count) records. Mode: $(if ($LogAnalyticsWorkspaceId) { 'LogAnalytics' } else { 'GraphAuditLog' })" }

# ── SCIM / Provisioning detection ─────────────────────────────────────────────
Write-Host "`n[5/6] Detecting SCIM provisioning..." -ForegroundColor Yellow

$scimStatus = Get-BulkScimStatus -AccessToken $accessToken -ServicePrincipals $servicePrincipals
$scimCount  = @($scimStatus.Values | Where-Object { $_ }).Count
Write-Host "  Found $scimCount app(s) with SCIM provisioning configured." -ForegroundColor Green
if ($DebugLog) { Write-Verbose "[DEBUG] SCIM detection complete. $scimCount of $($servicePrincipals.Count) apps have SCIM configured" }

# ── Combine & report ──────────────────────────────────────────────────────────
Write-Host "`n[6/6] Generating reports..." -ForegroundColor Yellow

$signInLookup = @{}
foreach ($sia in $signInResults) { $signInLookup[$sia.ServicePrincipalId] = $sia }

$combinedResults = foreach ($pr in $permissionResults) {
    $sia = $signInLookup[$pr.ServicePrincipal.id]
    if (-not $sia) {
        # Create a default empty activity record if somehow missing
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

$reportResult = Export-ReviewReport `
    -Results       $combinedResults `
    -TenantName    $tenantName `
    -TenantId      $tenantGuid `
    -OutputFolder  $OutputFolder `
    -IncludeRawJson:$IncludeRawJson

# Move debug transcript into the report folder if it was started in the base output folder
if ($DebugLog -and $script:DebugTranscriptPath -and (Test-Path $script:DebugTranscriptPath)) {
    $reportFolder = $reportResult.ReportFolder
    if ($reportFolder -and (Test-Path $reportFolder)) {
        $transcriptDest = Join-Path $reportFolder (Split-Path $script:DebugTranscriptPath -Leaf)
        if ($script:DebugTranscriptPath -ne $transcriptDest) {
            try {
                Stop-Transcript -ErrorAction SilentlyContinue
                Copy-Item -Path $script:DebugTranscriptPath -Destination $transcriptDest -Force
                Start-Transcript -Path $transcriptDest -Append
                Write-Host "[DEBUG] Transcript continued in report folder: $transcriptDest" -ForegroundColor Magenta
            }
            catch {
                Write-Warning "Could not move transcript to report folder: $_"
            }
        }
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
$highCount  = @($combinedResults | Where-Object { $_.OverallRiskLevel -eq 'High'     }).Count
$medCount   = @($combinedResults | Where-Object { $_.OverallRiskLevel -eq 'Medium'   }).Count
$inactCount = @($combinedResults | Where-Object { $_.IsInactive                      }).Count
$unusedCount = @($combinedResults | Where-Object { $_.IsLikelyUnused                 }).Count
$overpCount = @($combinedResults | Where-Object { $_.IsOverprivileged               }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "  Total reviewed    : $($combinedResults.Count)"
Write-Host "  High risk         : $highCount"   -ForegroundColor $(if ($highCount  -gt 0) { 'Red'    } else { 'Green' })
Write-Host "  Medium risk       : $medCount"    -ForegroundColor $(if ($medCount   -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Inactive apps     : $inactCount"  -ForegroundColor $(if ($inactCount -gt 0) { 'DarkGray' } else { 'Green' })
Write-Host "  Likely unused     : $unusedCount" -ForegroundColor $(if ($unusedCount -gt 0) { 'DarkYellow' } else { 'Green' })
Write-Host "  Overprivileged    : $overpCount"  -ForegroundColor $(if ($overpCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "  SCIM provisioning : $scimCount"
Write-Host "  Report folder     : $($reportResult.ReportFolder)" -ForegroundColor Cyan
Write-Host ""

if ($DebugLog) {
    Write-Verbose "[DEBUG] Review completed at $(Get-Date -Format 'o')"
    Stop-Transcript -ErrorAction SilentlyContinue
}

return $combinedResults
