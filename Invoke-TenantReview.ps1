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

.PARAMETER IncludeRawJson
    Also write a raw JSON file containing the full result set.

.EXAMPLE
    # Certificate (recommended)
    .\Invoke-TenantReview.ps1 -TenantId 'contoso.onmicrosoft.com' -ClientId 'xxxxxxxx' `
        -CertificateThumbprint 'AABBCC...' -OutputFolder ./reports

.EXAMPLE
    # Secret file
    .\Invoke-TenantReview.ps1 -TenantId 'contoso.onmicrosoft.com' -ClientId 'xxxxxxxx' `
        -ClientSecretFile ./secrets/contoso.secret

.NOTES
    Required app permissions: Application.Read.All, Directory.Read.All, AuditLog.Read.All
    (AuditLog.Read.All can be omitted with -SkipDetailedSignInLogs)
#>
[CmdletBinding(DefaultParameterSetName = 'SecretFile')]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
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
    [switch]$IncludeRawJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Resolve module path ───────────────────────────────────────────────────────
$moduleRoot = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $moduleRoot 'GraphAuth.psm1')      -Force
Import-Module (Join-Path $moduleRoot 'Applications.psm1')   -Force
Import-Module (Join-Path $moduleRoot 'Permissions.psm1')    -Force
Import-Module (Join-Path $moduleRoot 'SignIns.psm1')        -Force
Import-Module (Join-Path $moduleRoot 'LogAnalytics.psm1')   -Force
Import-Module (Join-Path $moduleRoot 'Reporting.psm1')      -Force

Write-Host "`n=== Application Review — Tenant: $TenantId ===" -ForegroundColor Cyan

# ── Authenticate ──────────────────────────────────────────────────────────────
Write-Host "`n[1/6] Authenticating..." -ForegroundColor Yellow

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

# ── Sign-in activity ──────────────────────────────────────────────────────────
Write-Host "`n[4/6] Retrieving sign-in activity..." -ForegroundColor Yellow

$signInParams = @{
    AccessToken             = $accessToken
    ServicePrincipals       = $servicePrincipals
    InactivityThresholdDays = $InactivityThresholdDays
}

if ($LogAnalyticsWorkspaceId) {
    # ── Log Analytics mode ────────────────────────────────────────────────────
    Write-Host "  Acquiring Log Analytics token..." -ForegroundColor Gray
    try {
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

# ── SCIM / Provisioning detection ─────────────────────────────────────────────
Write-Host "`n[5/6] Detecting SCIM provisioning..." -ForegroundColor Yellow

$scimStatus = Get-BulkScimStatus -AccessToken $accessToken -ServicePrincipals $servicePrincipals
$scimCount  = @($scimStatus.Values | Where-Object { $_ }).Count
Write-Host "  Found $scimCount app(s) with SCIM provisioning configured." -ForegroundColor Green

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

return $combinedResults
