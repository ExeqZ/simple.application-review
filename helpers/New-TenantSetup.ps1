<#
.SYNOPSIS
    Onboarding helper: registers the app, assigns required permissions, generates a
    self-signed certificate, uploads it, and writes the tenant config file.

.DESCRIPTION
    Run this script once per customer tenant to set up the app registration used by the
    Application Review solution.

    Before running this script, connect to the target tenant using the Microsoft Graph
    PowerShell module:

        Install-Module Microsoft.Graph -Scope CurrentUser   # first time only
        Connect-MgGraph -TenantId '<tenantId>' `
            -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All'

    What this script does:
      1. Verifies an active Microsoft Graph session (Connect-MgGraph must be run first).
      2. Creates an Entra ID app registration with the required application permissions:
           - Application.Read.All
           - Directory.Read.All
           - AuditLog.Read.All
           - Organization.Read.All
      3. Creates a service principal for the app.
      4. Generates a self-signed X.509 certificate (2-year validity, RSA-2048).
      5. Uploads the public key (.cer) to the app registration.
      6. Exports the certificate as a .pfx (or optionally to the certificate store).
      7. Writes a ready-to-use config file to ./tenants/<customer-shortname>.json.

    What you must do MANUALLY after this script:
      - Grant admin consent for the required application permissions in the Entra admin
        centre: https://entra.microsoft.com -> App registrations -> <app> -> API permissions
        -> Grant admin consent for <tenant>.
      - If you use Log Analytics: assign the "Log Analytics Reader" RBAC role to the app's
        service principal on the Log Analytics workspace in the Azure portal.

.PARAMETER TenantId
    The Azure AD tenant ID (GUID) or verified domain of the customer tenant.

.PARAMETER CustomerShortName
    Short slug used for the app name, certificate file name, and config file name
    (e.g. "contoso" → app "AppReview-contoso", config "./tenants/contoso.json").

.PARAMETER CustomerDisplayName
    Human-readable customer name written to the tenantName field in the config file.

.PARAMETER OutputFolder
    Folder where the generated config file and certificate are written.
    Defaults to the repository root (parent of the helpers folder).

.PARAMETER CertificateStoreInstead
    When set, the certificate is installed to the local certificate store
    (Cert:\CurrentUser\My) instead of exporting a PFX file. The config file will use
    certificateThumbprint instead of certificatePath.

.PARAMETER CertificateValidityYears
    Validity period of the generated certificate in years. Defaults to 1.

.EXAMPLE
    # Connect first, then run setup for a customer (PFX export)
    Connect-MgGraph -TenantId 'contoso.onmicrosoft.com' `
        -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All'
    .\helpers\New-TenantSetup.ps1 `
        -TenantId            'contoso.onmicrosoft.com' `
        -CustomerShortName   'contoso' `
        -CustomerDisplayName 'Contoso Ltd'

.EXAMPLE
    # Install cert to local store instead of exporting PFX
    Connect-MgGraph -TenantId 'fabrikam.onmicrosoft.com' `
        -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All'
    .\helpers\New-TenantSetup.ps1 `
        -TenantId            'fabrikam.onmicrosoft.com' `
        -CustomerShortName   'fabrikam' `
        -CustomerDisplayName 'Fabrikam Inc' `
        -CertificateStoreInstead

.NOTES
    Requires PowerShell 7.2+ on Windows or macOS/Linux (certificate store option requires Windows).
    Requires the Microsoft.Graph PowerShell module (Install-Module Microsoft.Graph).
    Certificate generation uses only built-in .NET cryptography — no other external modules needed.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [string]$CustomerShortName,

    [Parameter(Mandatory)]
    [string]$CustomerDisplayName,

    [string]$OutputFolder           = '',

    [switch]$CertificateStoreInstead,

    [int]   $CertificateValidityYears = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Resolve output folder ─────────────────────────────────────────────────────
if (-not $OutputFolder) {
    # Default: repository root (parent of helpers/)
    $OutputFolder = Split-Path $PSScriptRoot -Parent
}
$tenantsFolder  = Join-Path $OutputFolder 'tenants'
$secretsFolder  = Join-Path $OutputFolder 'secrets'

foreach ($dir in @($tenantsFolder, $secretsFolder)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

$configFile = Join-Path $tenantsFolder "$CustomerShortName.json"
if (Test-Path $configFile) {
    throw "Config file already exists: $configFile`nDelete it or choose a different CustomerShortName."
}

$appName     = "AppReview-$CustomerShortName"
$certSubject = "CN=AppReview-$CustomerShortName"
$certFile    = Join-Path $secretsFolder "$CustomerShortName.cer"
$pfxFile     = Join-Path $secretsFolder "$CustomerShortName.pfx"
$pfxPassFile = Join-Path $secretsFolder "$CustomerShortName.pfx.pass"

# ── Rollback state — track what was created so we can clean up on error ────────
$rollback = @{
    AppObjectId  = $null   # Graph application object ID
    SpObjectId   = $null   # service principal object ID
    FilesWritten = [System.Collections.Generic.List[string]]::new()
}

function Invoke-Rollback {
    param([hashtable]$State)
    Write-Host ""
    Write-Host "  Rolling back partially created resources..." -ForegroundColor Yellow
    if ($State.AppObjectId) {
        try {
            Invoke-MgGraphRequest -Method DELETE `
                -Uri "https://graph.microsoft.com/v1.0/applications/$($State.AppObjectId)" | Out-Null
            Write-Host "  Deleted app registration ($($State.AppObjectId))." -ForegroundColor Gray
        } catch {
            Write-Warning "  Could not delete app registration $($State.AppObjectId): $_"
            Write-Warning "  Delete it manually: https://entra.microsoft.com -> App registrations -> Deleted applications"
        }
    }
    foreach ($f in $State.FilesWritten) {
        if (Test-Path $f) {
            Remove-Item $f -Force
            Write-Host "  Deleted file: $f" -ForegroundColor Gray
        }
    }
}

Write-Host "`n=== Application Review — Tenant Onboarding ===" -ForegroundColor Cyan
Write-Host "  Tenant       : $TenantId"
Write-Host "  App name     : $appName"
Write-Host "  Config file  : $configFile"
Write-Host ""

try {

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Verify active Microsoft Graph session
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[1/5] Checking Microsoft Graph session..." -ForegroundColor Yellow

if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
    Write-Host ""
    Write-Host "  ERROR: Microsoft.Graph PowerShell module is not installed." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Install it first:" -ForegroundColor Yellow
    Write-Host "    Install-Module Microsoft.Graph -Scope CurrentUser"
    Write-Host ""
    exit 1
}

$mgContext = Get-MgContext
if (-not $mgContext) {
    Write-Host ""
    Write-Host "  ERROR: Not connected to Microsoft Graph." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Connect first, then re-run this script:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    Connect-MgGraph -TenantId '$TenantId' ``"
    Write-Host "        -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All'"
    Write-Host ""
    exit 1
}

# Verify the required scopes are present in the current session
$requiredScopes  = @('Application.ReadWrite.All', 'Directory.ReadWrite.All')
$missingScopes   = $requiredScopes | Where-Object { $_ -notin $mgContext.Scopes }
if ($missingScopes) {
    Write-Host ""
    Write-Host "  ERROR: The current session is missing required scopes: $($missingScopes -join ', ')" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Reconnect with all required scopes:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    Connect-MgGraph -TenantId '$TenantId' ``"
    Write-Host "        -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All'"
    Write-Host ""
    exit 1
}

Write-Host "  Connected as : $($mgContext.Account)" -ForegroundColor Green
Write-Host "  Tenant       : $($mgContext.TenantId)" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Resolve Microsoft Graph service principal ID and required permission GUIDs
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[2/5] Resolving Microsoft Graph permission IDs..." -ForegroundColor Yellow

$graphSpResponse = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appId,appRoles" `
    -OutputType PSObject
$graphSp = $graphSpResponse.value[0]

# Build a lookup: permission name -> id
$roleMap = @{}
foreach ($role in $graphSp.appRoles) { $roleMap[$role.value] = $role.id }

$requiredRoleNames = @(
    'Application.Read.All',
    'Directory.Read.All',
    'AuditLog.Read.All',
    'Organization.Read.All'
)

$resourceAccess = foreach ($name in $requiredRoleNames) {
    if (-not $roleMap.ContainsKey($name)) { throw "Could not resolve Graph permission: $name" }
    @{ id = $roleMap[$name]; type = 'Role' }
}

Write-Host "  Resolved $($requiredRoleNames.Count) permissions." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Create app registration
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[3/5] Creating app registration '$appName'..." -ForegroundColor Yellow

# Check if app already exists
$existingApps = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$appName'&`$select=id,appId" `
    -OutputType PSObject
if ($existingApps.value.Count -gt 0) {
    $existingAppId  = $existingApps.value[0].appId
    $existingObjId  = $existingApps.value[0].id
    Write-Host ""
    Write-Host "  WARNING: App registration '$appName' already exists (appId: $existingAppId)." -ForegroundColor Yellow
    Write-Host "  This is likely from a previous partial run." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Options:" -ForegroundColor Yellow
    Write-Host "    1. Delete the existing app and re-run this script:"
    Write-Host "         Invoke-MgGraphRequest -Method DELETE -Uri 'https://graph.microsoft.com/v1.0/applications/$existingObjId'"
    Write-Host "    2. Choose a different -CustomerShortName."
    Write-Host ""
    throw "Aborted. Resolve the existing app registration before re-running."
}

$app = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' `
    -Body @{
        displayName            = $appName
        signInAudience         = 'AzureADMyOrg'
        requiredResourceAccess = @(
            @{
                resourceAppId  = '00000003-0000-0000-c000-000000000000'
                resourceAccess = @($resourceAccess)
            }
        )
        notes = "Created by New-TenantSetup.ps1 for the Application Review solution on $(Get-Date -Format 'yyyy-MM-dd')."
    } -OutputType PSObject
$rollback.AppObjectId = $app.id
Write-Host "  Created app: $($app.displayName) (appId: $($app.appId), objectId: $($app.id))" -ForegroundColor Green

# Create service principal
Start-Sleep -Seconds 3   # allow replication
$sp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' `
    -Body @{ appId = $app.appId } -OutputType PSObject
$rollback.SpObjectId = $sp.id
Write-Host "  Created service principal (objectId: $($sp.id))" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Generate self-signed certificate and upload public key
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[4/5] Generating self-signed certificate ($CertificateValidityYears-year validity)..." -ForegroundColor Yellow

# Generate RSA key and certificate using .NET (no external modules)
$rsa        = [System.Security.Cryptography.RSA]::Create(2048)
$certReq    = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                  $certSubject, $rsa,
                  [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                  [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

# Add basic constraints and key usage extensions
$certReq.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $false))
$certReq.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $false))
$certReq.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($certReq.PublicKey, $false))

$notBefore  = [System.DateTimeOffset]::UtcNow
$notAfter   = $notBefore.AddYears($CertificateValidityYears)
$cert       = $certReq.CreateSelfSigned($notBefore, $notAfter)

if ($CertificateStoreInstead) {
    if (-not $IsWindows) { throw '-CertificateStoreInstead is only supported on Windows.' }
    # Install to current user cert store
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
    $store.Open('ReadWrite')
    $store.Add($cert)
    $store.Close()
    $thumbprint = $cert.Thumbprint
    Write-Host "  Certificate installed to Cert:\CurrentUser\My — thumbprint: $thumbprint" -ForegroundColor Green
}
else {
    # Generate a cryptographically random password (pure .NET — no System.Web dependency)
    $pwdBytes    = [byte[]]::new(24)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($pwdBytes)
    $pfxPassword = [Convert]::ToBase64String($pwdBytes)

    $pfxBytes    = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword)
    [System.IO.File]::WriteAllBytes($pfxFile, $pfxBytes)
    $rollback.FilesWritten.Add($pfxFile)
    $pfxPassword | Set-Content -Path $pfxPassFile -Encoding UTF8 -NoNewline
    $rollback.FilesWritten.Add($pfxPassFile)
    Write-Host "  PFX exported: $pfxFile" -ForegroundColor Green
    Write-Host "  Password file: $pfxPassFile  (restrict file permissions!)" -ForegroundColor Green
    $thumbprint    = $cert.Thumbprint
}

# Export public .cer (DER encoded) for upload to the app
$cerBytes = $cert.RawData
[System.IO.File]::WriteAllBytes($certFile, $cerBytes)
$rollback.FilesWritten.Add($certFile)
Write-Host "  Public .cer exported: $certFile" -ForegroundColor Green

# Upload certificate to app registration
Write-Host "  Uploading public key to app registration..." -ForegroundColor Gray
$certBase64 = [System.Convert]::ToBase64String($cerBytes)
Invoke-MgGraphRequest -Method PATCH `
    -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" `
    -Body @{
        keyCredentials = @(
            @{
                type          = 'AsymmetricX509Cert'
                usage         = 'Verify'
                key           = $certBase64
                displayName   = $certSubject
                startDateTime = $notBefore.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
                endDateTime   = $notAfter.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
        )
    } | Out-Null
Write-Host "  Certificate uploaded to app registration." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Write tenant config file
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[5/5] Writing tenant config file to $configFile..." -ForegroundColor Yellow

# Resolve actual tenant GUID (the user may have passed a domain)
$tenantInfo       = Invoke-MgGraphRequest -Method GET `
    -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName' `
    -OutputType PSObject
$resolvedTenantId = $tenantInfo.value[0].id

if ($CertificateStoreInstead) {
    $authConfig = [ordered]@{
        authMethod              = 'Certificate'
        clientId                = $app.appId
        certificateThumbprint   = $thumbprint
    }
}
else {
    # Store relative path (relative to repo root, where the script is launched from)
    $relativePfxPath  = 'secrets/' + [System.IO.Path]::GetFileName($pfxFile)
    $relativePassPath = 'secrets/' + [System.IO.Path]::GetFileName($pfxPassFile)
    $authConfig = [ordered]@{
        authMethod              = 'Certificate'
        clientId                = $app.appId
        certificatePath         = $relativePfxPath
        certificatePasswordFile = $relativePassPath
    }
}

$tenantConfig = [ordered]@{
    tenantId         = $resolvedTenantId
    tenantName       = $CustomerDisplayName
    enabled          = $true
    settings         = [ordered]@{
        inactivityThresholdDays        = 180
        signInLookbackDays             = 30
        includeDisabledApps            = $false
        includeManagedIdentities       = $true
        includeFirstPartyMicrosoftApps = $false
    }
    logAnalytics     = [ordered]@{
        '_comment'   = 'Set enabled=true and supply workspaceId to use Log Analytics for extended sign-in history.'
        enabled      = $false
        workspaceId  = ''
        lookbackDays = 365
    }
}

# Merge auth config into tenant config
foreach ($key in $authConfig.Keys) { $tenantConfig[$key] = $authConfig[$key] }

$tenantConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile -Encoding UTF8
$rollback.FilesWritten.Add($configFile)

Write-Host "  Config written." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Setup complete ===" -ForegroundColor Cyan
Write-Host "  App registration : $appName"
Write-Host "  App (client) ID  : $($app.appId)"
Write-Host "  Tenant ID        : $resolvedTenantId"
Write-Host "  Config file      : $configFile"
Write-Host ""
Write-Host "NEXT STEPS (manual):" -ForegroundColor Yellow
Write-Host "  1. Open the Entra admin centre for tenant '$TenantId':"
Write-Host "     https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($app.appId)"
Write-Host "  2. Click 'Grant admin consent for <tenant>' to approve the application permissions."
Write-Host "  3. (Optional) If using Log Analytics: assign 'Log Analytics Reader' RBAC to the"
Write-Host "     service principal on the target workspace in the Azure portal, then set"
Write-Host "     logAnalytics.enabled=true and logAnalytics.workspaceId in:"
Write-Host "     $configFile"
Write-Host ""
Write-Host "  Run the review:"
Write-Host "     .\Invoke-MultiTenantReview.ps1" -ForegroundColor Green
Write-Host ""

} catch {
    # ── Error handler: roll back everything created in this run ───────────────
    Write-Host ""
    Write-Host "ERROR: $_" -ForegroundColor Red
    Invoke-Rollback -State $rollback
    Write-Host ""
    Write-Host "  Setup did not complete. Fix the error above and re-run the script." -ForegroundColor Yellow
    exit 1
}
