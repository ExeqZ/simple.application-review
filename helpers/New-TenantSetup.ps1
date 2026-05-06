<#
.SYNOPSIS
    Onboarding helper: registers the app, assigns required permissions, generates a
    self-signed certificate, uploads it, and writes the tenant config file.

.DESCRIPTION
    Run this script once per customer tenant to set up the app registration used by the
    Application Review solution.

    What this script does:
      1. Authenticates to the target tenant interactively (browser-based).
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
    Validity period of the generated certificate in years. Defaults to 2.

.EXAMPLE
    # Interactive setup for a customer, PFX export
    .\helpers\New-TenantSetup.ps1 `
        -TenantId          'contoso.onmicrosoft.com' `
        -CustomerShortName 'contoso' `
        -CustomerDisplayName 'Contoso Ltd'

.EXAMPLE
    # Install cert to local store instead of exporting PFX
    .\helpers\New-TenantSetup.ps1 `
        -TenantId            'fabrikam.onmicrosoft.com' `
        -CustomerShortName   'fabrikam' `
        -CustomerDisplayName 'Fabrikam Inc' `
        -CertificateStoreInstead

.NOTES
    Requires PowerShell 7.2+ on Windows or macOS/Linux (certificate store option requires Windows).
    The script uses only built-in .NET cryptography — no external modules required.
    The interactive login uses device-code flow so it works without a browser on the current machine.
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

    [int]   $CertificateValidityYears = 2
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

$appName    = "AppReview-$CustomerShortName"
$certSubject = "CN=AppReview-$CustomerShortName"
$certFile    = Join-Path $secretsFolder "$CustomerShortName.cer"
$pfxFile     = Join-Path $secretsFolder "$CustomerShortName.pfx"
$pfxPassFile = Join-Path $secretsFolder "$CustomerShortName.pfx.pass"

Write-Host "`n=== Application Review — Tenant Onboarding ===" -ForegroundColor Cyan
Write-Host "  Tenant       : $TenantId"
Write-Host "  App name     : $appName"
Write-Host "  Config file  : $configFile"
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Authenticate via device-code flow (user must have Global Admin or
#           Application Administrator + Cloud Application Administrator in the target tenant)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[1/5] Authenticating to tenant $TenantId via device-code flow..." -ForegroundColor Yellow

$tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$deviceCodeEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"

# Scopes needed to call Graph for app registration management
$mgmtScope = 'https://graph.microsoft.com/Application.ReadWrite.All https://graph.microsoft.com/Directory.ReadWrite.All offline_access'

$dcBody = @{
    client_id = '1950a258-227b-4e31-a9cf-717495945fc2'   # Azure PowerShell well-known public client
    scope     = $mgmtScope
}
$dcResponse = Invoke-RestMethod -Method Post -Uri $deviceCodeEndpoint `
    -ContentType 'application/x-www-form-urlencoded' -Body $dcBody

Write-Host ""
Write-Host "  $($dcResponse.message)" -ForegroundColor Cyan
Write-Host ""

# Poll for the token
$pollBody = @{
    grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
    client_id   = '1950a258-227b-4e31-a9cf-717495945fc2'
    device_code = $dcResponse.device_code
}
$mgmtToken = $null
$deadline  = (Get-Date).AddSeconds($dcResponse.expires_in)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds $dcResponse.interval
    try {
        $mgmtToken = Invoke-RestMethod -Method Post -Uri $tokenEndpoint `
            -ContentType 'application/x-www-form-urlencoded' -Body $pollBody
        break
    }
    catch {
        $errBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($errBody.error -eq 'authorization_pending') { continue }
        if ($errBody.error -eq 'slow_down') { Start-Sleep -Seconds 5; continue }
        throw
    }
}
if (-not $mgmtToken) { throw 'Authentication timed out. Re-run the script and complete the device-code sign-in.' }

$accessToken = $mgmtToken.access_token
$graphHeaders = @{ Authorization = "Bearer $accessToken"; 'Content-Type' = 'application/json' }

Write-Host "  Authenticated successfully." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Resolve Microsoft Graph service principal ID and required permission GUIDs
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[2/5] Resolving Microsoft Graph permission IDs..." -ForegroundColor Yellow

$graphSpResponse = Invoke-RestMethod -Uri `
    "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appId,appRoles" `
    -Headers $graphHeaders
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
$existingApps = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$appName'&`$select=id,appId" `
    -Headers $graphHeaders
if ($existingApps.value.Count -gt 0) {
    throw "An app registration named '$appName' already exists (appId: $($existingApps.value[0].appId)).`nDelete it or choose a different CustomerShortName."
}

$appBody = @{
    displayName            = $appName
    signInAudience         = 'AzureADMyOrg'
    requiredResourceAccess = @(
        @{
            resourceAppId  = '00000003-0000-0000-c000-000000000000'
            resourceAccess = $resourceAccess
        }
    )
    notes = "Created by New-TenantSetup.ps1 for the Application Review solution on $(Get-Date -Format 'yyyy-MM-dd')."
} | ConvertTo-Json -Depth 10

$app = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/applications' `
    -Headers $graphHeaders -Body $appBody
Write-Host "  Created app: $($app.displayName) (appId: $($app.appId), objectId: $($app.id))" -ForegroundColor Green

# Create service principal
Start-Sleep -Seconds 3   # allow replication
$spBody = @{ appId = $app.appId } | ConvertTo-Json
$sp = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' `
    -Headers $graphHeaders -Body $spBody
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
    # Export PFX with random password
    Add-Type -AssemblyName System.Web
    $pfxPassword   = [System.Web.Security.Membership]::GeneratePassword(32, 8)
    $pfxBytes      = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword)
    [System.IO.File]::WriteAllBytes($pfxFile, $pfxBytes)
    $pfxPassword | Set-Content -Path $pfxPassFile -Encoding UTF8 -NoNewline
    Write-Host "  PFX exported: $pfxFile" -ForegroundColor Green
    Write-Host "  Password file: $pfxPassFile  (restrict file permissions!)" -ForegroundColor Green
    $thumbprint    = $cert.Thumbprint
}

# Export public .cer (DER encoded) for upload to the app
$cerBytes = $cert.RawData
[System.IO.File]::WriteAllBytes($certFile, $cerBytes)
Write-Host "  Public .cer exported: $certFile" -ForegroundColor Green

# Upload certificate to app registration
Write-Host "  Uploading public key to app registration..." -ForegroundColor Gray
$certBase64 = [System.Convert]::ToBase64String($cerBytes)
$keyBody    = @{
    keyCredentials = @(
        @{
            type        = 'AsymmetricX509Cert'
            usage       = 'Verify'
            key         = $certBase64
            displayName = $certSubject
            startDateTime = $notBefore.ToString('o')
            endDateTime   = $notAfter.ToString('o')
        }
    )
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Method Patch `
    -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" `
    -Headers $graphHeaders -Body $keyBody | Out-Null
Write-Host "  Certificate uploaded to app registration." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Write tenant config file
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[5/5] Writing tenant config file to $configFile..." -ForegroundColor Yellow

# Resolve actual tenant GUID (the user may have passed a domain)
$tenantInfo  = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName' `
    -Headers $graphHeaders
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
