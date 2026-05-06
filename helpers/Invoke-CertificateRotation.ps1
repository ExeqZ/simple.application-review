<#
.SYNOPSIS
    Rotates the authentication certificate for an existing tenant config.

.DESCRIPTION
    Generates a new self-signed certificate, uploads it to the existing app registration
    alongside the old certificate (zero-downtime), updates the tenant config file to point
    to the new certificate, then removes the old certificate from the app registration.

    Before running this script, connect to the target tenant:

        Connect-MgGraph -TenantId '<tenantId>' `
            -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All'

.PARAMETER TenantConfigFile
    Path to the tenant JSON config file (e.g. ./tenants/contoso.json).

.PARAMETER OutputFolder
    Root folder for secrets output. Defaults to the repository root (parent of helpers/).
    The new certificate files are written to <OutputFolder>/secrets/.

.PARAMETER CertificateValidityYears
    Validity period of the new certificate in years. Defaults to 1.

.PARAMETER KeepOldCertificate
    When set, the old certificate is NOT removed from the app registration after uploading
    the new one. Useful if you want to verify the new cert works before removing the old one.

.EXAMPLE
    Connect-MgGraph -TenantId 'contoso.onmicrosoft.com' `
        -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All'
    .\helpers\Invoke-CertificateRotation.ps1 -TenantConfigFile .\tenants\contoso.json

.EXAMPLE
    # Keep the old cert during a transition period, remove it manually later
    .\helpers\Invoke-CertificateRotation.ps1 `
        -TenantConfigFile  .\tenants\contoso.json `
        -KeepOldCertificate

.NOTES
    Requires PowerShell 7.2+ on Windows or macOS/Linux (certificate store option requires Windows).
    Requires the Microsoft.Graph PowerShell module (Install-Module Microsoft.Graph).
    Certificate generation uses only built-in .NET cryptography.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$TenantConfigFile,

    [string]$OutputFolder         = '',

    [int]   $CertificateValidityYears = 1,

    [switch]$KeepOldCertificate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Resolve paths ─────────────────────────────────────────────────────────────
if (-not $OutputFolder) {
    $OutputFolder = Split-Path $PSScriptRoot -Parent
}
$secretsFolder = Join-Path $OutputFolder 'secrets'
if (-not (Test-Path $secretsFolder)) { New-Item -ItemType Directory -Path $secretsFolder -Force | Out-Null }

if (-not (Test-Path $TenantConfigFile)) {
    throw "Tenant config file not found: $TenantConfigFile"
}

$config = Get-Content $TenantConfigFile -Raw | ConvertFrom-Json

# Validate required fields
foreach ($field in @('tenantId', 'clientId', 'authMethod')) {
    if (-not $config.$field) { throw "Config is missing required field: $field" }
}
if ($config.authMethod -ne 'Certificate') {
    throw "This script only supports authMethod=Certificate. Current authMethod: $($config.authMethod)"
}

$appId       = $config.clientId
$tenantId    = $config.tenantId
$shortName   = [System.IO.Path]::GetFileNameWithoutExtension($TenantConfigFile)
$certSubject = "CN=AppReview-$shortName"

Write-Host "`n=== Certificate Rotation ===" -ForegroundColor Cyan
Write-Host "  Tenant config : $TenantConfigFile"
Write-Host "  App (clientId): $appId"
Write-Host "  Tenant ID     : $tenantId"
Write-Host "  New validity  : $CertificateValidityYears year(s)"
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Verify Microsoft Graph session
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[1/5] Checking Microsoft Graph session..." -ForegroundColor Yellow

if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
    Write-Host ""
    Write-Host "  ERROR: Microsoft.Graph PowerShell module is not installed." -ForegroundColor Red
    Write-Host "    Install-Module Microsoft.Graph -Scope CurrentUser"
    Write-Host ""
    exit 1
}

$mgContext = Get-MgContext
if (-not $mgContext) {
    Write-Host ""
    Write-Host "  ERROR: Not connected to Microsoft Graph." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Connect first:" -ForegroundColor Yellow
    Write-Host "    Connect-MgGraph -TenantId '$tenantId' ``"
    Write-Host "        -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All'"
    Write-Host ""
    exit 1
}

$requiredScopes = @('Application.ReadWrite.All', 'Directory.ReadWrite.All')
$missingScopes  = $requiredScopes | Where-Object { $_ -notin $mgContext.Scopes }
if ($missingScopes) {
    Write-Host ""
    Write-Host "  ERROR: Missing required scopes: $($missingScopes -join ', ')" -ForegroundColor Red
    Write-Host "    Connect-MgGraph -TenantId '$tenantId' ``"
    Write-Host "        -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All'"
    Write-Host ""
    exit 1
}

Write-Host "  Connected as : $($mgContext.Account)" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Resolve app registration object ID and existing key credentials
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[2/5] Resolving app registration..." -ForegroundColor Yellow

$appResponse = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$appId'&`$select=id,appId,displayName,keyCredentials" `
    -OutputType PSObject

if ($appResponse.value.Count -eq 0) {
    throw "No app registration found with appId '$appId'. Verify the clientId in $TenantConfigFile."
}

$app         = $appResponse.value[0]
$appObjectId = $app.id
$oldKeys     = @($app.keyCredentials)

Write-Host "  App           : $($app.displayName) (objectId: $appObjectId)" -ForegroundColor Green
Write-Host "  Existing keys : $($oldKeys.Count)" -ForegroundColor Green
foreach ($k in $oldKeys) {
    $exp = if ($k.endDateTime) { [datetime]$k.endDateTime } else { $null }
    $expStr = if ($exp) { $exp.ToString('yyyy-MM-dd') } else { 'unknown' }
    Write-Host "    - $($k.displayName)  keyId=$($k.keyId)  expires=$expStr" -ForegroundColor Gray
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Generate new certificate
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[3/5] Generating new certificate..." -ForegroundColor Yellow

$timestamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$newPfxFile  = Join-Path $secretsFolder "$shortName-$timestamp.pfx"
$newPassFile = Join-Path $secretsFolder "$shortName-$timestamp.pfx.pass"
$newCerFile  = Join-Path $secretsFolder "$shortName-$timestamp.cer"

$rsa     = [System.Security.Cryptography.RSA]::Create(2048)
$certReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
               $certSubject, $rsa,
               [System.Security.Cryptography.HashAlgorithmName]::SHA256,
               [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

$certReq.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $false))
$certReq.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $false))
$certReq.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($certReq.PublicKey, $false))

$notBefore = [System.DateTimeOffset]::UtcNow
$notAfter  = $notBefore.AddYears($CertificateValidityYears)
$newCert   = $certReq.CreateSelfSigned($notBefore, $notAfter)

$pwdBytes    = [byte[]]::new(24)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($pwdBytes)
$pfxPassword = [Convert]::ToBase64String($pwdBytes)

$pfxBytes = $newCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword)
[System.IO.File]::WriteAllBytes($newPfxFile, $pfxBytes)
$pfxPassword | Set-Content -Path $newPassFile -Encoding UTF8 -NoNewline

$cerBytes   = $newCert.RawData
[System.IO.File]::WriteAllBytes($newCerFile, $cerBytes)

Write-Host "  New PFX      : $newPfxFile" -ForegroundColor Green
Write-Host "  Password file: $newPassFile" -ForegroundColor Green
Write-Host "  Public .cer  : $newCerFile" -ForegroundColor Green
Write-Host "  Thumbprint   : $($newCert.Thumbprint)" -ForegroundColor Green
Write-Host "  Expires      : $($notAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Upload new certificate alongside the old one (zero downtime)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[4/5] Uploading new certificate to app registration..." -ForegroundColor Yellow

$certBase64 = [Convert]::ToBase64String($cerBytes)

# Build the new key credential object
$newKeyCredential = @{
    type          = 'AsymmetricX509Cert'
    usage         = 'Verify'
    key           = $certBase64
    displayName   = "$certSubject (rotated $($notBefore.ToString('yyyy-MM-dd')))"
    startDateTime = $notBefore.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    endDateTime   = $notAfter.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# Include existing keys so we don't overwrite them (zero-downtime: both certs valid simultaneously)
$allKeyCredentials = @($newKeyCredential)
foreach ($k in $oldKeys) {
    $allKeyCredentials += @{
        type          = $k.type
        usage         = $k.usage
        key           = $k.key
        displayName   = $k.displayName
        startDateTime = $k.startDateTime
        endDateTime   = $k.endDateTime
        keyId         = $k.keyId
    }
}

Invoke-MgGraphRequest -Method PATCH `
    -Uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" `
    -Body @{ keyCredentials = $allKeyCredentials } | Out-Null

Write-Host "  New certificate uploaded. Both old and new are now active." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Update tenant config file
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[5/5] Updating tenant config file..." -ForegroundColor Yellow

# Archive old cert files by renaming them (don't delete — might still be needed briefly)
$oldPfxPath  = if ($config.certificatePath)         { Join-Path $OutputFolder $config.certificatePath } else { $null }
$oldPassPath = if ($config.certificatePasswordFile)  { Join-Path $OutputFolder $config.certificatePasswordFile } else { $null }
$oldCerPath  = $null
if ($oldPfxPath -and (Test-Path $oldPfxPath)) {
    $archiveName = [System.IO.Path]::GetFileNameWithoutExtension($oldPfxPath) + "-archived-$timestamp" +
                   [System.IO.Path]::GetExtension($oldPfxPath)
    $archivePath = Join-Path ([System.IO.Path]::GetDirectoryName($oldPfxPath)) $archiveName
    Rename-Item -Path $oldPfxPath -NewName $archiveName
    Write-Host "  Archived old PFX to: $archivePath" -ForegroundColor Gray
}
if ($oldPassPath -and (Test-Path $oldPassPath)) {
    $archiveName = [System.IO.Path]::GetFileNameWithoutExtension($oldPassPath) + "-archived-$timestamp" +
                   [System.IO.Path]::GetExtension($oldPassPath)
    $archivePath = Join-Path ([System.IO.Path]::GetDirectoryName($oldPassPath)) $archiveName
    Rename-Item -Path $oldPassPath -NewName $archiveName
    Write-Host "  Archived old password file to: $archivePath" -ForegroundColor Gray
}

# Update config to point to new files (relative path from repo root)
$relPfxPath  = 'secrets/' + [System.IO.Path]::GetFileName($newPfxFile)
$relPassPath = 'secrets/' + [System.IO.Path]::GetFileName($newPassFile)

$config.PSObject.Properties.Remove('certificateThumbprint')
$config.PSObject.Properties.Remove('certificatePath')
$config.PSObject.Properties.Remove('certificatePasswordFile')

$config | Add-Member -NotePropertyName 'certificatePath'         -NotePropertyValue $relPfxPath  -Force
$config | Add-Member -NotePropertyName 'certificatePasswordFile' -NotePropertyValue $relPassPath -Force

$config | ConvertTo-Json -Depth 10 | Set-Content -Path $TenantConfigFile -Encoding UTF8
Write-Host "  Config updated: $TenantConfigFile" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# Remove old key credentials from app registration (unless -KeepOldCertificate)
# ─────────────────────────────────────────────────────────────────────────────
if ($KeepOldCertificate) {
    Write-Host ""
    Write-Host "  -KeepOldCertificate is set. Old certificate(s) remain on the app registration." -ForegroundColor Yellow
    Write-Host "  Remove them manually when ready:" -ForegroundColor Yellow
    foreach ($k in $oldKeys) {
        Write-Host "    keyId: $($k.keyId)  displayName: $($k.displayName)" -ForegroundColor Gray
    }
}
else {
    if ($oldKeys.Count -gt 0) {
        Write-Host "  Removing old certificate(s) from app registration..." -ForegroundColor Gray
        # Upload only the new key credential — removes all others
        Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" `
            -Body @{ keyCredentials = @($newKeyCredential) } | Out-Null
        Write-Host "  Old certificate(s) removed." -ForegroundColor Green
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Rotation complete ===" -ForegroundColor Cyan
Write-Host "  New thumbprint : $($newCert.Thumbprint)"
Write-Host "  Expires        : $($notAfter.ToString('yyyy-MM-dd'))"
Write-Host "  Config file    : $TenantConfigFile"
Write-Host "  New PFX        : $newPfxFile"
Write-Host ""
if ($KeepOldCertificate) {
    Write-Host "REMINDER: Remove old key credentials from the app registration once you" -ForegroundColor Yellow
    Write-Host "          have verified the new certificate works." -ForegroundColor Yellow
    Write-Host ""
}
Write-Host "  Run the review to verify:"
Write-Host "     .\Invoke-MultiTenantReview.ps1" -ForegroundColor Green
Write-Host ""
