<#
.SYNOPSIS
    Microsoft Graph API authentication and request module.

.DESCRIPTION
    Provides functions to authenticate to Microsoft Graph API using client credentials
    (client secret or certificate) and to make paginated, throttle-aware REST requests.
    Supports multi-tenant scenarios for service providers.

.NOTES
    Required app permissions: Application.Read.All, Directory.Read.All, AuditLog.Read.All
#>

function Get-GraphAccessToken {
    <#
    .SYNOPSIS
        Acquires an OAuth2 access token for Microsoft Graph using client credentials.

    .PARAMETER TenantId
        Azure AD tenant ID (GUID or domain, e.g. contoso.onmicrosoft.com).

    .PARAMETER ClientId
        Application (client) ID of the registered app.

    .PARAMETER ClientSecret
        Client secret as a SecureString.

    .PARAMETER CertificateThumbprint
        Thumbprint of a certificate in the local certificate store (CurrentUser or LocalMachine).

    .PARAMETER CertificatePath
        File path to a PFX certificate file.

    .PARAMETER CertificatePassword
        Password for the PFX file as a SecureString.

    .EXAMPLE
        $token = Get-GraphAccessToken -TenantId $tid -ClientId $cid -CertificateThumbprint 'AABB...'
    #>
    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [securestring]$ClientSecret,

        [Parameter(Mandatory, ParameterSetName = 'CertThumbprint')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = 'CertFile')]
        [string]$CertificatePath,

        [Parameter(ParameterSetName = 'CertFile')]
        [securestring]$CertificatePassword,

        # OAuth2 resource scope. Override to target a different API (e.g. Log Analytics).
        [string]$Scope = 'https://graph.microsoft.com/.default'
    )

    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    switch ($PSCmdlet.ParameterSetName) {
        'ClientSecret' {
            $plainSecret = ConvertFrom-SecureStringPlainText -SecureString $ClientSecret
            $body = @{
                grant_type    = 'client_credentials'
                client_id     = $ClientId
                client_secret = $plainSecret
                scope         = $scope
            }
            try {
                $response = Invoke-RestMethod -Method POST -Uri $tokenEndpoint `
                    -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
                return $response.access_token
            }
            finally {
                $plainSecret = $null
            }
        }

        'CertThumbprint' {
            $cert = Get-Item "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
            if (-not $cert) {
                $cert = Get-Item "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction Stop
            }
            $jwtAssertion = New-ClientAssertionJwt -Certificate $cert -ClientId $ClientId -TenantId $TenantId
            return Invoke-ClientAssertionTokenRequest -TokenEndpoint $tokenEndpoint -ClientId $ClientId -JwtAssertion $jwtAssertion -Scope $scope
        }

        'CertFile' {
            # EphemeralKeySet is Windows-only; fall back to DefaultKeySet on macOS/Linux
            $keyFlag = if ($IsWindows) {
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
            } else {
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
            }
            if ($CertificatePassword) {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                    $CertificatePath, $CertificatePassword, $keyFlag
                )
            }
            else {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                    $CertificatePath,
                    [string]$null,
                    $keyFlag
                )
            }
            try {
                $jwtAssertion = New-ClientAssertionJwt -Certificate $cert -ClientId $ClientId -TenantId $TenantId
                return Invoke-ClientAssertionTokenRequest -TokenEndpoint $tokenEndpoint -ClientId $ClientId -JwtAssertion $jwtAssertion -Scope $scope
            }
            finally {
                $cert.Dispose()
            }
        }
    }
}

function Invoke-ClientAssertionTokenRequest {
    [CmdletBinding()]
    param(
        [string]$TokenEndpoint,
        [string]$ClientId,
        [string]$JwtAssertion,
        [string]$Scope
    )

    $body = @{
        grant_type             = 'client_credentials'
        client_id              = $ClientId
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion       = $JwtAssertion
        scope                  = $Scope
    }

    $response = Invoke-RestMethod -Method POST -Uri $TokenEndpoint `
        -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    return $response.access_token
}

function New-ClientAssertionJwt {
    <#
    .SYNOPSIS
        Builds a signed JWT client assertion for certificate-based app authentication.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$TenantId
    )

    $audience = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $now      = [DateTimeOffset]::UtcNow
    $exp      = $now.AddMinutes(10).ToUnixTimeSeconds()
    $nbf      = $now.ToUnixTimeSeconds()
    $jti      = [System.Guid]::NewGuid().ToString()

    # x5t: base64url of the raw SHA-1 thumbprint bytes
    $thumbprintBytes = [byte[]]::new(20)
    for ($i = 0; $i -lt 40; $i += 2) {
        $thumbprintBytes[$i / 2] = [Convert]::ToByte($Certificate.Thumbprint.Substring($i, 2), 16)
    }
    $x5t = ConvertTo-Base64Url -Bytes $thumbprintBytes

    $header = [ordered]@{ alg = 'RS256'; typ = 'JWT'; x5t = $x5t } | ConvertTo-Json -Compress
    $payload = [ordered]@{
        aud = $audience
        iss = $ClientId
        sub = $ClientId
        jti = $jti
        nbf = $nbf
        exp = $exp
    } | ConvertTo-Json -Compress

    $headerEncoded  = ConvertTo-Base64Url -Bytes ([System.Text.Encoding]::UTF8.GetBytes($header))
    $payloadEncoded = ConvertTo-Base64Url -Bytes ([System.Text.Encoding]::UTF8.GetBytes($payload))

    $signingInput = "$headerEncoded.$payloadEncoded"
    $signingBytes = [System.Text.Encoding]::UTF8.GetBytes($signingInput)

    $rsa       = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    $signature = $rsa.SignData($signingBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $signatureEncoded = ConvertTo-Base64Url -Bytes $signature

    return "$headerEncoded.$payloadEncoded.$signatureEncoded"
}

function Invoke-GraphRequest {
    <#
    .SYNOPSIS
        Makes a Microsoft Graph API request with automatic pagination and retry on throttling.

    .PARAMETER AccessToken
        Bearer access token for Graph API.

    .PARAMETER Uri
        The Graph API endpoint URI.

    .PARAMETER Method
        HTTP method. Defaults to GET.

    .PARAMETER Body
        Optional body object (serialized to JSON automatically).

    .PARAMETER All
        If specified, follows @odata.nextLink to retrieve all pages of results.

    .PARAMETER ApiVersion
        API version path segment. Defaults to 'v1.0'. Use 'beta' for beta endpoints.

    .EXAMPLE
        $apps = Invoke-GraphRequest -AccessToken $token -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -All
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [object]$Body,

        [switch]$All
    )

    $headers = @{
        'Authorization'    = "Bearer $AccessToken"
        'Content-Type'     = 'application/json'
        'ConsistencyLevel' = 'eventual'
    }

    $allResults  = [System.Collections.Generic.List[object]]::new()
    $currentUri  = $Uri
    $maxRetries  = 5

    do {
        $attempt = 0
        $success = $false

        while (-not $success -and $attempt -lt $maxRetries) {
            try {
                $params = @{
                    Uri     = $currentUri
                    Method  = $Method
                    Headers = $headers
                }

                if ($Body) {
                    $params['Body'] = ($Body | ConvertTo-Json -Depth 20 -Compress)
                }

                $response = Invoke-RestMethod @params -ErrorAction Stop
                $success  = $true

                if ($null -ne $response.value) {
                    $allResults.AddRange($response.value)
                }
                else {
                    # Single object response (no paging)
                    return $response
                }

                $currentUri = $response.'@odata.nextLink'
            }
            catch {
                $statusCode = $null
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }

                if ($statusCode -eq 429 -or $statusCode -eq 503) {
                    $attempt++
                    $retryAfter = 60
                    try {
                        $retryAfter = [int]$_.Exception.Response.Headers.GetValues('Retry-After')[0]
                    }
                    catch { }
                    $waitSeconds = [math]::Min($retryAfter * $attempt, 300)
                    Write-Warning "Graph API throttled (HTTP $statusCode). Waiting ${waitSeconds}s before retry $attempt/$maxRetries..."
                    Start-Sleep -Seconds $waitSeconds
                }
                elseif ($statusCode -eq 401) {
                    throw "HTTP 401 Unauthorized — access token may be expired or the app lacks required permissions. URI: $currentUri"
                }
                elseif ($statusCode -eq 403) {
                    throw "HTTP 403 Forbidden — the app lacks consent for this scope. URI: $currentUri"
                }
                else {
                    throw $_
                }
            }
        }

        if (-not $success) {
            throw "Graph API request failed after $maxRetries retries. URI: $currentUri"
        }

    } while ($All -and $currentUri)

    return $allResults
}

function Get-GraphAccessTokenFromConfig {
    <#
    .SYNOPSIS
        Resolves credentials from a tenant config object and returns an access token.

    .PARAMETER TenantConfig
        A tenant config hashtable/PSObject from tenants.json.

    .EXAMPLE
        $token = Get-GraphAccessTokenFromConfig -TenantConfig $config.tenants[0]
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$TenantConfig,

        # Override to request a token for a different API (e.g. Log Analytics).
        [string]$Scope = 'https://graph.microsoft.com/.default'
    )

    $tenantId = $TenantConfig.tenantId
    $clientId = $TenantConfig.clientId
    $method   = $TenantConfig.authMethod

    switch ($method) {
        'ClientSecret' {
            $secretFile = $TenantConfig.clientSecretFile
            if (-not (Test-Path $secretFile)) {
                throw "Client secret file not found: $secretFile (tenant: $($TenantConfig.tenantName))"
            }
            $secretPlain  = (Get-Content $secretFile -Raw).Trim()
            $secretSecure = ConvertTo-SecureString $secretPlain -AsPlainText -Force
            $secretPlain  = $null
            return Get-GraphAccessToken -TenantId $tenantId -ClientId $clientId -ClientSecret $secretSecure -Scope $Scope
        }

        'Certificate' {
            if ($TenantConfig.certificateThumbprint) {
                return Get-GraphAccessToken -TenantId $tenantId -ClientId $clientId `
                    -CertificateThumbprint $TenantConfig.certificateThumbprint -Scope $Scope
            }
            elseif ($TenantConfig.certificatePath) {
                $certPath = $TenantConfig.certificatePath
                if (-not (Test-Path $certPath)) {
                    throw "Certificate file not found: $certPath (tenant: $($TenantConfig.tenantName))"
                }
                $certPass = $null
                if ($TenantConfig.certificatePasswordFile -and (Test-Path $TenantConfig.certificatePasswordFile)) {
                    $passPlain = (Get-Content $TenantConfig.certificatePasswordFile -Raw).Trim()
                    $certPass  = ConvertTo-SecureString $passPlain -AsPlainText -Force
                    $passPlain = $null
                }
                $params = @{
                    TenantId        = $tenantId
                    ClientId        = $clientId
                    CertificatePath = $certPath
                    Scope           = $Scope
                }
                if ($certPass) { $params['CertificatePassword'] = $certPass }
                return Get-GraphAccessToken @params
            }
            else {
                throw "Certificate auth specified but neither certificateThumbprint nor certificatePath found in config for tenant: $($TenantConfig.tenantName)"
            }
        }

        default {
            throw "Unsupported authMethod '$method' for tenant: $($TenantConfig.tenantName). Valid values: ClientSecret, Certificate"
        }
    }
}

function Get-LogAnalyticsAccessToken {
    <#
    .SYNOPSIS
        Acquires an access token scoped for the Azure Monitor Log Analytics REST API.

    .DESCRIPTION
        Convenience wrapper around Get-GraphAccessToken that sets the scope to
        'https://api.loganalytics.io/.default'. The app registration must have the
        'Log Analytics Reader' Azure RBAC role on the target workspace.

    .PARAMETER TenantConfig
        Tenant config object from tenants.json (same as Get-GraphAccessTokenFromConfig).
        Use this OR the individual TenantId/ClientId/credential parameters.

    .EXAMPLE
        $laToken = Get-LogAnalyticsAccessToken -TenantConfig $tenant
    .EXAMPLE
        $laToken = Get-LogAnalyticsAccessToken -TenantId $tid -ClientId $cid -CertificateThumbprint 'AABB...'
    #>
    [CmdletBinding(DefaultParameterSetName = 'Config')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Config')]
        [object]$TenantConfig,

        [Parameter(Mandatory, ParameterSetName = 'Secret')]
        [Parameter(Mandatory, ParameterSetName = 'CertThumbprint')]
        [Parameter(Mandatory, ParameterSetName = 'CertFile')]
        [string]$TenantId,

        [Parameter(Mandatory, ParameterSetName = 'Secret')]
        [Parameter(Mandatory, ParameterSetName = 'CertThumbprint')]
        [Parameter(Mandatory, ParameterSetName = 'CertFile')]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'Secret')]
        [securestring]$ClientSecret,

        [Parameter(Mandatory, ParameterSetName = 'CertThumbprint')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = 'CertFile')]
        [string]$CertificatePath,

        [Parameter(ParameterSetName = 'CertFile')]
        [securestring]$CertificatePassword
    )

    $laScope = 'https://api.loganalytics.io/.default'

    if ($PSCmdlet.ParameterSetName -eq 'Config') {
        return Get-GraphAccessTokenFromConfig -TenantConfig $TenantConfig -Scope $laScope
    }

    $params = @{ TenantId = $TenantId; ClientId = $ClientId; Scope = $laScope }
    switch ($PSCmdlet.ParameterSetName) {
        'Secret'         { $params['ClientSecret']           = $ClientSecret           }
        'CertThumbprint' { $params['CertificateThumbprint']  = $CertificateThumbprint  }
        'CertFile'       {
            $params['CertificatePath'] = $CertificatePath
            if ($CertificatePassword) { $params['CertificatePassword'] = $CertificatePassword }
        }
    }
    return Get-GraphAccessToken @params
}

# ─── Internal helpers ───────────────────────────────────────────────────────

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-SecureStringPlainText {
    param([securestring]$SecureString)
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function Invoke-GraphBatchRequest {
    <#
    .SYNOPSIS
        Sends a Graph JSON $batch request containing multiple sub-requests and returns
        the individual responses. Each sub-request is processed independently by Graph,
        so failures in one sub-request do not affect the others.

    .PARAMETER AccessToken
        Bearer access token.

    .PARAMETER Requests
        Array of hashtables, each with keys: id (string), method (string), url (string).
        The url must be a relative path (e.g. '/auditLogs/signIns?$filter=...').

    .PARAMETER BatchEndpointVersion
        API version for the $batch endpoint itself. Defaults to 'v1.0'.
        Individual sub-request URLs determine their own API version.

    .OUTPUTS
        Array of response objects. Each has: id, status, headers, body.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [hashtable[]]$Requests,

        [string]$BatchEndpointVersion = 'v1.0'
    )

    $batchUri = "https://graph.microsoft.com/$BatchEndpointVersion/`$batch"

    $headers = @{
        'Authorization' = "Bearer $AccessToken"
        'Content-Type'  = 'application/json'
    }

    $body = @{ requests = $Requests } | ConvertTo-Json -Depth 20 -Compress

    $maxRetries = 5
    $attempt    = 0
    $success    = $false

    while (-not $success -and $attempt -lt $maxRetries) {
        try {
            # Use Invoke-WebRequest + manual JSON parsing to preserve deeply nested body objects.
            # Invoke-RestMethod's auto-deserialization can mangle nested sub-response bodies.
            $webResponse = Invoke-WebRequest -Method POST -Uri $batchUri -Headers $headers -Body $body -ErrorAction Stop
            # ConvertFrom-Json -Depth requires PS 7.3+; use -Depth when available, else rely on default
            if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('Depth')) {
                $parsed = $webResponse.Content | ConvertFrom-Json -Depth 50
            }
            else {
                $parsed = $webResponse.Content | ConvertFrom-Json
            }
            $success = $true
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            if ($statusCode -eq 429 -or $statusCode -eq 503) {
                $attempt++
                $retryAfter = 60
                try { $retryAfter = [int]$_.Exception.Response.Headers.GetValues('Retry-After')[0] } catch { }
                $waitSeconds = [math]::Min($retryAfter * $attempt, 300)
                Write-Warning "Graph batch API throttled (HTTP $statusCode). Waiting ${waitSeconds}s before retry $attempt/$maxRetries..."
                Start-Sleep -Seconds $waitSeconds
            }
            else {
                throw $_
            }
        }
    }

    if (-not $success) {
        throw "Graph batch API request failed after $maxRetries retries."
    }

    return $parsed.responses
}

Export-ModuleMember -Function Get-GraphAccessToken, Get-GraphAccessTokenFromConfig, Get-LogAnalyticsAccessToken, Invoke-GraphRequest, Invoke-GraphBatchRequest
