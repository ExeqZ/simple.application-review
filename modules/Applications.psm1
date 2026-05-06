<#
.SYNOPSIS
    Enumerates enterprise applications and managed identities from a Microsoft 365 tenant.

.DESCRIPTION
    Retrieves all service principals of type 'Application' (enterprise apps) and
    'ManagedIdentity' from Microsoft Graph, with their associated metadata.
    Uses the beta endpoint to retrieve signInActivity for last-used information.
#>

# Microsoft-owned publisher GUIDs — used to identify first-party apps
$script:MicrosoftPublisherIds = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a',  # Microsoft Services
    '72f988bf-86f1-41af-91ab-2d7cd011db47'   # Microsoft
)

function Get-EnterpriseApplications {
    <#
    .SYNOPSIS
        Returns all enterprise application service principals in the tenant.

    .PARAMETER AccessToken
        Bearer access token with Application.Read.All and Directory.Read.All.

    .PARAMETER IncludeFirstPartyMicrosoft
        If set, includes Microsoft-published first-party apps (e.g., Office 365, Azure AD).
        Defaults to $false to reduce noise.

    .PARAMETER IncludeDisabled
        If set, includes disabled service principals.

    .EXAMPLE
        $apps = Get-EnterpriseApplications -AccessToken $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$IncludeFirstPartyMicrosoft,
        [switch]$IncludeDisabled
    )

    Write-Verbose "Fetching enterprise applications (servicePrincipalType eq 'Application')..."

    $select = @(
        'id', 'appId', 'displayName', 'servicePrincipalType', 'accountEnabled',
        'appOwnerOrganizationId', 'createdDateTime', 'description', 'notes',
        'homepage', 'replyUrls', 'servicePrincipalNames', 'tags',
        'signInAudience', 'verifiedPublisher', 'appRoles', 'oauth2PermissionScopes',
        'signInActivity'  # beta-only — last interactive / non-interactive / SP sign-in
    ) -join ','

    # Use beta for signInActivity support
    $uri = "https://graph.microsoft.com/beta/servicePrincipals" +
           "?`$filter=servicePrincipalType eq 'Application'" +
           "&`$select=$select" +
           "&`$top=999"

    $servicePrincipals = Invoke-GraphRequest -AccessToken $AccessToken -Uri $uri -All

    $filtered = foreach ($sp in $servicePrincipals) {
        # Skip first-party Microsoft apps unless explicitly included
        if (-not $IncludeFirstPartyMicrosoft) {
            if ($sp.appOwnerOrganizationId -in $script:MicrosoftPublisherIds) {
                continue
            }
            # Also skip apps with Microsoft tags
            if ($sp.tags -contains 'WindowsAzureActiveDirectoryIntegratedApp' -and
                $sp.appOwnerOrganizationId -in $script:MicrosoftPublisherIds) {
                continue
            }
        }

        # Skip disabled service principals unless requested
        if (-not $IncludeDisabled -and $sp.accountEnabled -eq $false) {
            continue
        }

        Add-TypeFields -ServicePrincipal $sp -PrincipalType 'EnterpriseApplication'
        $sp
    }

    Write-Verbose "Found $(@($filtered).Count) enterprise applications."
    return $filtered
}

function Get-ManagedIdentities {
    <#
    .SYNOPSIS
        Returns all managed identity service principals in the tenant.

    .PARAMETER AccessToken
        Bearer access token with Application.Read.All and Directory.Read.All.

    .EXAMPLE
        $mis = Get-ManagedIdentities -AccessToken $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken
    )

    Write-Verbose "Fetching managed identities (servicePrincipalType eq 'ManagedIdentity')..."

    $select = @(
        'id', 'appId', 'displayName', 'servicePrincipalType', 'accountEnabled',
        'appOwnerOrganizationId', 'createdDateTime', 'description', 'notes',
        'alternativeNames', 'tags', 'signInActivity'
    ) -join ','

    $uri = "https://graph.microsoft.com/beta/servicePrincipals" +
           "?`$filter=servicePrincipalType eq 'ManagedIdentity'" +
           "&`$select=$select" +
           "&`$top=999"

    $servicePrincipals = Invoke-GraphRequest -AccessToken $AccessToken -Uri $uri -All

    foreach ($sp in $servicePrincipals) {
        Add-TypeFields -ServicePrincipal $sp -PrincipalType 'ManagedIdentity'

        # Extract Azure resource info from alternativeNames
        # Format: isExplicit/[subscription]/resourcegroups/[rg]/providers/[type]/[name]
        $sp | Add-Member -NotePropertyName 'azureResourceId' -NotePropertyValue $null -Force
        if ($sp.alternativeNames) {
            $resourceId = $sp.alternativeNames | Where-Object { $_ -like '/subscriptions/*' } | Select-Object -First 1
            if ($resourceId) {
                $sp.azureResourceId = $resourceId
            }
        }
    }

    Write-Verbose "Found $(@($servicePrincipals).Count) managed identities."
    return $servicePrincipals
}

function Get-AllApplications {
    <#
    .SYNOPSIS
        Convenience function that returns both enterprise apps and managed identities.

    .PARAMETER AccessToken
        Bearer access token.

    .PARAMETER IncludeFirstPartyMicrosoft
        Include Microsoft first-party apps in results.

    .PARAMETER IncludeDisabled
        Include disabled service principals.

    .PARAMETER IncludeManagedIdentities
        Include managed identities in results. Default is $true.

    .EXAMPLE
        $all = Get-AllApplications -AccessToken $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$IncludeFirstPartyMicrosoft,
        [switch]$IncludeDisabled,
        [switch]$IncludeManagedIdentities = $true
    )

    $results = [System.Collections.Generic.List[object]]::new()

    $enterpriseApps = Get-EnterpriseApplications -AccessToken $AccessToken `
        -IncludeFirstPartyMicrosoft:$IncludeFirstPartyMicrosoft `
        -IncludeDisabled:$IncludeDisabled
    $results.AddRange(@($enterpriseApps))

    if ($IncludeManagedIdentities) {
        $managedIds = Get-ManagedIdentities -AccessToken $AccessToken
        $results.AddRange(@($managedIds))
    }

    return $results
}

function Get-ServicePrincipalById {
    <#
    .SYNOPSIS
        Looks up a single service principal by its object ID, with caching.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$ServicePrincipalId
    )

    if ($script:SpCache -and $script:SpCache.ContainsKey($ServicePrincipalId)) {
        return $script:SpCache[$ServicePrincipalId]
    }

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId" +
           "?`$select=id,appId,displayName,appRoles,oauth2PermissionScopes,publishedPermissionScopes"

    try {
        $sp = Invoke-GraphRequest -AccessToken $AccessToken -Uri $uri
        if (-not $script:SpCache) { $script:SpCache = @{} }
        $script:SpCache[$ServicePrincipalId] = $sp
        return $sp
    }
    catch {
        Write-Warning "Could not resolve service principal $ServicePrincipalId`: $_"
        return $null
    }
}

function Clear-ServicePrincipalCache {
    <#
    .SYNOPSIS
        Clears the in-memory service principal lookup cache between tenants.
    #>
    $script:SpCache = @{}
}

# ─── Internal helpers ────────────────────────────────────────────────────────

function Add-TypeFields {
    param(
        [object]$ServicePrincipal,
        [string]$PrincipalType  # 'EnterpriseApplication' or 'ManagedIdentity'
    )

    $ServicePrincipal | Add-Member -NotePropertyName '_principalType' -NotePropertyValue $PrincipalType -Force

    # Normalise signInActivity nulls so downstream code doesn't need null checks
    if (-not $ServicePrincipal.signInActivity) {
        $ServicePrincipal | Add-Member -NotePropertyName 'signInActivity' -NotePropertyValue ([PSCustomObject]@{
            lastSignInDateTime               = $null
            lastNonInteractiveSignInDateTime = $null
            lastServicePrincipalSignInDateTime = $null
        }) -Force
    }
}

Export-ModuleMember -Function Get-EnterpriseApplications, Get-ManagedIdentities, Get-AllApplications,
    Get-ServicePrincipalById, Clear-ServicePrincipalCache
