<#
.SYNOPSIS
    Analyses application and delegated permissions for enterprise apps and managed identities.

.DESCRIPTION
    Retrieves app role assignments (application permissions) and OAuth2 permission grants
    (delegated permissions) for a service principal, then cross-references them against
    the sensitive permissions list to produce a risk assessment.
#>

# Loaded once per session; path resolved relative to this module file
$script:SensitivePermissionsPath = Join-Path $PSScriptRoot '../config/sensitive-permissions.json'
$script:SensitivePermissions     = $null

function Get-SensitivePermissions {
    <#
    .SYNOPSIS
        Returns the loaded sensitive permissions list, loading it on first call.
    #>
    if (-not $script:SensitivePermissions) {
        if (-not (Test-Path $script:SensitivePermissionsPath)) {
            throw "sensitive-permissions.json not found at: $($script:SensitivePermissionsPath)"
        }
        $data = Get-Content $script:SensitivePermissionsPath -Raw | ConvertFrom-Json
        $script:SensitivePermissions = $data.sensitivePermissions
    }
    return $script:SensitivePermissions
}

function Get-ApplicationPermissions {
    <#
    .SYNOPSIS
        Retrieves all permissions (app roles + delegated) assigned to a service principal.

    .PARAMETER AccessToken
        Bearer access token.

    .PARAMETER ServicePrincipalId
        Object ID of the service principal to inspect.

    .PARAMETER AppId
        Application ID (client ID) of the service principal.

    .EXAMPLE
        $perms = Get-ApplicationPermissions -AccessToken $token -ServicePrincipalId $sp.id -AppId $sp.appId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$ServicePrincipalId,

        [string]$AppId
    )

    $appRoleAssignments  = Get-AppRoleAssignments  -AccessToken $AccessToken -ServicePrincipalId $ServicePrincipalId
    $delegatedGrants     = Get-DelegatedPermissions -AccessToken $AccessToken -ServicePrincipalId $ServicePrincipalId

    return [PSCustomObject]@{
        ApplicationPermissions = $appRoleAssignments
        DelegatedPermissions   = $delegatedGrants
    }
}

function Get-AppRoleAssignments {
    <#
    .SYNOPSIS
        Gets application permissions (app roles) assigned to a service principal.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$ServicePrincipalId
    )

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignments"

    try {
        $assignments = Invoke-GraphRequest -AccessToken $AccessToken -Uri $uri -All
    }
    catch {
        Write-Warning "Could not retrieve app role assignments for SP $ServicePrincipalId`: $_"
        return @()
    }

    $results = foreach ($assignment in $assignments) {
        # Resolve the resource SP to get the role display name
        $resourceSp = Get-ServicePrincipalById -AccessToken $AccessToken -ServicePrincipalId $assignment.resourceId

        $roleName = 'Unknown'
        $roleDescription = ''
        if ($resourceSp -and $resourceSp.appRoles) {
            $role = $resourceSp.appRoles | Where-Object { $_.id -eq $assignment.appRoleId } | Select-Object -First 1
            if ($role) {
                $roleName        = $role.value          # e.g. "Mail.Read"
                $roleDescription = $role.description
            }
        }

        # Check if this role is in the sensitive permissions list
        $sensitiveMatch = Test-SensitivePermission -PermissionName $roleName -PermissionType 'Application'

        [PSCustomObject]@{
            PermissionType    = 'Application'
            ResourceId        = $assignment.resourceId
            ResourceName      = $assignment.resourceDisplayName
            PermissionName    = $roleName
            Description       = $roleDescription
            GrantedOn         = $assignment.createdDateTime
            IsSensitive       = $sensitiveMatch.IsSensitive
            RiskLevel         = $sensitiveMatch.RiskLevel
            DefenderRiskLevel = $sensitiveMatch.DefenderRiskLevel
            RiskDescription   = $sensitiveMatch.RiskDescription
            RiskCategory      = $sensitiveMatch.Category
        }
    }

    return @($results)
}

function Get-DelegatedPermissions {
    <#
    .SYNOPSIS
        Gets delegated permissions (OAuth2 grants) for a service principal.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$ServicePrincipalId
    )

    $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$ServicePrincipalId'"

    try {
        $grants = Invoke-GraphRequest -AccessToken $AccessToken -Uri $uri -All
    }
    catch {
        Write-Warning "Could not retrieve delegated permission grants for SP $ServicePrincipalId`: $_"
        return @()
    }

    $results = foreach ($grant in $grants) {
        $resourceSp = Get-ServicePrincipalById -AccessToken $AccessToken -ServicePrincipalId $grant.resourceId

        # Scopes is a space-delimited string of individual scope values
        $scopes = $grant.scope -split ' ' | Where-Object { $_ -ne '' }

        foreach ($scope in $scopes) {
            $scopeDescription = ''
            if ($resourceSp -and $resourceSp.publishedPermissionScopes) {
                $scopeObj = $resourceSp.publishedPermissionScopes |
                    Where-Object { $_.value -eq $scope } | Select-Object -First 1
                if ($scopeObj) { $scopeDescription = $scopeObj.adminConsentDescription }
            }

            $sensitiveMatch = Test-SensitivePermission -PermissionName $scope -PermissionType 'Delegated'

            [PSCustomObject]@{
                PermissionType    = 'Delegated'
                ConsentType       = $grant.consentType  # 'AllPrincipals' or 'Principal'
                PrincipalId       = $grant.principalId  # user ID if per-user consent
                ResourceId        = $grant.resourceId
                ResourceName      = $resourceSp.displayName ?? $grant.resourceId
                PermissionName    = $scope
                Description       = $scopeDescription
                GrantedOn         = $null
                IsSensitive       = $sensitiveMatch.IsSensitive
                RiskLevel         = $sensitiveMatch.RiskLevel
                DefenderRiskLevel = $sensitiveMatch.DefenderRiskLevel
                RiskDescription   = $sensitiveMatch.RiskDescription
                RiskCategory      = $sensitiveMatch.Category
            }
        }
    }

    return @($results)
}

function Test-SensitivePermission {
    <#
    .SYNOPSIS
        Checks whether a permission name is in the sensitive permissions list.

    .OUTPUTS
        PSCustomObject with IsSensitive, RiskLevel, RiskDescription, Category.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PermissionName,

        [string]$PermissionType  # 'Application' or 'Delegated'
    )

    $sensitiveList = Get-SensitivePermissions

    $match = $sensitiveList | Where-Object { $_.name -eq $PermissionName } | Select-Object -First 1

    if ($match) {
        return [PSCustomObject]@{
            IsSensitive        = $true
            RiskLevel          = $match.riskLevel
            RiskDescription    = $match.description
            Category           = $match.category
            DefenderRiskLevel  = $match.defenderRiskLevel ?? 'Unknown'
        }
    }

    return [PSCustomObject]@{
        IsSensitive        = $false
        RiskLevel          = 'None'
        RiskDescription    = ''
        Category           = ''
        DefenderRiskLevel  = 'Unknown'
    }
}

function Get-OverallRiskLevel {
    <#
    .SYNOPSIS
        Derives the highest risk level from a collection of permissions.

    .PARAMETER Permissions
        Array of permission objects as returned by Get-AppRoleAssignments / Get-DelegatedPermissions.

    .EXAMPLE
        $risk = Get-OverallRiskLevel -Permissions $perms.ApplicationPermissions
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Permissions
    )

    $rankMap = @{
        'Critical' = 4
        'High'     = 3
        'Medium'   = 2
        'Low'      = 1
        'None'     = 0
    }

    $maxRank = 0
    foreach ($p in $Permissions) {
        $rank = $rankMap[$p.RiskLevel]
        if ($rank -gt $maxRank) { $maxRank = $rank }
    }

    return ($rankMap.GetEnumerator() | Where-Object { $_.Value -eq $maxRank } | Select-Object -First 1).Key
}

function Get-PermissionSummary {
    <#
    .SYNOPSIS
        Produces a flat summary object for a service principal's permissions.

    .PARAMETER PermissionData
        Output of Get-ApplicationPermissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$PermissionData
    )

    $allPerms = @($PermissionData.ApplicationPermissions) + @($PermissionData.DelegatedPermissions)
    $sensitivePerms = $allPerms | Where-Object { $_.IsSensitive }

    $overallRisk = Get-OverallRiskLevel -Permissions ($allPerms.Count -gt 0 ? $allPerms : @([PSCustomObject]@{ RiskLevel = 'None' }))

    # Defender-level summary (High/Medium/Low — the three MDCA levels)
    $defenderHigh   = @($sensitivePerms | Where-Object { $_.DefenderRiskLevel -eq 'High'   } | Select-Object -ExpandProperty PermissionName)
    $defenderMedium = @($sensitivePerms | Where-Object { $_.DefenderRiskLevel -eq 'Medium' } | Select-Object -ExpandProperty PermissionName)
    $defenderLow    = @($sensitivePerms | Where-Object { $_.DefenderRiskLevel -eq 'Low'    } | Select-Object -ExpandProperty PermissionName)

    # Highest Defender risk level present
    $overallDefenderRisk = if ($defenderHigh.Count   -gt 0) { 'High'   }
                           elseif ($defenderMedium.Count -gt 0) { 'Medium' }
                           elseif ($defenderLow.Count    -gt 0) { 'Low'    }
                           else                                  { 'None'   }

    return [PSCustomObject]@{
        TotalPermissions              = $allPerms.Count
        SensitivePermissionCount      = $sensitivePerms.Count
        OverallRiskLevel              = $overallRisk
        OverallDefenderRiskLevel      = $overallDefenderRisk
        CriticalPermissions           = @($sensitivePerms | Where-Object { $_.RiskLevel -eq 'Critical' } | Select-Object -ExpandProperty PermissionName)
        HighPermissions               = @($sensitivePerms | Where-Object { $_.RiskLevel -eq 'High'     } | Select-Object -ExpandProperty PermissionName)
        MediumPermissions             = @($sensitivePerms | Where-Object { $_.RiskLevel -eq 'Medium'   } | Select-Object -ExpandProperty PermissionName)
        DefenderHighPermissions       = $defenderHigh
        DefenderMediumPermissions     = $defenderMedium
        DefenderLowPermissions        = $defenderLow
        AllSensitivePermissions       = @($sensitivePerms | Select-Object PermissionName, RiskLevel, DefenderRiskLevel, PermissionType)
    }
}

Export-ModuleMember -Function Get-ApplicationPermissions, Get-AppRoleAssignments, Get-DelegatedPermissions,
    Test-SensitivePermission, Get-OverallRiskLevel, Get-PermissionSummary, Get-SensitivePermissions
