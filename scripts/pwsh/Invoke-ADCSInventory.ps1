[CmdletBinding()]
param(
    [Parameter()]
    [string] $OutputPath = ".\reports",

    [switch] $IncludeCAs,
    [switch] $IncludeTemplates,
    [switch] $IncludeSecurityDescriptors,

    [switch] $IncludeTemplatePermissions,

    [switch] $IncludeLocalCerts,
    [switch] $IncludeCurrentUserCerts,

    [switch] $NoCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Repo root = two levels up from scripts\pwsh
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Resolve-RepoPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path,
        [Parameter(Mandatory)]
        [string] $Base
    )

    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }

    $normalized = ($Path -replace '^[.][\\/]', '')
    return (Join-Path $Base $normalized)
}

function Test-DomainJoined {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        return [bool]$cs.PartOfDomain
    }
    catch {
        # Fallback heuristic
        if ($env:USERDOMAIN -and $env:COMPUTERNAME) {
            return ($env:USERDOMAIN -ne $env:COMPUTERNAME)
        }
        return $false
    }
}

function Resolve-ConfigNC {
    # Prefer AD module when available
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction Stop
            $nc = (Get-ADRootDSE).configurationNamingContext
            return ([string]$nc).Trim()
        }
    }
    catch {
        # fall through to ADSI
    }

    $root = [ADSI]"LDAP://RootDSE"

    # ADSI can return property collections; normalize to string
    $raw = $root.Properties["configurationNamingContext"]
    if ($raw -and $raw.Count -gt 0) { return ([string]$raw[0]).Trim() }

    try {
        $direct = $root.configurationNamingContext
        if ($direct) { return ([string]$direct).Trim() }
    }
    catch { }

    throw "Unable to resolve configurationNamingContext from RootDSE."
}

function Test-DirectoryInventoryAvailable {
    param(
        [Parameter(Mandatory)]
        [string] $ConfigNC
    )

    $templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$templatesDn")
    $de.AuthenticationType = [System.DirectoryServices.AuthenticationTypes]::Secure

    # Force bind
    $null = $de.NativeObject
    return $true
}

# Dot-source shared helpers
. (Join-Path $PSScriptRoot "_shared\Write-InventoryLog.ps1")
. (Join-Path $PSScriptRoot "_shared\Assert-RunAsAdmin.ps1")
. (Join-Path $PSScriptRoot "_shared\Export-Inventory.ps1")

# Dot-source collectors
. (Join-Path $PSScriptRoot "Get-CAConfiguration.ps1")
. (Join-Path $PSScriptRoot "Get-CertificateTemplates.ps1")
. (Join-Path $PSScriptRoot "Get-CertificateUsage.ps1")
. (Join-Path $PSScriptRoot "Get-TemplatePermissions.ps1")

Write-InventoryLog -Message "Starting AD CS inventory (read-only)." -Level "INFO"
Assert-RunAsAdmin | Out-Null

# Resolve output path relative to repo root (prevents System32 writes)
$ResolvedOutputPath = Resolve-RepoPath -Path $OutputPath -Base $RepoRoot

if (-not (Test-Path $ResolvedOutputPath)) {
    New-Item -Path $ResolvedOutputPath -ItemType Directory -Force | Out-Null
}

# Defaults: include CA + Templates unless explicitly toggled
if (-not $PSBoundParameters.ContainsKey('IncludeCAs') -and -not $PSBoundParameters.ContainsKey('IncludeTemplates')) {
    $IncludeCAs = $true
    $IncludeTemplates = $true
}

# If user asked for template permissions but forgot SDDL, auto-enable SDDL collection
if ($IncludeTemplatePermissions -and -not $IncludeSecurityDescriptors) {
    Write-InventoryLog -Message "IncludeTemplatePermissions requires security descriptors; enabling IncludeSecurityDescriptors automatically." -Level "INFO"
    $IncludeSecurityDescriptors = $true
}

$IsDomainJoined = Test-DomainJoined
$configNC = $null
$DirectoryInventoryAvailable = $false

# Execution summary fields
$ExecutionMode = 'LocalOnly'
$SkippedModules = New-Object System.Collections.Generic.List[string]
$SkipReason = 'None'

if (-not $IsDomainJoined) {
    $SkipReason = 'NotDomainJoined'
    Write-InventoryLog -Message "Host is not domain-joined. AD-backed CA/template inventory will be skipped; local certificate inventory can still run." -Level "INFO"
}
else {
    try {
        $configNC = Resolve-ConfigNC
        if (-not $configNC -or $configNC.Trim().Length -eq 0) {
            throw "configurationNamingContext resolved to empty."
        }

        $DirectoryInventoryAvailable = Test-DirectoryInventoryAvailable -ConfigNC $configNC

        if ($DirectoryInventoryAvailable) {
            $ExecutionMode = 'DirectoryBacked'
            $SkipReason = 'None'
        }
    }
    catch {
        $SkipReason = 'DirectoryBindUnavailable'
        Write-InventoryLog -Message ("AD-backed inventory unavailable from this host/context. Skipping CA/template inventory. Reason: " + $_.Exception.Message) -Level "INFO"
        $DirectoryInventoryAvailable = $false
        $configNC = $null
        $ExecutionMode = 'LocalOnly'
    }
}

# Precompute skip list based on availability and requested switches
if (-not $DirectoryInventoryAvailable) {
    if ($IncludeCAs) { $SkippedModules.Add('CAs') | Out-Null }
    if ($IncludeTemplates) { $SkippedModules.Add('Templates') | Out-Null }
    if ($IncludeTemplatePermissions) { $SkippedModules.Add('TemplatePermissions') | Out-Null }
}

$meta = [ordered]@{
    timestampUtc                = (Get-Date).ToUniversalTime().ToString('o')
    machine                     = $env:COMPUTERNAME
    user                        = $env:USERNAME
    domain                      = $env:USERDNSDOMAIN
    readOnly                    = $true
    project                     = 'Active Directory Certificate Services Exposure & Dependency Inventory'
    repoRoot                    = $RepoRoot
    outputPath                  = $ResolvedOutputPath
    domainJoined                = $IsDomainJoined
    directoryInventoryAvailable = $DirectoryInventoryAvailable

    # Execution summary (new)
    executionMode               = $ExecutionMode
    skippedModules              = @($SkippedModules)
    skipReason                  = $SkipReason
}

$artifacts = [ordered]@{
    cas                = @()
    templates           = @()
    templatePermissions = @()
    localCertUsage      = $null
}

$findings = @()

# CA inventory (AD-backed)
if ($IncludeCAs) {
    if (-not $DirectoryInventoryAvailable) {
        Write-InventoryLog -Message "Skipping Enterprise CA inventory (AD-backed) because directory inventory is not available in this execution context." -Level "INFO"
    }
    else {
        Write-InventoryLog -Message "Collecting Enterprise CA objects from AD..." -Level "INFO"
        try {
            $cas = Get-ADCSCAConfiguration -ConfigNC $configNC -IncludeSecurityDescriptor:$IncludeSecurityDescriptors
            $artifacts.cas = @($cas)

            foreach ($ca in $cas) {
                $publishedCount = 0
                if ($null -ne $ca.publishedTemplates) { $publishedCount = @($ca.publishedTemplates).Count }

                $findings += [pscustomobject]@{
                    FindingType = 'CA'
                    Name        = $ca.name
                    DnsHostName  = $ca.dnsHostName
                    Notes       = "Enterprise CA published templates: $publishedCount"
                    Signals     = (@($ca.publishedTemplates) -join '; ')
                }
            }
        }
        catch {
            Write-InventoryLog -Message ("CA inventory failed (non-fatal). Continuing. Reason: " + $_.Exception.Message) -Level "INFO"
        }
    }
}

# Template inventory (AD-backed)
$templates = @()
if ($IncludeTemplates) {
    if (-not $DirectoryInventoryAvailable) {
        Write-InventoryLog -Message "Skipping Certificate Template inventory (AD-backed) because directory inventory is not available in this execution context." -Level "INFO"
    }
    else {
        Write-InventoryLog -Message "Collecting Certificate Template objects from AD..." -Level "INFO"
        try {
            $templates = Get-ADCSCertificateTemplates -ConfigNC $configNC -IncludeSecurityDescriptors:$IncludeSecurityDescriptors
            $artifacts.templates = @($templates)

            foreach ($t in $templates) {
                $signals = @()

                if ($t.enrollmentFlags -contains 'AutoEnrollment') { $signals += 'AutoEnrollment' }
                if ($t.privateKeyFlags -contains 'AllowKeyExport') { $signals += 'AllowKeyExport' }
                if ($t.nameFlags -contains 'EnrolleeSuppliesSubject') { $signals += 'EnrolleeSuppliesSubject' }

                if ($t.minimalKeySize) {
                    try {
                        $mk = [int]$t.minimalKeySize
                        if ($mk -lt 2048) { $signals += "MinimalKeySize<$mk" }
                    }
                    catch { }
                }

                $findings += [pscustomobject]@{
                    FindingType = 'Template'
                    Name        = $t.name
                    DisplayName = $t.displayName
                    Notes       = "SchemaVersion=$($t.schemaVersion); MinKey=$($t.minimalKeySize)"
                    Signals     = ($signals -join '; ')
                }
            }
        }
        catch {
            Write-InventoryLog -Message ("Template inventory failed (non-fatal). Continuing. Reason: " + $_.Exception.Message) -Level "INFO"
            $templates = @()
            $artifacts.templates = @()
        }
    }
}

# Template permissions (AD-backed)
if ($IncludeTemplatePermissions) {
    if (-not $DirectoryInventoryAvailable) {
        Write-InventoryLog -Message "Skipping template permission analysis because directory inventory is not available in this execution context." -Level "INFO"
    }
    elseif (-not $templates -or $templates.Count -eq 0) {
        Write-InventoryLog -Message "Template permission analysis skipped because no templates were collected." -Level "INFO"
    }
    else {
        Write-InventoryLog -Message "Summarizing template permissions (Enroll/AutoEnroll/high-impact rights)..." -Level "INFO"
        try {
            $permRows = Get-ADCSCertificateTemplatePermissions -Templates $templates
            $artifacts.templatePermissions = @($permRows)

            foreach ($r in $permRows) {
                $sig = @()
                if ($r.Enroll)        { $sig += 'Enroll' }
                if ($r.AutoEnroll)    { $sig += 'AutoEnroll' }
                if ($r.GenericAll)    { $sig += 'GenericAll' }
                if ($r.GenericWrite)  { $sig += 'GenericWrite' }
                if ($r.WriteDacl)     { $sig += 'WriteDacl' }
                if ($r.WriteOwner)    { $sig += 'WriteOwner' }
                if ($r.BroadIdentity) { $sig += 'BroadIdentity' }

                $findings += [pscustomobject]@{
                    FindingType = 'TemplatePermission'
                    Name        = $r.TemplateName
                    DisplayName = $r.DisplayName
                    Notes       = "Identity=$($r.Identity)"
                    Signals     = ($sig -join '; ')
                }
            }
        }
        catch {
            Write-InventoryLog -Message ("Template permission analysis failed (non-fatal). Continuing. Reason: " + $_.Exception.Message) -Level "INFO"
            $artifacts.templatePermissions = @()
        }
    }
}

# Local cert usage (works everywhere)
if ($IncludeLocalCerts) {
    Write-InventoryLog -Message "Collecting local certificate usage (read-only)..." -Level "INFO"
    try {
        $usage = Get-LocalCertificateTemplateUsage -IncludeMachine:$true -IncludeCurrentUser:$IncludeCurrentUserCerts
        $artifacts.localCertUsage = $usage

        foreach ($s in $usage.summary) {
            $name = '(unknown)'
            if ($s.templateHint -and ($s.templateHint.ToString().Trim().Length -gt 0)) {
                $name = $s.templateHint
            }

            $findings += [pscustomobject]@{
                FindingType = 'LocalCertTemplateUsage'
                Name        = $name
                Notes       = "Observed locally across inspected stores"
                Signals     = "Count=$($s.count)"
            }
        }
    }
    catch {
        Write-InventoryLog -Message ("Local cert usage collection failed (non-fatal). Reason: " + $_.Exception.Message) -Level "INFO"
    }
}

$inventory = [ordered]@{
    meta      = $meta
    artifacts = $artifacts
    findings  = $findings
}

Export-Inventory -Inventory $inventory -OutputPath $ResolvedOutputPath -BaseName "adcs_inventory" -NoCsv:$NoCsv

# Export permissions as a dedicated artifact if we produced rows
if ($IncludeTemplatePermissions -and $artifacts.templatePermissions -and $artifacts.templatePermissions.Count -gt 0) {
    $permOut = [ordered]@{
        meta = $meta
        templatePermissions = $artifacts.templatePermissions
    }
    Export-Inventory -Inventory $permOut -OutputPath $ResolvedOutputPath -BaseName "template_permissions" -NoCsv
}

Write-InventoryLog -Message "Completed AD CS inventory." -Level "INFO"
