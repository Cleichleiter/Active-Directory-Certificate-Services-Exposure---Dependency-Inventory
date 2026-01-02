[CmdletBinding()]
param(
    [Parameter()]
    [string] $OutputPath = ".\reports",

    [switch] $IncludeCAs,
    [switch] $IncludeTemplates,
    [switch] $IncludeSecurityDescriptors,

    [switch] $IncludeLocalCerts,
    [switch] $IncludeCurrentUserCerts,

    [switch] $NoCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Repo root = two levels up from scripts\pwsh
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# Resolve OutputPath relative to repo root (NOT current process directory)
function Resolve-RepoPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Base
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    # Normalize common relative prefixes like .\ or ./
    $normalized = ($Path -replace '^[.][\\/]', '')
    return (Join-Path $Base $normalized)
}

$ResolvedOutputPath = Resolve-RepoPath -Path $OutputPath -Base $RepoRoot

# Dot-source shared helpers
. (Join-Path $PSScriptRoot "_shared\Write-InventoryLog.ps1")
. (Join-Path $PSScriptRoot "_shared\Assert-RunAsAdmin.ps1")
. (Join-Path $PSScriptRoot "_shared\Export-Inventory.ps1")

# Dot-source collectors
. (Join-Path $PSScriptRoot "Get-CAConfiguration.ps1")
. (Join-Path $PSScriptRoot "Get-CertificateTemplates.ps1")
. (Join-Path $PSScriptRoot "Get-CertificateUsage.ps1")

Write-InventoryLog -Message "Starting AD CS inventory (read-only)." -Level "INFO"
Assert-RunAsAdmin | Out-Null

# Ensure output dir exists
if (-not (Test-Path $ResolvedOutputPath)) {
    New-Item -Path $ResolvedOutputPath -ItemType Directory -Force | Out-Null
}

# Defaults: include both CA + Templates unless explicitly toggled
if (-not $PSBoundParameters.ContainsKey('IncludeCAs') -and -not $PSBoundParameters.ContainsKey('IncludeTemplates')) {
    $IncludeCAs = $true
    $IncludeTemplates = $true
}

# Resolve Configuration NC
$configNC = $null
try {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $configNC = (Get-ADRootDSE).configurationNamingContext
    }
    else {
        $root = [ADSI]"LDAP://RootDSE"
        # In Windows PowerShell 5.1 ADSI properties return the value directly (no .Value)
        $configNC = $root.configurationNamingContext
    }
}
catch {
    Write-InventoryLog -Message ("Could not resolve configuration naming context: " + $_.Exception.Message) -Level "WARN"
}

$meta = [ordered]@{
    timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    machine      = $env:COMPUTERNAME
    user         = $env:USERNAME
    domain       = $env:USERDNSDOMAIN
    readOnly     = $true
    project      = 'Active Directory Certificate Services Exposure & Dependency Inventory'
    repoRoot     = $RepoRoot
    outputPath   = $ResolvedOutputPath
}

$artifacts = [ordered]@{
    cas            = @()
    templates      = @()
    localCertUsage = $null
}

$findings = @()

if ($IncludeCAs) {
    Write-InventoryLog -Message "Collecting Enterprise CA objects from AD..." -Level "INFO"
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

if ($IncludeTemplates) {
    Write-InventoryLog -Message "Collecting Certificate Template objects from AD..." -Level "INFO"
    $templates = Get-ADCSCertificateTemplates -ConfigNC $configNC -IncludeSecurityDescriptor:$IncludeSecurityDescriptors
    $artifacts.templates = @($templates)

    foreach ($t in $templates) {
        $signals = @()

        if ($t.enrollmentFlags -contains 'AutoEnrollment') { $signals += 'AutoEnrollment' }
        if ($t.enrollmentFlags -contains 'AllowKeyExport')  { $signals += 'AllowKeyExport' }
        if ($t.nameFlags -contains 'EnrolleeSuppliesSubject'){ $signals += 'EnrolleeSuppliesSubject' }

        if ($t.minimalKeySize) {
            try {
                $mk = [int]$t.minimalKeySize
                if ($mk -lt 2048) { $signals += "MinimalKeySize<$mk" }
            } catch { }
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

if ($IncludeLocalCerts) {
    Write-InventoryLog -Message "Collecting local certificate usage (read-only)..." -Level "INFO"
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

$inventory = [ordered]@{
    meta      = $meta
    artifacts = $artifacts
    findings  = $findings
}

Export-Inventory -Inventory $inventory -OutputPath $ResolvedOutputPath -BaseName "adcs_inventory" -NoCsv:$NoCsv

Write-InventoryLog -Message "Completed AD CS inventory." -Level "INFO"
