function Get-ADCSCertificateTemplates {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $ConfigNC,

        [switch] $IncludeSecurityDescriptor
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function Resolve-ConfigNC {
        param([string]$InputConfigNC)

        # If provided and non-empty, trust it as string DN
        if ($InputConfigNC -and $InputConfigNC.Trim().Length -gt 0) {
            return $InputConfigNC.Trim()
        }

        # Prefer AD module when available
        try {
            if (Get-Module -ListAvailable -Name ActiveDirectory) {
                Import-Module ActiveDirectory -ErrorAction Stop
                $nc = (Get-ADRootDSE).configurationNamingContext
                return ([string]$nc).Trim()
            }
        } catch { }

        # Fallback to ADSI RootDSE
        $root = [ADSI]"LDAP://RootDSE"

        # In Windows PowerShell 5.1 this might be a PropertyValueCollection-ish object.
        $raw = $root.Properties["configurationNamingContext"]

        if ($raw -and $raw.Count -gt 0) {
            return ([string]$raw[0]).Trim()
        }

        # Some environments expose it directly
        try {
            $direct = $root.configurationNamingContext
            if ($direct) { return ([string]$direct).Trim() }
        } catch { }

        throw "Unable to resolve configurationNamingContext from RootDSE."
    }

    $ConfigNC = Resolve-ConfigNC -InputConfigNC $ConfigNC

    if (-not $ConfigNC -or $ConfigNC.Trim().Length -eq 0) {
        throw "ConfigNC resolved to an empty value; cannot query AD CS template container."
    }

    $templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

    # Create SearchRoot with explicit auth; this is more reliable than default bindings.
    $searchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$templatesDn")
    $searchRoot.AuthenticationType = [System.DirectoryServices.AuthenticationTypes]::Secure

    $ds = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
    $ds.PageSize = 500
    $ds.Filter = "(objectClass=pKICertificateTemplate)"
    $ds.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None

    # Properties
    @(
        "cn",
        "displayName",
        "distinguishedName",
        "msPKI-Template-Schema-Version",
        "msPKI-Minimal-Key-Size",
        "msPKI-Enrollment-Flag",
        "msPKI-Private-Key-Flag",
        "msPKI-Certificate-Name-Flag",
        "pKIExtendedKeyUsage",
        "pKIKeyUsage"
    ) | ForEach-Object { [void]$ds.PropertiesToLoad.Add($_) }

    try {
        $results = $ds.FindAll()
    }
    catch {
        # Provide actionable diagnostics
        $msg = $_.Exception.Message
        throw "Directory search failed against '$templatesDn'. Error: $msg"
    }

    $out = New-Object System.Collections.Generic.List[object]

    foreach ($r in $results) {
        $p = $r.Properties

        $name = $null
        if ($p["cn"] -and $p["cn"].Count -gt 0) { $name = [string]$p["cn"][0] }

        $dn = $null
        if ($p["distinguishedname"] -and $p["distinguishedname"].Count -gt 0) { $dn = [string]$p["distinguishedname"][0] }

        $displayName = $null
        if ($p["displayname"] -and $p["displayname"].Count -gt 0) { $displayName = [string]$p["displayname"][0] }

        $schemaVersion = $null
        if ($p["mspki-template-schema-version"] -and $p["mspki-template-schema-version"].Count -gt 0) {
            $schemaVersion = [int]$p["mspki-template-schema-version"][0]
        }

        $minimalKeySize = $null
        if ($p["mspki-minimal-key-size"] -and $p["mspki-minimal-key-size"].Count -gt 0) {
            $minimalKeySize = [int]$p["mspki-minimal-key-size"][0]
        }

        $enrollmentFlags = $null
        if ($p["mspki-enrollment-flag"] -and $p["mspki-enrollment-flag"].Count -gt 0) {
            $enrollmentFlags = [int]$p["mspki-enrollment-flag"][0]
        }

        $privateKeyFlags = $null
        if ($p["mspki-private-key-flag"] -and $p["mspki-private-key-flag"].Count -gt 0) {
            $privateKeyFlags = [int]$p["mspki-private-key-flag"][0]
        }

        $nameFlags = $null
        if ($p["mspki-certificate-name-flag"] -and $p["mspki-certificate-name-flag"].Count -gt 0) {
            $nameFlags = [int]$p["mspki-certificate-name-flag"][0]
        }

        $ekus = @()
        if ($p["pkiextendedkeyusage"] -and $p["pkiextendedkeyusage"].Count -gt 0) {
            $ekus = @($p["pkiextendedkeyusage"] | ForEach-Object { [string]$_ })
        }

        $keyUsage = $null
        if ($p["pkikeyusage"] -and $p["pkikeyusage"].Count -gt 0) {
            $keyUsage = $p["pkikeyusage"][0]
        }

        # Minimal decoded signals
        $enrollmentFlagNames = New-Object System.Collections.Generic.List[string]
        if ($null -ne $enrollmentFlags) {
            if (($enrollmentFlags -band 0x00000010) -ne 0) { $enrollmentFlagNames.Add("AutoEnrollment") }
        }

        $privateKeyFlagNames = New-Object System.Collections.Generic.List[string]
        if ($null -ne $privateKeyFlags) {
            if (($privateKeyFlags -band 0x00000001) -ne 0) { $privateKeyFlagNames.Add("RequireKeyArchival") }
            if (($privateKeyFlags -band 0x00000010) -ne 0) { $privateKeyFlagNames.Add("AllowKeyExport") }
        }

        $nameFlagNames = New-Object System.Collections.Generic.List[string]
        if ($null -ne $nameFlags) {
            if (($nameFlags -band 0x00000001) -ne 0) { $nameFlagNames.Add("EnrolleeSuppliesSubject") }
        }

        $sddl = $null
        $sddlError = $null

        if ($IncludeSecurityDescriptor -and $dn) {
            try {
                $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
                $de.AuthenticationType = [System.DirectoryServices.AuthenticationTypes]::Secure

                $sddl = $de.ObjectSecurity.GetSecurityDescriptorSddlForm(
                    [System.Security.AccessControl.AccessControlSections]::All
                )
            }
            catch {
                $sddlError = $_.Exception.Message
                $sddl = $null
            }
        }

        $out.Add([pscustomobject]@{
            name                          = $name
            displayName                   = $displayName
            distinguishedName             = $dn
            schemaVersion                 = $schemaVersion
            minimalKeySize                = $minimalKeySize
            enrollmentFlagsRaw            = $enrollmentFlags
            privateKeyFlagsRaw            = $privateKeyFlags
            nameFlagsRaw                  = $nameFlags
            enrollmentFlags               = @($enrollmentFlagNames)
            privateKeyFlags               = @($privateKeyFlagNames)
            nameFlags                     = @($nameFlagNames)
            extendedKeyUsageOids          = @($ekus)
            keyUsageRaw                   = $keyUsage
            securityDescriptorSddl        = $sddl
            securityDescriptorReadError   = $sddlError
        })
    }

    return $out
}
