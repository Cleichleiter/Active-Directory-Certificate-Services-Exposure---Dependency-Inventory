function Get-ADCSCertificateTemplates {
    [CmdletBinding()]
    param(
        [string] $ConfigNC,

        [switch] $IncludeSecurityDescriptor
    )

    $results = @()

    function Convert-FlagValue {
        param([Nullable[int]]$Value, [hashtable]$Map)
        if ($null -eq $Value) { return @() }
        $set = @()
        foreach ($k in $Map.Keys) {
            if (($Value -band $k) -eq $k) { $set += $Map[$k] }
        }
        return $set
    }

    # Minimal, defensible maps (not exhaustive; avoids misleading labels)
    $enrollFlagMap = @{
        0x00000001 = 'IncludeSymmetricAlgorithms'
        0x00000002 = 'PublishToDS'
        0x00000004 = 'AutoEnrollment'
        0x00000010 = 'DoNotStoreCert'
        0x00000020 = 'AllowKeyExport'
        0x00000040 = 'ReuseKeys'
        0x00000100 = 'RequireUserInteraction'
        0x00000400 = 'RemoveInvalidCertFromStore'
    }

    $nameFlagMap = @{
        0x00000001 = 'EnrolleeSuppliesSubject'
        0x00000002 = 'AddEmail'
        0x00000004 = 'AddUPN'
        0x00000008 = 'AddDNS'
        0x00010000 = 'SubjectRequireCommonName'
        0x00400000 = 'SubjectAltRequireUPN'
        0x00800000 = 'SubjectAltRequireEmail'
        0x02000000 = 'SubjectAltRequireDNS'
        0x04000000 = 'SubjectAltRequireSPN'
    }

    try {
        $useADModule = [bool](Get-Module -ListAvailable -Name ActiveDirectory)

        if (-not $ConfigNC) {
            if ($useADModule) {
                Import-Module ActiveDirectory -ErrorAction Stop
                $root = Get-ADRootDSE
                $ConfigNC = $root.configurationNamingContext
            } else {
                $root = [ADSI]"LDAP://RootDSE"
                $ConfigNC = $root.configurationNamingContext.Value
            }
        }

        $templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

        if ($useADModule) {
            Import-Module ActiveDirectory -ErrorAction Stop

            $props = @(
                'cn','displayName','distinguishedName','msPKI-Template-Schema-Version',
                'msPKI-Template-Minor-Revision','msPKI-Certificate-Name-Flag',
                'msPKI-Enrollment-Flag','msPKI-Private-Key-Flag','msPKI-Minimal-Key-Size',
                'pKIExtendedKeyUsage','pKIKeyUsage','pKIDefaultKeySpec','whenCreated','whenChanged',
                'nTSecurityDescriptor'
            )

            $templates = Get-ADObject -LDAPFilter "(objectClass=pKICertificateTemplate)" -SearchBase $templatesDn -Properties $props

            foreach ($t in $templates) {
                $eku = @($t.pKIExtendedKeyUsage) | Where-Object { $_ } | ForEach-Object { $_.ToString() }
                $minKey = $t.'msPKI-Minimal-Key-Size'

                $enrollFlags = Convert-FlagValue -Value ([int]$t.'msPKI-Enrollment-Flag') -Map $enrollFlagMap
                $nameFlags   = Convert-FlagValue -Value ([int]$t.'msPKI-Certificate-Name-Flag') -Map $nameFlagMap

                $obj = [ordered]@{
                    type              = 'Template'
                    name              = $t.cn
                    displayName       = $t.displayName
                    distinguishedName = $t.DistinguishedName
                    schemaVersion     = $t.'msPKI-Template-Schema-Version'
                    minorRevision     = $t.'msPKI-Template-Minor-Revision'
                    minimalKeySize    = $minKey
                    defaultKeySpec    = $t.pKIDefaultKeySpec
                    ekuOids           = $eku
                    enrollmentFlags   = $enrollFlags
                    nameFlags         = $nameFlags
                    whenCreated       = $t.whenCreated
                    whenChanged       = $t.whenChanged
                }

                if ($IncludeSecurityDescriptor) {
                    try { $obj.securityDescriptorSddl = $t.nTSecurityDescriptor.Sddl } catch { $obj.securityDescriptorSddl = $null }
                }

                $results += [pscustomobject]$obj
            }
        }
        else {
            # ADSI fallback
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$templatesDn")
            $searcher.Filter = "(objectClass=pKICertificateTemplate)"
            $searcher.PageSize = 1000

            $props = @(
                'cn','displayName','distinguishedName','msPKI-Template-Schema-Version','msPKI-Template-Minor-Revision',
                'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-Minimal-Key-Size',
                'pKIExtendedKeyUsage','pKIDefaultKeySpec','whenCreated','whenChanged'
            )
            $searcher.PropertiesToLoad.AddRange($props) | Out-Null
            if ($IncludeSecurityDescriptor) { $searcher.PropertiesToLoad.Add('nTSecurityDescriptor') | Out-Null }

            $found = $searcher.FindAll()
            foreach ($r in $found) {
                $p = $r.Properties

                $enrollFlags = Convert-FlagValue -Value ([int]($p.'mspki-enrollment-flag' | Select-Object -First 1)) -Map $enrollFlagMap
                $nameFlags   = Convert-FlagValue -Value ([int]($p.'mspki-certificate-name-flag' | Select-Object -First 1)) -Map $nameFlagMap

                $obj = [ordered]@{
                    type              = 'Template'
                    name              = ($p.cn | Select-Object -First 1)
                    displayName       = ($p.displayname | Select-Object -First 1)
                    distinguishedName = ($p.distinguishedname | Select-Object -First 1)
                    schemaVersion     = ($p.'mspki-template-schema-version' | Select-Object -First 1)
                    minorRevision     = ($p.'mspki-template-minor-revision' | Select-Object -First 1)
                    minimalKeySize    = ($p.'mspki-minimal-key-size' | Select-Object -First 1)
                    defaultKeySpec    = ($p.'pkidefaultkeyspec' | Select-Object -First 1)
                    ekuOids           = @($p.'pkiextendedkeyusage')
                    enrollmentFlags   = $enrollFlags
                    nameFlags         = $nameFlags
                    whenCreated       = ($p.whencreated | Select-Object -First 1)
                    whenChanged       = ($p.whenchanged | Select-Object -First 1)
                }

                $results += [pscustomobject]$obj
            }
        }
    }
    catch {
        Write-Verbose "Get-ADCSCertificateTemplates failed: $($_.Exception.Message)"
    }

    return $results
}
