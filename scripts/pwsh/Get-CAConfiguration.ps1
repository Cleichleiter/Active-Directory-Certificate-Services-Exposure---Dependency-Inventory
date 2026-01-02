function Get-ADCSCAConfiguration {
    [CmdletBinding()]
    param(
        [string] $ConfigNC,

        [switch] $IncludeSecurityDescriptor
    )

    $results = @()

    try {
        # Use AD module if present; otherwise ADSI.
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

        $enrollServicesDn = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"

        if ($useADModule) {
            Import-Module ActiveDirectory -ErrorAction Stop

            $props = @(
                'cn','distinguishedName','dNSHostName','cACertificate','certificateTemplates',
                'flags','msPKI-Enrollment-Servers','whenCreated','whenChanged','nTSecurityDescriptor'
            )

            $cas = Get-ADObject -LDAPFilter "(objectClass=pKIEnrollmentService)" -SearchBase $enrollServicesDn -Properties $props

            foreach ($ca in $cas) {
                $obj = [ordered]@{
                    type               = 'CA'
                    name               = $ca.cn
                    distinguishedName  = $ca.DistinguishedName
                    dnsHostName        = $ca.dNSHostName
                    whenCreated        = $ca.whenCreated
                    whenChanged        = $ca.whenChanged
                    publishedTemplates = @($ca.certificateTemplates)
                    flags              = $ca.flags
                    enrollmentServers  = @($ca.'msPKI-Enrollment-Servers')
                }

                if ($IncludeSecurityDescriptor) {
                    try { $obj.securityDescriptorSddl = $ca.nTSecurityDescriptor.Sddl } catch { $obj.securityDescriptorSddl = $null }
                }

                $results += [pscustomobject]$obj
            }
        }
        else {
            # ADSI fallback
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$enrollServicesDn")
            $searcher.Filter = "(objectClass=pKIEnrollmentService)"
            $searcher.PageSize = 1000

            $searcher.PropertiesToLoad.AddRange(@('cn','distinguishedName','dNSHostName','certificateTemplates','flags','whenCreated','whenChanged')) | Out-Null
            if ($IncludeSecurityDescriptor) { $searcher.PropertiesToLoad.Add('nTSecurityDescriptor') | Out-Null }

            $found = $searcher.FindAll()

            foreach ($r in $found) {
                $p = $r.Properties

                $obj = [ordered]@{
                    type               = 'CA'
                    name               = ($p.cn | Select-Object -First 1)
                    distinguishedName  = ($p.distinguishedname | Select-Object -First 1)
                    dnsHostName        = ($p.dnshostname | Select-Object -First 1)
                    whenCreated        = ($p.whencreated | Select-Object -First 1)
                    whenChanged        = ($p.whenchanged | Select-Object -First 1)
                    publishedTemplates = @($p.certificatetemplates)
                    flags              = ($p.flags | Select-Object -First 1)
                }

                $results += [pscustomobject]$obj
            }
        }
    }
    catch {
        Write-Verbose "Get-ADCSCAConfiguration failed: $($_.Exception.Message)"
    }

    return $results
}
