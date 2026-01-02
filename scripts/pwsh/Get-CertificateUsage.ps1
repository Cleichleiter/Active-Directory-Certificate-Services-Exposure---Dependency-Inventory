function Get-LocalCertificateTemplateUsage {
    [CmdletBinding()]
    param(
        [switch] $IncludeCurrentUser,
        [switch] $IncludeMachine
    )

    $usage = @()

    function Get-TemplateNameFromCert {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

        # Best-effort: Template info often appears as extension text; avoid fragile OID parsing.
        $template = $null
        foreach ($ext in $Cert.Extensions) {
            try {
                $formatted = $ext.Format($false)
                if ($formatted -match 'Template=') {
                    $template = ($formatted -split 'Template=')[1].Trim()
                    break
                }
                if ($formatted -match 'Certificate Template') {
                    $template = $formatted.Trim()
                    break
                }
            } catch { }
        }
        return $template
    }

    $stores = @()

    if ($IncludeMachine) {
        $stores += @{ Scope='LocalMachine'; Names=@('My','WebHosting','CA','Root') }
    }
    if ($IncludeCurrentUser) {
        $stores += @{ Scope='CurrentUser'; Names=@('My','CA','Root') }
    }

    foreach ($s in $stores) {
        foreach ($name in $s.Names) {
            try {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, $s.Scope)
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

                foreach ($cert in $store.Certificates) {
                    $template = Get-TemplateNameFromCert -Cert $cert

                    $usage += [pscustomobject]@{
                        type        = 'LocalCert'
                        scope       = $s.Scope
                        store       = $name
                        subject     = $cert.Subject
                        issuer      = $cert.Issuer
                        notAfter    = $cert.NotAfter
                        thumbprint  = $cert.Thumbprint
                        hasPrivateKey = $cert.HasPrivateKey
                        signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
                        templateHint = $template
                    }
                }

                $store.Close()
            }
            catch {
                Write-Verbose "Failed reading $($s.Scope)\$name store: $($_.Exception.Message)"
            }
        }
    }

    # Summarize by template hint (best-effort)
    $summary = $usage |
        Group-Object -Property templateHint |
        ForEach-Object {
            [pscustomobject]@{
                templateHint = ($_.Name -as [string])
                count        = $_.Count
            }
        } |
        Sort-Object -Property count -Descending

    return [pscustomobject]@{
        records = $usage
        summary = $summary
    }
}
