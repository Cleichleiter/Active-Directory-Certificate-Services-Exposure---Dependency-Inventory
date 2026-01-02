function Get-ADCSCertificateTemplatePermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]] $Templates
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function New-PermissionRow {
        param(
            [string] $TemplateName,
            [string] $DisplayName,
            [string] $Identity,
            [bool]   $BroadIdentity,
            [bool]   $Enroll,
            [bool]   $AutoEnroll,
            [bool]   $GenericAll,
            [bool]   $GenericWrite,
            [bool]   $WriteDacl,
            [bool]   $WriteOwner
        )

        return [pscustomobject]@{
            TemplateName   = $TemplateName
            DisplayName    = $DisplayName
            Identity       = $Identity
            BroadIdentity  = $BroadIdentity
            Enroll         = $Enroll
            AutoEnroll     = $AutoEnroll
            GenericAll     = $GenericAll
            GenericWrite   = $GenericWrite
            WriteDacl      = $WriteDacl
            WriteOwner     = $WriteOwner
        }
    }

    function Test-BroadIdentity {
        param([string]$Name)

        if (-not $Name) { return $false }

        $n = $Name.Trim().ToLowerInvariant()
        return (
            $n -eq 'everyone' -or
            $n -eq 'authenticated users' -or
            $n -eq 'domain users' -or
            $n -like '*\domain users' -or
            $n -like '*\authenticated users' -or
            $n -like '*\everyone'
        )
    }

    function Try-TranslateSid {
        param([System.Security.Principal.SecurityIdentifier]$Sid)

        try {
            return $Sid.Translate([System.Security.Principal.NTAccount]).Value
        }
        catch {
            return $Sid.Value
        }
    }

    function Get-ExtendedRightName {
        param([Guid]$Guid)

        # AD CS template rights GUIDs (most relevant)
        # Enroll:     0e10c968-78fb-11d2-90d4-00c04f79dc55
        # AutoEnroll: a05b8cc2-17bc-4802-a710-e7c15ab866a2
        switch ($Guid.Guid.ToLowerInvariant()) {
            '0e10c968-78fb-11d2-90d4-00c04f79dc55' { return 'Enroll' }
            'a05b8cc2-17bc-4802-a710-e7c15ab866a2' { return 'AutoEnroll' }
            default { return $null }
        }
    }

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($t in $Templates) {
        $tName = $null
        $tDisplay = $null
        $sddl = $null

        try { $tName = [string]$t.name } catch { }
        try { $tDisplay = [string]$t.displayName } catch { }
        try { $sddl = [string]$t.securityDescriptorSddl } catch { $sddl = $null }

        if (-not $tName) { $tName = '(unknown)' }
        if (-not $tDisplay) { $tDisplay = $tName }

        if (-not $sddl -or $sddl.Trim().Length -eq 0) {
            # No SD available in this execution context; skip quietly
            continue
        }

        $rawAcl = $null
        try {
            $rawAcl = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
        }
        catch {
            # Malformed SD; skip quietly
            continue
        }

        $dacl = $rawAcl.DiscretionaryAcl
        if (-not $dacl) { continue }

        # Accumulate per-identity rights
        $byIdentity = @{}

        foreach ($ace in $dacl) {
            # We only care about Allow ACEs
            if ($ace.AceType.ToString() -notlike '*Allowed*') { continue }

            $sidObj = $ace.SecurityIdentifier
            if (-not $sidObj) { continue }

            $identity = Try-TranslateSid -Sid $sidObj
            if (-not $byIdentity.ContainsKey($identity)) {
                $byIdentity[$identity] = [ordered]@{
                    BroadIdentity = (Test-BroadIdentity -Name $identity)
                    Enroll        = $false
                    AutoEnroll    = $false
                    GenericAll    = $false
                    GenericWrite  = $false
                    WriteDacl     = $false
                    WriteOwner    = $false
                }
            }

            # Standard directory rights
            try {
                $mask = [int]$ace.AccessMask
            }
            catch {
                $mask = 0
            }

            # Map common rights based on ActiveDirectoryRights bitmask
            # GenericAll:   0x10000000
            # GenericWrite: 0x40000000
            # WriteDacl:    0x00040000
            # WriteOwner:   0x00080000
            if (($mask -band 0x10000000) -ne 0) { $byIdentity[$identity].GenericAll = $true }
            if (($mask -band 0x40000000) -ne 0) { $byIdentity[$identity].GenericWrite = $true }
            if (($mask -band 0x00040000) -ne 0) { $byIdentity[$identity].WriteDacl = $true }
            if (($mask -band 0x00080000) -ne 0) { $byIdentity[$identity].WriteOwner = $true }

            # Extended rights (Enroll / AutoEnroll) require object ACE handling
            # If this ACE has an ObjectType GUID, we can map it.
            $objTypeGuid = $null
            try {
                if ($ace.ObjectAceType -and $ace.ObjectAceType -ne [Guid]::Empty) {
                    $objTypeGuid = [Guid]$ace.ObjectAceType
                }
            }
            catch {
                $objTypeGuid = $null
            }

            if ($objTypeGuid) {
                $er = Get-ExtendedRightName -Guid $objTypeGuid
                if ($er -eq 'Enroll') { $byIdentity[$identity].Enroll = $true }
                if ($er -eq 'AutoEnroll') { $byIdentity[$identity].AutoEnroll = $true }
            }
        }

        foreach ($k in $byIdentity.Keys) {
            $v = $byIdentity[$k]
            $rows.Add((New-PermissionRow `
                -TemplateName $tName `
                -DisplayName $tDisplay `
                -Identity $k `
                -BroadIdentity ([bool]$v.BroadIdentity) `
                -Enroll ([bool]$v.Enroll) `
                -AutoEnroll ([bool]$v.AutoEnroll) `
                -GenericAll ([bool]$v.GenericAll) `
                -GenericWrite ([bool]$v.GenericWrite) `
                -WriteDacl ([bool]$v.WriteDacl) `
                -WriteOwner ([bool]$v.WriteOwner)
            ))
        }
    }

    return $rows
}
