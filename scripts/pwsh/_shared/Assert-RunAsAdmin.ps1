function Assert-RunAsAdmin {
    [CmdletBinding()]
    param()

    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        $isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $isAdmin) {
            Write-Verbose "Not running elevated. Continuing (admin not required for AD reads, but may be required for some local store access)."
        }
        return $isAdmin
    }
    catch {
        Write-Verbose "Admin check failed: $($_.Exception.Message)"
        return $false
    }
}
