function Write-InventoryLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Message,

        [ValidateSet('INFO','WARN','ERROR','DEBUG')]
        [string] $Level = 'INFO'
    )

    $ts = (Get-Date).ToString('s')
    Write-Host "[$ts][$Level] $Message"
}
