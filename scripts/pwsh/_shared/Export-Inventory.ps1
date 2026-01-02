function Export-Inventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Inventory,

        [Parameter(Mandatory)]
        [string] $OutputPath,

        [Parameter(Mandatory)]
        [string] $BaseName,

        [switch] $NoCsv
    )

    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory | Out-Null
    }

    $jsonPath = Join-Path $OutputPath "$BaseName.json"
    $csvPath  = Join-Path $OutputPath "$BaseName.csv"

    # JSON: UTF-8 *without BOM*
    $json = $Inventory | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "Wrote: $jsonPath"

    if (-not $NoCsv) {
        if ($Inventory -is [System.Collections.IDictionary] -and $Inventory.Contains('findings')) {
            $findings = $Inventory.findings
        } elseif ($Inventory.PSObject.Properties.Name -contains 'findings') {
            $findings = $Inventory.findings
        } else {
            $findings = @()
        }

        if ($findings -and $findings.Count -gt 0) {
            $findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Wrote: $csvPath"
        }
        else {
            Write-Host "No findings to export to CSV."
        }
    }
}
