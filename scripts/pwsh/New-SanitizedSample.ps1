param(
    [Parameter(Mandatory=$false)]
    [string]$RepoRoot = (Get-Location).Path,

    [Parameter(Mandatory=$false)]
    [string]$InputJson = (Join-Path (Get-Location).Path 'reports\adcs_inventory.json'),

    [Parameter(Mandatory=$false)]
    [string]$OutputJson = (Join-Path (Get-Location).Path 'samples\adcs_inventory.sample.json')
)

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Redact-CertRecord {
    param($r)

    # Keep structural fields, redact identifiers/content that can dox you or a tenant.
    [pscustomobject]@{
        type               = $r.type
        scope              = $r.scope
        store              = $r.store
        subject            = '<redacted>'
        issuer             = '<redacted>'
        notAfter           = $r.notAfter
        thumbprint         = '<redacted>'
        hasPrivateKey      = $r.hasPrivateKey
        signatureAlgorithm = $r.signatureAlgorithm
        templateHint       = $r.templateHint
    }
}

if (-not (Test-Path $InputJson)) {
    throw "Input JSON not found: $InputJson"
}

Ensure-Directory -Path (Split-Path $OutputJson -Parent)

# Load JSON
$raw = Get-Content -Path $InputJson -Raw
$obj = $raw | ConvertFrom-Json -Depth 50

# Sanitize meta
if ($null -ne $obj.meta) {
    $obj.meta.timestampUtc = '2000-01-01T00:00:00Z'
    $obj.meta.machine      = '<redacted>'
    $obj.meta.user         = '<redacted>'
    $obj.meta.domain       = $obj.meta.domain  # keep as-is (often null)
    $obj.meta.repoRoot     = '<redacted>'
    $obj.meta.outputPath   = '<redacted>'
}

# Sanitize artifacts.localCertUsage.records (if present)
if ($null -ne $obj.artifacts -and $null -ne $obj.artifacts.localCertUsage -and $null -ne $obj.artifacts.localCertUsage.records) {
    $newRecords = foreach ($r in $obj.artifacts.localCertUsage.records) {
        Redact-CertRecord -r $r
    }
    $obj.artifacts.localCertUsage.records = @($newRecords)
}

# Sanitize findings (optional: keep but remove signals that reveal counts tied to your host)
if ($null -ne $obj.findings) {
    foreach ($f in $obj.findings) {
        if ($f.Name)    { $f.Name = '(redacted)' }
        if ($f.Signals) { $f.Signals = 'Count=<redacted>' }
    }
}

# Write sanitized sample
$obj | ConvertTo-Json -Depth 50 | Set-Content -Path $OutputJson -Encoding UTF8

Write-Host "Wrote sanitized sample: $OutputJson"
