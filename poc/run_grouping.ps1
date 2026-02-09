param(
    [Parameter(Mandatory=$true, Position=0)]
    [int]$RecordingId,
    
    [Parameter(Mandatory=$false, Position=1)]
    [string]$Model = ""
)

function Read-DotEnv([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) {
        return @{}
    }
    $map = @{}
    foreach ($line in (Get-Content -LiteralPath $path)) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed.StartsWith('#')) { continue }
        $idx = $trimmed.IndexOf('=')
        if ($idx -lt 1) { continue }
        $key = $trimmed.Substring(0, $idx).Trim()
        $value = $trimmed.Substring($idx + 1).Trim()
        $map[$key] = $value
    }
    return $map
}

# Load environment
$envMap = Read-DotEnv (Join-Path $PSScriptRoot '.env')

# Container name
$GroupingContainer = "grouping"

Write-Host "Running packet grouping for recording $RecordingId..."

# Build command
$Cmd = "/app/run_grouping_internal.sh $RecordingId"
if ($Model) {
    $Cmd = "$Cmd $Model"
}

# Execute in container
docker exec -it $GroupingContainer bash -c $Cmd

if ($LASTEXITCODE -ne 0) {
    Write-Error "Grouping failed."
    exit 1
}

Write-Host "Packet grouping completed successfully!"
