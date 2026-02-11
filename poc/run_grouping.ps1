param(
    [Parameter(Mandatory=$true, Position=0)]
    [int]$RecordingId,
    
    [Parameter(Mandatory=$false, Position=1)]
    [string]$Model = "",

    [Parameter(Mandatory=$false)]
    [string]$AppDetails = "",

    [Parameter(Mandatory=$false)]
    [string]$UserIntend = ""
)

# Container-internal directory for context files
$ContainerDataDir = "/app/data"

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

# Ensure data directory exists in container
docker exec $GroupingContainer mkdir -p $ContainerDataDir

# Copy context files into the container and build env var flags
$EnvFlags = @()
if ($AppDetails) {
    $ContainerPath = "$ContainerDataDir/app_details.txt"
    docker cp $AppDetails "${GroupingContainer}:${ContainerPath}"
    $EnvFlags += @("-e", "APP_DETAILS=$ContainerPath")
    Write-Host "  App details: $AppDetails -> $ContainerPath"
}
if ($UserIntend) {
    $ContainerPath = "$ContainerDataDir/user_intend.txt"
    docker cp $UserIntend "${GroupingContainer}:${ContainerPath}"
    $EnvFlags += @("-e", "USER_INTEND=$ContainerPath")
    Write-Host "  User intend: $UserIntend -> $ContainerPath"
}

# Build command
$Cmd = "/app/run_grouping_internal.sh $RecordingId"
if ($Model) {
    $Cmd = "$Cmd $Model"
}

# Execute in container
docker exec -it @EnvFlags $GroupingContainer bash -c $Cmd

if ($LASTEXITCODE -ne 0) {
    Write-Error "Grouping failed."
    exit 1
}

Write-Host "Packet grouping completed successfully!"
