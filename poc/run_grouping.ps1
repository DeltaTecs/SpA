param(
    [Parameter(Mandatory=$true, Position=0)]
    [int]$RecordingId,
    
    [Parameter(Mandatory=$false, Position=1)]
    [string]$Model = "",

    [Parameter(Mandatory=$false)]
    [ValidateSet("ollama", "gemini", "openai", "deepseek")]
    [string]$Provider = "",

    [Parameter(Mandatory=$false)]
    [string]$ApiKey = "",

    [Parameter(Mandatory=$false)]
    [string]$ApiBaseUrl = "",

    [Parameter(Mandatory=$false)]
    [string]$AppDetails = "",

    [Parameter(Mandatory=$false)]
    [string]$UserIntend = "",

    [Parameter(Mandatory=$false)]
    [switch]$WebSearch
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
if (-not $Provider -and $envMap.ContainsKey("PROVIDER")) {
    $Provider = $envMap["PROVIDER"]
}
if (-not $ApiKey -and $Provider -eq "deepseek" -and $envMap.ContainsKey("DEEPSEEK_API_KEY")) {
    $ApiKey = $envMap["DEEPSEEK_API_KEY"]
}
if (-not $ApiKey -and $envMap.ContainsKey("API_KEY")) {
    $ApiKey = $envMap["API_KEY"]
}
if (-not $ApiBaseUrl -and $Provider -eq "deepseek" -and $envMap.ContainsKey("DEEPSEEK_API_BASE_URL")) {
    $ApiBaseUrl = $envMap["DEEPSEEK_API_BASE_URL"]
}
if (-not $ApiBaseUrl -and $envMap.ContainsKey("API_BASE_URL")) {
    $ApiBaseUrl = $envMap["API_BASE_URL"]
}

# Container name
$GroupingContainer = "grouping"

Write-Host "Running packet event assignment for recording $RecordingId..."

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
if ($Provider) {
    $EnvFlags += @("-e", "PROVIDER=$Provider")
    Write-Host "  Provider: $Provider"
}
if ($ApiKey) {
    $EnvFlags += @("-e", "API_KEY=$ApiKey")
    Write-Host "  API key: (set)"
}
if ($ApiBaseUrl) {
    $EnvFlags += @("-e", "API_BASE_URL=$ApiBaseUrl")
    Write-Host "  API base URL: $ApiBaseUrl"
}
if ($WebSearch) {
    $EnvFlags += @("-e", "GROUPING_ENABLE_WEB_SEARCH=1")
    Write-Host "  Web search: enabled"
}

# Build command
$Cmd = "/app/run_grouping_internal.sh $RecordingId"
if ($Model) {
    $Cmd = "$Cmd $Model"
}

# Execute in container
docker exec -it @EnvFlags $GroupingContainer bash -c $Cmd

if ($LASTEXITCODE -ne 0) {
    Write-Error "Packet analysis failed."
    exit 1
}

Write-Host "Packet analysis completed successfully!"
