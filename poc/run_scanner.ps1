param(
    [Parameter(Mandatory=$true, Position=0)]
    [int]$EventId,

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
    [string]$Output = ""
)

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

$ScannerContainer = "scanner"

Write-Host "Running scanner phase 1 for event $EventId..."

docker exec $ScannerContainer mkdir -p $ContainerDataDir

$EnvFlags = @()
if ($AppDetails) {
    $ContainerPath = "$ContainerDataDir/app_details.txt"
    docker cp $AppDetails "${ScannerContainer}:${ContainerPath}"
    $EnvFlags += @("-e", "APP_DETAILS=$ContainerPath")
    Write-Host "  App details: $AppDetails -> $ContainerPath"
}
if ($UserIntend) {
    $ContainerPath = "$ContainerDataDir/user_intend.txt"
    docker cp $UserIntend "${ScannerContainer}:${ContainerPath}"
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
if ($Output) {
    $EnvFlags += @("-e", "OUTPUT=$Output")
    Write-Host "  Output: $Output"
}

$Cmd = "/app/run_scanner_internal.sh $EventId"
if ($Model) {
    $Cmd = "$Cmd $Model"
}

docker exec -it @EnvFlags $ScannerContainer bash -c $Cmd

if ($LASTEXITCODE -ne 0) {
    Write-Error "Scanner phase 1 failed."
    exit 1
}

Write-Host "Scanner phase 1 completed successfully."
