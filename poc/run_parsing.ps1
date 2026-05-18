param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$PcapFile,
    
    [Parameter(Mandatory=$false, Position=1)]
    [string]$KeylogFile
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

$envMap = Read-DotEnv (Join-Path $PSScriptRoot '.env')
$ProcessorContainer = if ($envMap.ContainsKey('PCAP_PROCESSOR_CONTAINER_NAME') -and $envMap['PCAP_PROCESSOR_CONTAINER_NAME']) { $envMap['PCAP_PROCESSOR_CONTAINER_NAME'] } else { 'pcap-processor' }
$DbHost = if ($envMap.ContainsKey('DB_HOST') -and $envMap['DB_HOST']) { $envMap['DB_HOST'] } else { 'db' }
$DbPort = if ($envMap.ContainsKey('DB_PORT') -and $envMap['DB_PORT']) { $envMap['DB_PORT'] } else { '5432' }
$DbName = if ($envMap.ContainsKey('DB_NAME') -and $envMap['DB_NAME']) { $envMap['DB_NAME'] } else { 'main' }
$DbAdminUser = if ($envMap.ContainsKey('DB_ADMIN_USER') -and $envMap['DB_ADMIN_USER']) { $envMap['DB_ADMIN_USER'] } else { 'dbadmin' }
$DbAdminPassword = if ($envMap.ContainsKey('DB_ADMIN_PASSWORD')) { $envMap['DB_ADMIN_PASSWORD'] } else { 'dbadmin' }
$DbUser = if ($envMap.ContainsKey('DB_USER') -and $envMap['DB_USER']) { $envMap['DB_USER'] } else { 'dbuser' }
$DbPassword = if ($envMap.ContainsKey('DB_PASSWORD')) { $envMap['DB_PASSWORD'] } else { 'dbuser' }
$DbEnvArgs = @(
    "-e", "DB_HOST=$DbHost",
    "-e", "DB_PORT=$DbPort",
    "-e", "DB_NAME=$DbName",
    "-e", "DB_ADMIN_USER=$DbAdminUser",
    "-e", "DB_ADMIN_PASSWORD=$DbAdminPassword",
    "-e", "DB_USER=$DbUser",
    "-e", "DB_PASSWORD=$DbPassword"
)

# Container paths
$ContainerPcap = "/tmp/input.pcapng"
$ContainerKeylog = "/tmp/keylog.log"

Write-Host "Running full pipeline (Pre-processing -> Reset DB -> Import -> Post-processing)..."

# Copy PCAP file to container
Write-Host "Copying PCAP file to container..."
docker cp $PcapFile "$ProcessorContainer`:$ContainerPcap"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to copy PCAP file to container."
    exit 1
}

# Build command arguments
$CmdArgs = $ContainerPcap

# Copy keylog file if provided
if ($KeylogFile) {
    Write-Host "Copying keylog file to container..."
    docker cp $KeylogFile "$ProcessorContainer`:$ContainerKeylog"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to copy keylog file to container."
        exit 1
    }
    $CmdArgs = "$CmdArgs $ContainerKeylog"
}

# Run the internal pipeline script
if ($KeylogFile) {
    docker exec -it @DbEnvArgs $ProcessorContainer bash /app/run_pipeline_internal.sh $ContainerPcap $ContainerKeylog
} else {
    docker exec -it @DbEnvArgs $ProcessorContainer bash /app/run_pipeline_internal.sh $ContainerPcap
}
