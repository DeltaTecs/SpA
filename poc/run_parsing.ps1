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
    docker exec -it $ProcessorContainer bash /app/run_pipeline_internal.sh $ContainerPcap $ContainerKeylog
} else {
    docker exec -it $ProcessorContainer bash /app/run_pipeline_internal.sh $ContainerPcap
}
