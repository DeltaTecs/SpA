param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$PcapFile,
    
    [Parameter(Mandatory=$false, Position=1)]
    [string]$KeylogFile
)

# Container paths
$ContainerPcap = "/tmp/input.pcapng"
$ContainerKeylog = "/tmp/keylog.log"

Write-Host "Running full pipeline (Pre-processing -> Reset DB -> Import -> Post-processing)..."

# Copy PCAP file to container
Write-Host "Copying PCAP file to container..."
docker cp $PcapFile "pcap-processor:$ContainerPcap"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to copy PCAP file to container."
    exit 1
}

# Build command arguments
$CmdArgs = $ContainerPcap

# Copy keylog file if provided
if ($KeylogFile) {
    Write-Host "Copying keylog file to container..."
    docker cp $KeylogFile "pcap-processor:$ContainerKeylog"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to copy keylog file to container."
        exit 1
    }
    $CmdArgs = "$CmdArgs $ContainerKeylog"
}

# Run the internal pipeline script
if ($KeylogFile) {
    docker exec -it pcap-processor bash /app/run_pipeline_internal.sh $ContainerPcap $ContainerKeylog
} else {
    docker exec -it pcap-processor bash /app/run_pipeline_internal.sh $ContainerPcap
}
