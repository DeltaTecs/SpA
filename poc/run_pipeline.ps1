Write-Host "Running full pipeline (Pre-processing -> Reset DB -> Import -> Post-processing)..."
docker exec -it pcap-processor bash /app/run_pipeline.sh
