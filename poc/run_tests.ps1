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
$DbHost = if ($envMap.ContainsKey('DB_HOST') -and $envMap['DB_HOST']) { $envMap['DB_HOST'] } else { 'postgres' }
$DbPort = if ($envMap.ContainsKey('DB_PORT') -and $envMap['DB_PORT']) { $envMap['DB_PORT'] } else { '5432' }
$DbName = if ($envMap.ContainsKey('DB_NAME') -and $envMap['DB_NAME']) { $envMap['DB_NAME'] } else { 'main' }
$DbUser = if ($envMap.ContainsKey('DB_USER') -and $envMap['DB_USER']) { $envMap['DB_USER'] } else { 'appuser' }
$DbPassword = if ($envMap.ContainsKey('DB_PASSWORD')) { $envMap['DB_PASSWORD'] } else { 'appuser' }
$DbEnvArgs = @(
    "-e", "DB_HOST=$DbHost",
    "-e", "DB_PORT=$DbPort",
    "-e", "DB_NAME=$DbName",
    "-e", "DB_USER=$DbUser",
    "-e", "DB_PASSWORD=$DbPassword"
)

Write-Host "Running test_ssl_decryptor..."
docker exec $ProcessorContainer python3 -m unittest util/test/test_ssl_decryptor.py

Write-Host "Running test_parsing..."
docker exec @DbEnvArgs $ProcessorContainer python3 -m unittest parsing/test/test_parsing.py

Write-Host "Running test_post_processing..."
docker exec @DbEnvArgs $ProcessorContainer python3 -m unittest parsing/test/test_post_processing.py

Write-Host "Running test_mcp_packet_db_server..."
docker compose run --rm --build mcp-packet-db python -m unittest discover -s /app/test

Write-Host "Running test_mcp_hexstrike..."
docker compose run --rm --build --no-deps --entrypoint /opt/hexstrike-venv/bin/python mcp-hexstrike -m unittest discover -s /app/test
