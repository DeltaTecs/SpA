param(
  [Parameter(Mandatory = $false)]
  [switch]$Help,

  [Parameter(Mandatory = $false, Position = 0)]
  [string]$Action,

  [Parameter(Mandatory = $false, Position = 1)]
  [string]$File,

  [Parameter(Mandatory = $false)]
  [string]$EnvFile,

  # Optional overrides (otherwise read from .env)
  [Parameter(Mandatory = $false)]
  [string]$ContainerName,

  [Parameter(Mandatory = $false)]
  [string]$Database,

  [Parameter(Mandatory = $false)]
  [string]$DbUser,

  [Parameter(Mandatory = $false)]
  [string]$DbPassword
)

$ErrorActionPreference = 'Stop'

function Print-Usage {
  Write-Host "Usage:" -ForegroundColor Cyan
  Write-Host "  ./db/dump_load_db.ps1 dump <file> [-EnvFile <path>] [-ContainerName <name>] [-Database <name>] [-DbUser <user>] [-DbPassword <password>]"
  Write-Host "  ./db/dump_load_db.ps1 load <file> [-EnvFile <path>] [-ContainerName <name>] [-Database <name>] [-DbUser <user>] [-DbPassword <password>]"
  Write-Host "  ./db/dump_load_db.ps1 --help"
  Write-Host ""
  Write-Host "Defaults:" -ForegroundColor Cyan
  Write-Host "  Reads missing connection/container settings from ../.env (poc/.env)."
  Write-Host ""
  Write-Host "Examples:" -ForegroundColor Cyan
  Write-Host "  ./db/dump_load_db.ps1 dump ./db/dumps/main.dump"
  Write-Host "  ./db/dump_load_db.ps1 load ./db/dumps/main.dump"
}

$helpTokens = @('--help', '-h', '/?', 'help', '?')

if ($Help -or ($Action -and ($helpTokens -contains $Action.ToLowerInvariant()))) {
  Print-Usage
  exit 0
}

if (-not $Action -or -not $File) {
  Print-Usage
  exit 2
}

$actionNormalized = $Action.ToLowerInvariant()
if ($actionNormalized -ne 'dump' -and $actionNormalized -ne 'load') {
  throw "Invalid Action '$Action'. Expected: dump | load. Use --help for usage."
}

$Action = $actionNormalized

if (-not $EnvFile) {
  # Default: ../.env (poc/.env)
  $EnvFile = Join-Path (Split-Path -Parent $PSScriptRoot) '.env'
}

function Read-DotEnv([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) {
    throw "Missing .env file: $path"
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

$User = $null
$Password = $null

if (-not $ContainerName -or -not $Database -or -not $DbUser -or -not $DbPassword) {
  $envMap = Read-DotEnv $EnvFile

  foreach ($requiredKey in @('DB_CONTAINER_NAME','DB_NAME','DB_USER','DB_PASSWORD','DB_HOST','DB_PORT')) {
    if (-not $envMap.ContainsKey($requiredKey) -or [string]::IsNullOrWhiteSpace($envMap[$requiredKey])) {
      throw "Missing required key '$requiredKey' in $EnvFile"
    }
  }

  if (-not $ContainerName) { $ContainerName = $envMap['DB_CONTAINER_NAME'] }
  if (-not $Database) { $Database = $envMap['DB_NAME'] }
  if (-not $DbUser) { $DbUser = $envMap['DB_USER'] }
  if (-not $DbPassword) { $DbPassword = $envMap['DB_PASSWORD'] }
}

$User = $DbUser
$Password = $DbPassword

$PocRoot = Split-Path -Parent $PSScriptRoot

function Get-FullPath([string]$path) {
  try {
    $resolved = Resolve-Path -LiteralPath $path -ErrorAction Stop
    return [System.IO.Path]::GetFullPath($resolved.Path)
  }
  catch {
    return [System.IO.Path]::GetFullPath($path)
  }
}

function Resolve-OutputPath([string]$path) {
  if ([System.IO.Path]::IsPathRooted($path)) {
    return Get-FullPath $path
  }

  # Heuristic: paths like ./db/... are intended to be relative to the `poc` directory
  $normalized = $path.Replace('/', '\')
  if ($normalized -match '^(\.\\)?db\\') {
    return Get-FullPath (Join-Path $PocRoot $path)
  }

  return Get-FullPath $path
}

function Ensure-ParentDir([string]$path) {
  $parent = Split-Path -Parent $path
  if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent | Out-Null
  }
}

function Exec-InPostgres([string]$cmd) {
  & docker exec -e "PGPASSWORD=$Password" $ContainerName sh -lc $cmd
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed (exit $LASTEXITCODE): $cmd"
  }
}

function Copy-ToHost([string]$containerPath, [string]$hostPath) {
  Ensure-ParentDir $hostPath
  if (Test-Path -LiteralPath $hostPath) {
    Remove-Item -LiteralPath $hostPath -Force
  }
  & docker cp "$ContainerName`:$containerPath" $hostPath
  if ($LASTEXITCODE -ne 0) {
    throw "docker cp failed (exit $LASTEXITCODE): $containerPath -> $hostPath"
  }
}

function Copy-ToContainer([string]$hostPath, [string]$containerPath) {
  if (-not (Test-Path -LiteralPath $hostPath)) {
    throw "Input file not found: $hostPath"
  }
  & docker cp $hostPath "$ContainerName`:$containerPath"
  if ($LASTEXITCODE -ne 0) {
    throw "docker cp failed (exit $LASTEXITCODE): $hostPath -> $containerPath"
  }
}

$hostFile = Resolve-OutputPath $File

switch ($Action) {
  'dump' {
    Ensure-ParentDir $hostFile

    $tmp = "/tmp/${Database}_dump.dump"
    Write-Host "Dumping database '$Database' from container '$ContainerName' to '$hostFile'..."

    Exec-InPostgres "pg_dump -U '$User' -d '$Database' -Fc -f '$tmp'"
    Copy-ToHost $tmp $hostFile
    Exec-InPostgres "rm -f '$tmp'"

    Write-Host "Done."
  }

  'load' {
    $ext = [System.IO.Path]::GetExtension($hostFile).ToLowerInvariant()
    if ($ext -eq '') {
      throw "Dump file must have an extension (.dump/.backup/.tar or .sql): $hostFile"
    }

    $tmp = "/tmp/${Database}_restore$ext"
    Write-Host "Loading dump '$hostFile' into database '$Database' (overwriting) in container '$ContainerName'..."

    Copy-ToContainer $hostFile $tmp

    Exec-InPostgres "psql -U '$User' -d '$Database' -v ON_ERROR_STOP=1 -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'"

    if ($ext -eq '.sql') {
      Exec-InPostgres "psql -U '$User' -d '$Database' -v ON_ERROR_STOP=1 -f '$tmp'"
    }
    else {
      Exec-InPostgres "pg_restore -U '$User' -d '$Database' --no-owner --no-privileges --exit-on-error '$tmp'"
    }

    Exec-InPostgres "rm -f '$tmp'"
    Write-Host "Done."
  }
}
