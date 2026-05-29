[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('dump', 'load')]
    [string]$Action,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$DumpFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-DotEnv([string]$Path) {
    $map = @{}
    if (-not (Test-Path -LiteralPath $Path)) {
        return $map
    }

    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) {
            continue
        }

        $idx = $trimmed.IndexOf('=')
        if ($idx -lt 1) {
            continue
        }

        $key = $trimmed.Substring(0, $idx).Trim()
        if ($key -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
            continue
        }

        $value = $trimmed.Substring($idx + 1).Trim()
        if ($value.Length -ge 2) {
            $first = $value[0]
            $last = $value[$value.Length - 1]
            if (($first -eq '"' -and $last -eq '"') -or ($first -eq "'" -and $last -eq "'")) {
                $value = $value.Substring(1, $value.Length - 2)
            }
        }

        $map[$key] = $value
    }

    return $map
}

function Get-EnvValue([hashtable]$EnvMap, [string]$Name, [string]$DefaultValue) {
    if ($EnvMap.ContainsKey($Name) -and $EnvMap[$Name]) {
        return $EnvMap[$Name]
    }

    return $DefaultValue
}

function Resolve-UserPath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location).ProviderPath $Path))
}

function Invoke-Docker([string[]]$Arguments, [string]$Description) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Invoke-PostgresDocker([string[]]$Arguments, [string]$Description) {
    $oldPgPassword = [Environment]::GetEnvironmentVariable('PGPASSWORD')

    try {
        $env:PGPASSWORD = $DbAdminPassword
        Invoke-Docker (@('exec', '-e', 'PGPASSWORD', $DbContainer) + $Arguments) $Description
    }
    finally {
        if ($null -eq $oldPgPassword) {
            Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
        }
        else {
            $env:PGPASSWORD = $oldPgPassword
        }
    }
}

function Test-ContainerRunning([string]$ContainerName) {
    $running = & docker inspect --format '{{.State.Running}}' $ContainerName 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker container '$ContainerName' was not found. Start the stack from the poc directory first."
    }

    if ($running -ne 'true') {
        throw "Docker container '$ContainerName' is not running."
    }
}

function Invoke-DumpDatabase {
    $dumpDir = [System.IO.Path]::GetDirectoryName($ResolvedDumpFile)
    if ($dumpDir) {
        New-Item -ItemType Directory -Force -Path $dumpDir | Out-Null
    }

    Write-Host "Dumping '$DbName' from container '$DbContainer' to '$ResolvedDumpFile'..."
    Invoke-PostgresDocker @(
        'pg_dump',
        '--host=127.0.0.1',
        "--port=$DbPort",
        "--username=$DbAdminUser",
        "--dbname=$DbName",
        '--format=custom',
        '--data-only',
        '--no-owner',
        '--no-privileges',
        '--exclude-table-data=protocol',
        "--file=$ContainerDump"
    ) 'pg_dump'

    Invoke-Docker @(
        'cp',
        "$($DbContainer):$ContainerDump",
        $ResolvedDumpFile
    ) 'copy dump from container'

    Write-Host "Wrote dump to '$ResolvedDumpFile'."
}

function New-RestoreList {
    $toc = & docker exec $DbContainer pg_restore -l $ContainerDump
    if ($LASTEXITCODE -ne 0) {
        throw "pg_restore list failed with exit code $LASTEXITCODE."
    }

    # init_db.sql seeds the protocol lookup table; skip legacy dump rows to avoid duplicates.
    $filteredToc = foreach ($line in $toc) {
        if (
            $line -match ' TABLE DATA public protocol ' -or
            $line -match ' SEQUENCE SET public protocol_protocol_id_seq '
        ) {
            ";$line"
        }
        else {
            $line
        }
    }

    $localList = [System.IO.Path]::GetTempFileName()
    try {
        Set-Content -LiteralPath $localList -Value $filteredToc -Encoding ASCII
        Invoke-Docker @(
            'cp',
            $localList,
            "$($DbContainer):$ContainerList"
        ) 'copy restore list to container'
    }
    finally {
        Remove-Item -LiteralPath $localList -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-LoadDatabase {
    if (-not (Test-Path -LiteralPath $ResolvedDumpFile -PathType Leaf)) {
        throw "Dump file not found: $ResolvedDumpFile"
    }

    Write-Host "Loading '$ResolvedDumpFile' into '$DbName' in container '$DbContainer'..."
    Invoke-Docker @(
        'cp',
        $ResolvedDumpFile,
        "$($DbContainer):$ContainerDump"
    ) 'copy dump to container'

    New-RestoreList

    Invoke-PostgresDocker @(
        'pg_restore',
        '--host=127.0.0.1',
        "--port=$DbPort",
        "--username=$DbAdminUser",
        "--dbname=$DbName",
        '--data-only',
        '--no-owner',
        '--no-privileges',
        '--disable-triggers',
        '--single-transaction',
        '--exit-on-error',
        "--use-list=$ContainerList",
        $ContainerDump
    ) 'pg_restore'

    Write-Host "Loaded dump into '$DbName'."
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Required command not found: docker"
}

$pocRoot = Split-Path -Parent $PSScriptRoot
$envMap = Read-DotEnv (Join-Path $pocRoot '.env')

$DbContainer = Get-EnvValue $envMap 'DB_CONTAINER_NAME' 'db'
$DbPort = Get-EnvValue $envMap 'DB_PORT' '5432'
$DbName = Get-EnvValue $envMap 'DB_NAME' 'main'
$DbAdminUser = Get-EnvValue $envMap 'DB_ADMIN_USER' 'dbadmin'
$DbAdminPassword = Get-EnvValue $envMap 'DB_ADMIN_PASSWORD' 'dbadmin'
$ResolvedDumpFile = Resolve-UserPath $DumpFile
$safeDbName = $DbName -replace '[^A-Za-z0-9_.-]', '_'
$ContainerDump = "/tmp/dump_load_db_${safeDbName}_$PID.dump"
$ContainerList = "/tmp/dump_load_db_${safeDbName}_$PID.list"

Test-ContainerRunning $DbContainer

try {
    switch ($Action) {
        'dump' { Invoke-DumpDatabase }
        'load' { Invoke-LoadDatabase }
    }
}
finally {
    & docker exec $DbContainer rm -f $ContainerDump $ContainerList *> $null
}
