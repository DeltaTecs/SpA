# Postgres DB for PoC

The `docker-compose.yml` is located in the parent directory (`../`). It runs a PostgreSQL instance and uses the initialization SQL script in this directory to create the schema and seed default protocol names/stacks.

Quick start (PowerShell):

```powershell
cd ..
docker compose up -d
docker compose ps
```

Verify the DB was initialized (example using `psql` from the host or another container):

```powershell
# connect from host if psql is installed
psql -h localhost -U appuser -d main -W
SELECT * FROM protocol;
```

Dump / load (overwrite)

PowerShell (Windows):

```powershell
# From the `poc` directory
./db/dump_load_db.ps1 dump ./db/dumps/main.dump
./db/dump_load_db.ps1 load ./db/dumps/main.dump
```

Bash (Linux/WSL/macOS):

```bash
# From the `poc` directory
./db/dump_load_db.sh dump ./db/dumps/main.dump
./db/dump_load_db.sh load ./db/dumps/main.dump
```

Notes:
- `load` always overwrites existing schema objects.
- The scripts read DB/container settings from `poc/.env` by default.

Notes:
- `init_db.sql` is mounted into `/docker-entrypoint-initdb.d/` so it runs only on first container initialization.
- Change credentials in `docker-compose.yml` as needed.
