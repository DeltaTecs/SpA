# Postgres DB for PoC

The `docker-compose.yml` is located in the parent directory (`../`). It runs a PostgreSQL instance and uses the initialization SQL script in this directory to create the schema and seed default protocol names/stacks.

Quick start (PowerShell):

```powershell
cd ..
docker compose up -d
./reset_db.ps1
docker compose ps
```

Verify the DB was initialized (example using `psql` from the host or another container):

```powershell
# connect from host if psql is installed
psql -h localhost -U dbuser -d main -W
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
- `DB_ADMIN_USER`/`DB_ADMIN_PASSWORD` are used for schema reset/load only.
- `DB_USER`/`DB_PASSWORD` are used by runtime services and have DML privileges
  on the PoC schema without superuser, role-management, or schema-create rights.
- Existing `postgres_data` volumes initialized with the old single-user setup are
  not changed by editing compose. Recreate/reset the database, or apply an
  explicitly reviewed one-time role migration, before expecting `dbadmin` and
  `dbuser` to exist in that volume.

Notes:
- `init_db.sql` is mounted into `/docker-entrypoint-initdb.d/` so the base
  schema is created on first container initialization.
- Runtime role creation and grants are applied by `pcap_processing/reset_db.py`
  when the database is reset. Run `./reset_db.ps1` or `./reset_db.sh` after
  creating a fresh volume before relying on `dbuser`.
- Change credentials in `docker-compose.yml` as needed.
