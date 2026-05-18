# Postgres DB for PoC

The `docker-compose.yml` is located in the parent directory (`../`). It runs a PostgreSQL instance and uses the initialization SQL script in this directory to create the schema and seed default protocol names/stacks.

## Dump / load (overwrite)

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
- `load` does not clear existing table content, but simply inserts into the tables.
- The scripts read DB/container settings from `poc/.env` by default.

Notes:
- `init_db.sql` is mounted into `/docker-entrypoint-initdb.d/` so the base
  schema is created on first container initialization.
- Runtime role creation and grants are applied by `pcap_processing/reset_db.py`
  when the database is reset. Run `./reset_db.ps1` or `./reset_db.sh` after
  creating a fresh volume before relying on `dbuser`.
- Change credentials in `docker-compose.yml` as needed.
