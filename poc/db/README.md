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
SELECT * FROM protocol_name;
SELECT * FROM protocol_stack;
```

Notes:
- `init_db.sql` is mounted into `/docker-entrypoint-initdb.d/` so it runs only on first container initialization.
- Change credentials in `docker-compose.yml` as needed.
