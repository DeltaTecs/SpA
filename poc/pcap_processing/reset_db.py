import psycopg2
from psycopg2 import sql
import os
import argparse

def load_dotenv(path):
    if not os.path.exists(path):
        return

    with open(path, "r") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, value)


def reset_db(
    host,
    port,
    dbname,
    admin_user,
    admin_password,
    init_sql_path,
    runtime_user=None,
    runtime_password=None,
):
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=admin_user,
            password=admin_password
        )
        conn.autocommit = True
        cur = conn.cursor()

        print(f"Connected to {dbname} at {host}:{port} as admin user {admin_user}")

        # Drop tables to clear everything
        # We drop in an order that respects dependencies, or just use CASCADE.
        # Since we are resetting to init_db.sql, we want to wipe everything clean.
        tables_to_drop = [
            "packet_processing_tag",
            "recording_processing_tag",
            "packet_header_information",
            "packet",
            "ip_header_information",
            "http_header_information",
            "tcp_header_information",
            "udp_header_information",
            "header_information",
            "conversation",
            "recording",
            "protocol"
        ]

        print("Dropping existing tables...")
        for table in tables_to_drop:
            cur.execute(
                sql.SQL("DROP TABLE IF EXISTS {} CASCADE;").format(sql.Identifier(table))
            )
        
        print("Tables dropped.")

        # Read init_db.sql
        if not os.path.exists(init_sql_path):
            print(f"Error: {init_sql_path} not found.")
            return

        print(f"Reading schema from {init_sql_path}...")
        with open(init_sql_path, 'r') as f:
            sql_script = f.read()

        print("Executing init_db.sql...")
        cur.execute(sql_script)

        if runtime_user:
            print(f"Applying runtime privileges for {runtime_user}...")
            ensure_runtime_role(cur, runtime_user, runtime_password)
            grant_runtime_privileges(cur, dbname, admin_user, runtime_user)

        print("Database reset successfully.")

        cur.close()
        conn.close()

    except Exception as e:
        print(f"An error occurred: {e}")
        raise

def ensure_runtime_role(cur, runtime_user, runtime_password):
    if not runtime_password:
        raise ValueError("runtime_password is required when runtime_user is set")

    cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (runtime_user,))
    role_exists = cur.fetchone() is not None

    action = "ALTER ROLE" if role_exists else "CREATE ROLE"
    cur.execute(
        sql.SQL(
            """
            {} {}
              WITH LOGIN PASSWORD {}
              NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
            """
        ).format(
            sql.SQL(action),
            sql.Identifier(runtime_user),
            sql.Literal(runtime_password),
        )
    )


def grant_runtime_privileges(cur, dbname, admin_user, runtime_user):
    if runtime_user == admin_user:
        raise ValueError("Runtime database user must be different from admin user")

    cur.execute(
        sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(
            sql.Identifier(dbname)
        )
    )
    cur.execute(
        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
            sql.Identifier(dbname),
            sql.Identifier(runtime_user),
        )
    )
    cur.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    cur.execute(
        sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
            sql.Identifier(runtime_user)
        )
    )
    cur.execute(
        sql.SQL(
            """
            GRANT SELECT, INSERT, UPDATE, DELETE
              ON ALL TABLES IN SCHEMA public
              TO {}
            """
        ).format(sql.Identifier(runtime_user))
    )
    cur.execute(
        sql.SQL(
            """
            GRANT USAGE, SELECT
              ON ALL SEQUENCES IN SCHEMA public
              TO {}
            """
        ).format(sql.Identifier(runtime_user))
    )
    cur.execute(
        sql.SQL(
            """
            ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public
              GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}
            """
        ).format(sql.Identifier(admin_user), sql.Identifier(runtime_user))
    )
    cur.execute(
        sql.SQL(
            """
            ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public
              GRANT USAGE, SELECT ON SEQUENCES TO {}
            """
        ).format(sql.Identifier(admin_user), sql.Identifier(runtime_user))
    )


if __name__ == "__main__":
    load_dotenv("/app/.env")
    load_dotenv(".env")

    parser = argparse.ArgumentParser(description="Reset the database to init_db.sql state.")
    parser.add_argument("--host", default=os.getenv("DB_HOST", "127.0.0.1"), help="Database host")
    parser.add_argument("--port", default=os.getenv("DB_PORT", "5432"), help="Database port")
    parser.add_argument("--dbname", default=os.getenv("DB_NAME", "main"), help="Database name")
    parser.add_argument(
        "--user",
        default=os.getenv("DB_ADMIN_USER", "dbadmin"),
        help="Database admin user",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("DB_ADMIN_PASSWORD", "dbadmin"),
        help="Database admin password",
    )
    parser.add_argument(
        "--runtime-user",
        default=os.getenv("DB_USER", "dbuser"),
        help="Runtime database user to grant",
    )
    parser.add_argument(
        "--runtime-password",
        default=os.getenv("DB_PASSWORD", "dbuser"),
        help="Runtime database password",
    )
    parser.add_argument("--init-sql", default="db/init_db.sql", help="Path to init_db.sql")

    args = parser.parse_args()

    reset_db(
        args.host,
        args.port,
        args.dbname,
        args.user,
        args.password,
        args.init_sql,
        args.runtime_user,
        args.runtime_password,
    )
