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

def reset_db(host, port, dbname, user, password, init_sql_path):
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password
        )
        conn.autocommit = True
        cur = conn.cursor()

        print(f"Connected to {dbname} at {host}:{port} as {user}")

        # Drop tables to clear everything
        # We drop in an order that respects dependencies, or just use CASCADE.
        # Since we are resetting to init_db.sql, we want to wipe everything clean.
        tables_to_drop = [
            "pre_scan",
            "packet_processing_tag",
            "recording_processing_tag",
            "packet_event",
            "packet_header_information",
            "packet",
            "event",
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
        
        print("Database reset successfully.")

        cur.close()
        conn.close()

    except Exception as e:
        print(f"An error occurred: {e}")
        raise

if __name__ == "__main__":
    load_dotenv("/app/.env")
    load_dotenv(".env")

    parser = argparse.ArgumentParser(description="Reset the database to init_db.sql state.")
    parser.add_argument("--host", default=os.getenv("DB_HOST", "127.0.0.1"), help="Database host")
    parser.add_argument("--port", default=os.getenv("DB_PORT", "5432"), help="Database port")
    parser.add_argument("--dbname", default=os.getenv("DB_NAME", "main"), help="Database name")
    parser.add_argument("--user", default=os.getenv("DB_USER", "appuser"), help="Database user")
    parser.add_argument("--password", default=os.getenv("DB_PASSWORD", "appuser"), help="Database password")
    parser.add_argument("--init-sql", default="db/init_db.sql", help="Path to init_db.sql")

    args = parser.parse_args()

    reset_db(args.host, args.port, args.dbname, args.user, args.password, args.init_sql)
