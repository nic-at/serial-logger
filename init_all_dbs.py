import yaml
import psycopg2
from psycopg2 import sql

# Load credentials
with open("credentials.yaml", "r") as file:
    creds = yaml.safe_load(file)

# Load schema SQL
with open("init_db.sql", "r") as f:
    init_sql = f.read()

# Run init SQL for all databases
for db_env, db_config in creds["databases"].items():
    print(f"Connecting to {db_env} database...")
    try:
        conn = psycopg2.connect(
            dbname=db_config["database"],
            user=db_config["user"],
            password=db_config["password"],
            host=db_config["host"],
            port=db_config["port"]
        )
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(init_sql)
        print(f"Successfully initialized {db_env} database.")
    except Exception as e:
        print(f"Failed to initialize {db_env}: {e}")
    finally:
        if conn:
            conn.close()