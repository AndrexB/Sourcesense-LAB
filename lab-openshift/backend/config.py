
import os, psycopg2

SECRET_KEY = os.environ.get("SECRET_KEY", "super-secret-key")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "jwt-super-secret-key")

def get_db_conn():
    return psycopg2.connect(
        dbname=os.environ.get('POSTGRES_DB', 'labdb'),
        user=os.environ.get('POSTGRES_USER', 'labuser'),
        password=os.environ.get('POSTGRES_PASSWORD', 'labpass'),
        host=os.environ.get('POSTGRES_HOST', 'db'),
        port=os.environ.get('POSTGRES_PORT', 5432),
    )
