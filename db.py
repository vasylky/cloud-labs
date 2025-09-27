import mysql.connector
from app import get_secret  

def get_connection():
    creds = get_secret()
    return mysql.connector.connect(
        host=creds["host"],
        user=creds["user"],
        password=creds["password"],
        database=creds["database"]
    )
