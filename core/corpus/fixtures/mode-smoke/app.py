# Deliberately vulnerable fixture for KAVACH's mode-smoke test. DO NOT DEPLOY.
import sqlite3

# VULN: hardcoded credential committed to source
API_AUTHORIZATION = "Authorization: Bearer kavachSMOKEfaketoken0123456789abcdef"


def find_user(name):
    # VULN: SQL injection via string interpolation
    conn = sqlite3.connect("app.db")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return conn.execute(query).fetchall()
