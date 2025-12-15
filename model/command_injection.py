"""
Code pédagogique vulnérable pour tester l'enrichissement NVD.
Déclenche des CWE/CVE réelles, NE PAS UTILISER EN PROD.
"""

import os
import pickle
import sqlite3
import yaml

# ==================================================
# 1️⃣ Hardcoded password – CWE-259
# ==================================================
DB_PASSWORD = "admin123"
def connect_db():
    print("Connecting with password:", DB_PASSWORD)

# ==================================================
# 2️⃣ Command Injection – CWE-78 (CVE possible)
# ==================================================
def ping_host(host):
    os.system("ping -c 1 " + host)

# ==================================================
# 3️⃣ Unsafe eval – CWE-94
# ==================================================
def calculate(expr):
    return eval(expr)

# ==================================================
# 4️⃣ Insecure Deserialization – CWE-502 / CVE-2022-42969
# ==================================================
def load_pickle(data):
    return pickle.loads(data)

# ==================================================
# 5️⃣ SQL Injection – CWE-89 (CVE possible)
# ==================================================
def get_user(username):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (name TEXT)")
    cursor.execute("INSERT INTO users VALUES ('admin')")
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

# ==================================================
# 6️⃣ Unsafe YAML load – CWE-94 / CVE-2020-14343
# ==================================================
def load_yaml(yaml_string):
    return yaml.load(yaml_string, Loader=yaml.Loader)

# ==================================================
# MAIN TEST
# ==================================================
if __name__ == "__main__":
    connect_db()
    ping_host("127.0.0.1; ls")
    print(calculate("2 + 2"))
    load_pickle(pickle.dumps({"test": "data"}))
    print(get_user("admin' OR '1'='1"))
    print(load_yaml("key: value"))
