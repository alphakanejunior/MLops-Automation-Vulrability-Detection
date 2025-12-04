# Exemple éducatif ― Serveur IoT volontairement fragile (simulation)
from flask import Flask, request

app = Flask(__name__)

# 1. Mot de passe codé en dur
ADMIN_PASSWORD = "admin123"  # vulnérabilité intentionnelle

# 2. Endpoint sans authentification
@app.route("/temperature")
def temperature():
    return {"temperature": "22.5C"}

# 3. Pas de validation des entrées
@app.route("/set_name", methods=["POST"])
def set_name():
    device_name = request.form.get("name")  # aucune validation
    return {"status": "ok", "device_name_set_to": device_name}

# 4. Command injection simulée (ne lance rien)
@app.route("/diagnostic", methods=["POST"])
def diag():
    cmd = request.form.get("cmd", "")
    # Simulation : on ne l’exécute pas, on le retourne juste
    return {"received_command": cmd, "warning": "This would be dangerous on a real device"}

app.run(host="0.0.0.0", port=8080)