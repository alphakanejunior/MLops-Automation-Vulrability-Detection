import os
import yaml
import pickle
import subprocess
import tarfile

# ==========================================================
# CVE-2017-18342 — PyYAML unsafe load (RCE)
# CWE-502: Deserialization of Untrusted Data
# Bandit: B506
# ==========================================================
def load_yaml(data):
    return yaml.load(data)  # ❌ unsafe


# ==========================================================
# CVE-2011-2528 — Command Injection via os.system
# CWE-78: OS Command Injection
# Bandit: B605
# ==========================================================
def ping_host(host):
    os.system("ping -c 1 " + host)  # ❌ injection


# ==========================================================
# CVE-2019-20907 — Insecure pickle deserialization
# CWE-502
# Bandit: B301
# ==========================================================
def load_pickle(data):
    return pickle.loads(data)  # ❌ RCE


# ==========================================================
# CVE-2021-3177 — subprocess shell=True misuse
# CWE-78
# Bandit: B602
# ==========================================================
def list_directory(path):
    subprocess.call(f"ls {path}", shell=True)  # ❌ injection


# ==========================================================
# CVE-2007-4559 — Tarfile directory traversal
# CWE-22: Path Traversal
# Bandit: B202
# ==========================================================
def extract_tar(filename):
    with tarfile.open(filename) as tar:
        tar.extractall()  # ❌ path traversal


if __name__ == "__main__":
    load_yaml("!!python/object/apply:os.system ['echo YAML_RCE']")
    ping_host("127.0.0.1; whoami")
    load_pickle(b"cos\nsystem\n(S'echo PICKLE_RCE'\ntR.")
    list_directory("; id")
    extract_tar("evil.tar")
