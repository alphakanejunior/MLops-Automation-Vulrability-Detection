# Image de base volontairement vulnérable
FROM ubuntu:20.04

# Éviter interactions apt
ENV DEBIAN_FRONTEND=noninteractive

# Installer de vieux paquets vulnérables OS
RUN apt-get update && \
    apt-get install -y \
        wget=1.20.* \
        curl=7.68.* \
        openssl=1.1.* \
        python3=3.8.* \
        python3-pip \
        nodejs=10.* \
        npm=6.* \
        vim=2:8.1.* \
        sudo=1.8.* \
        netcat \
        && rm -rf /var/lib/apt/lists/*

# Installer des libs Python vulnérables
RUN pip3 install \
    flask==0.12 \
    requests==2.19.0 \
    numpy==1.15.0 \
    pillow==6.2.0 \
    django==1.11.0

# Installer des libs Node.js vulnérables
RUN npm install -g \
    lodash@4.17.4 \
    express@3.0.0 \
    jquery@1.6.0

# Ajouter un utilisateur avec un mot de passe faible
RUN useradd -ms /bin/bash tester && echo "tester:123" | chpasswd

# Ajout d’une mauvaise règle sudo (failles assurées)
RUN echo "tester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/vuln

# Ajouter des credentials en clair pour simulation
RUN echo "AWS_SECRET_KEY = 123456789TEST" >> /root/.env

# Exposer un port sensible
EXPOSE 22

# Script Python vulnérable intentionnellement
RUN echo " \
from flask import Flask\n\
app = Flask(__name__)\n\
@app.route('/')\n\
def home():\n\
    return 'Vulnerable test container'\n\
app.run(host='0.0.0.0', port=5000)\n\
" > /app.py

CMD [ "python3", "/app.py" ]
