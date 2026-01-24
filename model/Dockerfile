FROM python:3.10-slim

# Dossier de travail
WORKDIR /app

# Copier les dépendances
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copier le projet
COPY . .

# Exposer le port Flask
EXPOSE 5000

# Lancer l’API
CMD ["python", "app.py"]
