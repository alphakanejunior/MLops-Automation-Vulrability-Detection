FROM python:3.13-slim

# Créer utilisateur non-root
RUN useradd -m mluser

WORKDIR /app

# Installer les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt scikit-learn==1.7.2 joblib==1.5.2 flask pandas  # ajoute toutes les autres dépendances de ton app

# Copier TOUT le projet (dont app.py)
COPY . .

# Permissions
RUN chown -R mluser:mluser /app
USER mluser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://127.0.0.1:8080/ || exit 1

CMD ["python", "app.py"]
