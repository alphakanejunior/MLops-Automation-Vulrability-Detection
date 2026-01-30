FROM python:3.10-slim

# Créer utilisateur non-root
RUN useradd -m mluser

WORKDIR /app

# Dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier TOUT le projet (dont app.py)
COPY . .

# Permissions
RUN chown -R mluser:mluser /app
USER mluser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://127.0.0.1:8080/ || exit 1

CMD ["python", "app.py"]
