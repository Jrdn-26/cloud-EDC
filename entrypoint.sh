#!/bin/bash
set -e

echo "⏳ Attente de PostgreSQL..."
until python -c "import os, psycopg2; psycopg2.connect(host=os.environ['DB_HOST'], dbname=os.environ['DB_NAME'], user=os.environ['DB_USER'], password=os.environ['DB_PASSWORD'])" 2>/dev/null; do
    sleep 2
done
echo "✅ PostgreSQL prêt."

echo "🔄 Migrations..."
python manage.py migrate --noinput

echo "📦 Collecte des fichiers statiques..."
python manage.py collectstatic --noinput --clear

echo "👤 Création du superutilisateur (si absent)..."
python manage.py shell << 'PYEOF' || true
from django.contrib.auth.models import User
import os
email = os.getenv('DJANGO_SUPERUSER_EMAIL', 'admin@edc.cm')
password = os.environ['DJANGO_SUPERUSER_PASSWORD']
if not User.objects.filter(email=email).exists():
    User.objects.create_superuser(username=email.split('@')[0], email=email, password=password)
    print(f"✅ Superuser créé : {email}")
else:
    print("ℹ️ Superuser déjà existant.")
PYEOF

echo "🚀 Lancement de Gunicorn..."
exec gunicorn projet.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout 900
