import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
def _liste_env(nom, defaut=''):
    """Lit une variable d'environnement contenant une liste séparée par des virgules."""
    return [v.strip() for v in os.getenv(nom, defaut).split(',') if v.strip()]


# Secrets et mode : uniquement depuis le .env (aucune valeur par défaut connue)
SECRET_KEY = os.environ['SECRET_KEY']
DEBUG = os.getenv('DEBUG', 'False').strip().lower() == 'true'
ALLOWED_HOSTS = _liste_env('ALLOWED_HOSTS', 'localhost,127.0.0.1')
# « django » : nom du conteneur sur le réseau Docker, utilisé par Prometheus pour lire /metrics.
if 'django' not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append('django')
CSRF_TRUSTED_ORIGINS = _liste_env('CSRF_TRUSTED_ORIGINS', 'https://localhost')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'partage',
    'django_ratelimit',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Sans ce middleware, un dépassement donne une erreur 403 générique :
    # la page « Trop de tentatives » (429) et sa ligne de journal ne sont jamais produites.
    'django_ratelimit.middleware.RatelimitMiddleware',
]

ROOT_URLCONF = 'projet.urls'

TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [BASE_DIR / 'partage' / 'templates'],
    'APP_DIRS': True,
    'OPTIONS': {
        'context_processors': [
            'django.template.context_processors.debug',
            'django.template.context_processors.request',
            'django.contrib.auth.context_processors.auth',
            'django.contrib.messages.context_processors.messages',
        ],
    },
}]

WSGI_APPLICATION = 'projet.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME', 'clouddb'),
        'USER': os.getenv('DB_USER', 'cloudadmin'),
        'PASSWORD': os.environ["DB_PASSWORD"],
        'HOST': os.getenv('DB_HOST', 'postgres'),
        'PORT': os.getenv('DB_PORT', '5432'),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'fr-fr'
TIME_ZONE = 'Africa/Douala'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv('EMAIL_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
DEFAULT_FROM_EMAIL = f"Cloud EDC <{EMAIL_HOST_USER}>"


# ─────────────────────────────────────────
# SESSIONS, COOKIES ET EN-TÊTES DE SÉCURITÉ
# ─────────────────────────────────────────
SESSION_COOKIE_AGE = 3600
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True          # le cookie de session n'est pas lisible par JavaScript
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Lax'
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')   # écrit par Nginx
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Inscription réservée à certains domaines (ex. : ALLOWED_EMAIL_DOMAINS=edc.cm).
# Vide = tous les domaines acceptés.
ALLOWED_EMAIL_DOMAINS = [d.lower().lstrip('@') for d in _liste_env('ALLOWED_EMAIL_DOMAINS')]

# ─────────────────────────────────────────
# CHIFFREMENT DES FICHIERS
# ─────────────────────────────────────────
# Clé actuelle : 32 octets aléatoires en base64 (openssl rand -base64 32).
FILE_ENCRYPTION_KEY_V2 = os.getenv('FILE_ENCRYPTION_KEY_V2', '')
# Ancienne clé : conservée uniquement pour relire les fichiers pas encore rechiffrés.
FILE_ENCRYPTION_KEY = os.getenv('FILE_ENCRYPTION_KEY', '')

# ─────────────────────────────────────────
# ANTIVIRUS
# ─────────────────────────────────────────
CLAMAV_TCP_HOST = os.getenv('CLAMAV_HOST', 'clamav')
CLAMAV_TCP_PORT = 3310
# Jeton partagé avec Prometheus pour lire /metrics (vide = page désactivée).
METRICS_TOKEN = os.getenv('METRICS_TOKEN', '')
CLAMAV_TIMEOUT = 600  # analyse d'un fichier volumineux (jusqu'à 1 Go)

LOGIN_URL = '/connexion/'
LOGIN_REDIRECT_URL = '/mes-fichiers/'
LOGOUT_REDIRECT_URL = '/connexion/'
# ─────────────────────────────────────────
# LOGGING (DEBUG)
# ─────────────────────────────────────────
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}


# ─────────────────────────────────────────
# CACHE (pour la limitation de tentatives) — Redis
# django-ratelimit exige un cache partagé entre les workers Gunicorn et capable
# d'incrémenter ses compteurs de façon atomique : c'est le rôle de Redis.
# ─────────────────────────────────────────
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.getenv('REDIS_URL', 'redis://redis:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'KEY_PREFIX': 'cloud-edc',
    }
}

# ─────────────────────────────────────────
# LIMITATION DE TENTATIVES
# ─────────────────────────────────────────
RATELIMIT_VIEW = 'partage.views.ratelimited_view'
RATELIMIT_USE_CACHE = 'default'
RATELIMIT_FAIL_OPEN = False
# Adresse réelle du client, écrite par Nginx (sinon tous les clients auraient l'IP de Nginx).
RATELIMIT_IP_META_KEY = 'HTTP_X_REAL_IP'

# ─────────────────────────────────────────
# TAILLE DES ENVOIS
# ─────────────────────────────────────────
# Au-delà de 10 Mo, Django écrit le fichier reçu sur disque temporaire au lieu
# de le garder en mémoire. La taille maximale d'un fichier se règle dans
# l'administration du cloud (ConfigurationCloud.taille_max_mb).
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024
