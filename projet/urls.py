import os

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', include('partage.urls')),
]

# L'interface d'administration native de Django se connecte par mot de passe
# seul (sans OTP). Elle est désactivée par défaut ; l'administration du cloud
# se fait par /admin-cloud/, protégée par la connexion avec OTP.
if os.getenv('ENABLE_DJANGO_ADMIN', 'False').strip().lower() == 'true':
    urlpatterns.insert(0, path('django-admin/', admin.site.urls))

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
