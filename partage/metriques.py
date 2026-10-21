"""Métriques de Cloud EDC au format Prometheus (page /metrics).

Ces métriques complètent celles du système (node-exporter, cAdvisor) avec ce
que seule l'application connaît : connexions, codes refusés, virus bloqués,
consultations par un administrateur, fichiers conservés…

Accès : uniquement avec le jeton METRICS_TOKEN (en-tête « Authorization:
Bearer … »), envoyé par Prometheus sur le réseau Docker interne. Nginx bloque
de son côté /metrics depuis l'extérieur. Sans METRICS_TOKEN, la page n'existe pas.
"""
import secrets
import socket

from django.conf import settings
from django.contrib.auth.models import User
from django.db.models import Count, Q, Sum
from django.http import Http404, HttpResponse
from django.utils import timezone
from django.views.decorators.http import require_GET

from .models import Fichier, LogAcces, ProfilUtilisateur


def _ligne(nom, valeur, etiquettes=None):
    if etiquettes:
        texte = ','.join(f'{cle}="{val}"' for cle, val in etiquettes.items())
        return f'{nom}{{{texte}}} {valeur}'
    return f'{nom} {valeur}'


def _metrique(lignes, nom, type_, aide, valeurs):
    """Ajoute une métrique ; `valeurs` est une liste de (étiquettes, valeur)."""
    lignes.append(f'# HELP {nom} {aide}')
    lignes.append(f'# TYPE {nom} {type_}')
    for etiquettes, valeur in valeurs:
        lignes.append(_ligne(nom, valeur, etiquettes))


def _clamav_disponible():
    """PING rapide (3 s maximum) : la lecture des métriques ne doit jamais bloquer Prometheus."""
    try:
        with socket.create_connection((getattr(settings, 'CLAMAV_TCP_HOST', 'clamav'),
                                       getattr(settings, 'CLAMAV_TCP_PORT', 3310)), timeout=3) as s:
            s.sendall(b'zPING\0')
            return 1 if s.recv(16).startswith(b'PONG') else 0
    except OSError:
        return 0


def generer_metriques():
    lignes = []
    maintenant = timezone.now()

    # Événements du journal, par type : compteurs qui ne font qu'augmenter.
    # Dans Grafana : increase(cloud_edc_evenements_total{action="connexion_echec"}[5m])
    par_action = dict(LogAcces.objects.values_list('action').annotate(n=Count('id')))
    _metrique(lignes, 'cloud_edc_evenements_total', 'counter',
              "Nombre d'événements enregistrés dans le journal, par type d'action.",
              [({'action': code}, par_action.get(code, 0)) for code, _ in LogAcces.ACTION_CHOICES])

    utilisateurs = User.objects.aggregate(actifs=Count('id', filter=Q(is_active=True)),
                                          desactives=Count('id', filter=Q(is_active=False)))
    _metrique(lignes, 'cloud_edc_utilisateurs', 'gauge', "Nombre de comptes utilisateurs.",
              [({'etat': 'actif'}, utilisateurs['actifs']), ({'etat': 'desactive'}, utilisateurs['desactives'])])

    _metrique(lignes, 'cloud_edc_comptes_sous_conservation', 'gauge',
              "Comptes placés sous conservation (enquête en cours).",
              [(None, ProfilUtilisateur.objects.filter(sous_conservation=True).count())])

    etats = {
        'actif': Q(supprime=False),
        'corbeille': Q(supprime=True, efface_par_utilisateur__isnull=True),
        'conserve': Q(efface_par_utilisateur__isnull=False),
    }
    fichiers = Fichier.objects.aggregate(**{
        f'n_{e}': Count('id', filter=q) for e, q in etats.items()
    }, **{
        f'o_{e}': Sum('taille', filter=q) for e, q in etats.items()
    })
    _metrique(lignes, 'cloud_edc_fichiers', 'gauge', "Nombre de fichiers, par état.",
              [({'etat': e}, fichiers[f'n_{e}']) for e in etats])
    _metrique(lignes, 'cloud_edc_stockage_octets', 'gauge', "Volume des fichiers d'origine, par état.",
              [({'etat': e}, fichiers[f'o_{e}'] or 0) for e in etats])

    _metrique(lignes, 'cloud_edc_fichiers_echeance_depassee', 'gauge',
              "Fichiers dont la conservation est échue mais pas encore effacés (la purge ne tourne pas ?).",
              [(None, Fichier.objects.filter(conserve_jusqua__lt=maintenant)
                .exclude(proprietaire__profil__sous_conservation=True).count())])

    ratio = 0.0
    for p in ProfilUtilisateur.objects.filter(quota_octets__gt=0).only('espace_utilise', 'quota_octets'):
        ratio = max(ratio, p.espace_utilise / p.quota_octets)
    _metrique(lignes, 'cloud_edc_quota_utilisation_max_ratio', 'gauge',
              "Taux d'utilisation du quota le plus rempli (0 à 1).", [(None, round(ratio, 4))])

    _metrique(lignes, 'cloud_edc_clamav_disponible', 'gauge',
              "1 si l'antivirus répond, 0 sinon (les dépôts sont alors refusés).",
              [(None, _clamav_disponible())])

    return '\n'.join(lignes) + '\n'


@require_GET
def metriques(request):
    jeton = getattr(settings, 'METRICS_TOKEN', '')
    if not jeton:
        raise Http404()
    attendu = f'Bearer {jeton}'
    if not secrets.compare_digest(request.headers.get('Authorization', ''), attendu):
        raise Http404()
    return HttpResponse(generer_metriques(), content_type='text/plain; version=0.0.4; charset=utf-8')
