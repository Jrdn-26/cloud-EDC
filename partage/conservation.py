"""Conservation des fichiers supprimés et effacement à l'échéance.

Quand un utilisateur supprime définitivement un fichier (depuis sa corbeille),
le fichier disparaît de son compte mais reste conservé, chiffré, pendant la
durée fixée dans les Règles de dépôt (90 jours par défaut). Pendant ce délai,
seul un administrateur peut le voir, avec un motif enregistré dans le journal.

À l'échéance, le fichier est effacé du disque. Le journal garde son nom, sa
taille et son empreinte SHA-256 : on peut toujours prouver ce qui a circulé.
Un compte placé « sous conservation » (enquête en cours) n'est jamais purgé.
"""
import logging
from datetime import timedelta

from django.utils import timezone

from .models import ConfigurationCloud, Fichier, LogAcces

logger = logging.getLogger(__name__)


def effacer_pour_utilisateur(fichier):
    """Retire le fichier du compte de son propriétaire et démarre la conservation.

    Libère l'espace dans le quota de l'utilisateur. Retourne la date de fin
    de conservation.
    """
    maintenant = timezone.now()
    duree = ConfigurationCloud.get_config().duree_conservation_jours
    fichier.supprime = True
    fichier.date_suppression = fichier.date_suppression or maintenant
    fichier.efface_par_utilisateur = maintenant
    fichier.conserve_jusqua = maintenant + timedelta(days=duree)
    fichier.save(update_fields=['supprime', 'date_suppression',
                                'efface_par_utilisateur', 'conserve_jusqua'])
    profil = fichier.proprietaire.profil
    profil.espace_utilise = max(0, profil.espace_utilise - fichier.taille)
    profil.save(update_fields=['espace_utilise'])
    return fichier.conserve_jusqua


def effacer_du_disque(fichier, journal_detail, utilisateur=None, adresse_ip=None):
    """Efface réellement le fichier (disque + base) en gardant sa trace dans le journal."""
    LogAcces.objects.create(
        utilisateur=utilisateur,
        adresse_ip=adresse_ip,
        action='purge',
        nom_fichier=fichier.nom_original[:255],
        taille_fichier=fichier.taille,
        empreinte_fichier=fichier.empreinte_sha256,
        detail=journal_detail[:255],
    )
    if fichier.efface_par_utilisateur is None:
        # Le fichier comptait encore dans le quota de son propriétaire.
        profil = fichier.proprietaire.profil
        profil.espace_utilise = max(0, profil.espace_utilise - fichier.taille)
        profil.save(update_fields=['espace_utilise'])
    fichier.fichier.delete(save=False)
    fichier.delete()


def purger_fichiers_expires():
    """Efface les fichiers dont la durée de conservation est écoulée. Retourne leur nombre."""
    expires = (Fichier.objects
               .filter(conserve_jusqua__lt=timezone.now())
               .exclude(proprietaire__profil__sous_conservation=True)
               .select_related('proprietaire__profil'))
    nombre = 0
    for fichier in expires:
        try:
            effacer_du_disque(
                fichier,
                f"Fin de la durée de conservation (propriétaire : {fichier.proprietaire.username})",
            )
            nombre += 1
        except Exception:
            logger.exception(f"Effacement impossible du fichier #{fichier.id}")
    if nombre:
        logger.info(f"{nombre} fichier(s) effacé(s) à la fin de leur durée de conservation.")
    return nombre
