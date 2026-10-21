"""Analyse antivirus des fichiers déposés, via le démon ClamAV (clamd).

Principes de sécurité :
- le contenu est envoyé à ClamAV par le réseau (commande INSTREAM), par blocs
  de 1 Mo : ClamAV tourne dans un autre conteneur et ne voit pas les fichiers
  de Django, et un fichier volumineux n'est jamais chargé en mémoire ;
- « fail closed » : si ClamAV est injoignable ou renvoie une erreur
  (fichier trop volumineux, base de signatures absente…), le fichier est
  refusé. Aucun fichier n'est accepté sans analyse réelle.
"""
import io
import logging
import socket
import struct

import clamd
from django.conf import settings

logger = logging.getLogger(__name__)


class ScanIndisponible(Exception):
    """ClamAV ne répond pas : le fichier ne peut pas être analysé."""


class ScanErreur(Exception):
    """ClamAV a répondu par une erreur (ex. taille maximale d'analyse dépassée)."""


def get_client():
    try:
        cd = clamd.ClamdNetworkSocket(
            host=getattr(settings, 'CLAMAV_TCP_HOST', 'clamav'),
            port=getattr(settings, 'CLAMAV_TCP_PORT', 3310),
            timeout=10,  # simple vérification de disponibilité
        )
        cd.ping()
        return cd
    except Exception as e:
        raise ScanIndisponible(f"ClamAV injoignable : {e}")


BLOC = 1024 * 1024  # taille des morceaux envoyés à ClamAV (1 Mo)


def _instream(source):
    """Envoie le contenu de `source` à clamd (protocole INSTREAM) par blocs de 1 Mo.

    Le fichier n'est jamais chargé entièrement en mémoire. Retourne la réponse
    brute de clamd, par exemple « stream: OK » ou « stream: Eicar-Signature FOUND ».
    """
    hote = getattr(settings, 'CLAMAV_TCP_HOST', 'clamav')
    port = getattr(settings, 'CLAMAV_TCP_PORT', 3310)
    delai = getattr(settings, 'CLAMAV_TIMEOUT', 600)
    try:
        connexion = socket.create_connection((hote, port), timeout=delai)
    except OSError as e:
        raise ScanIndisponible(f"ClamAV injoignable : {e}")

    with connexion:
        try:
            connexion.sendall(b'zINSTREAM\0')
            while True:
                bloc = source.read(BLOC)
                if not bloc:
                    break
                connexion.sendall(struct.pack('!L', len(bloc)) + bloc)
            connexion.sendall(struct.pack('!L', 0))
            reponse = b''
            while not reponse.endswith(b'\0'):
                recu = connexion.recv(4096)
                if not recu:
                    break
                reponse += recu
        except OSError as e:
            # clamd ferme la connexion quand StreamMaxLength est dépassé.
            raise ScanErreur(f"Analyse interrompue (fichier trop volumineux pour ClamAV ?) : {e}")
    return reponse.rstrip(b'\0').decode('utf-8', errors='replace').strip()


def scanner_fichier(source):
    """Analyse un fichier ouvert en mode binaire (lu depuis sa position actuelle).

    Retourne ('sain', None) ou ('infecte', nom_de_la_signature).
    Lève ScanIndisponible ou ScanErreur si l'analyse n'a pas pu être faite.
    """
    reponse = _instream(source)
    if reponse.endswith('OK') and not reponse.endswith('FOUND'):
        return 'sain', None
    if reponse.endswith('FOUND'):
        signature = reponse.split(':', 1)[-1].rsplit('FOUND', 1)[0].strip()
        return 'infecte', signature or 'signature inconnue'
    logger.error(f"ClamAV a renvoyé une erreur : {reponse}")
    raise ScanErreur(reponse or 'réponse vide')


def scanner_contenu(contenu: bytes):
    """Analyse un contenu déjà en mémoire (petits fichiers, tests)."""
    return scanner_fichier(io.BytesIO(contenu))


def get_statut_clamav() -> dict:
    try:
        cd = get_client()
        version = cd.version()
        return {'disponible': True, 'version': version, 'mode': 'ClamAV actif'}
    except ScanIndisponible:
        return {'disponible': False, 'version': None, 'mode': 'ClamAV indisponible (dépôts refusés)'}
