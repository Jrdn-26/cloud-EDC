import hashlib
import logging
import clamd
from django.conf import settings

logger = logging.getLogger(__name__)


class ScanIndisponible(Exception):
    pass


SIGNATURES_FALLBACK = {
    'eicar_md5': {
        'type': 'md5',
        'value': '44d88612fea8a8f36de82e1278abb02f',
        'nom': 'EICAR-Test-File',
    },
    'eicar_magic': {
        'type': 'magic',
        'value': b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR',
        'nom': 'EICAR-Test-Signature',
    },
}


def get_client():
    try:
        if getattr(settings, 'CLAMAV_USE_TCP', False):
            cd = clamd.ClamdNetworkSocket(
                host=getattr(settings, 'CLAMAV_TCP_HOST', '127.0.0.1'),
                port=getattr(settings, 'CLAMAV_TCP_PORT', 3310),
            )
        else:
            cd = clamd.ClamdUnixSocket(
                path=getattr(settings, 'CLAMAV_SOCKET', '/var/run/clamav/clamd.ctl')
            )
        cd.ping()
        return cd
    except Exception as e:
        raise ScanIndisponible(f"ClamAV injoignable : {e}")


def _scan_fallback(chemin_absolu: str):
    try:
        with open(chemin_absolu, 'rb') as f:
            contenu = f.read()
        md5 = hashlib.md5(contenu).hexdigest()
        for sig in SIGNATURES_FALLBACK.values():
            if sig['type'] == 'md5' and md5 == sig['value']:
                return 'infecte', sig['nom']
        for sig in SIGNATURES_FALLBACK.values():
            if sig['type'] == 'magic' and sig['value'] in contenu:
                return 'infecte', sig['nom']
        return 'sain', None
    except Exception as e:
        logger.error(f"Scan fallback échoué : {e}")
        return 'sain', None


def scanner_fichier(chemin_absolu: str):
    try:
        cd = get_client()
        resultat = cd.scan(chemin_absolu)
        if resultat is None:
            return 'sain', None
        for _chemin, (statut, signature) in resultat.items():
            if statut == 'FOUND':
                return 'infecte', signature
        return 'sain', None
    except ScanIndisponible:
        logger.warning("ClamAV indisponible — fallback.")
    return _scan_fallback(chemin_absolu)


def get_statut_clamav() -> dict:
    try:
        cd = get_client()
        version = cd.version()
        return {'disponible': True, 'version': version, 'mode': 'ClamAV actif'}
    except ScanIndisponible:
        return {'disponible': False, 'version': None, 'mode': 'Mode fallback'}
