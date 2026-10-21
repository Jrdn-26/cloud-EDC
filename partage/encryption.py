"""Chiffrement des fichiers stockés.

Format actuel (v2) : AES-256-GCM
- clé aléatoire de 256 bits lue dans FILE_ENCRYPTION_KEY_V2 (base64) ;
- nonce aléatoire de 96 bits par fichier, stocké dans Fichier.iv_chiffrement
  sous la forme « gcm:<nonce hex> » ;
- l'étiquette d'authentification (16 octets) est ajoutée à la fin du fichier :
  toute modification du fichier chiffré est détectée au déchiffrement.

Ancien format (v1, lecture seule) : AES-256-CBC, clé = SHA-256 de
FILE_ENCRYPTION_KEY, IV stocké en hexadécimal. Il reste lisible pour les
fichiers existants ; la commande « python manage.py rechiffrer_fichiers »
les convertit au format v2.
"""
import base64
import binascii
import hashlib
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

PREFIXE_GCM = 'gcm:'
TAILLE_NONCE = 12
TAILLE_TAG = 16
BLOC = 1024 * 1024  # 1 Mo : la mémoire utilisée ne dépend pas de la taille du fichier


def _cle_v2() -> bytes:
    brute = getattr(settings, 'FILE_ENCRYPTION_KEY_V2', '') or ''
    try:
        cle = base64.b64decode(brute, validate=True)
    except (binascii.Error, ValueError):
        cle = b''
    if len(cle) != 32:
        raise ImproperlyConfigured(
            "FILE_ENCRYPTION_KEY_V2 doit contenir 32 octets aléatoires encodés en base64 "
            "(générer avec : openssl rand -base64 32)."
        )
    return cle


def _cle_v1() -> bytes:
    """Clé de l'ancien format, conservée uniquement pour relire les anciens fichiers."""
    raw = getattr(settings, 'FILE_ENCRYPTION_KEY', '') or settings.SECRET_KEY
    return hashlib.sha256(raw.encode()).digest()


def est_format_v2(iv_champ: str) -> bool:
    return bool(iv_champ) and iv_champ.startswith(PREFIXE_GCM)


def chiffrer_en_memoire(data: bytes):
    """Chiffre en AES-256-GCM. Retourne (contenu_chiffre, valeur_du_champ_iv)."""
    nonce = os.urandom(TAILLE_NONCE)
    cipher = AES.new(_cle_v2(), AES.MODE_GCM, nonce=nonce)
    chiffre, tag = cipher.encrypt_and_digest(data)
    return chiffre + tag, PREFIXE_GCM + nonce.hex()


def dechiffrer_en_memoire(data: bytes, iv_champ: str) -> bytes:
    """Déchiffre un contenu, quel que soit son format (v2 GCM ou ancien v1 CBC).

    En v2, lève ValueError si le fichier a été modifié ou si la clé est fausse.
    """
    if est_format_v2(iv_champ):
        nonce = bytes.fromhex(iv_champ[len(PREFIXE_GCM):])
        if len(data) < TAILLE_TAG:
            raise ValueError("Fichier chiffré tronqué.")
        chiffre, tag = data[:-TAILLE_TAG], data[-TAILLE_TAG:]
        cipher = AES.new(_cle_v2(), AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(chiffre, tag)

    iv = bytes.fromhex(iv_champ)
    cipher = AES.new(_cle_v1(), AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)


# ── Traitement par blocs (fichiers volumineux) ─────────────────────────────

def chiffrer_flux(source, destination, empreinte=None) -> str:
    """Chiffre en AES-256-GCM le contenu de `source` vers `destination`, par blocs de 1 Mo.

    `source` et `destination` sont des objets fichier ouverts en mode binaire.
    L'étiquette d'authentification est écrite à la fin de `destination`.
    Si `empreinte` (un objet hashlib) est fourni, il est mis à jour avec le
    contenu d'origine au passage : l'empreinte ne coûte aucune lecture de plus.
    Retourne la valeur à enregistrer dans Fichier.iv_chiffrement.
    """
    nonce = os.urandom(TAILLE_NONCE)
    cipher = AES.new(_cle_v2(), AES.MODE_GCM, nonce=nonce)
    while True:
        bloc = source.read(BLOC)
        if not bloc:
            break
        if empreinte is not None:
            empreinte.update(bloc)
        destination.write(cipher.encrypt(bloc))
    destination.write(cipher.digest())
    return PREFIXE_GCM + nonce.hex()


def _nonce(iv_champ: str) -> bytes:
    return bytes.fromhex(iv_champ[len(PREFIXE_GCM):])


def taille_claire_v2(chemin: str) -> int:
    """Taille du fichier d'origine (fichier chiffré moins l'étiquette)."""
    taille = os.path.getsize(chemin)
    if taille < TAILLE_TAG:
        raise ValueError("Fichier chiffré tronqué.")
    return taille - TAILLE_TAG


def verifier_fichier_v2(chemin: str, iv_champ: str) -> None:
    """Relit tout le fichier et vérifie l'étiquette GCM, sans rien garder en mémoire.

    Lève ValueError si le fichier a été modifié ou si la clé est fausse.
    """
    reste = taille_claire_v2(chemin)
    cipher = AES.new(_cle_v2(), AES.MODE_GCM, nonce=_nonce(iv_champ))
    with open(chemin, 'rb') as f:
        while reste > 0:
            bloc = f.read(min(BLOC, reste))
            if not bloc:
                raise ValueError("Fichier chiffré tronqué.")
            reste -= len(bloc)
            cipher.decrypt(bloc)
        cipher.verify(f.read(TAILLE_TAG))


def dechiffrer_fichier_v2(chemin: str, iv_champ: str):
    """Générateur : renvoie le contenu déchiffré par blocs de 1 Mo.

    Ne vérifie pas l'étiquette : appeler verifier_fichier_v2() avant d'envoyer
    le moindre octet à l'utilisateur.
    """
    reste = taille_claire_v2(chemin)
    cipher = AES.new(_cle_v2(), AES.MODE_GCM, nonce=_nonce(iv_champ))
    with open(chemin, 'rb') as f:
        while reste > 0:
            bloc = f.read(min(BLOC, reste))
            if not bloc:
                raise ValueError("Fichier chiffré tronqué.")
            reste -= len(bloc)
            yield cipher.decrypt(bloc)


def chiffrer_v1_pour_tests(data: bytes):
    """Produit un contenu à l'ancien format (utilisé uniquement par les tests)."""
    iv = os.urandom(16)
    cipher = AES.new(_cle_v1(), AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size)), iv.hex()
