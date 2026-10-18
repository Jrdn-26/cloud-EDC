import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from django.conf import settings


BLOC_SIZE = 64 * 1024


def _get_key() -> bytes:
    raw = getattr(settings, 'FILE_ENCRYPTION_KEY', settings.SECRET_KEY)
    return hashlib.sha256(raw.encode()).digest()


def chiffrer_fichier(chemin_source: str, chemin_dest: str) -> str:
    cle = _get_key()
    iv = os.urandom(16)
    cipher = AES.new(cle, AES.MODE_CBC, iv)
    with open(chemin_source, 'rb') as f_in, open(chemin_dest, 'wb') as f_out:
        while True:
            bloc = f_in.read(BLOC_SIZE)
            if not bloc:
                break
            f_out.write(cipher.encrypt(pad(bloc, AES.block_size)))
    return iv.hex()


def dechiffrer_fichier(chemin_chiffre: str, iv_hex: str) -> bytes:
    cle = _get_key()
    iv = bytes.fromhex(iv_hex)
    cipher = AES.new(cle, AES.MODE_CBC, iv)
    chunks = []
    with open(chemin_chiffre, 'rb') as f:
        while True:
            bloc = f.read(BLOC_SIZE)
            if not bloc:
                break
            chunks.append(cipher.decrypt(bloc))
    if not chunks:
        return b''
    last = unpad(chunks[-1], AES.block_size)
    return b''.join(chunks[:-1]) + last


def chiffrer_en_memoire(data: bytes):
    cle = _get_key()
    iv = os.urandom(16)
    cipher = AES.new(cle, AES.MODE_CBC, iv)
    chiffre = cipher.encrypt(pad(data, AES.block_size))
    return chiffre, iv.hex()


def dechiffrer_en_memoire(data: bytes, iv_hex: str) -> bytes:
    cle = _get_key()
    iv = bytes.fromhex(iv_hex)
    cipher = AES.new(cle, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)
