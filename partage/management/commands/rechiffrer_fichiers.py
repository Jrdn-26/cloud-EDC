"""Convertit les fichiers chiffrés à l'ancien format (AES-CBC) vers AES-256-GCM.

Usage :
    python manage.py rechiffrer_fichiers --simulation   # liste sans rien modifier
    python manage.py rechiffrer_fichiers                # conversion réelle

Principes :
- traitement PAR BLOCS (1 Mo) : la mémoire utilisée reste constante, même pour
  des vidéos de plusieurs Go ;
- le nouveau fichier est écrit à côté (« .rechiffrement »), relu et vérifié
  (étiquette GCM + empreinte SHA-256 du contenu clair) AVANT tout remplacement ;
- reprise sûre après une interruption (Ctrl+C, plantage, coupure) : au
  démarrage, la commande répare les fichiers laissés dans un état intermédiaire
  par une exécution précédente, y compris par l'ancienne version de la commande.

Ordre des opérations pour un fichier :
    1. écrire <chemin>.rechiffrement (nouveau format), puis le vérifier ;
    2. enregistrer le nouvel IV en base (transaction validée) ;
    3. remplacer <chemin> par <chemin>.rechiffrement (opération atomique).
Si l'exécution s'arrête entre 2 et 3, la reprise termine l'étape 3.
"""
import hashlib
import os

from Crypto.Cipher import AES
from django.core.management.base import BaseCommand
from django.db import transaction

from partage.encryption import (PREFIXE_GCM, TAILLE_NONCE, TAILLE_TAG,
                                _cle_v1, _cle_v2, est_format_v2)
from partage.models import Fichier

BLOC = 1024 * 1024  # 1 Mo, multiple de 16


def _dechiffrer_v1_par_blocs(chemin, iv_hex):
    """Générateur : déchiffre un fichier AES-CBC (ancien format) bloc par bloc."""
    taille = os.path.getsize(chemin)
    if taille == 0 or taille % 16:
        raise ValueError("taille du fichier chiffré invalide")
    cipher = AES.new(_cle_v1(), AES.MODE_CBC, bytes.fromhex(iv_hex))
    lu = 0
    with open(chemin, 'rb') as f:
        while lu < taille:
            bloc = f.read(BLOC)
            lu += len(bloc)
            clair = cipher.decrypt(bloc)
            if lu >= taille:  # dernier bloc : retirer le remplissage PKCS#7
                n = clair[-1]
                if not 1 <= n <= 16 or clair[-n:] != bytes([n]) * n:
                    raise ValueError("clé incorrecte (remplissage invalide)")
                clair = clair[:-n]
            yield clair


def _verifier_v2_par_blocs(chemin, nonce):
    """Relit un fichier AES-GCM bloc par bloc, vérifie l'étiquette, renvoie le SHA-256 du clair."""
    taille = os.path.getsize(chemin)
    if taille < TAILLE_TAG:
        raise ValueError("fichier rechiffré tronqué")
    reste = taille - TAILLE_TAG
    cipher = AES.new(_cle_v2(), AES.MODE_GCM, nonce=nonce)
    empreinte = hashlib.sha256()
    with open(chemin, 'rb') as f:
        while reste > 0:
            bloc = f.read(min(BLOC, reste))
            reste -= len(bloc)
            empreinte.update(cipher.decrypt(bloc))
        cipher.verify(f.read(TAILLE_TAG))  # lève ValueError si le fichier est altéré
    return empreinte.hexdigest()


class Command(BaseCommand):
    help = "Rechiffre les fichiers de l'ancien format (AES-CBC) en AES-256-GCM, par blocs."

    def add_arguments(self, parser):
        parser.add_argument('--simulation', action='store_true',
                            help="Affiche les fichiers concernés sans rien modifier.")

    # ------------------------------------------------------------------
    def _reparer(self, simulation):
        """Remet en état les fichiers laissés à mi-parcours par une exécution interrompue."""
        repares = 0
        for f in Fichier.objects.filter(est_chiffre=True):
            chemin = f.fichier.path
            tmp = chemin + '.rechiffrement'
            ancien = chemin + '.ancien'  # laissé par l'ancienne version de la commande
            v2 = est_format_v2(f.iv_chiffrement)

            if os.path.exists(ancien):
                if v2 and not os.path.exists(chemin):
                    self.stderr.write(f"  ! #{f.id} {f.nom_original} : état inattendu, "
                                      f"aucune action (copie conservée : {ancien})")
                    continue
                if v2:
                    action = "conversion validée : suppression de la copie .ancien"
                    if not simulation:
                        os.unlink(ancien)
                else:
                    action = "conversion non validée : restauration de l'original"
                    if not simulation:
                        os.replace(ancien, chemin)
                repares += 1
                self.stdout.write(f"  ↺ #{f.id} {f.nom_original} : {action}")

            if os.path.exists(tmp):
                if v2:
                    action = "IV déjà en base : finalisation du remplacement"
                    if not simulation:
                        os.replace(tmp, chemin)
                else:
                    action = "conversion inachevée : suppression du fichier temporaire"
                    if not simulation:
                        os.unlink(tmp)
                repares += 1
                self.stdout.write(f"  ↺ #{f.id} {f.nom_original} : {action}")
        if repares:
            self.stdout.write(f"{repares} reprise(s) après interruption.")

    # ------------------------------------------------------------------
    def _convertir(self, f):
        chemin = f.fichier.path
        tmp = chemin + '.rechiffrement'
        nonce = os.urandom(TAILLE_NONCE)
        cipher = AES.new(_cle_v2(), AES.MODE_GCM, nonce=nonce)
        empreinte_source = hashlib.sha256()

        # 1. Écriture du nouveau fichier, bloc par bloc.
        try:
            with open(tmp, 'wb') as dst:
                for clair in _dechiffrer_v1_par_blocs(chemin, f.iv_chiffrement):
                    empreinte_source.update(clair)
                    dst.write(cipher.encrypt(clair))
                dst.write(cipher.digest())
                dst.flush()
                os.fsync(dst.fileno())
            # 2. Vérification complète avant de toucher à l'original.
            if _verifier_v2_par_blocs(tmp, nonce) != empreinte_source.hexdigest():
                raise ValueError("vérification après rechiffrement échouée")
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

        # 3. Base d'abord (transaction validée), puis remplacement atomique du fichier.
        with transaction.atomic():
            f.iv_chiffrement = PREFIXE_GCM + nonce.hex()
            f.save(update_fields=['iv_chiffrement'])
        os.replace(tmp, chemin)

    # ------------------------------------------------------------------
    def handle(self, *args, **options):
        simulation = options['simulation']
        self._reparer(simulation)

        anciens = [f for f in Fichier.objects.filter(est_chiffre=True).order_by('taille')
                   if f.iv_chiffrement and not est_format_v2(f.iv_chiffrement)]
        self.stdout.write(f"{len(anciens)} fichier(s) à l'ancien format.")
        if simulation:
            for f in anciens:
                self.stdout.write(f"  - #{f.id} {f.nom_original} ({round(f.taille / 1024**2, 1)} Mo)")
            return

        ok, erreurs = 0, 0
        for f in anciens:
            try:
                self._convertir(f)
                ok += 1
                self.stdout.write(f"  ✓ #{f.id} {f.nom_original}")
            except Exception as e:
                erreurs += 1
                self.stderr.write(f"  ✗ #{f.id} {f.nom_original} : {e}")

        self.stdout.write(self.style.SUCCESS(f"{ok} fichier(s) rechiffré(s), {erreurs} erreur(s)."))
