"""Calcule l'empreinte SHA-256 des fichiers déposés avant son introduction.

    python manage.py calculer_empreintes

Le fichier est déchiffré par blocs de 1 Mo, en mémoire seulement : rien n'est
écrit sur le disque. L'empreinte est aussi recopiée dans les lignes du journal
qui concernent ce fichier. Sans effet sur les fichiers qui ont déjà une empreinte.
"""
import hashlib

from django.core.management.base import BaseCommand

from partage.encryption import dechiffrer_en_memoire, dechiffrer_fichier_v2, est_format_v2, verifier_fichier_v2
from partage.models import Fichier, LogAcces


class Command(BaseCommand):
    help = "Calcule l'empreinte SHA-256 des fichiers qui n'en ont pas encore."

    def handle(self, *args, **options):
        ok = erreurs = 0
        for f in Fichier.objects.filter(empreinte_sha256=''):
            try:
                chemin = f.fichier.path
                empreinte = hashlib.sha256()
                if f.est_chiffre and est_format_v2(f.iv_chiffrement):
                    verifier_fichier_v2(chemin, f.iv_chiffrement)
                    for bloc in dechiffrer_fichier_v2(chemin, f.iv_chiffrement):
                        empreinte.update(bloc)
                elif f.est_chiffre and f.iv_chiffrement:
                    with open(chemin, 'rb') as h:
                        empreinte.update(dechiffrer_en_memoire(h.read(), f.iv_chiffrement))
                else:
                    with open(chemin, 'rb') as h:
                        for bloc in iter(lambda: h.read(1024 * 1024), b''):
                            empreinte.update(bloc)
                f.empreinte_sha256 = empreinte.hexdigest()
                f.save(update_fields=['empreinte_sha256'])
                LogAcces.objects.filter(fichier=f, empreinte_fichier='').update(empreinte_fichier=f.empreinte_sha256)
                ok += 1
                self.stdout.write(f"  ✓ #{f.id} {f.nom_original}  {f.empreinte_sha256[:16]}…")
            except Exception as e:
                erreurs += 1
                self.stderr.write(f"  ✗ #{f.id} {f.nom_original} : {e}")
        self.stdout.write(self.style.SUCCESS(f"{ok} empreinte(s) calculée(s), {erreurs} erreur(s)."))
