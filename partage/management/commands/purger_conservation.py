"""Efface les fichiers dont la durée de conservation est écoulée.

À lancer chaque jour, par exemple avec cron sur la VM :
    15 2 * * *  docker exec djc-django python manage.py purger_conservation
(La purge est aussi lancée à chaque ouverture de la Corbeille générale.)
"""
from django.core.management.base import BaseCommand

from partage.conservation import purger_fichiers_expires


class Command(BaseCommand):
    help = "Efface les fichiers supprimés dont la durée de conservation est écoulée."

    def handle(self, *args, **options):
        nombre = purger_fichiers_expires()
        self.stdout.write(f"{nombre} fichier(s) effacé(s).")
