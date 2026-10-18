from django.contrib import admin
from .models import Fichier, LienPartage, LogAcces, ProfilUtilisateur


@admin.register(ProfilUtilisateur)
class ProfilAdmin(admin.ModelAdmin):
    list_display  = ('utilisateur', 'quota_gb', 'espace_utilise_mb', 'pourcentage_utilise')
    search_fields = ('utilisateur__username', 'utilisateur__email')
    readonly_fields = ('espace_utilise',)


@admin.register(Fichier)
class FichierAdmin(admin.ModelAdmin):
    list_display   = ('nom_original', 'proprietaire', 'taille', 'statut_scan', 'est_chiffre', 'date_upload')
    list_filter    = ('statut_scan', 'est_chiffre')
    search_fields  = ('nom_original', 'proprietaire__username')
    readonly_fields = ('iv_chiffrement',)


@admin.register(LienPartage)
class LienPartageAdmin(admin.ModelAdmin):
    list_display = ('fichier', 'cree_par', 'date_expiration', 'nb_telechargements', 'actif')
    list_filter  = ('actif',)


@admin.register(LogAcces)
class LogAccesAdmin(admin.ModelAdmin):
    list_display  = ('date_evenement', 'utilisateur', 'action', 'fichier', 'adresse_ip', 'detail')
    list_filter   = ('action',)
    search_fields = ('utilisateur__username', 'adresse_ip', 'detail')
    readonly_fields = ('date_evenement',)
