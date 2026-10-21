import os
import uuid
import secrets
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from django.db.models.signals import post_save
from django.dispatch import receiver


LONGUEUR_MAX_CHEMIN = 500


def chemin_upload(instance, filename):
    """Stocke chaque fichier dans 'CLOUD EDC/<username>/' sur le disque externe.

    Le nom d'origine est raccourci dans le chemin (il reste entier dans
    Fichier.nom_original) pour que le chemin tienne toujours dans la colonne.
    """
    base, ext = os.path.splitext(filename)
    nom_court = base[:120] + ext[:20]
    return f"CLOUD EDC/{instance.proprietaire.username}/{uuid.uuid4()}_{nom_court}.enc"


class ProfilUtilisateur(models.Model):
    utilisateur    = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profil')
    quota_octets   = models.BigIntegerField(default=20 * 1024 * 1024 * 1024)
    espace_utilise = models.BigIntegerField(default=0)
    sous_conservation = models.BooleanField(
        default=False,
        help_text="Conservation pour enquête : aucun fichier de ce compte n'est effacé, même après le délai."
    )
    taille_max_fichier_mb = models.PositiveIntegerField(
        default=100,
        help_text="Taille maximale d'un fichier uploadable par cet utilisateur (en MB)."
    )

    @property
    def quota_gb(self):
        return round(self.quota_octets / (1024 ** 3), 2)

    @property
    def espace_utilise_mb(self):
        return round(self.espace_utilise / (1024 ** 2), 2)

    @property
    def pourcentage_utilise(self):
        if self.quota_octets == 0:
            return 100
        return round((self.espace_utilise / self.quota_octets) * 100, 1)

    @property
    def espace_libre(self):
        return max(0, self.quota_octets - self.espace_utilise)

    def __str__(self):
        return f"Profil de {self.utilisateur.username} ({self.quota_gb} GB)"


@receiver(post_save, sender=User)
def creer_profil(sender, instance, created, **kwargs):
    if created:
        ProfilUtilisateur.objects.create(utilisateur=instance)


@receiver(post_save, sender=User)
def sauvegarder_profil(sender, instance, **kwargs):
    if hasattr(instance, 'profil'):
        instance.profil.save()


class Fichier(models.Model):
    STATUT_CHOICES = [
        ('en_attente', 'En attente de scan'),
        ('sain',       'Sain'),
        ('infecte',    'Infecté'),
    ]

    proprietaire   = models.ForeignKey(User, on_delete=models.CASCADE, related_name='fichiers')
    nom_original   = models.CharField(max_length=255)
    fichier        = models.FileField(upload_to=chemin_upload, max_length=LONGUEUR_MAX_CHEMIN)
    taille         = models.PositiveIntegerField(default=0)
    date_upload    = models.DateTimeField(auto_now_add=True)
    statut_scan    = models.CharField(max_length=20, choices=STATUT_CHOICES, default='en_attente')
    resultat_scan  = models.CharField(max_length=255, blank=True, null=True)
    est_chiffre    = models.BooleanField(default=True)
    iv_chiffrement = models.CharField(max_length=64, blank=True, null=True)
    empreinte_sha256 = models.CharField(
        max_length=64, blank=True, db_index=True,
        help_text="Empreinte SHA-256 du contenu d'origine, calculée au dépôt."
    )
    duree_upload   = models.FloatField(default=0, help_text="Durée d'upload en secondes")
    # Corbeille
    supprime          = models.BooleanField(default=False, help_text="True = dans la corbeille")
    date_suppression  = models.DateTimeField(null=True, blank=True)
    # Suppression définitive demandée par l'utilisateur : le fichier disparaît de
    # son compte mais reste conservé (chiffré) jusqu'à « conserve_jusqua ».
    efface_par_utilisateur = models.DateTimeField(null=True, blank=True)
    conserve_jusqua        = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-date_upload']

    def __str__(self):
        return f"{self.nom_original} ({self.proprietaire.username})"



class LienPartage(models.Model):
    fichier                = models.ForeignKey(Fichier, on_delete=models.CASCADE, related_name='liens')
    token                  = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    cree_par               = models.ForeignKey(User, on_delete=models.CASCADE)
    date_creation          = models.DateTimeField(auto_now_add=True)
    date_expiration        = models.DateTimeField()
    nb_telechargements_max = models.PositiveIntegerField(null=True, blank=True)
    nb_telechargements     = models.PositiveIntegerField(default=0)
    actif                  = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        if not self.date_expiration:
            self.date_expiration = timezone.now() + timedelta(days=7)
        super().save(*args, **kwargs)

    def est_valide(self):
        if not self.actif:
            return False
        if timezone.now() > self.date_expiration:
            return False
        if self.nb_telechargements_max is not None and self.nb_telechargements >= self.nb_telechargements_max:
            return False
        if self.fichier.statut_scan != 'sain':
            return False
        if self.fichier.supprime:
            return False
        return True

    def __str__(self):
        return f"Lien {self.token} -> {self.fichier.nom_original}"


class LogAcces(models.Model):
    ACTION_CHOICES = [
        ('upload',             'Dépôt'),
        ('upload_refuse',      'Dépôt refusé'),
        ('creation_lien',      'Création de lien'),
        ('telechargement',     'Téléchargement'),
        ('fichier_altere',     'Fichier altéré, envoi refusé'),
        ('acces_refuse',       'Accès refusé'),
        ('suppression',        'Suppression'),
        ('restauration',       'Restauration'),
        ('config',             'Configuration'),
        ('consultation_admin', 'Consultation par un administrateur'),
        ('conservation',       'Conservation pour enquête'),
        ('purge',              'Effacement définitif'),
        ('connexion',          'Connexion'),
        ('connexion_echec',    'Échec de connexion'),
        ('otp_echec',          'Code de vérification refusé'),
        ('limite_depassee',    'Trop de tentatives'),
    ]

    utilisateur    = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    adresse_ip     = models.GenericIPAddressField(null=True, blank=True)
    action         = models.CharField(max_length=30, choices=ACTION_CHOICES)
    fichier        = models.ForeignKey(Fichier, on_delete=models.SET_NULL, null=True, blank=True)
    lien           = models.ForeignKey(LienPartage, on_delete=models.SET_NULL, null=True, blank=True)
    detail         = models.CharField(max_length=255, blank=True)
    date_evenement = models.DateTimeField(auto_now_add=True)
    # Copie des informations du fichier au moment de l'événement : le journal
    # reste lisible et probant même après l'effacement du fichier.
    nom_fichier       = models.CharField(max_length=255, blank=True)
    taille_fichier    = models.BigIntegerField(null=True, blank=True)
    empreinte_fichier = models.CharField(max_length=64, blank=True, db_index=True)

    @property
    def nom_affiche(self):
        return self.nom_fichier or (self.fichier.nom_original if self.fichier else '')

    class Meta:
        ordering = ['-date_evenement']

    def __str__(self):
        who = self.utilisateur.username if self.utilisateur else self.adresse_ip
        return f"[{self.date_evenement:%Y-%m-%d %H:%M}] {who} - {self.action}"


class CodeOTP(models.Model):
    """Code a usage unique (6 chiffres) envoye par courriel.

    Securite : genere avec le module `secrets`, valable 10 minutes,
    invalide apres MAX_TENTATIVES essais incorrects.
    """
    MAX_TENTATIVES = 5
    DUREE_VALIDITE = timedelta(minutes=10)

    utilisateur = models.ForeignKey(User, on_delete=models.CASCADE, related_name='codes_otp')
    code        = models.CharField(max_length=6)
    expire_le   = models.DateTimeField()
    utilise     = models.BooleanField(default=False)
    tentatives  = models.PositiveSmallIntegerField(default=0)
    cree_le     = models.DateTimeField(auto_now_add=True)

    def est_valide(self):
        return (
            not self.utilise
            and self.tentatives < self.MAX_TENTATIVES
            and timezone.now() <= self.expire_le
        )

    @classmethod
    def generer(cls, utilisateur):
        cls.objects.filter(utilisateur=utilisateur, utilise=False).delete()
        code = f"{secrets.randbelow(10 ** 6):06d}"
        return cls.objects.create(
            utilisateur=utilisateur,
            code=code,
            expire_le=timezone.now() + cls.DUREE_VALIDITE,
        )

    @classmethod
    def verifier(cls, utilisateur, code_saisi):
        """Verifie le code saisi pour cet utilisateur.

        Retourne 'ok', 'incorrect', 'expire' ou 'bloque'.
        Chaque echec est compte ; au-dela de MAX_TENTATIVES le code est inutilisable.
        """
        if utilisateur is None:
            return 'incorrect'
        otp = (cls.objects.filter(utilisateur=utilisateur, utilise=False)
               .order_by('-cree_le').first())
        if otp is None:
            return 'expire'
        if otp.tentatives >= cls.MAX_TENTATIVES:
            return 'bloque'
        if timezone.now() > otp.expire_le:
            return 'expire'
        if not secrets.compare_digest(otp.code, (code_saisi or '').strip()):
            otp.tentatives += 1
            otp.save(update_fields=['tentatives'])
            return 'bloque' if otp.tentatives >= cls.MAX_TENTATIVES else 'incorrect'
        otp.utilise = True
        otp.save(update_fields=['utilise'])
        return 'ok'

    def __str__(self):
        etat = 'utilise' if self.utilise else 'valide'
        return f"OTP {self.utilisateur.username} ({etat})"



# ==============================================================================
# CONFIGURATION GLOBALE DU CLOUD (singleton)
# ==============================================================================
class ConfigurationCloud(models.Model):
    """Configuration globale du cloud (une seule ligne)."""
    extensions_autorisees = models.TextField(
        default='pdf,doc,docx,xls,xlsx,ppt,pptx,odt,ods,odp,txt,csv,'
                'jpg,jpeg,png,gif,bmp,svg,webp,'
                'mp4,avi,mov,mkv,webm,'
                'mp3,wav,ogg,flac,'
                'zip,rar,7z,tar,gz,'
                'json,xml,html,css,js,py',
        help_text="Liste des extensions autorisées, séparées par des virgules (sans le point)."
    )
    taille_max_mb = models.PositiveIntegerField(
        default=100,
        help_text="Taille maximale d'un fichier en MB."
    )
    duree_conservation_jours = models.PositiveIntegerField(
        default=90,
        help_text="Durée de conservation d'un fichier après sa suppression définitive par l'utilisateur."
    )
    maj_le = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Configuration du Cloud"
        verbose_name_plural = "Configuration du Cloud"

    def __str__(self):
        return "Configuration globale"

    def liste_extensions(self):
        """Retourne la liste propre des extensions (sans point, en minuscules)."""
        return [
            ext.strip().lower().lstrip('.')
            for ext in self.extensions_autorisees.split(',')
            if ext.strip()
        ]

    def taille_max_bytes(self):
        return self.taille_max_mb * 1024 * 1024

    @classmethod
    def get_config(cls):
        """Récupère l'unique configuration (crée si elle n'existe pas)."""
        config, _ = cls.objects.get_or_create(pk=1)
        return config
