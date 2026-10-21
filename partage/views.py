import hashlib
import os
import time
import logging
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.db.models import Sum
from django.http import FileResponse, Http404, HttpResponse, JsonResponse, StreamingHttpResponse
from django.urls import reverse
from django.utils.http import content_disposition_header
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils import timezone

from .antivirus import scanner_fichier, get_statut_clamav, ScanIndisponible, ScanErreur
from .encryption import (chiffrer_flux, dechiffrer_en_memoire, dechiffrer_fichier_v2,
                         est_format_v2, taille_claire_v2, verifier_fichier_v2)
from .forms import (
    InscriptionForm, UploadFichierForm, CreerLienForm,
    AllouerQuotaForm, VerifierOTPForm,
    MotDePasseOublieForm, NouveauMotDePasseForm,
)
from .models import (Fichier, LienPartage, LogAcces, ProfilUtilisateur, CodeOTP,
                     ConfigurationCloud, chemin_upload)
from .conservation import effacer_du_disque, effacer_pour_utilisateur, purger_fichiers_expires
from django_ratelimit.decorators import ratelimit

logger = logging.getLogger(__name__)


def get_ip(request):
    """Adresse IP reelle du client.

    Nginx ecrit X-Real-IP avec $remote_addr et ecrase toute valeur envoyee par
    le client. On ne lit jamais X-Forwarded-For, qui peut etre falsifie.
    """
    return request.META.get('HTTP_X_REAL_IP') or request.META.get('REMOTE_ADDR')


def journaliser(request, action, fichier=None, lien=None, detail='', nom=None, taille=None, utilisateur=None):
    """Enregistre un événement. Le nom, la taille et l'empreinte du fichier sont
    recopiés dans le journal pour qu'il reste probant après l'effacement du fichier."""
    LogAcces.objects.create(
        utilisateur=utilisateur or (request.user if request.user.is_authenticated else None),
        adresse_ip=get_ip(request),
        action=action,
        fichier=fichier,
        lien=lien,
        detail=detail[:255],
        nom_fichier=(nom if nom is not None else (fichier.nom_original if fichier else ''))[:255],
        taille_fichier=taille if taille is not None else (fichier.taille if fichier else None),
        empreinte_fichier=fichier.empreinte_sha256 if fichier else '',
    )


def is_admin(user):
    return user.is_authenticated and (user.is_staff or user.is_superuser)


def _masquer_email(email):
    if not email or '@' not in email:
        return email or '—'
    local, domaine = email.split('@', 1)
    return f"{local[0]}***@{domaine}"


def _envoyer_otp(user, code):
    """Envoie le code OTP par email. Retourne True si succès, False sinon."""
    sujet = f"Cloud EDC — Votre code de vérification : {code}"
    try:
        corps_html  = render_to_string('partage/email_otp.html', {'user': user, 'code': code})
        corps_texte = (
            f"Bonjour {user.username},\n\n"
            f"Votre code Cloud EDC : {code}\n\n"
            f"Valable 10 minutes. Ne le communiquez à personne.\n\n"
            f"— Electricity Development Corporation"
        )
        send_mail(
            subject=sujet,
            message=corps_texte,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@edc.cm'),
            recipient_list=[user.email],
            html_message=corps_html,
            fail_silently=False,
        )
        logger.info(f"Code OTP envoyé à {user.email}")
        return True
    except Exception as e:
        logger.error(f"Échec de l'envoi du code OTP à {user.email} : {e}")
        return False


def accueil(request):
    if request.user.is_authenticated:
        return redirect('mes_fichiers')
    return redirect('connexion')


@ratelimit(key='ip', rate='3/h', method='POST', block=True)
def inscription(request):
    if request.user.is_authenticated:
        return redirect('mes_fichiers')
    if request.method == 'POST':
        form = InscriptionForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Créer le dossier personnel de l'utilisateur sur le disque externe
            dossier_utilisateur = os.path.join(settings.MEDIA_ROOT, 'CLOUD EDC', user.username)
            os.makedirs(dossier_utilisateur, exist_ok=True)
            logger.info(f"Dossier créé pour {user.username} : {dossier_utilisateur}")

            otp = CodeOTP.generer(user)
            _envoyer_otp(user, otp.code)
            request.session['otp_user_id'] = user.id
            request.session['otp_context'] = 'inscription'
            messages.info(request, f"Un code de vérification a été envoyé à {_masquer_email(user.email)}.")
            return redirect('verifier_otp')
        else:
            messages.error(request, "Le formulaire contient des erreurs.")
    else:
        form = InscriptionForm()
    return render(request, 'partage/inscription.html', {'form': form})

@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def connexion_2fa(request):
    if request.user.is_authenticated:
        return redirect('mes_fichiers')

    if request.method == 'POST':
        email    = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')

        message_echec = "Adresse e-mail ou mot de passe incorrect."
        user_obj = User.objects.filter(email__iexact=email).first()
        user = None
        if user_obj is not None:
            user = authenticate(request, username=user_obj.username, password=password)

        if user is not None:
            # Tous les comptes, administrateurs compris, passent par l'OTP.
            otp = CodeOTP.generer(user)
            _envoyer_otp(user, otp.code)
            request.session['otp_user_id'] = user.id
            request.session['otp_context'] = 'connexion'
            messages.info(request, f"Un code de vérification a été envoyé à {_masquer_email(user.email)}. Il est valable 10 minutes.")
            return redirect('verifier_otp')

        if user_obj is not None and not user_obj.is_active and user_obj.check_password(password):
            journaliser(request, 'connexion_echec', utilisateur=user_obj, detail='Compte désactivé')
            messages.error(request, "Ce compte est désactivé. Contactez le service informatique.")
        else:
            journaliser(request, 'connexion_echec', utilisateur=user_obj,
                        detail=f"Adresse saisie : {email[:120]}" if user_obj is None else 'Mot de passe incorrect')
            messages.error(request, message_echec)
        return render(request, 'partage/connexion.html', {'email_saisi': email})

    return render(request, 'partage/connexion.html')

@ratelimit(key='ip', rate='10/5m', method='POST', block=True)
def verifier_otp(request):
    user_id = request.session.get('otp_user_id')
    if not user_id:
        messages.error(request, "Session expirée.")
        return redirect('connexion')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return redirect('connexion')

    if request.method == 'POST':
        form = VerifierOTPForm(request.POST)
        if form.is_valid():
            resultat = CodeOTP.verifier(user, form.cleaned_data['code'])

            if resultat == 'ok':
                contexte = request.session.pop('otp_context', 'connexion')
                next_url = request.session.pop('next_after_login', None)
                del request.session['otp_user_id']
                login(request, user)
                journaliser(request, 'connexion', detail='Connexion avec code de vérification')
                if contexte == 'inscription':
                    messages.success(request, f"Compte vérifié. Bienvenue, {user.username}.")
                else:
                    messages.success(request, f"Vous êtes connecté en tant que {user.username}.")

                # Redirection vers le lien partagé si présent (chemin interne uniquement)
                if next_url and next_url.startswith('/') and not next_url.startswith('//'):
                    messages.info(request, "Vous pouvez maintenant accéder au fichier partagé.")
                    return redirect(next_url)
                return redirect('mes_fichiers')
            journaliser(request, 'otp_echec', utilisateur=user, detail={
                'bloque': 'Code bloqué après 5 erreurs', 'expire': 'Code expiré'}.get(resultat, 'Code incorrect'))
            if resultat == 'bloque':
                messages.error(request, "Trop de tentatives incorrectes. Demandez un nouveau code.")
            elif resultat == 'expire':
                messages.error(request, "Ce code a expiré. Demandez un nouveau code.")
            else:
                messages.error(request, "Code incorrect.")
    else:
        form = VerifierOTPForm()

    return render(request, 'partage/verifier_otp.html', {
        'form': form,
        'email_masque': _masquer_email(user.email),
    })

@ratelimit(key='ip', rate='3/5m', method='POST', block=True)
def renvoyer_otp(request):
    """Renvoie un nouveau code OTP."""
    user_id = request.session.get('otp_user_id')
    if not user_id:
        messages.error(request, "Session expirée. Veuillez vous reconnecter.")
        return redirect('connexion')
    try:
        user = User.objects.get(id=user_id)
        otp = CodeOTP.generer(user)
        succes = _envoyer_otp(user, otp.code)
        if succes:
            messages.success(request, f"Un nouveau code a été envoyé à {_masquer_email(user.email)}.")
        else:
            messages.error(request, "Le code n'a pas pu être envoyé. Réessayez dans quelques minutes ou contactez le service informatique.")
    except User.DoesNotExist:
        messages.error(request, "Utilisateur introuvable.")
        return redirect('connexion')
    return redirect('verifier_otp')


@ratelimit(key='ip', rate='3/h', method='POST', block=True)
def mot_de_passe_oublie(request):
    if request.user.is_authenticated:
        return redirect('mes_fichiers')

    if request.method == 'POST':
        form = MotDePasseOublieForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email'].lower()
            user = User.objects.filter(email__iexact=email, is_active=True).first()
            if user is not None:
                otp = CodeOTP.generer(user)
                _envoyer_otp(user, otp.code)
            # Même réponse que le compte existe ou non (pas de fuite d'information).
            request.session['reset_user_id'] = user.id if user else None
            request.session['reset_email'] = email
            messages.info(request, "Si un compte est associé à cette adresse, un code vient d'y être envoyé.")
            return redirect('reinitialiser_mdp')
    else:
        form = MotDePasseOublieForm()

    return render(request, 'partage/mot_de_passe_oublie.html', {'form': form})


@ratelimit(key='ip', rate='10/5m', method='POST', block=True)
def reinitialiser_mdp(request):
    if 'reset_email' not in request.session:
        messages.error(request, "Session expirée.")
        return redirect('mot_de_passe_oublie')

    user_id = request.session.get('reset_user_id')
    user = User.objects.filter(id=user_id).first() if user_id else None
    contexte = {'email_masque': _masquer_email(request.session.get('reset_email'))}

    if request.method == 'POST':
        code_saisi = request.POST.get('code', '').strip()
        form       = NouveauMotDePasseForm(request.POST)
        contexte['form'] = form

        if not form.is_valid():
            return render(request, 'partage/reinitialiser_mdp.html', contexte)

        resultat = CodeOTP.verifier(user, code_saisi)
        if resultat == 'ok':
            user.set_password(form.cleaned_data['password1'])
            user.save()
            request.session.pop('reset_user_id', None)
            request.session.pop('reset_email', None)
            logger.info(f"Mot de passe réinitialisé pour {user.username} depuis {get_ip(request)}")
            messages.success(request, "Votre mot de passe a été modifié. Vous pouvez vous connecter.")
            return redirect('connexion')
        journaliser(request, 'otp_echec', utilisateur=user,
                    detail=f"Réinitialisation du mot de passe : {'code ' + resultat if resultat != 'incorrect' else 'code incorrect'}")
        if resultat in ('bloque', 'expire'):
            messages.error(request, "Code expiré ou trop de tentatives. Recommencez la demande.")
            return redirect('mot_de_passe_oublie')
        messages.error(request, "Code incorrect.")
        return render(request, 'partage/reinitialiser_mdp.html', contexte)

    contexte['form'] = NouveauMotDePasseForm()
    return render(request, 'partage/reinitialiser_mdp.html', contexte)


@login_required
def mes_fichiers(request):
    fichiers = Fichier.objects.filter(proprietaire=request.user, supprime=False)
    profil   = request.user.profil
    nb_corbeille = Fichier.objects.filter(proprietaire=request.user, supprime=True,
                                       efface_par_utilisateur__isnull=True).count()
    return render(request, 'partage/mes_fichiers.html', {
        'fichiers': fichiers,
        'profil': profil,
        'nb_corbeille': nb_corbeille,
    })


def _fin_depot(request, nom_url):
    """Fin d'un dépôt : redirection classique, ou adresse en JSON si la page a envoyé
    les fichiers en arrière-plan (barre de progression). Les messages restent en
    attente et s'affichent sur la page suivante."""
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'redirection': reverse(nom_url)})
    return redirect(nom_url)


@login_required
@ratelimit(key='user', rate='60/h', method='POST', block=True)
def upload_fichier(request):
    profil = request.user.profil
    config = ConfigurationCloud.get_config()
    extensions_ok = config.liste_extensions()
    taille_max = config.taille_max_bytes()

    if request.method == 'POST':
        fichiers_recus = request.FILES.getlist('fichiers')

        if not fichiers_recus:
            messages.error(request, "Aucun fichier sélectionné.")
            return _fin_depot(request, 'upload_fichier')

        succes = 0
        erreurs = []

        for f in fichiers_recus:
            debut_upload = time.time()
            nom = f.name

            # Vérification de l'extension (whitelist)
            ext_fichier = os.path.splitext(nom)[1].lower().lstrip('.')
            if ext_fichier not in extensions_ok:
                erreurs.append(
                    f"« {nom} » — extension « .{ext_fichier} » non autorisée. "
                    f"Extensions acceptées : {', '.join(extensions_ok[:8])}{'...' if len(extensions_ok) > 8 else ''}"
                )
                continue

            # Vérification de la taille maximale
            if f.size > taille_max:
                erreurs.append(
                    f"« {nom} » — dépasse la taille maximale de {config.taille_max_mb} MB "
                    f"(fichier : {round(f.size / (1024**2), 1)} MB)."
                )
                continue

            if profil.espace_utilise + f.size > profil.quota_octets:
                erreurs.append(f"« {nom} » — quota insuffisant.")
                continue

            # S'assurer que le dossier utilisateur existe sur le disque externe
            dossier_utilisateur = os.path.join(settings.MEDIA_ROOT, 'CLOUD EDC', request.user.username)
            os.makedirs(dossier_utilisateur, exist_ok=True)

            # 1. Analyse antivirus AVANT tout stockage. Le fichier est lu par blocs
            #    de 1 Mo depuis le fichier temporaire de Django : la mémoire
            #    utilisée reste la même quelle que soit sa taille.
            try:
                f.seek(0)
                statut, signature = scanner_fichier(f)
            except ScanIndisponible:
                logger.error("Dépôt refusé : ClamAV injoignable.")
                journaliser(request, 'upload_refuse', detail='Antivirus indisponible', nom=nom, taille=f.size)
                erreurs.append(f"« {nom} » — antivirus indisponible, dépôt refusé. Réessayez plus tard.")
                continue
            except ScanErreur as e:
                journaliser(request, 'upload_refuse', detail=f'Erreur antivirus : {e}', nom=nom, taille=f.size)
                erreurs.append(
                    f"« {nom} » — l'antivirus n'a pas pu analyser ce fichier "
                    f"(il est peut-être trop volumineux). Dépôt refusé."
                )
                continue

            if statut == 'infecte':
                journaliser(request, 'upload_refuse', detail=f'Menace : {signature}', nom=nom, taille=f.size)
                erreurs.append(f"« {nom} » — menace détectée par l'antivirus ({signature}). Dépôt refusé.")
                continue

            # 2. Chiffrement AES-256-GCM par blocs, écrit directement à son
            #    emplacement définitif (via un fichier « .partiel » renommé à la fin).
            fichier_obj = Fichier(
                proprietaire=request.user,
                nom_original=nom,
                taille=f.size,
                statut_scan='sain',
                est_chiffre=True,
            )
            stockage = fichier_obj.fichier.storage
            nom_stockage = stockage.get_available_name(chemin_upload(fichier_obj, nom))
            chemin_final = stockage.path(nom_stockage)
            chemin_partiel = chemin_final + '.partiel'
            os.makedirs(os.path.dirname(chemin_final), exist_ok=True)
            try:
                f.seek(0)
                empreinte = hashlib.sha256()
                with open(chemin_partiel, 'wb') as destination:
                    fichier_obj.iv_chiffrement = chiffrer_flux(f, destination, empreinte=empreinte)
                    destination.flush()
                    os.fsync(destination.fileno())
                fichier_obj.empreinte_sha256 = empreinte.hexdigest()
                os.replace(chemin_partiel, chemin_final)
                fichier_obj.fichier.name = nom_stockage
                fichier_obj.save()
            except Exception:
                logger.exception(f"Échec de l'enregistrement de « {nom} »")
                for chemin in (chemin_partiel, chemin_final):
                    if os.path.exists(chemin) and not Fichier.objects.filter(fichier=nom_stockage).exists():
                        os.unlink(chemin)
                erreurs.append(f"« {nom} » — erreur lors de l'enregistrement. Réessayez ou contactez le service informatique.")
                continue

            fichier_obj.duree_upload = time.time() - debut_upload
            fichier_obj.save(update_fields=['duree_upload'])
            profil.espace_utilise += f.size
            profil.save()
            journaliser(request, 'upload', fichier=fichier_obj,
                       detail=f'Durée: {fichier_obj.duree_upload:.2f}s')
            succes += 1

        if succes:
            messages.success(request, f"{succes} fichier{'s' if succes > 1 else ''} déposé{'s' if succes > 1 else ''}.")
        for err in erreurs:
            messages.error(request, err)

        return _fin_depot(request, 'mes_fichiers')

    return render(request, 'partage/upload.html', {
        'profil': profil,
        'extensions_ok': extensions_ok,
        'taille_max_mb': config.taille_max_mb,
    })


@login_required
def supprimer_fichier(request, fichier_id):
    """Met le fichier dans la corbeille (soft delete)."""
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, proprietaire=request.user)
    if request.method == 'POST':
        nom = fichier_obj.nom_original
        fichier_obj.supprime = True
        fichier_obj.date_suppression = timezone.now()
        fichier_obj.save()
        journaliser(request, 'suppression', fichier=fichier_obj, detail=f'Mis à la corbeille : {nom}')
        messages.success(request, f"« {nom} » a été placé dans la corbeille. Vous pouvez le restaurer pendant 30 jours.")
    return redirect('mes_fichiers')


@login_required
def corbeille(request):
    """Affiche la corbeille de l'utilisateur.

    Au-delà de 30 jours, un fichier quitte la corbeille : il est retiré du compte
    et entre en période de conservation (voir conservation.py).
    """
    limite = timezone.now() - timedelta(days=30)
    for f in Fichier.objects.filter(proprietaire=request.user, supprime=True,
                                    efface_par_utilisateur__isnull=True, date_suppression__lt=limite):
        effacer_pour_utilisateur(f)
        journaliser(request, 'suppression', fichier=f, detail='Retiré de la corbeille après 30 jours')
    fichiers = Fichier.objects.filter(proprietaire=request.user, supprime=True,
                                      efface_par_utilisateur__isnull=True).order_by('-date_suppression')
    return render(request, 'partage/corbeille.html', {
        'fichiers': fichiers,
        'profil': request.user.profil,
        'duree_conservation': ConfigurationCloud.get_config().duree_conservation_jours,
    })


@login_required
def restaurer_fichier(request, fichier_id):
    """Restaure un fichier depuis la corbeille."""
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, proprietaire=request.user, supprime=True,
                                    efface_par_utilisateur__isnull=True)
    if request.method == 'POST':
        nom = fichier_obj.nom_original
        fichier_obj.supprime = False
        fichier_obj.date_suppression = None
        fichier_obj.save()
        journaliser(request, 'restauration', fichier=fichier_obj, detail=f'Restauré : {nom}')
        messages.success(request, f"« {nom} » a été restauré.")
    return redirect('corbeille')


@login_required
def supprimer_definitivement(request, fichier_id):
    """Retire définitivement un fichier de la corbeille de l'utilisateur.

    Le fichier n'est plus accessible à l'utilisateur ni par ses liens de partage,
    mais EDC le conserve (chiffré) pendant la durée fixée avant de l'effacer.
    """
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, proprietaire=request.user, supprime=True,
                                    efface_par_utilisateur__isnull=True)
    if request.method == 'POST':
        fin = effacer_pour_utilisateur(fichier_obj)
        journaliser(request, 'suppression', fichier=fichier_obj,
                    detail=f"Supprimé définitivement par l'utilisateur — conservé jusqu'au {fin:%d/%m/%Y}")
        messages.success(request, f"« {fichier_obj.nom_original} » a été supprimé de votre espace.")
    return redirect('corbeille')


@login_required
def vider_corbeille(request):
    """Vide la corbeille de l'utilisateur (mêmes règles que supprimer_definitivement)."""
    if request.method == 'POST':
        fichiers = Fichier.objects.filter(proprietaire=request.user, supprime=True,
                                          efface_par_utilisateur__isnull=True)
        count = 0
        for f in fichiers:
            fin = effacer_pour_utilisateur(f)
            journaliser(request, 'suppression', fichier=f,
                        detail=f"Corbeille vidée par l'utilisateur — conservé jusqu'au {fin:%d/%m/%Y}")
            count += 1
        messages.success(request, f"Corbeille vidée : {count} fichier{'s' if count > 1 else ''} supprimé{'s' if count > 1 else ''} de votre espace.")
    return redirect('corbeille')


@login_required
def creer_lien(request, fichier_id):
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, proprietaire=request.user)
    if fichier_obj.statut_scan != 'sain':
        messages.error(request, "Ce fichier n'a pas été validé par l'antivirus et ne peut pas être partagé.")
        return redirect('mes_fichiers')

    if request.method == 'POST':
        form = CreerLienForm(request.POST)
        if form.is_valid():
            jours = int(form.cleaned_data['duree_validite'])
            lien  = LienPartage.objects.create(
                fichier=fichier_obj,
                cree_par=request.user,
                date_expiration=timezone.now() + timedelta(days=jours),
                nb_telechargements_max=form.cleaned_data['nb_telechargements_max'],
            )
            journaliser(request, 'creation_lien', fichier=fichier_obj, lien=lien)
            url_partage = request.build_absolute_uri(f'/partage/{lien.token}/')
            return render(request, 'partage/lien_cree.html', {
                'lien': lien, 'url_partage': url_partage,
            })
    else:
        form = CreerLienForm()
    return render(request, 'partage/creer_lien.html', {'form': form, 'fichier': fichier_obj})


def telecharger_via_lien(request, token):
    """L'utilisateur DOIT être connecté pour télécharger via un lien partagé."""
    try:
        lien = LienPartage.objects.get(token=token)
    except LienPartage.DoesNotExist:
        journaliser(request, 'acces_refuse', detail=f'Token inconnu: {token}')
        raise Http404("Lien invalide.")

    if not lien.est_valide():
        journaliser(request, 'acces_refuse', fichier=lien.fichier, lien=lien,
                    detail='Lien expiré ou quota atteint')
        return render(request, 'partage/lien_expire.html', status=410)

    if not request.user.is_authenticated:
        next_url = request.get_full_path()
        request.session['next_after_login'] = next_url
        messages.info(
            request,
            "Connexion requise pour accéder à ce fichier partagé. "
            "Connectez-vous ou créez un compte pour continuer."
        )
        return redirect(f"/connexion/?next={next_url}")

    if not os.path.exists(lien.fichier.fichier.path):
        journaliser(request, 'acces_refuse', fichier=lien.fichier, lien=lien,
                    detail='Fichier physique introuvable')
        return render(request, 'partage/lien_expire.html', {'indisponible': True}, status=503)

    if not _fichier_intact(request, lien.fichier, lien=lien):
        return render(request, 'partage/lien_expire.html', {'indisponible': True}, status=503)
    lien.nb_telechargements += 1
    lien.save()
    journaliser(request, 'telechargement', fichier=lien.fichier, lien=lien,
                detail=f'Téléchargé par {request.user.username} ({request.user.email})')
    return _servir_fichier(lien.fichier, deja_verifie=True)


@login_required
def telecharger_fichier(request, fichier_id):
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, proprietaire=request.user)
    if fichier_obj.supprime:
        messages.error(request, "Ce fichier est dans la corbeille.")
        return redirect('mes_fichiers')
    if fichier_obj.statut_scan != 'sain':
        messages.error(request, "Ce fichier ne peut pas être téléchargé.")
        return redirect('mes_fichiers')
    if not _fichier_intact(request, fichier_obj):
        messages.error(request, "Ce fichier a été modifié sur le disque depuis son dépôt : il ne peut pas "
                                "être envoyé. L'incident est inscrit au journal.")
        return redirect('mes_fichiers')
    journaliser(request, 'telechargement', fichier=fichier_obj)
    return _servir_fichier(fichier_obj, deja_verifie=True)


def _fichier_intact(request, fichier_obj, lien=None):
    """Vérifie l'étiquette d'authentification AES-GCM du fichier avant tout envoi.

    Un fichier modifié sur le disque n'est jamais envoyé, et le refus est inscrit
    au journal (« Fichier altéré, envoi refusé ») au lieu d'un téléchargement.
    """
    if not (fichier_obj.est_chiffre and fichier_obj.iv_chiffrement and est_format_v2(fichier_obj.iv_chiffrement)):
        return True
    try:
        verifier_fichier_v2(fichier_obj.fichier.path, fichier_obj.iv_chiffrement)
        return True
    except Exception as e:
        logger.error(f"Fichier #{fichier_obj.id} illisible ou modifié : {e}")
        journaliser(request, 'fichier_altere', fichier=fichier_obj, lien=lien,
                    detail="Contrôle d'intégrité échoué : envoi refusé")
        return False


def _servir_fichier(fichier_obj, deja_verifie=False):
    """Envoie le fichier déchiffré à l'utilisateur.

    Format actuel (AES-256-GCM) : le fichier est d'abord relu en entier pour
    vérifier son étiquette d'authentification, puis déchiffré et envoyé par
    blocs de 1 Mo. Aucun octet n'est envoyé si le fichier a été modifié, et
    la mémoire utilisée ne dépend pas de la taille du fichier.
    """
    chemin = fichier_obj.fichier.path
    if fichier_obj.est_chiffre and fichier_obj.iv_chiffrement:
        if est_format_v2(fichier_obj.iv_chiffrement):
            try:
                if not deja_verifie:
                    verifier_fichier_v2(chemin, fichier_obj.iv_chiffrement)
                taille = taille_claire_v2(chemin)
            except Exception as e:
                logger.error(f"Fichier #{fichier_obj.id} illisible ou modifié : {e}")
                raise Http404("Fichier indisponible.")
            response = StreamingHttpResponse(
                dechiffrer_fichier_v2(chemin, fichier_obj.iv_chiffrement),
                content_type='application/octet-stream',
            )
            response['Content-Length'] = str(taille)
        else:
            # Ancien format (AES-CBC) : fichiers déposés avant la migration, traités en mémoire.
            try:
                with open(chemin, 'rb') as f:
                    contenu_clair = dechiffrer_en_memoire(f.read(), fichier_obj.iv_chiffrement)
            except Exception as e:
                logger.error(f"Déchiffrement impossible du fichier #{fichier_obj.id} : {e}")
                raise Http404("Fichier indisponible.")
            response = HttpResponse(contenu_clair, content_type='application/octet-stream')
        response['Content-Disposition'] = content_disposition_header(True, fichier_obj.nom_original)
        response['X-Content-Type-Options'] = 'nosniff'
        return response
    return FileResponse(open(chemin, 'rb'), as_attachment=True, filename=fichier_obj.nom_original)


@login_required
def historique(request):
    logs = LogAcces.objects.filter(utilisateur=request.user)
    return render(request, 'partage/historique.html', {'logs': logs})


@user_passes_test(is_admin, login_url='connexion')
def admin_dashboard(request):
    depuis = timezone.now() - timedelta(days=7)
    espace_utilise = ProfilUtilisateur.objects.aggregate(total=Sum('espace_utilise'))['total'] or 0
    espace_alloue  = ProfilUtilisateur.objects.aggregate(total=Sum('quota_octets'))['total'] or 0

    context = {
        'total_users':             User.objects.count(),
        'total_fichiers':          Fichier.objects.count(),
        'fichiers_sains':          Fichier.objects.filter(statut_scan='sain').count(),
        'fichiers_infectes':       Fichier.objects.filter(statut_scan='infecte').count(),
        'espace_total_utilise_gb': round(espace_utilise / (1024**3), 2),
        'espace_total_alloue_gb':  round(espace_alloue  / (1024**3), 2),
        'derniers_logs':           LogAcces.objects.select_related('utilisateur', 'fichier')[:20],
        'utilisateurs':            User.objects.select_related('profil').prefetch_related('fichiers').order_by('-date_joined'),
        'uploads_recents':         LogAcces.objects.filter(action='upload',         date_evenement__gte=depuis).count(),
        'telechargements_recents': LogAcces.objects.filter(action='telechargement', date_evenement__gte=depuis).count(),
        'menaces_recentes':        LogAcces.objects.filter(action='upload_refuse',  date_evenement__gte=depuis).count(),
        'statut_clamav':           get_statut_clamav(),
    }
    return render(request, 'partage/admin_dashboard.html', context)


@user_passes_test(is_admin, login_url='connexion')
def admin_allouer_quota(request, user_id):
    utilisateur = get_object_or_404(User, id=user_id)
    profil      = utilisateur.profil
    if request.method == 'POST':
        form = AllouerQuotaForm(request.POST)
        if form.is_valid():
            quota_gb = form.cleaned_data['quota_final_gb']
            profil.quota_octets = int(quota_gb * 1024 ** 3)
            profil.save()
            messages.success(request, f"Quota de {utilisateur.username} fixé à {quota_gb} Go.")
            return redirect('admin_dashboard')
    else:
        form = AllouerQuotaForm()
    return render(request, 'partage/admin_allouer_quota.html', {
        'form': form, 'utilisateur': utilisateur, 'profil': profil,
    })


@user_passes_test(is_admin, login_url='connexion')
def admin_supprimer_fichier(request, fichier_id):
    """Admin : met le fichier dans la corbeille."""
    fichier_obj = get_object_or_404(Fichier, id=fichier_id)
    if request.method == 'POST':
        nom = fichier_obj.nom_original
        fichier_obj.supprime = True
        fichier_obj.date_suppression = timezone.now()
        fichier_obj.save()
        journaliser(request, 'suppression', fichier=fichier_obj, detail=f'Admin : mis à la corbeille {nom}')
        messages.success(request, f"« {nom} » a été placé dans la corbeille.")
    return redirect('admin_dashboard')


@user_passes_test(is_admin, login_url='connexion')
def admin_toggle_user(request, user_id):
    utilisateur = get_object_or_404(User, id=user_id)
    if utilisateur == request.user:
        messages.error(request, "Vous ne pouvez pas désactiver votre propre compte.")
        return redirect('admin_dashboard')
    utilisateur.is_active = not utilisateur.is_active
    utilisateur.save()
    etat = "réactivé" if utilisateur.is_active else "désactivé"
    messages.success(request, f"Compte de {utilisateur.username} {etat}.")
    return redirect('admin_dashboard')


@user_passes_test(is_admin, login_url='connexion')
def admin_logs(request):
    """Journal complet, avec recherche par nom de fichier, empreinte, utilisateur ou adresse IP."""
    from django.db.models import Q
    logs = LogAcces.objects.select_related('utilisateur', 'fichier')
    q = request.GET.get('q', '').strip()
    if q:
        logs = logs.filter(
            Q(nom_fichier__icontains=q) | Q(empreinte_fichier__istartswith=q.lower()) |
            Q(utilisateur__username__icontains=q) | Q(adresse_ip__icontains=q) |
            Q(detail__icontains=q)
        )
    return render(request, 'partage/admin_logs.html', {'logs': logs[:1000], 'nb_logs': logs.count(), 'q': q})


# ─────────────────────────────────────────────────────────────────────────────
# STATISTIQUES DE PERFORMANCE (admin)
# ─────────────────────────────────────────────────────────────────────────────

@user_passes_test(is_admin, login_url='connexion')
def admin_performance(request):
    """Page de statistiques de performance du serveur."""
    import shutil
    import psutil
    from django.db.models import Avg, Count
    from django.db.models.functions import ExtractHour

    # ── 1. Temps moyen d'upload ─────────────────────────────────────────
    stats_upload = Fichier.objects.filter(duree_upload__gt=0).aggregate(
        avg=Avg('duree_upload'),
        count=Count('id'),
    )
    temps_moyen = stats_upload['avg'] or 0
    nb_fichiers_chronometres = stats_upload['count'] or 0

    # ── 2. Heures de pointe (uploads par heure) ─────────────────────────
    heures_activite = (
        LogAcces.objects
        .filter(action='upload')
        .annotate(heure=ExtractHour('date_evenement'))
        .values('heure')
        .annotate(total=Count('id'))
        .order_by('heure')
    )
    heures_labels = [f"{h:02d}h" for h in range(24)]
    heures_data = [0] * 24
    for h in heures_activite:
        if h['heure'] is not None:
            heures_data[h['heure']] = h['total']
    heure_pointe = heures_data.index(max(heures_data)) if any(heures_data) else None

    # ── 3. Espace disque ────────────────────────────────────────────────
    try:
        usage = shutil.disk_usage('/app/media')
        disk_total_gb = round(usage.total / (1024**3), 2)
        disk_used_gb = round(usage.used / (1024**3), 2)
        disk_free_gb = round(usage.free / (1024**3), 2)
        disk_percent = round((usage.used / usage.total) * 100, 1)
    except Exception as e:
        logger.error(f"Erreur disk_usage : {e}")
        disk_total_gb = disk_used_gb = disk_free_gb = disk_percent = 0

    # ── 4. CPU / RAM / Disque (via psutil) ──────────────────────────────
    try:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        cpu_count = psutil.cpu_count()
        ram = psutil.virtual_memory()
        ram_total_gb = round(ram.total / (1024**3), 2)
        ram_used_gb = round(ram.used / (1024**3), 2)
        ram_percent = ram.percent
        # Charge système
        load1, load5, load15 = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)
    except Exception as e:
        logger.error(f"Erreur psutil : {e}")
        cpu_percent = cpu_count = 0
        ram_total_gb = ram_used_gb = ram_percent = 0
        load1 = load5 = load15 = 0

    # ── 5. Taille totale des fichiers stockés ───────────────────────────
    taille_stockage = Fichier.objects.aggregate(total=Sum('taille'))['total'] or 0

    context = {
        # Temps d'upload
        'temps_moyen': temps_moyen,
        'nb_fichiers_chronometres': nb_fichiers_chronometres,
        # Heures de pointe
        'heures_labels': heures_labels,
        'heures_data': heures_data,
        'heure_pointe': heure_pointe,
        'heure_pointe_valeur': max(heures_data) if any(heures_data) else 0,
        'heures': [
            {'label': lbl, 'valeur': v,
             'pourcent': round(100 * v / max(heures_data)) if any(heures_data) else 0}
            for lbl, v in zip(heures_labels, heures_data)
        ],
        # Disque
        'disk_total_gb': disk_total_gb,
        'disk_used_gb': disk_used_gb,
        'disk_free_gb': disk_free_gb,
        'disk_percent': disk_percent,
        # CPU / RAM
        'cpu_percent': cpu_percent,
        'cpu_count': cpu_count,
        'ram_total_gb': ram_total_gb,
        'ram_used_gb': ram_used_gb,
        'ram_percent': ram_percent,
        'load1': round(load1, 2),
        'load5': round(load5, 2),
        'load15': round(load15, 2),
        # Stockage fichiers
        'taille_stockage_gb': round(taille_stockage / (1024**3), 2),
    }
    return render(request, 'partage/admin_performance.html', context)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE PROFIL UTILISATEUR DÉTAILLÉE (admin)
# ─────────────────────────────────────────────────────────────────────────────

@user_passes_test(is_admin, login_url='connexion')
def admin_user_detail(request, user_id):
    """Page complète sur un utilisateur : infos, fichiers, liens, logs."""
    utilisateur = get_object_or_404(User, id=user_id)
    profil = utilisateur.profil

    # Fichiers de l'utilisateur
    fichiers = Fichier.objects.filter(proprietaire=utilisateur).order_by('-date_upload')

    # Liens de partage créés par cet utilisateur
    liens = LienPartage.objects.filter(cree_par=utilisateur).select_related('fichier').order_by('-date_creation')

    # Historique des 50 dernières actions
    logs = LogAcces.objects.filter(utilisateur=utilisateur).order_by('-date_evenement')[:50]

    # Statistiques
    stats = {
        'nb_fichiers': fichiers.count(),
        'nb_liens': liens.count(),
        'nb_liens_actifs': liens.filter(actif=True).count(),
        'taille_totale': sum(f.taille for f in fichiers),
        'nb_uploads_30j': LogAcces.objects.filter(
            utilisateur=utilisateur, action='upload',
            date_evenement__gte=timezone.now() - timedelta(days=30)
        ).count(),
        'derniere_connexion': LogAcces.objects.filter(
            utilisateur=utilisateur, action='upload'
        ).order_by('-date_evenement').first(),
    }

    context = {
        'utilisateur': utilisateur,
        'profil': profil,
        'fichiers': fichiers,
        'liens': liens,
        'logs': logs,
        'stats': stats,
    }
    return render(request, 'partage/admin_user_detail.html', context)



# ─────────────────────────────────────────────────────────────────────────────
# CORBEILLE ADMIN
# ─────────────────────────────────────────────────────────────────────────────

@user_passes_test(is_admin, login_url='connexion')
def admin_corbeille(request):
    """Vue admin : fichiers dans les corbeilles et fichiers conservés après suppression."""
    purger_fichiers_expires()
    fichiers = (Fichier.objects.filter(supprime=True)
                .select_related('proprietaire__profil').order_by('-date_suppression'))
    context = {
        'fichiers': fichiers,
        'total_taille': sum(f.taille for f in fichiers),
        'nb_total': fichiers.count(),
        'duree_conservation': ConfigurationCloud.get_config().duree_conservation_jours,
    }
    return render(request, 'partage/admin_corbeille.html', context)


@user_passes_test(is_admin, login_url='connexion')
def admin_supprimer_definitivement(request, fichier_id):
    """Effacement immédiat par l'administrateur (impossible si le compte est sous conservation)."""
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, supprime=True)
    if request.method == 'POST':
        nom = fichier_obj.nom_original
        if fichier_obj.proprietaire.profil.sous_conservation:
            messages.error(request, f"Le compte {fichier_obj.proprietaire.username} est sous conservation : "
                                    f"ses fichiers ne peuvent pas être effacés.")
            return redirect('admin_corbeille')
        effacer_du_disque(fichier_obj, f"Effacé par l'administrateur {request.user.username}",
                          utilisateur=request.user, adresse_ip=get_ip(request))
        messages.success(request, f"« {nom} » a été effacé définitivement.")
    return redirect('admin_corbeille')


@user_passes_test(is_admin, login_url='connexion')
def admin_restaurer_fichier(request, fichier_id):
    """Rend le fichier à son propriétaire (y compris un fichier en conservation)."""
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, supprime=True)
    if request.method == 'POST':
        nom = fichier_obj.nom_original
        proprietaire = fichier_obj.proprietaire
        if fichier_obj.efface_par_utilisateur is not None:
            profil = proprietaire.profil
            profil.espace_utilise += fichier_obj.taille
            profil.save(update_fields=['espace_utilise'])
        fichier_obj.supprime = False
        fichier_obj.date_suppression = None
        fichier_obj.efface_par_utilisateur = None
        fichier_obj.conserve_jusqua = None
        fichier_obj.save()
        journaliser(request, 'restauration', fichier=fichier_obj,
                    detail=f'Rendu à {proprietaire.username} par un administrateur')
        messages.success(request, f"« {nom} » a été rendu à {proprietaire.username}.")
    return redirect('admin_corbeille')


@user_passes_test(is_admin, login_url='connexion')
def admin_consulter_fichier(request, fichier_id):
    """Téléchargement d'un fichier supprimé par un administrateur, avec motif obligatoire.

    Réservé aux fichiers de la Corbeille générale (supprimés ou conservés).
    Chaque consultation est inscrite au journal avec son motif.
    """
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, supprime=True)
    erreur = ''
    if request.method == 'POST':
        motif = ' '.join(request.POST.get('motif', '').split())
        if len(motif) < 15:
            erreur = "Indiquez un motif précis (15 caractères minimum)."
        else:
            if not _fichier_intact(request, fichier_obj):
                raise Http404("Fichier indisponible.")
            journaliser(request, 'consultation_admin', fichier=fichier_obj,
                        detail=f"Motif : {motif}")
            return _servir_fichier(fichier_obj, deja_verifie=True)
    return render(request, 'partage/admin_consulter_fichier.html', {
        'fichier': fichier_obj, 'erreur': erreur, 'motif': request.POST.get('motif', ''),
    })


@user_passes_test(is_admin, login_url='connexion')
def admin_basculer_conservation(request, user_id):
    """Place un compte sous conservation (enquête) ou lève la conservation."""
    utilisateur = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        profil = utilisateur.profil
        profil.sous_conservation = not profil.sous_conservation
        profil.save(update_fields=['sous_conservation'])
        etat = "placé sous conservation" if profil.sous_conservation else "n'est plus sous conservation"
        journaliser(request, 'conservation', detail=f"Compte {utilisateur.username} {etat}")
        messages.success(request, f"Le compte {utilisateur.username} {etat}.")
    return redirect('admin_user_detail', user_id=user_id)



# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION DES EXTENSIONS (admin)
# ─────────────────────────────────────────────────────────────────────────────

@user_passes_test(is_admin, login_url='connexion')
def admin_config_extensions(request):
    """Page admin pour configurer les extensions autorisées."""
    config = ConfigurationCloud.get_config()

    if request.method == 'POST':
        extensions_str = request.POST.get('extensions_autorisees', '').strip()
        taille_max = request.POST.get('taille_max_mb', '100')

        # Nettoyer la liste
        extensions = [
            e.strip().lower().lstrip('.')
            for e in extensions_str.replace(' ', ',').split(',')
            if e.strip()
        ]

        if not extensions:
            messages.error(request, "La liste des extensions ne peut pas être vide.")
        else:
            config.extensions_autorisees = ','.join(sorted(set(extensions)))
            try:
                config.taille_max_mb = max(1, int(taille_max))
            except ValueError:
                config.taille_max_mb = 100
            try:
                config.duree_conservation_jours = max(1, int(request.POST.get('duree_conservation_jours', 90)))
            except ValueError:
                config.duree_conservation_jours = 90
            config.save()
            journaliser(request, 'config', detail=f'Règles de dépôt : {len(extensions)} extensions, '
                                                  f'{config.taille_max_mb} Mo max, conservation {config.duree_conservation_jours} j')
            messages.success(request, f"Règles de dépôt enregistrées : {len(extensions)} extensions autorisées.")
            return redirect('admin_config_extensions')

    context = {
        'config': config,
        'extensions_liste': config.liste_extensions(),
        'nb_extensions': len(config.liste_extensions()),
    }
    return render(request, 'partage/admin_config_extensions.html', context)



# ─────────────────────────────────────────────────────────────────────────────
# EXPORT CSV DES LOGS (admin)
# ─────────────────────────────────────────────────────────────────────────────

@user_passes_test(is_admin, login_url='connexion')
def export_logs_csv(request):
    """Exporte les logs en CSV (respecte les filtres appliqués)."""
    import csv
    from django.db.models import Q
    from django.utils import timezone
    from datetime import timedelta
    from django.http import HttpResponse

    logs = LogAcces.objects.select_related('utilisateur', 'fichier', 'lien').all()

    # Appliquer les mêmes filtres que admin_logs
    q         = request.GET.get('q', '').strip()
    action_f  = request.GET.get('action', '')
    periode_f = request.GET.get('periode', '')
    user_f    = request.GET.get('user', '').strip()

    if q:
        logs = logs.filter(
            Q(utilisateur__username__icontains=q) |
            Q(utilisateur__email__icontains=q) |
            Q(adresse_ip__icontains=q) |
            Q(detail__icontains=q) |
            Q(nom_fichier__icontains=q) |
            Q(empreinte_fichier__istartswith=q)
        )
    if action_f:
        logs = logs.filter(action=action_f)
    if user_f:
        logs = logs.filter(utilisateur__username__iexact=user_f)
    if periode_f:
        maintenant = timezone.now()
        if periode_f == 'today':
            logs = logs.filter(date_evenement__gte=maintenant.replace(hour=0, minute=0, second=0, microsecond=0))
        elif periode_f == '7d':
            logs = logs.filter(date_evenement__gte=maintenant - timedelta(days=7))
        elif periode_f == '30d':
            logs = logs.filter(date_evenement__gte=maintenant - timedelta(days=30))

    logs = logs.order_by('-date_evenement')

    # Nom du fichier
    date_str = timezone.now().strftime('%Y-%m-%d_%H%M')
    filename = f'logs-cloud-edc-{date_str}.csv'

    # Créer la réponse HTTP
    response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    # BOM UTF-8 pour Excel
    response.write('\ufeff')

    writer = csv.writer(response, delimiter=';', quoting=csv.QUOTE_MINIMAL)

    # En-tête
    writer.writerow([
        'Date',
        'Utilisateur',
        'Email',
        'Action',
        'Fichier',
        'Taille (octets)',
        'Empreinte SHA-256',
        'Adresse IP',
        'Détail',
        'ID Log',
    ])

    # Dictionnaire des actions (labels)
    actions_labels = dict(LogAcces.ACTION_CHOICES)

    # Écrire chaque ligne
    for log in logs:
        writer.writerow([
            log.date_evenement.strftime('%d/%m/%Y %H:%M:%S') if log.date_evenement else '',
            log.utilisateur.username if log.utilisateur else 'Anonyme',
            log.utilisateur.email if log.utilisateur else '',
            actions_labels.get(log.action, log.action),
            log.nom_affiche,
            log.taille_fichier if log.taille_fichier is not None else '',
            log.empreinte_fichier,
            log.adresse_ip or '',
            (log.detail or '').replace('\n', ' ').replace(';', ','),
            log.id,
        ])

    # Log de l'export
    journaliser(request, 'config', detail=f'Export CSV : {logs.count()} logs')

    return response


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITING — Vue 429
# ─────────────────────────────────────────────────────────────────────────────

def ratelimited_view(request, exception=None):
    """Vue appelée quand la limite est dépassée."""
    journaliser(request, 'limite_depassee', detail=f'Limite atteinte sur {request.path}')
    return render(request, 'partage/ratelimited.html', status=429)
