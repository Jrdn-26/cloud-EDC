import os
import time
import tempfile
import logging
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.mail import send_mail
from django.db.models import Sum
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils import timezone

from django.views.decorators.csrf import csrf_exempt
from .antivirus import scanner_fichier, get_statut_clamav
from .encryption import chiffrer_en_memoire, dechiffrer_en_memoire
from .forms import (
    InscriptionForm, UploadFichierForm, CreerLienForm,
    AllouerQuotaForm, VerifierOTPForm,
    MotDePasseOublieForm, NouveauMotDePasseForm,
)
from .models import Fichier, LienPartage, LogAcces, ProfilUtilisateur, CodeOTP, ConfigurationCloud
from django_ratelimit.decorators import ratelimit

logger = logging.getLogger(__name__)


def get_ip(request):
    x = request.META.get('HTTP_X_FORWARDED_FOR')
    return x.split(',')[0].strip() if x else request.META.get('REMOTE_ADDR')


def journaliser(request, action, fichier=None, lien=None, detail=''):
    LogAcces.objects.create(
        utilisateur=request.user if request.user.is_authenticated else None,
        adresse_ip=get_ip(request),
        action=action,
        fichier=fichier,
        lien=lien,
        detail=detail,
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
        logger.info(f"✅ OTP envoyé à {user.email}")
        return True
    except Exception as e:
        logger.error(f"❌ Erreur envoi OTP à {user.email} : {e}")
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
            messages.info(request, f"📧 Code de vérification envoyé à {_masquer_email(user.email)}.")
            return redirect('verifier_otp')
        else:
            messages.error(request, "❌ Des erreurs sont présentes.")
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

        try:
            user_obj = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            messages.error(request, f"❌ Aucun compte n'est associé à l'adresse « {email} ». Vérifiez votre saisie ou créez un compte.")
            return render(request, 'partage/connexion.html', {
                'email_not_found': True,
                'email_saisi': email,
            })
        except User.MultipleObjectsReturned:
            messages.error(request, "❌ Erreur : plusieurs comptes utilisent cet email. Contactez l'administrateur.")
            return render(request, 'partage/connexion.html', {'email_not_found': False, 'email_saisi': ''})

        user = authenticate(request, username=user_obj.username, password=password)

        if user is not None:
            if not user.is_active:
                messages.error(request, "❌ Ce compte est désactivé.")
                return render(request, 'partage/connexion.html', {'email_not_found': False, 'email_saisi': ''})

            ip        = get_ip(request)
            est_local = ip in ('127.0.0.1', '::1', 'localhost')
            if (user.is_superuser or user.is_staff) and est_local:
                login(request, user)
                messages.success(request, f"✅ Connexion admin. Bon retour, {user.username} !")
                return redirect('mes_fichiers')

            otp = CodeOTP.generer(user)
            _envoyer_otp(user, otp.code)
            request.session['otp_user_id'] = user.id
            request.session['otp_context'] = 'connexion'
            messages.info(request, f"📧 Code envoyé à {_masquer_email(user.email)}. Valable 10 minutes.")
            return redirect('verifier_otp')
        else:
            messages.error(request, "❌ Mot de passe incorrect.")

    return render(request, 'partage/connexion.html', {'email_not_found': False, 'email_saisi': ''})

@csrf_exempt
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
            code_saisi = form.cleaned_data['code']
            otp = CodeOTP.objects.filter(
                utilisateur=user, code=code_saisi, utilise=False,
            ).last()

            if otp and otp.est_valide():
                otp.utilise = True
                otp.save()
                contexte = request.session.pop('otp_context', 'connexion')
                del request.session['otp_user_id']
                login(request, user)
                if contexte == 'inscription':
                    messages.success(request, f"🎉 Bienvenue {user.username} ! Compte vérifié.")
                else:
                    messages.success(request, f"✅ Connexion réussie. Bon retour, {user.username} !")

                # Redirection vers le lien partagé si présent
                next_url = request.session.pop('next_after_login', None)
                if next_url:
                    messages.info(request, "🎯 Redirection vers le fichier partagé...")
                    return redirect(next_url)
                return redirect('mes_fichiers')
            elif otp and not otp.est_valide():
                messages.error(request, "⏰ Code expiré.")
            else:
                messages.error(request, "❌ Code incorrect.")
    else:
        form = VerifierOTPForm()

    return render(request, 'partage/verifier_otp.html', {
        'form': form,
        'email_masque': _masquer_email(user.email),
    })

@csrf_exempt
@csrf_exempt
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
            messages.success(request, f"📧 Nouveau code envoyé à {_masquer_email(user.email)}.")
        else:
            messages.error(request, "⚠️ Impossible d'envoyer l'email. Vérifiez la configuration Gmail.")
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
            try:
                user = User.objects.get(email__iexact=email)
                otp = CodeOTP.generer(user)
                _envoyer_otp(user, otp.code)
                request.session['reset_user_id'] = user.id
                messages.info(request, f"📧 Code envoyé à {_masquer_email(email)}.")
                return redirect('reinitialiser_mdp')
            except User.DoesNotExist:
                messages.info(request, "📧 Si un compte est associé à cet email, vous recevrez un code.")
    else:
        form = MotDePasseOublieForm()

    return render(request, 'partage/mot_de_passe_oublie.html', {'form': form})


def reinitialiser_mdp(request):
    user_id = request.session.get('reset_user_id')
    if not user_id:
        messages.error(request, "Session expirée.")
        return redirect('mot_de_passe_oublie')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return redirect('mot_de_passe_oublie')

    if request.method == 'POST':
        code_saisi = request.POST.get('code', '').strip()
        form       = NouveauMotDePasseForm(request.POST)

        otp = CodeOTP.objects.filter(
            utilisateur=user, code=code_saisi, utilise=False,
        ).last()

        if not otp:
            messages.error(request, "❌ Code incorrect.")
            return render(request, 'partage/reinitialiser_mdp.html', {
                'form': form, 'email_masque': _masquer_email(user.email)
            })

        if not otp.est_valide():
            messages.error(request, "⏰ Code expiré.")
            return redirect('mot_de_passe_oublie')

        if form.is_valid():
            nouveau_mdp = form.cleaned_data['password1']
            otp.utilise = True
            otp.save()
            user.set_password(nouveau_mdp)
            user.save()
            del request.session['reset_user_id']
            messages.success(request, "✅ Mot de passe réinitialisé !")
            return redirect('connexion')
        else:
            return render(request, 'partage/reinitialiser_mdp.html', {
                'form': form, 'email_masque': _masquer_email(user.email)
            })
    else:
        form = NouveauMotDePasseForm()

    return render(request, 'partage/reinitialiser_mdp.html', {
        'form': form, 'email_masque': _masquer_email(user.email),
    })


@login_required
def mes_fichiers(request):
    fichiers = Fichier.objects.filter(proprietaire=request.user, supprime=False)
    profil   = request.user.profil
    nb_corbeille = Fichier.objects.filter(proprietaire=request.user, supprime=True).count()
    return render(request, 'partage/mes_fichiers.html', {
        'fichiers': fichiers,
        'profil': profil,
        'nb_corbeille': nb_corbeille,
    })


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
            messages.error(request, "❌ Aucun fichier sélectionné.")
            return redirect('upload_fichier')

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

            contenu_original        = f.read()
            contenu_chiffre, iv_hex = chiffrer_en_memoire(contenu_original)

            suffix = os.path.splitext(nom)[1] or '.tmp'
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(contenu_original)
                chemin_tmp = tmp.name

            fichier_obj = Fichier(
                proprietaire=request.user,
                nom_original=nom,
                taille=f.size,
                statut_scan='en_attente',
                est_chiffre=True,
                iv_chiffrement=iv_hex,
            )
            fichier_obj.fichier.save(nom + '.enc', ContentFile(contenu_chiffre), save=False)
            fichier_obj.save()

            try:
                statut, signature = scanner_fichier(chemin_tmp)
            except Exception as e:
                if os.path.exists(chemin_tmp):
                    os.unlink(chemin_tmp)
                fichier_obj.fichier.delete(save=False)
                fichier_obj.delete()
                erreurs.append(f"« {nom} » — erreur antivirus.")
                continue
            finally:
                if os.path.exists(chemin_tmp):
                    os.unlink(chemin_tmp)

            if statut == 'infecte':
                fichier_obj.fichier.delete(save=False)
                fichier_obj.delete()
                journaliser(request, 'upload_refuse', detail=f'Virus: {signature}')
                erreurs.append(f"🦠 « {nom} » — menace : {signature}.")
                continue

            fichier_obj.statut_scan = 'sain'
            fichier_obj.duree_upload = time.time() - debut_upload
            fichier_obj.save()
            profil.espace_utilise += f.size
            profil.save()
            journaliser(request, 'upload', fichier=fichier_obj,
                       detail=f'Durée: {fichier_obj.duree_upload:.2f}s')
            succes += 1

        if succes:
            messages.success(request, f"✅ {succes} fichier(s) uploadé(s) !")
        for err in erreurs:
            messages.error(request, f"❌ {err}")

        return redirect('mes_fichiers')

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
        messages.success(request, f"🗑️ « {nom} » déplacé dans la corbeille. Restauration possible pendant 30 jours.")
    return redirect('mes_fichiers')


@login_required
def corbeille(request):
    """Affiche les fichiers supprimés de l'utilisateur."""
    fichiers = Fichier.objects.filter(proprietaire=request.user, supprime=True).order_by('-date_suppression')
    profil = request.user.profil
    # Purge automatique : fichiers supprimés depuis > 30 jours
    limite = timezone.now() - timedelta(days=30)
    a_purger = Fichier.objects.filter(proprietaire=request.user, supprime=True, date_suppression__lt=limite)
    for f in a_purger:
        taille = f.taille
        f.fichier.delete(save=False)
        f.delete()
        profil.espace_utilise = max(0, profil.espace_utilise - taille)
        profil.save()
    return render(request, 'partage/corbeille.html', {
        'fichiers': fichiers,
        'profil': profil,
    })


@login_required
def restaurer_fichier(request, fichier_id):
    """Restaure un fichier depuis la corbeille."""
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, proprietaire=request.user, supprime=True)
    if request.method == 'POST':
        nom = fichier_obj.nom_original
        fichier_obj.supprime = False
        fichier_obj.date_suppression = None
        fichier_obj.save()
        journaliser(request, 'restauration', fichier=fichier_obj, detail=f'Restauré : {nom}')
        messages.success(request, f"♻️ « {nom} » restauré avec succès !")
    return redirect('corbeille')


@login_required
def supprimer_definitivement(request, fichier_id):
    """Supprime définitivement un fichier de la corbeille."""
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, proprietaire=request.user, supprime=True)
    if request.method == 'POST':
        nom = fichier_obj.nom_original
        taille = fichier_obj.taille
        fichier_obj.fichier.delete(save=False)
        fichier_obj.delete()
        profil = request.user.profil
        profil.espace_utilise = max(0, profil.espace_utilise - taille)
        profil.save()
        journaliser(request, 'suppression', detail=f'Supprimé définitivement : {nom}')
        messages.success(request, f"💥 « {nom} » supprimé définitivement.")
    return redirect('corbeille')


@login_required
def vider_corbeille(request):
    """Vide entièrement la corbeille de l'utilisateur."""
    if request.method == 'POST':
        fichiers = Fichier.objects.filter(proprietaire=request.user, supprime=True)
        profil = request.user.profil
        total_taille = 0
        count = 0
        for f in fichiers:
            total_taille += f.taille
            f.fichier.delete(save=False)
            f.delete()
            count += 1
        profil.espace_utilise = max(0, profil.espace_utilise - total_taille)
        profil.save()
        journaliser(request, 'suppression', detail=f'Corbeille vidée : {count} fichier(s)')
        messages.success(request, f"💥 Corbeille vidée : {count} fichier(s) supprimé(s) définitivement.")
    return redirect('corbeille')


@login_required
def creer_lien(request, fichier_id):
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, proprietaire=request.user)
    if fichier_obj.statut_scan != 'sain':
        messages.error(request, "❌ Fichier non validé.")
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
        messages.error(request, "Fichier temporairement indisponible.")
        return render(request, 'partage/lien_expire.html', status=503)

    lien.nb_telechargements += 1
    lien.save()
    journaliser(request, 'telechargement', fichier=lien.fichier, lien=lien,
                detail=f'Téléchargé par {request.user.username} ({request.user.email})')
    return _servir_fichier(lien.fichier)


@login_required
def telecharger_fichier(request, fichier_id):
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, proprietaire=request.user)
    if fichier_obj.supprime:
        messages.error(request, "❌ Ce fichier est dans la corbeille.")
        return redirect('mes_fichiers')
    if fichier_obj.statut_scan != 'sain':
        messages.error(request, "❌ Ce fichier ne peut pas être téléchargé.")
        return redirect('mes_fichiers')
    journaliser(request, 'telechargement', fichier=fichier_obj)
    return _servir_fichier(fichier_obj)


def _servir_fichier(fichier_obj):
    """Sert le fichier déchiffré depuis son emplacement CLOUD EDC/<username>/."""
    if fichier_obj.est_chiffre and fichier_obj.iv_chiffrement:
        try:
            with open(fichier_obj.fichier.path, 'rb') as f:
                contenu_chiffre = f.read()
            contenu_clair = dechiffrer_en_memoire(contenu_chiffre, fichier_obj.iv_chiffrement)
            response = HttpResponse(contenu_clair, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{fichier_obj.nom_original}"'
            return response
        except Exception as e:
            raise Http404(f"Impossible de déchiffrer : {e}")
    return FileResponse(
        open(fichier_obj.fichier.path, 'rb'),
        as_attachment=True,
        filename=fichier_obj.nom_original,
    )


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
            messages.success(request, f"✅ Quota de {utilisateur.username} : {quota_gb} GB.")
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
        messages.success(request, f"🗑️ « {nom} » déplacé dans la corbeille.")
    return redirect('admin_dashboard')


@user_passes_test(is_admin, login_url='connexion')
def admin_toggle_user(request, user_id):
    utilisateur = get_object_or_404(User, id=user_id)
    if utilisateur == request.user:
        messages.error(request, "Vous ne pouvez pas désactiver votre propre compte.")
        return redirect('admin_dashboard')
    utilisateur.is_active = not utilisateur.is_active
    utilisateur.save()
    etat = "activé" if utilisateur.is_active else "désactivé"
    messages.success(request, f"✅ Compte de {utilisateur.username} {etat}.")
    return redirect('admin_dashboard')


@user_passes_test(is_admin, login_url='connexion')
def admin_logs(request):
    logs = LogAcces.objects.select_related('utilisateur', 'fichier').all()
    return render(request, 'partage/admin_logs.html', {'logs': logs})


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
    """Vue admin : tous les fichiers en corbeille, tous utilisateurs confondus."""
    fichiers = Fichier.objects.filter(supprime=True).select_related('proprietaire').order_by('-date_suppression')
    total_taille = sum(f.taille for f in fichiers)
    context = {
        'fichiers': fichiers,
        'total_taille': total_taille,
        'nb_total': fichiers.count(),
    }
    return render(request, 'partage/admin_corbeille.html', context)


@user_passes_test(is_admin, login_url='connexion')
def admin_supprimer_definitivement(request, fichier_id):
    """Suppression définitive par l'admin."""
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, supprime=True)
    if request.method == 'POST':
        nom = fichier_obj.nom_original
        proprietaire = fichier_obj.proprietaire
        taille = fichier_obj.taille
        fichier_obj.fichier.delete(save=False)
        fichier_obj.delete()
        profil = proprietaire.profil
        profil.espace_utilise = max(0, profil.espace_utilise - taille)
        profil.save()
        journaliser(request, 'suppression', detail=f'Admin : supprimé définitivement {nom}')
        messages.success(request, f"💥 « {nom} » supprimé définitivement.")
    return redirect('admin_corbeille')


@user_passes_test(is_admin, login_url='connexion')
def admin_restaurer_fichier(request, fichier_id):
    """Restauration par l'admin."""
    fichier_obj = get_object_or_404(Fichier, id=fichier_id, supprime=True)
    if request.method == 'POST':
        nom = fichier_obj.nom_original
        proprietaire = fichier_obj.proprietaire
        fichier_obj.supprime = False
        fichier_obj.date_suppression = None
        fichier_obj.save()
        journaliser(request, 'restauration', fichier=fichier_obj,
                   detail=f'Admin : restauré {nom} (propriétaire: {proprietaire.username})')
        messages.success(request, f"♻️ « {nom} » restauré.")
    return redirect('admin_corbeille')



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
            messages.error(request, "❌ La liste des extensions ne peut pas être vide.")
        else:
            config.extensions_autorisees = ','.join(sorted(set(extensions)))
            try:
                config.taille_max_mb = max(1, int(taille_max))
            except ValueError:
                config.taille_max_mb = 100
            config.save()
            journaliser(request, 'config', detail=f'Extensions mises à jour ({len(extensions)} autorisées)')
            messages.success(request, f"✅ Configuration mise à jour : {len(extensions)} extensions autorisées.")
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
            Q(fichier__nom_original__icontains=q)
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
            log.fichier.nom_original if log.fichier else '',
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
    journaliser(request, 'acces_refuse',
                detail=f'Rate limit atteint sur {request.path}')
    return render(request, 'partage/ratelimited.html', status=429)
