"""Tests de sécurité de Cloud EDC.

Lancer dans le conteneur :  python manage.py test partage
Chaque test correspond à une faille corrigée (voir l'audit de sécurité).
"""
import base64
import os
import tempfile
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings

from .antivirus import ScanIndisponible, ScanErreur
from .encryption import (chiffrer_en_memoire, dechiffrer_en_memoire,
                         chiffrer_v1_pour_tests, est_format_v2)
from .models import CodeOTP, Fichier, LienPartage

CLE_TEST = base64.b64encode(os.urandom(32)).decode()
# Les tests écrivent dans un dossier temporaire, jamais dans le vrai stockage du cloud.
MEDIA_TEST = tempfile.mkdtemp(prefix='cloud_edc_tests_')


@override_settings(MEDIA_ROOT=MEDIA_TEST)
@override_settings(FILE_ENCRYPTION_KEY_V2=CLE_TEST, FILE_ENCRYPTION_KEY='ancienne-phrase')
class ChiffrementTests(TestCase):
    def test_aller_retour_gcm(self):
        data = os.urandom(200_000)
        chiffre, iv = chiffrer_en_memoire(data)
        self.assertTrue(est_format_v2(iv))
        self.assertNotIn(data[:64], chiffre)
        self.assertEqual(dechiffrer_en_memoire(chiffre, iv), data)

    def test_nonce_different_a_chaque_fichier(self):
        _, iv1 = chiffrer_en_memoire(b'meme contenu')
        _, iv2 = chiffrer_en_memoire(b'meme contenu')
        self.assertNotEqual(iv1, iv2)

    def test_modification_detectee(self):
        chiffre, iv = chiffrer_en_memoire(b'rapport financier')
        altere = bytes([chiffre[0] ^ 1]) + chiffre[1:]
        with self.assertRaises(ValueError):
            dechiffrer_en_memoire(altere, iv)

    def test_ancien_format_toujours_lisible(self):
        chiffre, iv = chiffrer_v1_pour_tests(b'ancien fichier')
        self.assertFalse(est_format_v2(iv))
        self.assertEqual(dechiffrer_en_memoire(chiffre, iv), b'ancien fichier')


@override_settings(MEDIA_ROOT=MEDIA_TEST)
class OTPTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('agent', 'agent@edc.cm', 'MotDePasse!2026')

    def test_code_six_chiffres(self):
        otp = CodeOTP.generer(self.user)
        self.assertEqual(len(otp.code), 6)
        self.assertTrue(otp.code.isdigit())

    def test_code_bloque_apres_cinq_echecs(self):
        otp = CodeOTP.generer(self.user)
        faux = '000000' if otp.code != '000000' else '111111'
        for _ in range(CodeOTP.MAX_TENTATIVES):
            CodeOTP.verifier(self.user, faux)
        # Même le bon code est refusé une fois le maximum atteint.
        self.assertEqual(CodeOTP.verifier(self.user, otp.code), 'bloque')

    def test_code_a_usage_unique(self):
        otp = CodeOTP.generer(self.user)
        self.assertEqual(CodeOTP.verifier(self.user, otp.code), 'ok')
        self.assertNotEqual(CodeOTP.verifier(self.user, otp.code), 'ok')


@override_settings(MEDIA_ROOT=MEDIA_TEST)
class ConnexionTests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser('admin', 'admin@edc.cm', 'MotDePasse!2026')

    @mock.patch('partage.views._envoyer_otp', return_value=True)
    def test_admin_passe_par_otp_meme_avec_en_tete_falsifie(self, _mail):
        reponse = self.client.post(
            '/connexion/',
            {'email': 'admin@edc.cm', 'password': 'MotDePasse!2026'},
            HTTP_X_FORWARDED_FOR='127.0.0.1',
            HTTP_X_REAL_IP='203.0.113.7',
        )
        self.assertRedirects(reponse, '/verifier-otp/', fetch_redirect_response=False)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_message_identique_compte_inconnu_ou_mauvais_mot_de_passe(self):
        r1 = self.client.post('/connexion/', {'email': 'inconnu@edc.cm', 'password': 'x'},
                              HTTP_X_REAL_IP='203.0.113.8')
        r2 = self.client.post('/connexion/', {'email': 'admin@edc.cm', 'password': 'mauvais'},
                              HTTP_X_REAL_IP='203.0.113.9')
        self.assertContains(r1, 'Adresse e-mail ou mot de passe incorrect')
        self.assertContains(r2, 'Adresse e-mail ou mot de passe incorrect')
        self.assertNotContains(r1, 'Aucun compte')

    def test_sixieme_tentative_refusee_en_429_et_journalisee(self):
        from .models import LogAcces
        for _ in range(5):
            r = self.client.post('/connexion/', {'email': 'admin@edc.cm', 'password': 'mauvais'},
                                 HTTP_X_REAL_IP='203.0.113.50')
            self.assertEqual(r.status_code, 200)
        r = self.client.post('/connexion/', {'email': 'admin@edc.cm', 'password': 'mauvais'},
                             HTTP_X_REAL_IP='203.0.113.50')
        self.assertEqual(r.status_code, 429)
        self.assertTrue(LogAcces.objects.filter(action='limite_depassee').exists())


@override_settings(MEDIA_ROOT=MEDIA_TEST)
class ReinitialisationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('agent', 'agent@edc.cm', 'AncienMdp!2026')

    @mock.patch('partage.views._envoyer_otp', return_value=True)
    def test_force_brute_impossible(self, _mail):
        self.client.post('/mot-de-passe-oublie/', {'email': 'agent@edc.cm'},
                         HTTP_X_REAL_IP='203.0.113.10')
        vrai_code = CodeOTP.objects.get(utilisateur=self.user).code
        faux = [f'{i:06d}' for i in range(20) if f'{i:06d}' != vrai_code][:CodeOTP.MAX_TENTATIVES]
        for code in faux:
            self.client.post('/reinitialiser-mot-de-passe/',
                             {'code': code, 'password1': 'NouveauMdp!2026', 'password2': 'NouveauMdp!2026'},
                             HTTP_X_REAL_IP='203.0.113.10')
        # Après 5 échecs, le vrai code ne fonctionne plus.
        self.client.post('/reinitialiser-mot-de-passe/',
                         {'code': vrai_code, 'password1': 'NouveauMdp!2026', 'password2': 'NouveauMdp!2026'},
                         HTTP_X_REAL_IP='203.0.113.10')
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('AncienMdp!2026'))

    @mock.patch('partage.views._envoyer_otp', return_value=True)
    def test_meme_reponse_si_compte_inexistant(self, _mail):
        r = self.client.post('/mot-de-passe-oublie/', {'email': 'personne@edc.cm'},
                             HTTP_X_REAL_IP='203.0.113.11')
        self.assertRedirects(r, '/reinitialiser-mot-de-passe/', fetch_redirect_response=False)


@override_settings(MEDIA_ROOT=MEDIA_TEST)
@override_settings(FILE_ENCRYPTION_KEY_V2=CLE_TEST)
class UploadTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('agent', 'agent@edc.cm', 'MotDePasse!2026')
        self.client.force_login(self.user)

    def _envoyer(self):
        f = SimpleUploadedFile('rapport.pdf', b'%PDF-1.4 contenu de test')
        return self.client.post('/upload/', {'fichiers': [f]}, HTTP_X_REAL_IP='203.0.113.20')

    @mock.patch('partage.views.scanner_fichier', side_effect=ScanIndisponible('arrêté'))
    def test_refus_si_clamav_indisponible(self, _scan):
        self._envoyer()
        self.assertEqual(Fichier.objects.count(), 0)

    @mock.patch('partage.views.scanner_fichier', side_effect=ScanErreur('INSTREAM size limit exceeded'))
    def test_refus_si_clamav_en_erreur(self, _scan):
        self._envoyer()
        self.assertEqual(Fichier.objects.count(), 0)

    @mock.patch('partage.views.scanner_fichier', return_value=('infecte', 'Eicar-Signature'))
    def test_refus_si_infecte(self, _scan):
        self._envoyer()
        self.assertEqual(Fichier.objects.count(), 0)

    @mock.patch('partage.views.scanner_fichier', return_value=('sain', None))
    def test_fichier_sain_stocke_chiffre_et_relisible(self, _scan):
        self._envoyer()
        fichier = Fichier.objects.get()
        self.assertTrue(est_format_v2(fichier.iv_chiffrement))
        with open(fichier.fichier.path, 'rb') as f:
            self.assertNotIn(b'contenu de test', f.read())
        r = self.client.get(f'/telecharger/{fichier.id}/', HTTP_X_REAL_IP='203.0.113.20')
        self.assertEqual(b''.join(r.streaming_content), b'%PDF-1.4 contenu de test')
        fichier.fichier.delete(save=False)

    @mock.patch('partage.views.scanner_fichier', return_value=('sain', None))
    def test_envoi_en_arriere_plan_repond_en_json(self, _scan):
        f = SimpleUploadedFile('note.pdf', b'%PDF-1.4 note')
        r = self.client.post('/upload/', {'fichiers': [f]}, HTTP_X_REAL_IP='203.0.113.20',
                             HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertEqual(r.json(), {'redirection': '/mes-fichiers/'})
        # Le message de confirmation attend la page suivante.
        self.assertContains(self.client.get('/mes-fichiers/', HTTP_X_REAL_IP='203.0.113.20'), '1 fichier déposé')
        Fichier.objects.get().fichier.delete(save=False)

    @mock.patch('partage.views.scanner_fichier', return_value=('sain', None))
    def test_lien_inutilisable_si_fichier_en_corbeille(self, _scan):
        from datetime import timedelta
        from django.utils import timezone
        self._envoyer()
        fichier = Fichier.objects.get()
        lien = LienPartage.objects.create(fichier=fichier, cree_par=self.user,
                                          date_expiration=timezone.now() + timedelta(days=1))
        fichier.supprime = True
        fichier.save()
        self.assertFalse(lien.est_valide())
        fichier.fichier.delete(save=False)

    def test_jauge_d_espace_a_la_bonne_largeur(self):
        # En français, 1.2 s'affiche « 1,2 » : dans un style CSS, la largeur serait ignorée
        # et la jauge s'afficherait pleine.
        profil = self.user.profil
        profil.espace_utilise = int(profil.quota_octets * 0.012)
        profil.save()
        r = self.client.get('/mes-fichiers/', HTTP_X_REAL_IP='203.0.113.20')
        self.assertContains(r, 'width: 1.2%')
        self.assertNotContains(r, 'width: 1,2%')

    @mock.patch('partage.views.scanner_fichier', return_value=('sain', None))
    def test_nom_de_fichier_long_accepte(self, _scan):
        # Chemin de 101 caractères avec l'ancien format : refusé par PostgreSQL (limite 100).
        nom = 'Plan_localisation_NYA_CELESTINE_NIU_' + 'x' * 200 + '.pdf'
        f = SimpleUploadedFile(nom, b'%PDF-1.4 long')
        self.client.post('/upload/', {'fichiers': [f]}, HTTP_X_REAL_IP='203.0.113.20')
        fichier = Fichier.objects.get()
        self.assertEqual(fichier.nom_original, nom)
        champ = Fichier._meta.get_field('fichier')
        self.assertLessEqual(len(fichier.fichier.name), champ.max_length)
        self.assertTrue(fichier.fichier.name.endswith('.pdf.enc'))
        fichier.fichier.delete(save=False)


@override_settings(MEDIA_ROOT=MEDIA_TEST, FILE_UPLOAD_MAX_MEMORY_SIZE=1024 * 1024)
@override_settings(FILE_ENCRYPTION_KEY_V2=CLE_TEST, FILE_ENCRYPTION_KEY='ancienne-phrase')
class GrosFichiersTests(TestCase):
    """Dépôt et téléchargement par blocs : la taille du fichier ne change pas la mémoire utilisée."""
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('agent', 'agent@edc.cm', 'MotDePasse!2026')
        self.client.force_login(self.user)
        # 3,5 Mo : plusieurs blocs de 1 Mo, et plus que FILE_UPLOAD_MAX_MEMORY_SIZE,
        # donc Django passe par un fichier temporaire sur disque comme en production.
        self.contenu = os.urandom(3 * 1024 * 1024 + 512 * 1024)

    def _deposer(self):
        f = SimpleUploadedFile('video.mp4', self.contenu)
        with mock.patch('partage.views.scanner_fichier', return_value=('sain', None)) as scan:
            self.client.post('/upload/', {'fichiers': [f]}, HTTP_X_REAL_IP='203.0.113.20')
        return scan, Fichier.objects.get()

    def test_depot_et_telechargement_par_blocs(self):
        _scan, fichier = self._deposer()
        self.assertEqual(os.path.getsize(fichier.fichier.path), len(self.contenu) + 16)
        r = self.client.get(f'/telecharger/{fichier.id}/', HTTP_X_REAL_IP='203.0.113.20')
        self.assertEqual(int(r['Content-Length']), len(self.contenu))
        blocs = list(r.streaming_content)
        self.assertGreater(len(blocs), 1)
        self.assertTrue(all(len(b) <= 1024 * 1024 for b in blocs))
        self.assertEqual(b''.join(blocs), self.contenu)
        fichier.fichier.delete(save=False)

    def test_aucun_fichier_partiel_laisse_sur_le_disque(self):
        _scan, fichier = self._deposer()
        dossier = os.path.dirname(fichier.fichier.path)
        self.assertFalse([n for n in os.listdir(dossier) if n.endswith('.partiel')])
        fichier.fichier.delete(save=False)

    def test_fichier_modifie_jamais_envoye(self):
        _scan, fichier = self._deposer()
        with open(fichier.fichier.path, 'r+b') as h:
            h.seek(2 * 1024 * 1024)
            octet = h.read(1)
            h.seek(2 * 1024 * 1024)
            h.write(bytes([octet[0] ^ 1]))
        r = self.client.get(f'/telecharger/{fichier.id}/', HTTP_X_REAL_IP='203.0.113.20')
        self.assertRedirects(r, '/mes-fichiers/', fetch_redirect_response=False)
        from .models import LogAcces
        self.assertTrue(LogAcces.objects.filter(action='fichier_altere', fichier=fichier).exists())
        self.assertFalse(LogAcces.objects.filter(action='telechargement', fichier=fichier).exists())
        fichier.fichier.delete(save=False)


class FausseConnexionClamd:
    """Imite clamd : enregistre ce qui est envoyé et renvoie une réponse fixe."""
    def __init__(self, reponse=b'stream: OK\0', erreur_envoi=None):
        self.envoye, self.reponse, self.erreur_envoi = [], reponse, erreur_envoi
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def sendall(self, donnees):
        if self.erreur_envoi:
            raise self.erreur_envoi
        self.envoye.append(donnees)
    def recv(self, n):
        r, self.reponse = self.reponse, b''
        return r


class AntivirusTests(TestCase):
    def test_envoi_par_blocs_de_1_mo(self):
        import io
        from .antivirus import scanner_fichier
        faux = FausseConnexionClamd()
        with mock.patch('partage.antivirus.socket.create_connection', return_value=faux):
            self.assertEqual(scanner_fichier(io.BytesIO(b'x' * (2 * 1024 * 1024 + 10))), ('sain', None))
        self.assertEqual(faux.envoye[0], b'zINSTREAM\0')
        self.assertEqual(faux.envoye[-1], b'\0\0\0\0')
        self.assertTrue(all(len(m) <= 1024 * 1024 + 4 for m in faux.envoye))

    def test_menace_detectee(self):
        import io
        from .antivirus import scanner_fichier
        faux = FausseConnexionClamd(b'stream: Eicar-Test-Signature FOUND\0')
        with mock.patch('partage.antivirus.socket.create_connection', return_value=faux):
            self.assertEqual(scanner_fichier(io.BytesIO(b'X5O')), ('infecte', 'Eicar-Test-Signature'))

    def test_clamav_arrete(self):
        import io
        from .antivirus import scanner_fichier
        with mock.patch('partage.antivirus.socket.create_connection', side_effect=ConnectionRefusedError()):
            with self.assertRaises(ScanIndisponible):
                scanner_fichier(io.BytesIO(b'abc'))

    def test_fichier_trop_gros_pour_clamav(self):
        import io
        from .antivirus import scanner_fichier
        faux = FausseConnexionClamd(erreur_envoi=BrokenPipeError())
        with mock.patch('partage.antivirus.socket.create_connection', return_value=faux):
            with self.assertRaises(ScanErreur):
                scanner_fichier(io.BytesIO(b'abc'))


@override_settings(MEDIA_ROOT=MEDIA_TEST)
@override_settings(FILE_ENCRYPTION_KEY_V2=CLE_TEST, FILE_ENCRYPTION_KEY='ancienne-phrase')
class RechiffrementTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('agent', 'agent@edc.cm', 'MotDePasse!2026')

    def _fichier_ancien(self, contenu, nom='doc.bin'):
        from django.core.files.base import ContentFile
        chiffre, iv = chiffrer_v1_pour_tests(contenu)
        f = Fichier(proprietaire=self.user, nom_original=nom, taille=len(contenu),
                    statut_scan='sain', est_chiffre=True, iv_chiffrement=iv)
        f.fichier.save(nom + '.enc', ContentFile(chiffre), save=False)
        f.save()
        return f

    def _lire(self, f):
        f.refresh_from_db()
        with open(f.fichier.path, 'rb') as h:
            return dechiffrer_en_memoire(h.read(), f.iv_chiffrement)

    def _commande(self):
        from django.core.management import call_command
        call_command('rechiffrer_fichiers', stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))

    def tearDown(self):
        for f in Fichier.objects.all():
            for suffixe in ('', '.ancien', '.rechiffrement'):
                if os.path.exists(f.fichier.path + suffixe):
                    os.unlink(f.fichier.path + suffixe)

    def test_conversion_gros_fichier_par_blocs(self):
        contenu = os.urandom(3 * 1024 * 1024 + 123)   # plusieurs blocs, taille non alignée
        f = self._fichier_ancien(contenu)
        self._commande()
        self.assertTrue(est_format_v2(Fichier.objects.get(id=f.id).iv_chiffrement))
        self.assertEqual(self._lire(f), contenu)

    def test_reprise_apres_plantage_ancienne_version(self):
        # Ancienne version interrompue : original déplacé en .ancien, base non validée.
        contenu = b'document important' * 1000
        f = self._fichier_ancien(contenu)
        os.replace(f.fichier.path, f.fichier.path + '.ancien')
        with open(f.fichier.path + '.rechiffrement', 'wb') as h:
            h.write(b'contenu partiel')
        self._commande()
        self.assertFalse(os.path.exists(f.fichier.path + '.ancien'))
        self.assertFalse(os.path.exists(f.fichier.path + '.rechiffrement'))
        self.assertEqual(self._lire(f), contenu)

    def test_reprise_entre_base_et_remplacement(self):
        # Nouvelle version interrompue après la mise à jour de la base, avant le remplacement.
        from partage.encryption import chiffrer_en_memoire as chiffrer_v2
        contenu = b'rapport' * 500
        f = self._fichier_ancien(contenu)
        chiffre, iv = chiffrer_v2(contenu)
        with open(f.fichier.path + '.rechiffrement', 'wb') as h:
            h.write(chiffre)
        Fichier.objects.filter(id=f.id).update(iv_chiffrement=iv)
        self._commande()
        self.assertEqual(self._lire(f), contenu)

    def test_mauvaise_cle_ne_modifie_rien(self):
        contenu = b'secret'
        f = self._fichier_ancien(contenu)
        with open(f.fichier.path, 'rb') as h:
            avant = h.read()
        with self.settings(FILE_ENCRYPTION_KEY='autre-phrase'):
            self._commande()
        f.refresh_from_db()
        self.assertFalse(est_format_v2(f.iv_chiffrement))
        with open(f.fichier.path, 'rb') as h:
            self.assertEqual(h.read(), avant)
        self.assertFalse(os.path.exists(f.fichier.path + '.rechiffrement'))


@override_settings(MEDIA_ROOT=MEDIA_TEST)
@override_settings(FILE_ENCRYPTION_KEY_V2=CLE_TEST, FILE_ENCRYPTION_KEY='ancienne-phrase')
class TracabiliteTests(TestCase):
    """Le journal reste probant et les fichiers supprimés sont conservés, puis effacés."""
    IP = {'HTTP_X_REAL_IP': '203.0.113.30'}

    def setUp(self):
        import hashlib
        cache.clear()
        self.agent = User.objects.create_user('agent', 'agent@edc.cm', 'MotDePasse!2026')
        self.collegue = User.objects.create_user('collegue', 'collegue@edc.cm', 'MotDePasse!2026')
        self.admin = User.objects.create_user('chef', 'chef@edc.cm', 'MotDePasse!2026', is_staff=True)
        self.contenu = b'Budget confidentiel 2026 ' * 1000
        self.empreinte = hashlib.sha256(self.contenu).hexdigest()
        self.client.force_login(self.agent)
        with mock.patch('partage.views.scanner_fichier', return_value=('sain', None)):
            self.client.post('/upload/', {'fichiers': [SimpleUploadedFile('Budget.xlsx', self.contenu)]}, **self.IP)
        self.fichier = Fichier.objects.get()

    def tearDown(self):
        for f in Fichier.objects.all():
            f.fichier.delete(save=False)

    def _supprimer_par_l_agent(self):
        self.client.force_login(self.agent)
        self.client.post(f'/supprimer/{self.fichier.id}/', **self.IP)
        self.client.post(f'/supprimer-definitif/{self.fichier.id}/', **self.IP)
        self.fichier.refresh_from_db()

    def test_empreinte_calculee_au_depot(self):
        from .models import LogAcces
        self.assertEqual(self.fichier.empreinte_sha256, self.empreinte)
        log = LogAcces.objects.get(action='upload')
        self.assertEqual((log.nom_fichier, log.taille_fichier, log.empreinte_fichier),
                         ('Budget.xlsx', len(self.contenu), self.empreinte))

    def test_suppression_par_l_utilisateur_conserve_le_fichier(self):
        from datetime import timedelta
        from django.utils import timezone
        lien = LienPartage.objects.create(fichier=self.fichier, cree_par=self.agent,
                                          date_expiration=timezone.now() + timedelta(days=1))
        self._supprimer_par_l_agent()
        # Plus visible ni téléchargeable pour l'utilisateur, ni par lien…
        r = self.client.get('/corbeille/', **self.IP)
        self.assertEqual(list(r.context['fichiers']), [])
        self.assertEqual(self.client.get(f'/telecharger/{self.fichier.id}/', **self.IP).status_code, 302)
        self.assertFalse(lien.est_valide())
        self.assertEqual(self.agent.profil.__class__.objects.get(utilisateur=self.agent).espace_utilise, 0)
        # … mais toujours présent sur le disque, avec une échéance de 90 jours.
        self.assertTrue(os.path.exists(self.fichier.fichier.path))
        self.assertEqual((self.fichier.conserve_jusqua - self.fichier.efface_par_utilisateur).days, 90)

    def test_journal_garde_la_trace_apres_effacement(self):
        from datetime import timedelta
        from django.utils import timezone
        from .conservation import purger_fichiers_expires
        from .models import LogAcces
        self.client.get(f'/telecharger/{self.fichier.id}/', **self.IP)
        self._supprimer_par_l_agent()
        chemin = self.fichier.fichier.path
        Fichier.objects.filter(pk=self.fichier.pk).update(conserve_jusqua=timezone.now() - timedelta(seconds=1))
        self.assertEqual(purger_fichiers_expires(), 1)
        self.assertFalse(os.path.exists(chemin))
        self.assertFalse(Fichier.objects.exists())
        for action in ('upload', 'telechargement', 'suppression', 'purge'):
            log = LogAcces.objects.filter(action=action).first()
            self.assertIsNotNone(log, action)
            self.assertEqual(log.nom_affiche, 'Budget.xlsx', action)
            self.assertEqual(log.empreinte_fichier, self.empreinte, action)

    def test_compte_sous_conservation_jamais_purge(self):
        from datetime import timedelta
        from django.utils import timezone
        from .conservation import purger_fichiers_expires
        self._supprimer_par_l_agent()
        profil = self.agent.profil
        profil.sous_conservation = True
        profil.save()
        Fichier.objects.filter(pk=self.fichier.pk).update(conserve_jusqua=timezone.now() - timedelta(days=1))
        self.assertEqual(purger_fichiers_expires(), 0)
        self.client.force_login(self.admin)
        self.client.post(f'/admin-cloud/supprimer-definitif/{self.fichier.id}/', **self.IP)
        self.assertTrue(Fichier.objects.filter(pk=self.fichier.pk).exists())

    def test_consultation_admin_exige_un_motif_et_est_journalisee(self):
        from .models import LogAcces
        self._supprimer_par_l_agent()
        self.client.force_login(self.admin)
        r = self.client.post(f'/admin-cloud/consulter/{self.fichier.id}/', {'motif': 'curiosité'}, **self.IP)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(LogAcces.objects.filter(action='consultation_admin').exists())
        motif = 'Enquête fuite de document, demande DG du 20/10/2026'
        r = self.client.post(f'/admin-cloud/consulter/{self.fichier.id}/', {'motif': motif}, **self.IP)
        self.assertEqual(b''.join(r.streaming_content), self.contenu)
        log = LogAcces.objects.get(action='consultation_admin')
        self.assertEqual(log.utilisateur, self.admin)
        self.assertIn(motif, log.detail)
        self.assertEqual(log.empreinte_fichier, self.empreinte)

    def test_consultation_interdite_hors_administrateurs(self):
        self._supprimer_par_l_agent()
        self.client.force_login(self.collegue)
        r = self.client.post(f'/admin-cloud/consulter/{self.fichier.id}/',
                             {'motif': 'Je veux voir ce fichier supprimé'}, **self.IP)
        self.assertEqual(r.status_code, 302)

    def test_consultation_impossible_pour_un_fichier_actif(self):
        self.client.force_login(self.admin)
        r = self.client.post(f'/admin-cloud/consulter/{self.fichier.id}/',
                             {'motif': 'Enquête fuite de document, demande DG'}, **self.IP)
        self.assertEqual(r.status_code, 404)

    def test_restauration_par_admin_rend_le_quota(self):
        self._supprimer_par_l_agent()
        self.client.force_login(self.admin)
        self.client.post(f'/admin-cloud/restaurer/{self.fichier.id}/', **self.IP)
        self.fichier.refresh_from_db()
        self.assertFalse(self.fichier.supprime)
        self.assertIsNone(self.fichier.conserve_jusqua)
        self.agent.profil.refresh_from_db()
        self.assertEqual(self.agent.profil.espace_utilise, len(self.contenu))

    def test_calcul_des_empreintes_des_anciens_fichiers(self):
        from django.core.management import call_command
        from .models import LogAcces
        Fichier.objects.update(empreinte_sha256='')
        LogAcces.objects.update(empreinte_fichier='')
        call_command('calculer_empreintes', stdout=open(os.devnull, 'w'))
        self.fichier.refresh_from_db()
        self.assertEqual(self.fichier.empreinte_sha256, self.empreinte)
        self.assertEqual(LogAcces.objects.get(action='upload').empreinte_fichier, self.empreinte)

    def test_recherche_par_empreinte_dans_le_journal(self):
        self.client.force_login(self.admin)
        r = self.client.get('/admin-cloud/logs/', {'q': self.empreinte[:16]}, **self.IP)
        self.assertContains(r, 'Budget.xlsx')


@override_settings(METRICS_TOKEN='jeton-de-test')
class MetriquesTests(TestCase):
    """Page /metrics lue par Prometheus : protégée par jeton, compteurs à jour."""
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('agent', 'agent@edc.cm', 'MotDePasse!2026')

    def _lire(self, jeton='jeton-de-test'):
        return self.client.get('/metrics', HTTP_AUTHORIZATION=f'Bearer {jeton}', HTTP_HOST='django')

    def test_invisible_sans_le_bon_jeton(self):
        self.assertEqual(self.client.get('/metrics', HTTP_HOST='django').status_code, 404)
        self.assertEqual(self._lire('mauvais').status_code, 404)

    @override_settings(METRICS_TOKEN='')
    def test_desactivee_sans_jeton_configure(self):
        self.assertEqual(self._lire('').status_code, 404)

    @mock.patch('partage.metriques._clamav_disponible', return_value=1)
    def test_echecs_de_connexion_comptes(self, _clam):
        for _ in range(3):
            self.client.post('/connexion/', {'email': 'agent@edc.cm', 'password': 'faux'},
                             HTTP_X_REAL_IP='203.0.113.40')
        texte = self._lire().content.decode()
        self.assertIn('cloud_edc_evenements_total{action="connexion_echec"} 3', texte)
        self.assertIn('cloud_edc_utilisateurs{etat="actif"} 1', texte)
        self.assertIn('cloud_edc_clamav_disponible 1', texte)
        self.assertIn('# TYPE cloud_edc_evenements_total counter', texte)
