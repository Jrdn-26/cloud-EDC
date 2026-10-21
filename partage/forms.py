from django import forms
from django.conf import settings
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class InscriptionForm(UserCreationForm):
    email      = forms.EmailField(required=True, label="Adresse e-mail")
    first_name = forms.CharField(max_length=50, required=False, label="Prénom")
    last_name  = forms.CharField(max_length=50, required=False, label="Nom")

    class Meta:
        model  = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password1', 'password2']

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()
        domaines = getattr(settings, 'ALLOWED_EMAIL_DOMAINS', [])
        if domaines and email.rsplit('@', 1)[-1] not in domaines:
            raise forms.ValidationError(
                "L'inscription est reservee aux adresses : "
                + ", ".join('@' + d for d in domaines) + "."
            )
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("Cette adresse e-mail est déjà associée à un compte.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email      = self.cleaned_data['email']
        user.first_name = self.cleaned_data.get('first_name', '')
        user.last_name  = self.cleaned_data.get('last_name', '')
        if commit:
            user.save()
        return user


class UploadFichierForm(forms.Form):
    pass


class CreerLienForm(forms.Form):
    duree_validite = forms.ChoiceField(
        label="Durée de validité",
        choices=[(1,"1 jour"),(7,"7 jours"),(30,"30 jours"),(90,"90 jours")],
        initial=7,
    )
    nb_telechargements_max = forms.IntegerField(
        label="Nombre max de téléchargements (vide = illimité)",
        required=False, min_value=1,
    )


class AllouerQuotaForm(forms.Form):
    QUOTA_CHOICES = [
        (2,"2 Go"),(5,"5 Go"),(10,"10 Go"),
        (20,"20 Go"),(50,"50 Go"),(100,"100 Go"),
    ]
    quota_gb = forms.ChoiceField(label="Nouveau quota", choices=QUOTA_CHOICES)
    quota_personnalise_gb = forms.FloatField(
        label="Ou saisir un quota personnalisé (Go)",
        required=False, min_value=0.1,
    )

    def clean(self):
        cleaned = super().clean()
        custom = cleaned.get('quota_personnalise_gb')
        cleaned['quota_final_gb'] = custom if custom else float(cleaned.get('quota_gb', 2))
        return cleaned


class VerifierOTPForm(forms.Form):
    code = forms.CharField(
        max_length=6, min_length=6,
        label="Code de verification",
        widget=forms.TextInput(attrs={
            'placeholder': '•  •  •  •  •  •',
            'autocomplete': 'one-time-code',
            'inputmode': 'numeric',
            'pattern': '[0-9]{6}',
            'autofocus': True,
            'maxlength': '6',
        })
    )

    def clean_code(self):
        code = self.cleaned_data.get('code', '').strip()
        if not code.isdigit() or len(code) != 6:
            raise forms.ValidationError("Le code doit contenir exactement 6 chiffres.")
        return code


class MotDePasseOublieForm(forms.Form):
    email = forms.EmailField(
        label="Adresse e-mail",
        widget=forms.EmailInput(attrs={
            'placeholder': 'votre.email@edc.cm',
            'autocomplete': 'email',
            'autofocus': True,
        })
    )


class NouveauMotDePasseForm(forms.Form):
    password1 = forms.CharField(
        label="Nouveau mot de passe",
        min_length=8,
        widget=forms.PasswordInput(attrs={'placeholder': '••••••••', 'autocomplete': 'new-password'})
    )
    password2 = forms.CharField(
        label="Confirmer le mot de passe",
        widget=forms.PasswordInput(attrs={'placeholder': '••••••••', 'autocomplete': 'new-password'})
    )

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get('password1')
        p2 = cleaned.get('password2')
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("Les deux mots de passe ne correspondent pas.")
        return cleaned
