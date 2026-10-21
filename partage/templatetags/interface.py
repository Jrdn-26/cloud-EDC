"""Balises de gabarit de l'interface : icônes SVG et type de fichier."""
import os
from datetime import timedelta

from django import template
from django.templatetags.static import static
from django.utils.html import format_html

register = template.Library()

TYPES_FICHIER = {
    'file-text': {'pdf', 'doc', 'docx', 'odt', 'txt', 'rtf'},
    'file-spreadsheet': {'xls', 'xlsx', 'ods', 'csv'},
    'image': {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp'},
    'file-video': {'mp4', 'avi', 'mov', 'mkv', 'webm'},
    'file-audio': {'mp3', 'wav', 'ogg', 'flac'},
    'file-archive': {'zip', 'rar', '7z', 'tar', 'gz'},
    'file-code': {'json', 'xml', 'html', 'css', 'js', 'py'},
}


@register.simple_tag
def icone(nom, classe=''):
    """Affiche une icône du fichier static/icons/icones.svg : {% icone "folder" %}."""
    return format_html(
        '<svg class="ic {}" aria-hidden="true" focusable="false"><use href="{}#{}"></use></svg>',
        classe, static('icons/icones.svg'), nom,
    )


@register.filter
def icone_fichier(nom_fichier):
    """Nom de l'icône correspondant à l'extension d'un fichier."""
    ext = os.path.splitext(nom_fichier or '')[1].lower().lstrip('.')
    for icone_nom, extensions in TYPES_FICHIER.items():
        if ext in extensions:
            return icone_nom
    return 'file'


@register.filter
def date_purge(date_suppression, jours=30):
    """Date à laquelle un fichier de la corbeille sera supprimé définitivement."""
    if not date_suppression:
        return None
    return date_suppression + timedelta(days=int(jours))
