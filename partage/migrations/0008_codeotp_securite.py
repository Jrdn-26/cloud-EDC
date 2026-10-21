from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('partage', '0007_alter_profilutilisateur_quota_octets'),
    ]

    operations = [
        migrations.AlterField(
            model_name='codeotp',
            name='code',
            field=models.CharField(max_length=6),
        ),
        migrations.AddField(
            model_name='codeotp',
            name='tentatives',
            field=models.PositiveSmallIntegerField(default=0),
        ),
    ]
