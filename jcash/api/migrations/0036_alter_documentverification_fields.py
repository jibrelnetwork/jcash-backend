from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0035_documentverification_onfido_applicant_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='documentverification',
            name='passport',
            field=models.OneToOneField(on_delete=django.db.models.deletion.DO_NOTHING, related_name='passport_verification', to='api.Document'),
        ),
        migrations.AlterField(
            model_name='documentverification',
            name='selfie',
            field=models.OneToOneField(on_delete=django.db.models.deletion.DO_NOTHING, related_name='selfie_verification', to='api.Document'),
        ),
        migrations.AlterField(
            model_name='documentverification',
            name='utilitybills',
            field=models.OneToOneField(on_delete=django.db.models.deletion.DO_NOTHING, related_name='utilitybills_verification', to='api.Document'),
        ),
    ]
