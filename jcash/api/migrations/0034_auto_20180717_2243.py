from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0033_documentverification'),
    ]

    operations = [
        migrations.AddField(
            model_name='documentverification',
            name='corporate',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='document_verifications', to='api.Corporate'),
        ),
        migrations.AddField(
            model_name='documentverification',
            name='personal',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='document_verifications', to='api.Personal'),
        ),
    ]
