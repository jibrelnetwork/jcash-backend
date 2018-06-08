from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0016_currency_license_registry_address'),
    ]

    operations = [
        migrations.AlterField(
            model_name='refund',
            name='application',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='refundes', to='api.Application'),
        ),
    ]
