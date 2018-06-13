from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0018_auto_20180613_1312'),
    ]

    operations = [
        migrations.AddField(
            model_name='exchange',
            name='incoming_transaction',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='refundes', to='api.IncomingTransaction'),
        ),
        migrations.AddField(
            model_name='refund',
            name='incoming_transaction',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='exchanges', to='api.IncomingTransaction'),
        ),
    ]
