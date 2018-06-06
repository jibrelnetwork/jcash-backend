from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0014_rm_setting_and_add_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='currencypair',
            name='buy_fee_percent',
            field=models.FloatField(default=0.0),
        ),
        migrations.AddField(
            model_name='currencypair',
            name='sell_fee_percent',
            field=models.FloatField(default=0.0),
        ),
    ]
