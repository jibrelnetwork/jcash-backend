from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0015_buy_sell_fee'),
    ]

    operations = [
        migrations.AddField(
            model_name='currency',
            name='license_registry_address',
            field=models.CharField(blank=True, max_length=255, null=True, unique=True),
        ),
    ]
