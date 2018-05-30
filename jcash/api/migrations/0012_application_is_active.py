from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0011_address_is_allowed'),
    ]

    operations = [
        migrations.AddField(
            model_name='application',
            name='is_active',
            field=models.BooleanField(default=False),
        ),
    ]
