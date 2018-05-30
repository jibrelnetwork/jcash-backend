from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_address_is_removed'),
    ]

    operations = [
        migrations.AddField(
            model_name='address',
            name='is_allowed',
            field=models.BooleanField(default=False),
        ),
    ]
