# Generated by Django 2.0.4 on 2018-08-09 12:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0057_application_reason'),
    ]

    operations = [
        migrations.AddField(
            model_name='currency',
            name='is_disabled',
            field=models.BooleanField(default=True),
        ),
    ]
