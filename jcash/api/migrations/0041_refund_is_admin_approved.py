# Generated by Django 2.0.4 on 2018-07-30 12:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0040_auto_20180729_1346'),
    ]

    operations = [
        migrations.AddField(
            model_name='refund',
            name='is_admin_approved',
            field=models.BooleanField(default=False),
        ),
    ]
