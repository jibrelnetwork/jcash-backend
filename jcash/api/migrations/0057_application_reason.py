# Generated by Django 2.0.4 on 2018-08-07 20:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0056_remove_currency_version'),
    ]

    operations = [
        migrations.AddField(
            model_name='application',
            name='reason',
            field=models.CharField(blank=True, default='', max_length=35),
        ),
    ]
