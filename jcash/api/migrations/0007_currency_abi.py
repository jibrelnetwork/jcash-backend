# Generated by Django 2.0.4 on 2018-05-28 07:29

import django.contrib.postgres.fields.jsonb
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_remove_document_url'),
    ]

    operations = [
        migrations.AddField(
            model_name='currency',
            name='abi',
            field=django.contrib.postgres.fields.jsonb.JSONField(default=dict),
        ),
    ]
