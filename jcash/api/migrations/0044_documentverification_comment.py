# Generated by Django 2.0.4 on 2018-08-01 09:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0043_documentverification_meta'),
    ]

    operations = [
        migrations.AddField(
            model_name='documentverification',
            name='comment',
            field=models.TextField(blank=True, null=True),
        ),
    ]
