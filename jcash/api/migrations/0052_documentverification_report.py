# Generated by Django 2.0.4 on 2018-08-03 19:18

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0051_auto_20180803_0423'),
    ]

    operations = [
        migrations.AddField(
            model_name='documentverification',
            name='report',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='report_verification', to='api.Document'),
        ),
    ]
