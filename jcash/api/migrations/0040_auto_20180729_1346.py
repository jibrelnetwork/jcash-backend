# Generated by Django 2.0.4 on 2018-07-29 13:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0039_licenseaddress_created_at'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='licenseaddress',
            name='user',
        ),
        migrations.AlterField(
            model_name='licenseaddress',
            name='status',
            field=models.CharField(default='created', max_length=20),
        ),
        migrations.AlterModelTable(
            name='licenseaddress',
            table='license_address',
        ),
    ]
