# Generated by Django 2.0.4 on 2018-11-03 07:00

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0069_migrate_video_verifications'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='videoverification',
            name='document',
        ),
        migrations.RemoveField(
            model_name='videoverification',
            name='user',
        ),
        migrations.RemoveField(
            model_name='documentverification',
            name='video_verification',
        ),
        migrations.AddField(
            model_name='documentverification',
            name='video',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='video_verification', to='api.Document'),
        ),
        migrations.AddField(
            model_name='documentverification',
            name='video_message',
            field=models.CharField(default='', max_length=1024),
        ),
        migrations.AddField(
            model_name='documentverification',
            name='video_reg_id',
            field=models.CharField(blank=True, max_length=1024, null=True),
        ),
        migrations.AlterField(
            model_name='personal',
            name='kyc_step',
            field=models.IntegerField(default=-2),
        ),
    ]
