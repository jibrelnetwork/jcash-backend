# Generated by Django 2.0.4 on 2018-11-03 07:30

from django.db import migrations, transaction
from django.db.models import Q


def migrate_video_verifications(apps, schema_editor):
    Account = apps.get_model('api', 'Account')
    VideoVerification = apps.get_model('api', 'VideoVerification')
    DocumentVerification = apps.get_model('api', 'DocumentVerification')

    accounts = Account.objects.all()

    with transaction.atomic():
        for account in accounts:
            last_video_verification = None
            try:
                last_video_verification = VideoVerification.objects\
                    .filter(user=account.user)\
                    .latest('created_at')
            except VideoVerification.DoesNotExist:
                pass

            last_document_verification = None
            try:
                if account.type == 'personal':
                    last_document_verification = DocumentVerification.objects\
                        .filter(Q(user=account.user) & ~Q(personal=None))\
                        .latest('created_at')
                elif account.type == 'corporate':
                    last_document_verification = DocumentVerification.objects \
                        .filter(Q(user=account.user) & ~Q(corporate=None)) \
                        .latest('created_at')
            except DocumentVerification.DoesNotExist:
                pass

            if last_document_verification and last_video_verification:
                last_document_verification.video = last_video_verification.document
                last_document_verification.video_req_id = last_video_verification.video_id
                last_document_verification.video_message = last_video_verification.message
                last_document_verification.save()


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0068_auto_20181103_0711'),
    ]

    operations = [
        migrations.RunPython(migrate_video_verifications),
    ]
