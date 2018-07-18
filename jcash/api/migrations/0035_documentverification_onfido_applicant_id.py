from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0034_auto_20180717_2243'),
    ]

    operations = [
        migrations.AddField(
            model_name='documentverification',
            name='onfido_applicant_id',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
