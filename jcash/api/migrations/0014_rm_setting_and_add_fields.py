from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_incomingtx_add_islinked'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Setting',
        ),
        migrations.AddField(
            model_name='application',
            name='expired_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='application',
            name='is_reverse',
            field=models.BooleanField(default=False),
        ),
    ]
