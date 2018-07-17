from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('api', '0032_replenisher_type'),
    ]

    operations = [
        migrations.CreateModel(
            name='DocumentVerification',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('status', models.CharField(default='created', max_length=20)),
                ('passport', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='passport_verification', to='api.Document')),
                ('selfie', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='selfie_verification', to='api.Document')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='documentverification', to=settings.AUTH_USER_MODEL)),
                ('utilitybills', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='utilitybills_verification', to='api.Document')),
            ],
        ),
    ]
