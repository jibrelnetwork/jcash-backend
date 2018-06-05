from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_application_is_active'),
    ]

    operations = [
        migrations.CreateModel(
            name='Setting',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('back_url', models.CharField(default='', max_length=512)),
                ('front_url', models.CharField(default='', max_length=512)),
            ],
        ),
        migrations.AddField(
            model_name='incomingtransaction',
            name='is_linked',
            field=models.BooleanField(default=False),
        ),
    ]
