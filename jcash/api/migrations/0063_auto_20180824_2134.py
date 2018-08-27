import django.contrib.postgres.fields.jsonb
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0062_auto_20180823_0756'),
    ]

    operations = [
        migrations.CreateModel(
            name='JntRate',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source', models.CharField(max_length=30)),
                ('price', models.FloatField()),
                ('created_at', models.DateTimeField()),
                ('meta', django.contrib.postgres.fields.jsonb.JSONField(default={})),
            ],
            options={
                'db_table': 'jnt_rate',
            },
        ),
        migrations.CreateModel(
            name='LiquidityProvider',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('entity', models.CharField(max_length=255)),
                ('address', models.CharField(blank=True, max_length=255, null=True)),
                ('jnt_pledge', models.FloatField(default=0.0)),
            ],
            options={
                'db_table': 'liquidity_provider',
            },
        ),
        migrations.CreateModel(
            name='ProofOfSolvency',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('meta', django.contrib.postgres.fields.jsonb.JSONField(default={})),
            ],
            options={
                'db_table': 'proof_of_solvency',
            },
        ),
        migrations.AddField(
            model_name='currency',
            name='total_supply',
            field=models.FloatField(default=0.0),
        ),
        migrations.AlterField(
            model_name='currency',
            name='balance',
            field=models.FloatField(default=0.0),
        ),
        migrations.AddIndex(
            model_name='proofofsolvency',
            index=models.Index(fields=['created_at'], name='proof_of_so_created_7cc2e2_idx'),
        ),
        migrations.AddIndex(
            model_name='liquidityprovider',
            index=models.Index(fields=['entity'], name='liquidity_p_entity_74835d_idx'),
        ),
        migrations.AddIndex(
            model_name='jntrate',
            index=models.Index(fields=['created_at'], name='jnt_rate_created_e931e9_idx'),
        ),
        migrations.AddIndex(
            model_name='jntrate',
            index=models.Index(fields=['source'], name='jnt_rate_source_cab711_idx'),
        ),
    ]
