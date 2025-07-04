# Generated by Django 2.0.4 on 2018-05-22 14:51

from django.conf import settings
import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion
import jcash.api.models
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('api', '0002_remove_old_models'),
    ]

    operations = [
        migrations.CreateModel(
            name='Account',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(blank=True, max_length=120)),
                ('last_name', models.CharField(blank=True, max_length=120)),
                ('fullname', models.CharField(blank=True, max_length=120)),
                ('citizenship', models.CharField(blank=True, max_length=120)),
                ('birthday', models.DateField(blank=True, null=True)),
                ('residency', models.CharField(blank=True, max_length=120)),
                ('country', models.CharField(blank=True, max_length=120)),
                ('street', models.CharField(blank=True, max_length=120)),
                ('town', models.CharField(blank=True, max_length=120)),
                ('postcode', models.CharField(blank=True, max_length=120)),
                ('terms_confirmed', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_updated_at', models.DateTimeField(auto_now_add=True)),
                ('is_identity_verified', models.BooleanField(default=False, verbose_name='Verified')),
                ('is_identity_declined', models.BooleanField(default=False, verbose_name='Declined')),
                ('is_blocked', models.BooleanField(default=False, verbose_name='Blocked')),
                ('comment', models.TextField(blank=True, null=True)),
                ('tracking', django.contrib.postgres.fields.jsonb.JSONField(blank=True, default=dict)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'account',
            },
        ),
        migrations.CreateModel(
            name='AccountAddress',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('address', models.CharField(max_length=255, unique=True)),
                ('is_verified', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'account_address',
            },
        ),
        migrations.CreateModel(
            name='Address',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('address', models.CharField(max_length=255, unique=True)),
                ('type', models.CharField(max_length=10)),
                ('is_verified', models.BooleanField(default=False)),
                ('is_rejected', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('meta', django.contrib.postgres.fields.jsonb.JSONField(default=dict)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='addresses', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'address',
            },
        ),
        migrations.CreateModel(
            name='AddressVerify',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('sig', models.CharField(blank=True, max_length=255, null=True, unique=True)),
                ('message', models.CharField(max_length=1024)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('is_verified', models.BooleanField(default=False)),
                ('address', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='verifies', to='api.Address')),
            ],
            options={
                'db_table': 'address_verify',
            },
        ),
        migrations.CreateModel(
            name='Affiliate',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event', models.CharField(max_length=20)),
                ('url', models.CharField(max_length=300)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('sended', models.DateTimeField(null=True)),
                ('status', models.IntegerField(blank=True, null=True)),
                ('meta', django.contrib.postgres.fields.jsonb.JSONField(default=dict)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'affiliate',
            },
        ),
        migrations.CreateModel(
            name='Application',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('base_currency', models.CharField(max_length=10)),
                ('reciprocal_currency', models.CharField(max_length=10)),
                ('rate', models.FloatField()),
                ('base_amount', models.FloatField()),
                ('reciprocal_amount', models.FloatField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('status', models.CharField(default='created', max_length=10)),
                ('meta', django.contrib.postgres.fields.jsonb.JSONField(default=dict)),
                ('address', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='applications', to='api.Address')),
            ],
            options={
                'db_table': 'application',
            },
        ),
        migrations.CreateModel(
            name='Currency',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('display_name', models.CharField(max_length=10)),
                ('symbol', models.CharField(max_length=10)),
                ('exchanger_address', models.CharField(blank=True, max_length=255, null=True)),
                ('view_address', models.CharField(blank=True, max_length=255, null=True, unique=True)),
                ('controller_address', models.CharField(blank=True, max_length=255, null=True, unique=True)),
                ('is_erc20_token', models.BooleanField(default=False)),
                ('balance', models.FloatField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'currency',
            },
        ),
        migrations.CreateModel(
            name='CurrencyPair',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('display_name', models.CharField(max_length=10)),
                ('symbol', models.CharField(max_length=10)),
                ('is_exchangeable', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('is_buyable', models.BooleanField(default=False)),
                ('is_sellable', models.BooleanField(default=False)),
                ('base_currency', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='base_currencies', to='api.Currency')),
                ('reciprocal_currency', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='reciprocal_currencies', to='api.Currency')),
            ],
            options={
                'db_table': 'currency_pair',
            },
        ),
        migrations.CreateModel(
            name='CurrencyPairRate',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('buy_price', models.FloatField()),
                ('sell_price', models.FloatField()),
                ('created_at', models.DateTimeField()),
                ('meta', django.contrib.postgres.fields.jsonb.JSONField(default={})),
                ('currency_pair', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='currency_pair_rates', to='api.CurrencyPair')),
            ],
            options={
                'db_table': 'currency_pair_rate',
            },
        ),
        migrations.CreateModel(
            name='Document',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.FileField(upload_to=jcash.api.models.DocumentHelper.unique_document_filename, verbose_name='uploaded document')),
                ('url', models.URLField(blank=True, max_length=250)),
                ('ext', models.CharField(blank=True, max_length=20)),
                ('type', models.CharField(blank=True, max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('onfido_applicant_id', models.CharField(blank=True, max_length=200, null=True)),
                ('onfido_document_id', models.CharField(blank=True, max_length=200, null=True)),
                ('onfido_check_id', models.CharField(blank=True, max_length=200, null=True)),
                ('onfido_check_status', models.CharField(blank=True, max_length=200, null=True)),
                ('onfido_check_result', models.CharField(blank=True, max_length=200, null=True)),
                ('onfido_check_created', models.DateTimeField(blank=True, null=True)),
                ('verification_started_at', models.DateTimeField(blank=True, null=True)),
                ('verification_attempts', models.IntegerField(default=0)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='documents', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'document',
            },
        ),
        migrations.CreateModel(
            name='Exchange',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transaction_id', models.CharField(blank=True, max_length=120, null=True)),
                ('created_at', models.DateTimeField()),
                ('mined_at', models.DateTimeField(blank=True, null=True)),
                ('block_height', models.IntegerField(blank=True, null=True)),
                ('value', models.FloatField(default=0)),
                ('status', models.CharField(default='not_confirmed', max_length=20)),
                ('meta', django.contrib.postgres.fields.jsonb.JSONField(default=dict)),
                ('application', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='exchanges', to='api.Application')),
            ],
            options={
                'db_table': 'exchange',
            },
        ),
        migrations.CreateModel(
            name='IncomingTransaction',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transaction_id', models.CharField(blank=True, max_length=120, null=True)),
                ('created_at', models.DateTimeField()),
                ('mined_at', models.DateTimeField(blank=True, null=True)),
                ('block_height', models.IntegerField(blank=True, null=True)),
                ('value', models.FloatField(default=0)),
                ('status', models.CharField(default='not_confirmed', max_length=20)),
                ('meta', django.contrib.postgres.fields.jsonb.JSONField(default=dict)),
                ('application', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='incoming_txs', to='api.Application')),
            ],
            options={
                'db_table': 'incoming_transaction',
            },
        ),
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(max_length=100)),
                ('email', models.CharField(max_length=120)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('sended', models.DateTimeField(null=True)),
                ('is_sended', models.BooleanField(default=False)),
                ('rendered_message', models.TextField(blank=True, null=True)),
                ('meta', django.contrib.postgres.fields.jsonb.JSONField(default=dict)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='notifications', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'notification',
            },
        ),
        migrations.CreateModel(
            name='Refund',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transaction_id', models.CharField(blank=True, max_length=120, null=True)),
                ('created_at', models.DateTimeField()),
                ('mined_at', models.DateTimeField(blank=True, null=True)),
                ('block_height', models.IntegerField(blank=True, null=True)),
                ('value', models.FloatField(default=0)),
                ('status', models.CharField(default='not_confirmed', max_length=20)),
                ('meta', django.contrib.postgres.fields.jsonb.JSONField(default=dict)),
                ('application', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='refundes', to='api.Application')),
            ],
            options={
                'db_table': 'refund',
            },
        ),
        migrations.CreateModel(
            name='SystemEvents',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_type', models.CharField(choices=[('account_reg_data_filled', 'account_reg_data_filled'), ('account_approved', 'account_approved'), ('account_rejected', 'account_rejected'), ('account_docs_uploaded', 'account_docs_uploaded'), ('document_uploaded', 'document_uploaded'), ('application_created', 'application_created'), ('application_rejected', 'application_rejected'), ('application approved', 'application approved'), ('application_refunded', 'application_refunded'), ('transaction_received', 'transaction_received'), ('exchane_cancelled', 'exchane_cancelled'), ('exchange_started', 'exchange_started'), ('exchange_failed', 'exchange_failed'), ('exchange_successed', 'exchange_successed'), ('notification_created', 'notification_created'), ('notification_sended', 'notification_sended')], max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('params', django.contrib.postgres.fields.jsonb.JSONField(default=dict)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'systemevents',
            },
        ),
        migrations.AddField(
            model_name='application',
            name='currency_pair',
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='applications', to='api.CurrencyPair'),
        ),
        migrations.AddField(
            model_name='application',
            name='currency_pair_rate',
            field=models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='applications', to='api.CurrencyPairRate'),
        ),
        migrations.AddField(
            model_name='application',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='applications', to=settings.AUTH_USER_MODEL),
        ),
    ]
