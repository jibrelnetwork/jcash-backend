from django.db import migrations


def create_countries(apps, schema_editor):
    Country = apps.get_model('api', 'Country')

    country = Country.objects.create(type="residential", name="Jordan", is_removed=False)
    country.save()


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0076_auto_20181120_1045'),
    ]

    operations = [
        migrations.RunPython(create_countries),
    ]
