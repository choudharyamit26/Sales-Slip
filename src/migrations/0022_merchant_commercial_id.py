# Generated by Django 3.1.3 on 2020-12-22 07:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('src', '0021_auto_20201210_0544'),
    ]

    operations = [
        migrations.AddField(
            model_name='merchant',
            name='commercial_id',
            field=models.CharField(default='', max_length=256),
        ),
    ]