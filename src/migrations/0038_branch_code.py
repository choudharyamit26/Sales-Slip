# Generated by Django 3.1.3 on 2021-01-28 09:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('src', '0037_hiddenusers'),
    ]

    operations = [
        migrations.AddField(
            model_name='branch',
            name='code',
            field=models.CharField(default='', max_length=100),
        ),
    ]
