# Generated by Django 3.1.3 on 2020-11-19 07:57

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('src', '0015_orderitem_total'),
    ]

    operations = [
        migrations.AddField(
            model_name='receipt',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=datetime.datetime(2020, 11, 19, 7, 57, 39, 58773, tzinfo=utc)),
            preserve_default=False,
        ),
    ]
