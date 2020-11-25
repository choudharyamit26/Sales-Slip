# Generated by Django 3.1.3 on 2020-11-24 06:58

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('src', '0018_merchant_profile_pic'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanneddata',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=datetime.datetime(2020, 11, 24, 6, 58, 10, 723791, tzinfo=utc)),
            preserve_default=False,
        ),
        migrations.CreateModel(
            name='Otp',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp', models.IntegerField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
