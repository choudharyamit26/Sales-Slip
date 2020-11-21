# Generated by Django 3.1.3 on 2020-11-09 09:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('src', '0007_settings_usernotification'),
    ]

    operations = [
        migrations.CreateModel(
            name='AboutUs',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('conditions', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='ContactUs',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone_number', models.CharField(default='+9199999', max_length=13)),
                ('email', models.EmailField(default='support@snapic.com', max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='PrivacyPolicy',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('policy', models.TextField()),
                ('policy_in_arabic', models.TextField(default='')),
            ],
        ),
        migrations.CreateModel(
            name='TermsAndCondition',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('conditions', models.TextField()),
                ('conditions_in_arabic', models.TextField(default='')),
            ],
        ),
    ]
