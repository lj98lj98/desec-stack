# Generated by Django 4.0.1 on 2022-01-20 11:21

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('desecapi', '0023_authenticatedemailuseraction'),
    ]

    operations = [
        migrations.CreateModel(
            name='AuthenticatedChangeOutreachPreferenceUserAction',
            fields=[
                ('authenticatedemailuseraction_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='desecapi.authenticatedemailuseraction')),
                ('outreach_preference', models.BooleanField()),
            ],
            options={
                'managed': False,
            },
            bases=('desecapi.authenticatedemailuseraction',),
        ),
    ]
