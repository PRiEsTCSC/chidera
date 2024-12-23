# Generated by Django 4.0 on 2024-10-29 22:13

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserPassword',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=100)),
                ('password', models.CharField(max_length=500)),
                ('application_type', models.CharField(max_length=30)),
                ('website_name', models.CharField(blank=True, max_length=30)),
                ('website_url', models.CharField(blank=True, max_length=100)),
                ('application_name', models.CharField(blank=True, max_length=20)),
                ('game_name', models.CharField(blank=True, max_length=20)),
                ('game_developer', models.CharField(blank=True, max_length=30)),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('date_last_updated', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='auth.user')),
            ],
        ),
    ]
