from django.db import models

from django.contrib.auth.models import User

class Post(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	content = models.TextField()