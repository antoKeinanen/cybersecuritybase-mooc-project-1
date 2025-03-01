from django.db import models

class User(models.Model):
	username = models.TextField()
	password = models.TextField()

class Post(models.Model):
	user = models.ForeignKey(User, on_delete=models.CASCADE)
	content = models.TextField()