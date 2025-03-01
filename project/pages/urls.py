"""
URL configuration for project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path
from .views import indexView, post, signin, signup, signinView, signupView

urlpatterns = [
    path("", indexView, name="index"),
    path("post", post, name="post"),
    path("auth/signin", signin, name="signin-api"),
    path("auth/signup", signup, name="signup-api"),
    path("signin", signinView, name="signin"),
    path("signup", signupView, name="signup"),
]
