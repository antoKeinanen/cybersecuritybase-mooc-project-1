from django.shortcuts import render, redirect
from django import db
from .models import User, Post
from argon2 import PasswordHasher
import secrets

hasher = PasswordHasher()


def signup(request):
    username = request.GET.get("username")
    password = request.GET.get("password")
    password = hasher.hash(password)
    token = secrets.token_urlsafe(64)

    cursor = db.connection.cursor()
    cursor.execute(
        "INSERT INTO pages_user (username, password, token) VALUES (%s, %s, %s);",
        (username, password, token),
    )

    resp = redirect("/")
    resp.set_cookie("authentication", f"bearer {token}", httponly=True)
    return resp


def signin(request):
    username = request.GET.get("username")
    password = request.GET.get("password")

    cursor = db.connection.cursor()
    cursor.execute(
        "SELECT * FROM pages_user WHERE username=%s",
        (username,),
    )
    user = cursor.fetchone()
    if user:
        resp = redirect("/")
        id, username, hash, token = user
        if not hasher.verify(hash, password):
            return redirect("/signin")

        token = secrets.token_urlsafe(64)
        cursor.execute(
            "UPDATE pages_user SET token=%s WHERE id=%s",
            (token, id),
        )

        resp.set_cookie(
            "authentication",
            f"bearer {token}",
            httponly=True,
        )
        return resp
    return redirect("/signin")


def indexView(request):
    posts = Post.objects.all()
    posts = list(
        map(
            lambda post: {"username": post.user.username, "content": post.content},
            posts,
        )
    )
    return render(request, "pages/index.html", {"posts": posts})


def signinView(request):
    return render(request, "pages/signin.html")


def signupView(request):
    return render(request, "pages/signup.html")


def post(request):
    message = request.GET.get("message")
    auth = request.COOKIES["authentication"]
    auth = auth.split(" ")[1]
    username = auth.split(":")[0]
    user = User.objects.get(username=username)
    """
    Vulnerability 5: A07:2021 - Identification and Authentication Failures 
    CWE-306 Missing Authentication for Critical Function

    When posting password is not validated. This allows attackers to impersonate users just by sending the username.

    Fix: When querying the user also match for password. Also check if user exists before creating post object.
    """
    Post.objects.create(user=user, content=message)
    return redirect("/")
