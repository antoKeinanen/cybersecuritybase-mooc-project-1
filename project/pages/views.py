from django.shortcuts import render, redirect
from django import db
from .models import User, Post
from argon2 import PasswordHasher

hasher = PasswordHasher()


def signup(request):
    username = request.GET.get("username")
    password = request.GET.get("password")
    password = hasher.hash(password)

    cursor = db.connection.cursor()
    cursor.execute(
        "INSERT INTO pages_user (username, password) VALUES (%s, %s);",
        (username, password),
    )

    resp = redirect("/")
    """
    Vulnerability 4: A05:2021 - Security Misconfiguration
    CWE-315 Cleartext Storage of Sensitive Information in a Cookie
    CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag

    Authentication information is stored in plaintext in misconfigured cookie.

    Fix: instead of basic authentication use bearer authentication with tokens
    Fix: configure the cookie with secure=True and httponly=True
    """
    resp.set_cookie(
        "authentication", f"basic {username}:{password}", httponly=False, secure=False
    )
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
        """
        Vulnerability 4: A05:2021 - Security Misconfiguration
        CWE-315 Cleartext Storage of Sensitive Information in a Cookie
        CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
        CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag

        Authentication information is stored in plaintext in misconfigured cookie.

        Fix: instead of basic authentication use bearer authentication with tokens
        Fix: configure the cookie with secure=True and httponly=True
        """
        id, username, hash = user
        if not hasher.verify(hash, password):
            return redirect("/signin")

        resp.set_cookie(
            "authentication",
            f"basic {username}:{hash}",
            httponly=False,
            secure=False,
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
