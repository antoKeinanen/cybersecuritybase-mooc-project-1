from django.shortcuts import render, redirect
from django import db
from .models import User, Post


def signup(request):
    username = request.GET.get("username")
    password = request.GET.get("password")
    """
    Vulnerability 2: A03:2021 - Injection
    CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

    User input is not properly sanitized. This leads to sql injection attack,
    where attacker can execute sql queries on server.

    Fix: Properly sanitize the input by replacing quotes with their relative escape sequences \' and \".
    Fix: Alternatively use the provided sql object relation mapper that sanitizes strings automatically.

    ---

    Vulnerability 3: A02:2021 - Cryptographic failures
    CWE-261 Weak Encoding for Password

    Password is stored in plaintext. Combined with the sql injection above attackers
    could access all the passwords in the database.

    Fix: properly hash, salt and pepper the password with a secure hashing algorithm like argon2id
    """
    cursor = db.connection.cursor()
    cursor.execute(
        f"INSERT INTO pages_user (username, password) VALUES ('{username}', '{password}');"
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
    """
    Vulnerability 2: A03:2021 - Injection
    CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
    User input is not properly sanitized. This leads to sql injection attack,
    where attacker can execute sql queries on server.
    Fix: Properly sanitize the input by replacing quotes with their relative escape sequences \' and \".
    Fix: Alternatively use the provided sql object relation mapper that sanitizes strings automatically.
    """
    cursor = db.connection.cursor()
    cursor.execute(
        f"SELECT * FROM pages_user WHERE username='{username}' AND password='{password}'"
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
        resp.set_cookie(
            "authentication",
            f"basic {username}:{password}",
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
