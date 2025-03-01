from django.shortcuts import HttpResponse, render, redirect
from django.views.decorators.csrf import csrf_exempt


posts = []

def index(request):
    return render(request, "pages/index.html", {"posts": posts})

@csrf_exempt
def post(request):
    posts.append(request.GET.get("message"))
    return redirect("/")