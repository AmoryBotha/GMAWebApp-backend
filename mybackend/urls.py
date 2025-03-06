from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse

def home_view(request):
    return HttpResponse("<h1>Welcome to the GMA Backend</h1>")

urlpatterns = [
    path('', home_view, name='home'),
    path('api/', include('api.urls')),
]
