
from django.urls import path
from devices import views

urlpatterns = [
    path("api/challenge/", views.create_challenge),
    path("api/verify/", views.verify_challenge),
    path("api/health/", views.health),
]
