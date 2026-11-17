from django.contrib import admin
from django.urls import path
from devices import views
urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/register/", views.register_device),
    path("api/challenge/", views.create_challenge),
    path("api/verify/", views.verify_challenge),
    path("api/health/", views.health),
]
