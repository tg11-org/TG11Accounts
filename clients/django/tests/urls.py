# SPDX-License-Identifier: AGPL-3.0-or-later
from django.http import HttpResponse
from django.urls import include, path

urlpatterns = [
    path("auth/tg11/", include("tg11_auth.urls")),
    path("home/", lambda r: HttpResponse("home"), name="home"),
    path("bye/", lambda r: HttpResponse("bye"), name="bye"),
    path("accounts/login/", lambda r: HttpResponse("local login"), name="login"),
    path("settings/", lambda r: HttpResponse("settings"), name="account_settings"),
]
