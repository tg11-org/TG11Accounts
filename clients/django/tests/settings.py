# SPDX-License-Identifier: AGPL-3.0-or-later
"""Throwaway project settings for the tg11_auth test suite."""
SECRET_KEY = "test-only-not-a-secret"
DEBUG = False
ALLOWED_HOSTS = ["testserver", "localhost"]
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "tg11_auth",
]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "tg11_auth.backends.TG11Backend",
]
ROOT_URLCONF = "tests.urls"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
        "tg11_auth.context_processors.tg11",
    ]},
}]
USE_TZ = True
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/home/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]  # fast tests

TG11_OIDC_ISSUER = "https://accounts.example.test"
TG11_OIDC_CLIENT_ID = "testapp"
TG11_OIDC_CLIENT_SECRET = "s3cret"
TG11_OIDC_REDIRECT_URI = "http://testserver/auth/tg11/callback/"
TG11_OIDC_SCOPES = "openid profile email tg11.profile"
TG11_APPLICATION = "testapp"
TG11_AUTH_POST_LOGOUT_REDIRECT = "/bye/"
