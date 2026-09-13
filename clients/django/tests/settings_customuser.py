# SPDX-License-Identifier: AGPL-3.0-or-later
"""Same project, but with a FreeParty/Shop-shaped custom user model."""
from tests.settings import *  # noqa: F401,F403

INSTALLED_APPS = INSTALLED_APPS + ["tests.customuser"]  # noqa: F405
AUTH_USER_MODEL = "customuser.User"
