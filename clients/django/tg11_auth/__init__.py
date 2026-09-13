# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""tg11-auth - the TG11 ecosystem OpenID Connect relying party for Django.

One TG11 identity (a UUID, the `sub` claim) across every TG11 service, while
each application keeps owning its own data.  See docs/TG11_IDENTITY.md for the
architecture and docs/TG11_APP_INTEGRATION.md for the per-application recipe.
"""
from __future__ import annotations

__version__ = "0.1.0"
