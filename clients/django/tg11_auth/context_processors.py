# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 TG11
"""Optional: add ``tg11_auth.context_processors.tg11`` to TEMPLATES and every
template gets ``tg11_configured``, ``tg11_linked`` and ``tg11_issuer_host``.
"""
from __future__ import annotations

from typing import Any, Dict

from . import views


def tg11(request) -> Dict[str, Any]:
    return views.status(request)
