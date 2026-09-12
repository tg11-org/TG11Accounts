# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 TG11
"""SMS delivery (phone verification).  Twilio Messages API via plain HTTPS; any
other gateway can be added by implementing `send_sms`."""
from __future__ import annotations

import logging
import re

import httpx

from .config import settings

log = logging.getLogger("tg11.sms")
E164 = re.compile(r"^\+[1-9]\d{6,14}$")


def normalize_phone(raw: str) -> str:
    digits = re.sub(r"[^\d+]", "", raw or "")
    if digits and not digits.startswith("+"):
        digits = "+1" + digits if len(digits) == 10 else "+" + digits
    if not E164.match(digits):
        raise ValueError("Enter the number in international format, e.g. +1 555 123 4567")
    return digits


def send_sms(to: str, body: str) -> bool:
    if not settings.sms_configured:
        log.warning("SMS not configured; would send to %s: %s", to, body)
        return False
    url = f"https://api.twilio.com/2010-04-01/Accounts/{settings.TWILIO_ACCOUNT_SID}/Messages.json"
    try:
        r = httpx.post(url, data={"To": to, "From": settings.TWILIO_FROM_NUMBER, "Body": body}, auth=(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN), timeout=20)
        if r.status_code >= 300:
            log.error("twilio error %s: %s", r.status_code, r.text[:200])
            return False
        return True
    except httpx.HTTPError as exc:  # pragma: no cover
        log.error("twilio request failed: %s", exc)
        return False
