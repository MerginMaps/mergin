# Copyright (C) Lutra Consulting Limited
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-MerginMaps-Commercial

import re


def contains_email_invalid_characters(email: str) -> bool:
    """Check for invalid characters for the email address"""
    invalid_characters = r"[ ;:’\–\—|,]"
    return bool(re.search(invalid_characters, email))


def is_utf8(text: str) -> bool:
    """Check if given text is in UTF-8 encoding"""
    try:
        text.encode("utf-8").decode("utf-8")
        return "�" not in text
    except UnicodeDecodeError:
        return False
