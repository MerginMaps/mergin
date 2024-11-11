# Copyright (C) Lutra Consulting Limited
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-MerginMaps-Commercial

import re


def is_email_address_valid(email: str) -> bool:
    """Check if email address contains only ASCII characters and basic email address requirements"""
    email_ascii = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+.[A-Za-z]{2,}$"
    return re.match(email_ascii, email) is not None
