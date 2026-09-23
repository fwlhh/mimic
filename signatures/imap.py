#!/usr/bin/env python3
"""IMAP dialogue handler."""

from __future__ import annotations


def handle_imap(data: bytes) -> bytes:
    """Minimal IMAP: greeting on empty input, per-command otherwise."""
    if not data:
        return (
            b"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS "
            b"ID ENABLE IDLE LITERAL+] Dovecot ready.\r\n"
        )

    cmd = data.strip().upper()
    if cmd.endswith(b"CAPABILITY"):
        return (
            b"* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS "
            b"ID ENABLE IDLE LITERAL+\r\n"
            b"a001 OK Pre-login capabilities listed, post-login "
            b"capabilities have more.\r\n"
        )
    if cmd.endswith(b"LOGOUT"):
        return b"* BYE Logging out\r\na001 OK Logout completed.\r\n"
    return b"a001 NO Unknown command.\r\n"