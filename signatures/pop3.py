#!/usr/bin/env python3
"""POP3 dialogue handler."""

from __future__ import annotations


def handle_pop3(data: bytes) -> bytes:
    """Minimal POP3: greeting on empty input, per-command otherwise."""
    if not data:
        return b"+OK Dovecot ready.\r\n"

    cmd = data.strip().upper()
    if cmd.startswith(b"USER"):
        return b"+OK\r\n"
    if cmd.startswith(b"PASS"):
        return b"-ERR [AUTH] Authentication failed.\r\n"
    if cmd.startswith(b"CAPA"):
        return b"+OK\r\nUSER\r\nUIDL\r\nTOP\r\n.\r\n"
    if cmd.startswith(b"QUIT"):
        return b"+OK Logging out.\r\n"
    return b"-ERR Unknown command.\r\n"