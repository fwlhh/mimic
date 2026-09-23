#!/usr/bin/env python3
"""SMTP dialogue handler."""

from __future__ import annotations


def handle_smtp(data: bytes) -> bytes:
    """Minimal SMTP dialogue: EHLO, AUTH, MAIL, RCPT, DATA, QUIT."""
    if not data:
        return b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"

    line = data.split(b"\r\n", 1)[0]
    cmd = line.split(b" ", 1)[0].upper()

    if cmd in (b"EHLO", b"HELO"):
        return (
            b"250-mail.example.com\r\n"
            b"250-PIPELINING\r\n"
            b"250-SIZE 10240000\r\n"
            b"250-VRFY\r\n"
            b"250-ETRN\r\n"
            b"250-STARTTLS\r\n"
            b"250-ENHANCEDSTATUSCODES\r\n"
            b"250-8BITMIME\r\n"
            b"250-DSN\r\n"
            b"250-SMTPUTF8\r\n"
            b"250 CHUNKING\r\n"
        )

    if cmd == b"STARTTLS":
        return b"454 4.7.0 TLS not available due to local problem\r\n"

    if cmd == b"AUTH":
        return b"535 5.7.8 Error: authentication failed: bad credentials\r\n"

    if cmd == b"MAIL":
        return b"250 2.1.0 Ok\r\n"
    if cmd == b"RCPT":
        return b"250 2.1.5 Ok\r\n"
    if cmd == b"DATA":
        return b"354 End data with <CR><LF>.<CR><LF>\r\n"
    if cmd == b"RSET":
        return b"250 2.0.0 Ok\r\n"
    if cmd == b"NOOP":
        return b"250 2.0.0 Ok\r\n"
    if cmd == b"VRFY":
        return b"252 2.0.0 Cannot VRFY user, but will accept message\r\n"
    if cmd == b"QUIT":
        return b"221 2.0.0 Bye\r\n"

    return b"502 5.5.2 Error: command not recognized\r\n"