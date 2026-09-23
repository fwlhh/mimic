#!/usr/bin/env python3
"""Redis RESP protocol handler."""

from __future__ import annotations


def _first_arg(data: bytes) -> bytes:
    """Extract the first argument from a RESP or inline command."""
    if data.startswith(b"*"):
        try:
            first_crlf = data.index(b"\r\n")
            rest = data[first_crlf + 2:]
            if rest.startswith(b"$"):
                second_crlf = rest.index(b"\r\n")
                arg_len = int(rest[1:second_crlf])
                arg_start = second_crlf + 2
                return rest[arg_start:arg_start + arg_len]
        except (ValueError, IndexError):
            return b""
        return b""
    return data.split(b"\r\n", 1)[0].split(b" ", 1)[0]


def handle_redis(data: bytes) -> bytes:
    """Password-protected Redis emulation (RESP)."""
    cmd = _first_arg(data).lower() if data else b""

    if cmd == b"quit":
        return b"+OK\r\n"
    if cmd == b"auth":
        return b"-ERR invalid password\r\n"
    return b"-NOAUTH Authentication required.\r\n"

    cmd = _first_arg(data).lower()

    if cmd == b"quit":
        return b"+OK\r\n"
    if cmd == b"auth":
        return b"-ERR invalid password\r\n"
    if cmd == b"hello":
        return b"-NOAUTH Authentication required.\r\n"
    if cmd == b"ping":
        return b"-NOAUTH Authentication required.\r\n"
    return b"-NOAUTH Authentication required.\r\n"