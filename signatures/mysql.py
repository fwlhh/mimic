#!/usr/bin/env python3
"""MySQL server greeting handler."""

from __future__ import annotations

import struct


_PROTOCOL_VERSION = 0x0A
_SERVER_VERSION = b"8.0.35\x00"
_CHARSET = 0x2D
_STATUS_FLAGS = 0x0002
_CAPABILITY_FLAGS = 0xFFFF
_AUTH_PLUGIN = b"mysql_native_password\x00"


def handle_mysql(_data: bytes) -> bytes:
    """Return the MySQL 8.0.x server greeting packet."""
    payload = (
        bytes([_PROTOCOL_VERSION])
        + _SERVER_VERSION
        + struct.pack("<I", 42)
        + b"abcdefgh"
        + b"\x00"
        + struct.pack("<H", _CAPABILITY_FLAGS)
        + bytes([_CHARSET])
        + struct.pack("<H", _STATUS_FLAGS)
        + struct.pack("<H", _CAPABILITY_FLAGS)
        + b"\x15"
        + b"\x00" * 10
        + b"ijklmnopqrst\x00"
        + _AUTH_PLUGIN
    )
    header = struct.pack("<I", len(payload))[:3] + b"\x00"
    return header + payload