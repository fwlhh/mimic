#!/usr/bin/env python3
"""PostgreSQL wire protocol handler."""

from __future__ import annotations

import struct


def _pg_msg(type_byte: bytes, payload: bytes) -> bytes:
    return type_byte + struct.pack(">I", len(payload) + 4) + payload


def _pg_cstr(s: str) -> bytes:
    return s.encode("utf-8") + b"\x00"


def _pg_auth_cleartext() -> bytes:
    return _pg_msg(b"R", struct.pack(">I", 3))


def _pg_auth_ok() -> bytes:
    out = b""
    out += _pg_msg(b"R", struct.pack(">I", 0))
    params = {
        "server_version": "16.3 (Ubuntu 16.3-1.pgdg22.04+1)",
        "server_encoding": "UTF8",
        "client_encoding": "UTF8",
        "application_name": "",
        "DateStyle": "ISO, MDY",
        "IntervalStyle": "postgres",
        "TimeZone": "Etc/UTC",
        "integer_datetimes": "on",
        "standard_conforming_strings": "on",
    }
    for k, v in params.items():
        out += _pg_msg(b"S", _pg_cstr(k) + _pg_cstr(v))
    out += _pg_msg(b"K", struct.pack(">II", 42, 1234567890))
    out += _pg_msg(b"Z", b"I")
    return out


def _pg_parse_query(data: bytes) -> str:
    try:
        body = data[5:]
        nul = body.index(b"\x00")
        return body[:nul].decode("utf-8", errors="replace").strip()
    except (ValueError, IndexError):
        return ""


def _pg_field(name: str, type_oid: int, type_size: int) -> bytes:
    return (
        _pg_cstr(name)
        + struct.pack(">IhIhih", 0, 0, type_oid, type_size, -1, 0)
    )


def _pg_row_desc(fields: list[tuple[str, int, int]]) -> bytes:
    payload = struct.pack(">h", len(fields))
    for name, oid, size in fields:
        payload += _pg_field(name, oid, size)
    return _pg_msg(b"T", payload)


def _pg_data_row(values: list[str]) -> bytes:
    payload = struct.pack(">h", len(values))
    for v in values:
        b = v.encode("utf-8")
        payload += struct.pack(">i", len(b)) + b
    return _pg_msg(b"D", payload)


def _pg_command_complete(tag: str) -> bytes:
    return _pg_msg(b"C", _pg_cstr(tag))


def _pg_ready() -> bytes:
    return _pg_msg(b"Z", b"I")


def _pg_error(msg: str) -> bytes:
    payload = (
        b"S" + _pg_cstr("ERROR")
        + b"C" + _pg_cstr("42601")
        + b"M" + _pg_cstr(msg)
        + b"\x00"
    )
    return _pg_msg(b"E", payload)


def _answer_query(sql: str) -> bytes:
    low = sql.lower().rstrip(";")

    if low.startswith("select version"):
        fields = [("version", 25, -1)]
        row = [
            "PostgreSQL 16.3 (Ubuntu 16.3-1.pgdg22.04+1) "
            "on x86_64-pc-linux-gnu, compiled by gcc "
            "(Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, 64-bit"
        ]
        return (
            _pg_row_desc(fields) + _pg_data_row(row)
            + _pg_command_complete("SELECT 1") + _pg_ready()
        )

    if "server_version" in low:
        fields = [("server_version", 25, -1)]
        row = ["16.3 (Ubuntu 16.3-1.pgdg22.04+1)"]
        return (
            _pg_row_desc(fields) + _pg_data_row(row)
            + _pg_command_complete("SHOW") + _pg_ready()
        )

    if "current_database" in low:
        fields = [("current_database", 19, 64)]
        row = ["postgres"]
        return (
            _pg_row_desc(fields) + _pg_data_row(row)
            + _pg_command_complete("SELECT 1") + _pg_ready()
        )

    if "current_user" in low or low == "select user":
        fields = [("current_user", 19, 64)]
        row = ["postgres"]
        return (
            _pg_row_desc(fields) + _pg_data_row(row)
            + _pg_command_complete("SELECT 1") + _pg_ready()
        )

    if low.startswith(("begin", "commit", "rollback", "set ", "discard")):
        return _pg_command_complete(low.split()[0].upper()) + _pg_ready()

    return _pg_error(f'syntax error at or near "{sql[:32]}"') + _pg_ready()


def handle_postgres(data: bytes) -> bytes:
    """Minimal PostgreSQL wire protocol server."""
    if not data:
        return b""

    msg_type = data[0:1]

    if msg_type not in (b"p", b"Q", b"X"):
        return _pg_auth_cleartext()

    if msg_type == b"p":
        return _pg_auth_ok()

    if msg_type == b"Q":
        return _answer_query(_pg_parse_query(data))

    if msg_type == b"X":
        return b""

    return b""