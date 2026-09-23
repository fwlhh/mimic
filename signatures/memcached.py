#!/usr/bin/env python3
"""Memcached text protocol handler."""

from __future__ import annotations


def handle_memcached(data: bytes) -> bytes:
    """Minimal Memcached emulation (version, stats, get/set)."""
    cmd = data.strip().lower()

    if cmd.startswith(b"version"):
        return b"VERSION 1.6.21\r\n"

    if cmd.startswith(b"stats"):
        return (
            b"STAT pid 1\r\n"
            b"STAT uptime 847293\r\n"
            b"STAT time 1700000000\r\n"
            b"STAT version 1.6.21\r\n"
            b"STAT libevent 2.1.12-stable\r\n"
            b"STAT pointer_size 64\r\n"
            b"STAT max_connections 1024\r\n"
            b"STAT curr_connections 5\r\n"
            b"STAT total_connections 1234\r\n"
            b"STAT cmd_get 100\r\n"
            b"STAT cmd_set 50\r\n"
            b"STAT bytes_read 5000\r\n"
            b"STAT bytes_written 10000\r\n"
            b"STAT limit_maxbytes 67108864\r\n"
            b"STAT threads 4\r\n"
            b"END\r\n"
        )

    if cmd.startswith(b"get ") or cmd.startswith(b"gets "):
        return b"END\r\n"
    if cmd.startswith(b"set ") or cmd.startswith(b"add "):
        return b"STORED\r\n"
    if cmd.startswith(b"replace "):
        return b"NOT_STORED\r\n"
    if (
        cmd.startswith(b"delete ")
        or cmd.startswith(b"incr ")
        or cmd.startswith(b"decr ")
    ):
        return b"NOT_FOUND\r\n"
    if cmd.startswith(b"quit"):
        return b""
    if cmd.startswith(b"flush_all") or cmd.startswith(b"verbosity"):
        return b"OK\r\n"
    return b"ERROR\r\n"