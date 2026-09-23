#!/usr/bin/env python3
"""Shared helpers for signature handlers."""

from __future__ import annotations


def build_http_response(
    status: str,
    headers: dict[str, str],
    body: str,
) -> bytes:
    """Build a valid HTTP/1.1 response with auto Content-Length."""
    body_bytes = body.encode("utf-8")
    lines = [f"HTTP/1.1 {status}"]
    for key, value in headers.items():
        lines.append(f"{key}: {value}")
    if not any(h.lower() == "content-length" for h in headers):
        lines.append(f"Content-Length: {len(body_bytes)}")
    if not any(h.lower() == "connection" for h in headers):
        lines.append("Connection: close")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("utf-8") + body_bytes


def build_raw_response(body: str | bytes) -> bytes:
    """Return the body as-is, encoding to UTF-8 if needed."""
    if isinstance(body, bytes):
        return body
    return body.encode("utf-8")


_HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"OPTIONS ",
    b"PUT ",
    b"DELETE ",
    b"TRACE ",
    b"PATCH ",
)


def is_http(data: bytes) -> bool:
    """Return True if data looks like an HTTP request."""
    if not data:
        return False
    upper = data[:16].upper()
    return any(upper.startswith(method) for method in _HTTP_METHODS)


def is_proxy_like(data: bytes) -> bool:
    """Return True if data looks like an open-proxy probe."""
    if data[:8].upper().startswith(b"CONNECT "):
        return True
    first_line = data.split(b"\r\n", 1)[0]
    parts = first_line.split(b" ", 2)
    return len(parts) >= 2 and b"://" in parts[1]


def http_400() -> bytes:
    """Minimal 400 Bad Request response with empty body."""
    return (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )