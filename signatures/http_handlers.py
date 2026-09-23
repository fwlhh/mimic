#!/usr/bin/env python3
"""HTTP JSON handlers (etcd, CI runner)."""

from __future__ import annotations

from ._common import (
    build_http_response,
    http_400,
    is_http,
    is_proxy_like,
)


def handle_etcd(data: bytes) -> bytes:
    """etcd /version on HTTP; 400 otherwise or on proxy-like probes."""
    if not is_http(data) or is_proxy_like(data):
        return http_400()
    return build_http_response(
        "200 OK",
        {"Content-Type": "application/json"},
        (
            '{"etcdserver":"3.5.10","etcdcluster":"3.5.0",'
            '"etcdserver_version":"3.5.10"}'
        ),
    )


def handle_ci_runner(data: bytes) -> bytes:
    """Generic CI runner JSON API."""
    if not is_http(data) or is_proxy_like(data):
        return http_400()
    return build_http_response(
        "200 OK",
        {"Content-Type": "application/json"},
        '{"status":"ok","service":"ci-runner","version":"1.2.4"}',
    )