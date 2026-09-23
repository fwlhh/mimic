#!/usr/bin/env python3
"""Signature and handler library for Mimic.

Public API:
    HANDLERS        -- dict of handler name -> callable
    SIGNATURES      -- dict of signature name -> spec
    KNOWN_PORTS     -- port -> conventional protocol name
    TLS_ONLY_PORTS  -- ports where TLS is required by convention
    Handler         -- type alias for handler callables
    build_http_response
    build_raw_response
"""

from __future__ import annotations

from typing import Callable

# --- _common -----------------------------------------------------------
from ._common import (
    build_http_response,
    build_raw_response,
    http_400,
    is_http,
    is_proxy_like,
)

# --- protocol handlers -------------------------------------------------
from .http_handlers import handle_ci_runner, handle_etcd
from .imap import handle_imap
from .memcached import handle_memcached
from .mongodb import handle_mongodb
from .mqtt import handle_amqp, handle_mqtt, handle_ssh
from .mysql import handle_mysql
from .pop3 import handle_pop3
from .postgres import handle_postgres
from .redis import handle_redis
from .smtp import handle_smtp

# --- library -----------------------------------------------------------
from .library import KNOWN_PORTS, SIGNATURES, TLS_ONLY_PORTS


# --- SSH full handshake (optional, requires asyncssh) ------------------
try:
    from .ssh import RejectAuthServer, start_ssh_server
    SSH_AVAILABLE = True
except ImportError:
    RejectAuthServer = None  # type: ignore[assignment]
    start_ssh_server = None  # type: ignore[assignment]
    SSH_AVAILABLE = False


# ============================================================
# Public API
# ============================================================

Handler = Callable[[bytes], bytes]

HANDLERS: dict[str, Handler] = {
    "redis": handle_redis,
    "memcached": handle_memcached,
    "etcd": handle_etcd,
    "ci-runner": handle_ci_runner,
    "mysql": handle_mysql,
    "postgres": handle_postgres,
    "mongodb": handle_mongodb,
    "mqtt": handle_mqtt,
    "amqp": handle_amqp,
    "smtp": handle_smtp,
    "pop3": handle_pop3,
    "imap": handle_imap,
    "ssh": handle_ssh,
}


__all__ = [
    "HANDLERS",
    "SIGNATURES",
    "KNOWN_PORTS",
    "TLS_ONLY_PORTS",
    "Handler",
    "build_http_response",
    "build_raw_response",
    "http_400",
    "is_http",
    "is_proxy_like",
    "start_ssh_server",
    "RejectAuthServer",
    "SSH_AVAILABLE",
]