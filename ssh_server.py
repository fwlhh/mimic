#!/usr/bin/env python3
"""Full SSH server for Mimic.

Runs a complete SSH handshake (banner, KEX, host key exchange) so
scanners like Censys and Shodan see a real SSH server. All auth
attempts are rejected -- no shell, no exec, no access.
"""

from __future__ import annotations

import logging
from pathlib import Path

import asyncssh

log = logging.getLogger("mimic.ssh")

DEFAULT_HOST_KEYS = (
    "/opt/mimic/ssh_host_ed25519_key",
    "/opt/mimic/ssh_host_rsa_key",
)


class RejectAuthServer(asyncssh.SSHServer):
    """SSH server that completes the handshake but rejects all auth."""

    def begin_auth(self, username: str) -> bool:
        log.info("[ssh] auth attempt for user %r", username)
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        log.info("[ssh] rejected password for %r", username)
        return False

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key) -> bool:
        log.info("[ssh] rejected public key for %r", username)
        return False

    def kbdint_auth_supported(self) -> bool:
        return False


async def start_ssh_server(
    port: int,
    host: str = "0.0.0.0",
    server_version: str = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19",
    host_keys: tuple[str, ...] = DEFAULT_HOST_KEYS,
):
    """Start an asyncssh server that completes the handshake and
    rejects every authentication attempt."""
    existing = [p for p in host_keys if Path(p).exists()]
    if not existing:
        raise SystemExit(
            "No SSH host keys found. Run:\n"
            "  ssh-keygen -t ed25519 "
            "-f /opt/mimic/ssh_host_ed25519_key -N ''\n"
            "  ssh-keygen -t rsa -b 4096 "
            "-f /opt/mimic/ssh_host_rsa_key -N ''"
        )

    log.info("[ssh] starting full-handshake server on :%d", port)
    return await asyncssh.create_server(
        RejectAuthServer,
        host=host,
        port=port,
        server_host_keys=list(existing),
        server_version=server_version,
        encoding=None,
    )