#!/usr/bin/env python3
"""Full SSH server for Mimic.

Runs a complete SSH handshake (banner, KEX, host key exchange) so
scanners like Censys and Shodan see a real SSH server. All auth
attempts are rejected -- no shell, no exec, no access.

Algorithm lists are pinned to match Ubuntu 24.04's OpenSSH 9.6p1
defaults. Post-quantum KEX (sntrup761x25519-sha512@openssh.com)
requires liboqs; it is silently dropped if the local asyncssh
build does not support it, so the service always starts.
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

# asyncssh prepends "SSH-2.0-" automatically, so do NOT include it here.
DEFAULT_SERVER_VERSION = "OpenSSH_9.6p1 Ubuntu-3ubuntu13.19"


def _supported_kex_algs() -> list[str]:
    """Return the KEX algorithms this asyncssh build actually supports.

    Filters the desired list against what asyncssh reports. This lets
    us advertise sntrup761x25519-sha512@openssh.com when liboqs is
    available, and silently skip it otherwise.
    """
    desired = [
        "sntrup761x25519-sha512@openssh.com",
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group14-sha256",
    ]

    try:
        from asyncssh.kex import get_kex_algs
        available = set(get_kex_algs())
    except Exception:
        # Very old asyncssh -- fall back to whatever it accepts.
        return desired

    filtered = [alg for alg in desired if alg in available]
    missing = [alg for alg in desired if alg not in available]
    if missing:
        log.info(
            "[ssh] KEX algorithms not supported by local asyncssh: %s",
            ", ".join(missing),
        )
    return filtered


# signature_algs controls host key and public key signature algorithms.
SIGNATURE_ALGS = [
    "ssh-ed25519",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ecdsa-sha2-nistp256",
]

ENCRYPTION_ALGS = [
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
]

MAC_ALGS = [
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
]


class RejectAuthServer(asyncssh.SSHServer):
    """SSH server that completes the handshake but rejects all auth."""

    def begin_auth(self, username: str) -> bool:
        log.info("[ssh] auth attempt for user %r", username)
        return True

    def password_auth_supported(self) -> bool:
        return False

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key) -> bool:
        log.info(
            "[ssh] rejected public key for %r (algo=%s)",
            username,
            getattr(key, "algorithm", "unknown"),
        )
        return False

    def kbdint_auth_supported(self) -> bool:
        return False


async def start_ssh_server(
    port: int,
    host: str = "0.0.0.0",
    server_version: str = DEFAULT_SERVER_VERSION,
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

    kex = _supported_kex_algs()
    log.info("[ssh] starting full-handshake server on :%d", port)
    log.debug("[ssh] KEX algorithms: %s", ", ".join(kex))

    return await asyncssh.create_server(
        RejectAuthServer,
        host=host,
        port=port,
        server_host_keys=list(existing),
        server_version=server_version,
        encoding=None,
        kex_algs=kex,
        encryption_algs=ENCRYPTION_ALGS,
        mac_algs=MAC_ALGS,
        signature_algs=SIGNATURE_ALGS,
    )