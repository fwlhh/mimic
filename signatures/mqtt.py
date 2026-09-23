#!/usr/bin/env python3
"""MQTT, AMQP and raw SSH banner handlers."""

from __future__ import annotations


def handle_mqtt(data: bytes) -> bytes:
    """MQTT 3.1.1 CONNACK with return code 0 (accepted)."""
    if not data:
        return b""
    return b"\x20\x02\x00\x00"


def handle_amqp(_data: bytes) -> bytes:
    """AMQP 0-9-1 protocol header."""
    return b"AMQP\x00\x00\x09\x01"


def handle_ssh(_data: bytes) -> bytes:
    """SSH banner, sent on connect."""
    return b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19\r\n"