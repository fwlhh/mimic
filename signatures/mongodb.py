#!/usr/bin/env python3
"""MongoDB wire protocol handler."""

from __future__ import annotations

import struct


def _bson_encode_document(d: dict) -> bytes:
    body = b""
    for key, value in d.items():
        key_b = key.encode("utf-8") + b"\x00"
        if isinstance(value, bool):
            body += b"\x08" + key_b + (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            if -2**31 <= value < 2**31:
                body += b"\x10" + key_b + struct.pack("<i", value)
            else:
                body += b"\x12" + key_b + struct.pack("<q", value)
        elif isinstance(value, float):
            body += b"\x01" + key_b + struct.pack("<d", value)
        elif isinstance(value, str):
            s = value.encode("utf-8") + b"\x00"
            body += b"\x02" + key_b + struct.pack("<i", len(s)) + s
        elif value is None:
            body += b"\x0a" + key_b
        elif isinstance(value, dict):
            sub = _bson_encode_document(value)
            body += b"\x03" + key_b + sub
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _mongo_msg(request_id: int, response_to: int, op_code: int,
               payload: bytes) -> bytes:
    header = struct.pack(
        "<iiii", 16 + len(payload), request_id, response_to, op_code
    )
    return header + payload


def _mongo_op_reply(response_to: int, doc: dict) -> bytes:
    payload = struct.pack("<iqii", 8, 0, 0, 1)
    payload += _bson_encode_document(doc)
    return _mongo_msg(1, response_to, 1, payload)


def _extract_request_id(data: bytes) -> int:
    if len(data) < 12:
        return 0
    return struct.unpack("<i", data[4:8])[0]


def _ismaster_doc() -> dict:
    return {
        "isWritablePrimary": True,
        "topologyVersion": {
            "processId": "507f1f77bcf86cd799439011",
            "counter": 0,
        },
        "maxBsonObjectSize": 16777216,
        "maxMessageSizeBytes": 48000000,
        "maxWriteBatchSize": 100000,
        "localTime": "2026-09-23T00:00:00.000Z",
        "logicalSessionTimeoutMinutes": 30,
        "connectionId": 42,
        "minWireVersion": 0,
        "maxWireVersion": 17,
        "readOnly": False,
        "ok": 1.0,
    }


def handle_mongodb(data: bytes) -> bytes:
    """MongoDB isMaster/hello responder."""
    if not data:
        return b""
    return _mongo_op_reply(_extract_request_id(data), _ismaster_doc())