#!/usr/bin/env python3
"""Mimic -- a lightweight, dependency-free port spoofer.

Listens on configured TCP ports and returns realistic banners and
HTTP responses imitating real services. Useful for disguising a VPS,
running decoys, or reducing the value of automated port scans.

See README.md for usage.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import ssl
import sys
from pathlib import Path
from typing import Any

from signatures import (
    HANDLERS,
    SIGNATURES,
    Handler,
    build_http_response,
    build_raw_response,
)


# ============================================================
# Logging
# ============================================================

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"


def _setup_logging(level: str) -> None:
    """Configure the root logger with a simple format."""
    logging.basicConfig(
        format=LOG_FORMAT,
        level=getattr(logging, level.upper(), logging.INFO),
    )


log = logging.getLogger("mimic")


# ============================================================
# Constants
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = BASE_DIR / "config.json"
PRESETS_DIR = BASE_DIR / "presets"

DEFAULT_MAX_CONNS = 20
DEFAULT_READ_TIMEOUT = 0.3
DEFAULT_HANDLER_TIMEOUT = 1.0


# ============================================================
# Server
# ============================================================

class SpoofServer:
    """One spoofed service bound to one TCP port."""

    def __init__(
        self,
        name: str,
        port: int,
        response_bytes: bytes | None = None,
        tls: bool = False,
        delay: float = 0.0,
        keep_open: bool = False,
        handler: Handler | None = None,
        cert_file: Path | None = None,
        key_file: Path | None = None,
        max_conns: int = DEFAULT_MAX_CONNS,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        handler_timeout: float = DEFAULT_HANDLER_TIMEOUT,
    ) -> None:
        self.name = name
        self.port = port
        self.response = response_bytes or b""
        self.tls = tls
        self.delay = delay
        self.keep_open = keep_open
        self.handler = handler
        self.cert_file = cert_file
        self.key_file = key_file
        self.max_conns = max_conns
        self.read_timeout = read_timeout
        self.handler_timeout = handler_timeout
        self.server: asyncio.AbstractServer | None = None
        self.ssl_context: ssl.SSLContext | None = None
        self._connections: dict[str, int] = {}

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        """Build an SSL context if TLS is enabled."""
        if not self.tls:
            return None
        if not self.cert_file or not self.key_file:
            log.error(
                "[%s] TLS enabled but cert/key not configured",
                self.name,
            )
            sys.exit(1)
        if not self.cert_file.exists() or not self.key_file.exists():
            log.error("[%s] TLS cert or key not found", self.name)
            sys.exit(1)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(
            certfile=str(self.cert_file),
            keyfile=str(self.key_file),
        )
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle one client connection."""
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else "unknown"

        count = self._connections.get(peer_ip, 0)
        if count >= self.max_conns:
            log.warning(
                "[%s:%d] dropping %s (conn limit)",
                self.name,
                self.port,
                peer_ip,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return
        self._connections[peer_ip] = count + 1

        try:
            if self.handler is not None:
                await self._serve_handler(reader, writer)
            else:
                await self._serve_static(reader, writer)

            log.info(
                "[%s:%d] served %s",
                self.name,
                self.port,
                peer_ip,
            )
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            log.warning(
                "[%s:%d] error: %s",
                self.name,
                self.port,
                exc,
            )
        finally:
            if not self.keep_open:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            self._connections[peer_ip] -= 1
            if self._connections[peer_ip] <= 0:
                del self._connections[peer_ip]

    async def _serve_handler(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Run the protocol handler for one round."""
        assert self.handler is not None
        try:
            data = await asyncio.wait_for(
                reader.read(4096),
                timeout=self.handler_timeout,
            )
        except asyncio.TimeoutError:
            data = b""

        response = self.handler(data)
        if response:
            writer.write(response)
            await writer.drain()

    async def _serve_static(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Send the static response for this service."""
        try:
            await asyncio.wait_for(
                reader.read(4096),
                timeout=self.read_timeout,
            )
        except asyncio.TimeoutError:
            pass

        if self.delay:
            await asyncio.sleep(self.delay)

        writer.write(self.response)
        await writer.drain()

    async def start(self) -> None:
        """Start listening on the configured port."""
        self.ssl_context = self._build_ssl_context()
        self.server = await asyncio.start_server(
            self._handle_client,
            host="0.0.0.0",
            port=self.port,
            ssl=self.ssl_context,
        )
        suffix = " (TLS)" if self.tls else ""
        kind = "handler" if self.handler else "static"
        log.info(
            "listening on :%d as %s [%s]%s",
            self.port,
            self.name,
            kind,
            suffix,
        )

    async def stop(self) -> None:
        """Stop the server and close all connections."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()


# ============================================================
# Config loading
# ============================================================

def load_config(path: Path) -> dict[str, Any]:
    """Load and parse a JSON config file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"Cannot read config {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def merge_service_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """Resolve a service spec against a signature, if present."""
    sig_name = spec.get("service")
    if not sig_name:
        return dict(spec)

    base = SIGNATURES.get(sig_name)
    if base is None:
        raise SystemExit(
            f"Unknown signature '{sig_name}'. "
            f"Run 'mimic list-signatures' to see options."
        )

    merged = dict(base)
    for key, value in spec.items():
        if key == "service":
            continue
        merged[key] = value
    merged.setdefault("name", sig_name)
    return merged


def _resolve_handler(
    spec: dict[str, Any],
    name: str,
) -> Handler | None:
    """Resolve the handler for a service spec, if any."""
    handler_name = spec.get("handler")
    if not handler_name:
        return None
    handler = HANDLERS.get(handler_name)
    if handler is None:
        raise SystemExit(
            f"Unknown handler '{handler_name}' for service '{name}'"
        )
    return handler


def _build_response(spec: dict[str, Any]) -> bytes:
    """Build the static response bytes for a service spec."""
    if spec.get("raw"):
        return build_raw_response(spec.get("body", ""))
    return build_http_response(
        spec.get("status", "200 OK"),
        spec.get("headers", {}),
        spec.get("body", ""),
    )


def build_servers(cfg: dict[str, Any]) -> list[SpoofServer]:
    """Build the list of SpoofServer instances from a config dict."""
    settings = cfg.get("settings", {})
    tls_cfg = cfg.get("tls", {})

    cert_file = (
        Path(tls_cfg["cert_file"]) if tls_cfg.get("cert_file") else None
    )
    key_file = (
        Path(tls_cfg["key_file"]) if tls_cfg.get("key_file") else None
    )

    max_conns = int(
        settings.get("max_connections_per_ip", DEFAULT_MAX_CONNS)
    )
    read_timeout = float(
        settings.get("read_timeout", DEFAULT_READ_TIMEOUT)
    )
    handler_timeout = float(
        settings.get("handler_read_timeout", DEFAULT_HANDLER_TIMEOUT)
    )

    servers: list[SpoofServer] = []
    for raw in cfg.get("services", []):
        spec = merge_service_spec(raw)
        port = int(spec["port"])
        name = spec.get("name", f"port-{port}")
        handler = _resolve_handler(spec, name)

        if handler is not None:
            response_bytes = b""
        else:
            response_bytes = _build_response(spec)

        servers.append(
            SpoofServer(
                name=name,
                port=port,
                response_bytes=response_bytes,
                tls=bool(spec.get("tls", False)),
                delay=float(spec.get("delay", 0.0)),
                keep_open=bool(spec.get("keep_open", False)),
                handler=handler,
                cert_file=cert_file,
                key_file=key_file,
                max_conns=max_conns,
                read_timeout=read_timeout,
                handler_timeout=handler_timeout,
            )
        )
    return servers


# ============================================================
# Async runner
# ============================================================

async def run_servers(cfg: dict[str, Any]) -> None:
    """Start all servers and wait for a shutdown signal."""
    servers = build_servers(cfg)
    if not servers:
        raise SystemExit("No services configured")

    started: list[SpoofServer] = []
    for srv in servers:
        try:
            await srv.start()
            started.append(srv)
        except OSError as exc:
            log.error("cannot bind :%d -- %s", srv.port, exc)

    stop_event = asyncio.Event()

    def _shutdown(*_: Any) -> None:
        log.info("shutting down")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown)

    await stop_event.wait()

    for srv in started:
        await srv.stop()


# ============================================================
# CLI commands
# ============================================================

def cmd_run(args: argparse.Namespace) -> int:
    """Run the spoofer with the given config file."""
    cfg_path = Path(args.config).resolve()
    if not cfg_path.exists():
        print(f"config not found: {cfg_path}", file=sys.stderr)
        return 1
    cfg = load_config(cfg_path)
    _setup_logging(
        cfg.get("settings", {}).get("log_level", args.log_level)
    )
    log.info("using config %s", cfg_path)
    try:
        asyncio.run(run_servers(cfg))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_list_presets(_: argparse.Namespace) -> int:
    """Print available preset names."""
    if not PRESETS_DIR.exists():
        print("no presets directory found")
        return 1
    for preset in sorted(PRESETS_DIR.glob("*.json")):
        print(preset.stem)
    return 0


def cmd_list_signatures(_: argparse.Namespace) -> int:
    """Print available signature names and kinds."""
    for name in sorted(SIGNATURES):
        sig = SIGNATURES[name]
        if "handler" in sig:
            kind = "handler"
        elif sig.get("raw"):
            kind = "raw"
        else:
            kind = "http"
        tls = " tls" if sig.get("tls") else ""
        print(f"{name:<28} {kind}{tls}")
    return 0


def cmd_show_signature(args: argparse.Namespace) -> int:
    """Print one signature as JSON."""
    sig = SIGNATURES.get(args.name)
    if sig is None:
        print(f"unknown signature: {args.name}", file=sys.stderr)
        return 1
    print(json.dumps(sig, indent=2, ensure_ascii=False))
    return 0


def cmd_gen_config(args: argparse.Namespace) -> int:
    """Generate a config file from a preset."""
    preset_path = PRESETS_DIR / f"{args.preset}.json"
    if not preset_path.exists():
        print(f"preset not found: {preset_path}", file=sys.stderr)
        return 1

    preset = load_config(preset_path)
    out = Path(args.output).resolve()
    if out.exists() and not args.force:
        print(
            f"{out} already exists; use --force to overwrite",
            file=sys.stderr,
        )
        return 1

    preset.setdefault("settings", {})
    preset["settings"].setdefault("log_level", "INFO")
    preset["settings"].setdefault(
        "max_connections_per_ip",
        DEFAULT_MAX_CONNS,
    )
    preset["settings"].setdefault("read_timeout", DEFAULT_READ_TIMEOUT)
    preset["settings"].setdefault(
        "handler_read_timeout",
        DEFAULT_HANDLER_TIMEOUT,
    )

    preset.setdefault("tls", {})
    preset["tls"].setdefault(
        "cert_file",
        "/etc/letsencrypt/live/example.com/fullchain.pem",
    )
    preset["tls"].setdefault(
        "key_file",
        "/etc/letsencrypt/live/example.com/privkey.pem",
    )

    out.write_text(
        json.dumps(preset, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {out}")
    return 0


# ============================================================
# Argument parser
# ============================================================

def build_argparser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="mimic",
        description="Lightweight port spoofer for disguising servers.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser(
        "run",
        help="run the spoofer with a config file",
    )
    p_run.add_argument(
        "--config",
        "-c",
        default=str(DEFAULT_CONFIG),
    )
    p_run.set_defaults(func=cmd_run)

    p_lp = sub.add_parser(
        "list-presets",
        help="list bundled presets",
    )
    p_lp.set_defaults(func=cmd_list_presets)

    p_ls = sub.add_parser(
        "list-signatures",
        help="list built-in signatures",
    )
    p_ls.set_defaults(func=cmd_list_signatures)

    p_ss = sub.add_parser(
        "show-signature",
        help="show one signature as JSON",
    )
    p_ss.add_argument("name")
    p_ss.set_defaults(func=cmd_show_signature)

    p_gen = sub.add_parser(
        "gen-config",
        help="generate a config from a preset",
    )
    p_gen.add_argument("--preset", required=True)
    p_gen.add_argument("--output", "-o", required=True)
    p_gen.add_argument("--force", action="store_true")
    p_gen.set_defaults(func=cmd_gen_config)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = build_argparser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())