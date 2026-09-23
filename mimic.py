#!/usr/bin/env python3
"""Mimic -- a lightweight, dependency-free port spoofer.

Listens on configured TCP ports and returns realistic banners and
HTTP responses imitating real services. Optionally runs a full SSH
handshake server (requires asyncssh) for ports that must survive
deep fingerprinting like Censys or Shodan.

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
import time
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
    logging.basicConfig(
        format=LOG_FORMAT,
        level=getattr(logging, level.upper(), logging.INFO),
    )
    # asyncssh logs every handshake at INFO; that's too noisy.
    logging.getLogger("asyncssh").setLevel(logging.WARNING)


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
DEFAULT_RATE_LIMIT = 30           # new connections per IP per window
DEFAULT_RATE_WINDOW = 60.0        # seconds
DEFAULT_GLOBAL_CONNECTIONS = 200  # hard cap across all ports
DEFAULT_SHUTDOWN_GRACE = 5.0      # seconds to wait for active conns
DEFAULT_METRICS_INTERVAL = 60.0   # seconds between metric dumps
DEFAULT_SSH_LOGIN_TIMEOUT = 30.0  # seconds for SSH handshake + auth


# ============================================================
# Global metrics
# ============================================================

class Metrics:
    """Simple in-memory counters, dumped to the log periodically."""

    def __init__(self) -> None:
        self.started_at = time.monotonic()
        self.total_connections = 0
        self.active_connections = 0
        self.rejected_rate = 0
        self.rejected_limit = 0
        self.per_port_total: dict[int, int] = {}

    def snapshot(self) -> str:
        uptime = int(time.monotonic() - self.started_at)
        ports = ", ".join(
            f"{port}={count}"
            for port, count in sorted(self.per_port_total.items())
        )
        return (
            f"uptime={uptime}s "
            f"total={self.total_connections} "
            f"active={self.active_connections} "
            f"rejected_rate={self.rejected_rate} "
            f"rejected_limit={self.rejected_limit} "
            f"per_port=[{ports}]"
        )


metrics = Metrics()


# ============================================================
# Server
# ============================================================

class SpoofServer:
    """One spoofed service bound to one TCP port.

    Modes:
      - static HTTP/raw: sends a fixed response
      - handler: calls a protocol handler per connection
      - ssh-full: runs a full SSH handshake server (asyncssh)
    """

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
        rate_limit: int = DEFAULT_RATE_LIMIT,
        rate_window: float = DEFAULT_RATE_WINDOW,
        ssh_full: bool = False,
        ssh_version: str = "OpenSSH_9.6p1 Ubuntu-3ubuntu13.19",
        ssh_login_timeout: float = DEFAULT_SSH_LOGIN_TIMEOUT,
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
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.ssh_full = ssh_full
        self.ssh_version = ssh_version
        self.ssh_login_timeout = ssh_login_timeout
        self.server: asyncio.AbstractServer | None = None
        self.ssl_context: ssl.SSLContext | None = None
        self.ssh_acceptor: Any = None
        self._connections: dict[str, int] = {}
        self._recent: dict[str, list[float]] = {}
        self._shutdown = asyncio.Event()

    # ---------- TLS ----------

    def _build_ssl_context(self) -> ssl.SSLContext | None:
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

    # ---------- Rate limiting ----------

    def _rate_limited(self, peer_ip: str) -> bool:
        """Return True if this IP has exceeded the rate limit."""
        now = time.monotonic()
        cutoff = now - self.rate_window
        recent = self._recent.get(peer_ip, [])
        # Drop entries older than the window.
        recent = [t for t in recent if t > cutoff]
        if len(recent) >= self.rate_limit:
            self._recent[peer_ip] = recent
            return True
        recent.append(now)
        self._recent[peer_ip] = recent
        return False

    # ---------- Static / handler modes ----------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else "unknown"

        # Per-IP concurrent connection limit.
        count = self._connections.get(peer_ip, 0)
        if count >= self.max_conns:
            log.warning(
                "[%s:%d] dropping %s (conn limit)",
                self.name,
                self.port,
                peer_ip,
            )
            metrics.rejected_limit += 1
            await self._close_writer(writer)
            return

        # Per-IP rate limit.
        if self._rate_limited(peer_ip):
            log.warning(
                "[%s:%d] dropping %s (rate limit)",
                self.name,
                self.port,
                peer_ip,
            )
            metrics.rejected_rate += 1
            await self._close_writer(writer)
            return

        self._connections[peer_ip] = count + 1
        metrics.total_connections += 1
        metrics.active_connections += 1
        metrics.per_port_total[self.port] = (
            metrics.per_port_total.get(self.port, 0) + 1
        )

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
                await self._close_writer(writer)
            self._connections[peer_ip] -= 1
            if self._connections[peer_ip] <= 0:
                del self._connections[peer_ip]
            metrics.active_connections -= 1

    async def _serve_handler(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
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

    @staticmethod
    async def _close_writer(writer: asyncio.StreamWriter) -> None:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    # ---------- SSH full-handshake mode ----------

    async def _start_ssh(self) -> None:
        try:
            from ssh_server import start_ssh_server
        except ImportError:
            log.error(
                "[%s] ssh_full requires the 'asyncssh' package. "
                "Install with: sudo apt install python3-asyncssh",
                self.name,
            )
            sys.exit(1)

        self.ssh_acceptor = await start_ssh_server(
            port=self.port,
            server_version=self.ssh_version,
            login_timeout=self.ssh_login_timeout,
        )
        log.info(
            "listening on :%d as %s [ssh-full]",
            self.port,
            self.name,
        )

    # ---------- Lifecycle ----------

    async def start(self) -> None:
        if self.ssh_full:
            await self._start_ssh()
            return

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

    async def stop(self, grace: float = DEFAULT_SHUTDOWN_GRACE) -> None:
        """Stop the server, waiting up to `grace` seconds for active
        connections to drain."""
        if self.ssh_full and self.ssh_acceptor is not None:
            self.ssh_acceptor.close()
            await self.ssh_acceptor.wait_closed()
            return

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        # Wait for active connections to finish, up to `grace` seconds.
        deadline = time.monotonic() + grace
        while metrics.active_connections > 0 and time.monotonic() < deadline:
            await asyncio.sleep(0.1)


# ============================================================
# Config loading
# ============================================================

def load_config(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"Cannot read config {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def merge_service_spec(spec: dict[str, Any]) -> dict[str, Any]:
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
    if spec.get("raw"):
        return build_raw_response(spec.get("body", ""))
    return build_http_response(
        spec.get("status", "200 OK"),
        spec.get("headers", {}),
        spec.get("body", ""),
    )


def build_servers(cfg: dict[str, Any]) -> list[SpoofServer]:
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
    rate_limit = int(
        settings.get("rate_limit_per_ip", DEFAULT_RATE_LIMIT)
    )
    rate_window = float(
        settings.get("rate_window_seconds", DEFAULT_RATE_WINDOW)
    )
    ssh_login_timeout = float(
        settings.get("ssh_login_timeout", DEFAULT_SSH_LOGIN_TIMEOUT)
    )

    servers: list[SpoofServer] = []
    for raw in cfg.get("services", []):
        spec = merge_service_spec(raw)
        port = int(spec["port"])
        name = spec.get("name", f"port-{port}")
        handler = _resolve_handler(spec, name)
        ssh_full = bool(spec.get("ssh_full", False))

        if handler is not None or ssh_full:
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
                rate_limit=rate_limit,
                rate_window=rate_window,
                ssh_full=ssh_full,
                ssh_version=spec.get(
                    "ssh_version",
                    "OpenSSH_9.6p1 Ubuntu-3ubuntu13.19",
                ),
                ssh_login_timeout=ssh_login_timeout,
            )
        )
    return servers


# ============================================================
# Async runner
# ============================================================

async def _metrics_loop(interval: float) -> None:
    """Log a metrics snapshot every `interval` seconds."""
    while True:
        await asyncio.sleep(interval)
        log.info("[metrics] %s", metrics.snapshot())


async def run_servers(cfg: dict[str, Any], cfg_path: Path) -> None:
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
        except Exception as exc:
            log.error("failed to start :%d -- %s", srv.port, exc)

    if not started:
        raise SystemExit("No services started")

    stop_event = asyncio.Event()
    reload_event = asyncio.Event()

    def _shutdown(*_: Any) -> None:
        log.info("shutting down")
        stop_event.set()

    def _reload(*_: Any) -> None:
        log.info("reload requested")
        reload_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown)
    loop.add_signal_handler(signal.SIGHUP, _reload)

    metrics_task = asyncio.create_task(
        _metrics_loop(DEFAULT_METRICS_INTERVAL)
    )

    try:
        while not stop_event.is_set():
            stop_task = asyncio.create_task(stop_event.wait())
            reload_task = asyncio.create_task(reload_event.wait())
            done, pending = await asyncio.wait(
                {stop_task, reload_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()

            if stop_event.is_set():
                break

            if reload_event.is_set():
                reload_event.clear()
                log.info("reloading configuration")
                try:
                    new_cfg = load_config(cfg_path)
                except SystemExit as exc:
                    log.error("reload failed: %s -- keeping old config", exc)
                    continue

                # Stop old servers.
                for srv in started:
                    try:
                        await srv.stop(grace=2.0)
                    except Exception as exc:
                        log.warning("error stopping %s: %s", srv.name, exc)

                # Start new ones.
                started = []
                for srv in build_servers(new_cfg):
                    try:
                        await srv.start()
                        started.append(srv)
                    except OSError as exc:
                        log.error(
                            "cannot bind :%d after reload -- %s",
                            srv.port,
                            exc,
                        )
                    except Exception as exc:
                        log.error(
                            "failed to start :%d after reload -- %s",
                            srv.port,
                            exc,
                        )
                log.info("reload complete: %d services", len(started))
    finally:
        metrics_task.cancel()
        try:
            await metrics_task
        except asyncio.CancelledError:
            pass

        for srv in started:
            try:
                await srv.stop()
            except Exception as exc:
                log.warning("error stopping %s: %s", srv.name, exc)


# ============================================================
# CLI commands
# ============================================================

def cmd_run(args: argparse.Namespace) -> int:
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
        asyncio.run(run_servers(cfg, cfg_path))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_list_presets(_: argparse.Namespace) -> int:
    if not PRESETS_DIR.exists():
        print("no presets directory found")
        return 1
    for preset in sorted(PRESETS_DIR.glob("*.json")):
        print(preset.stem)
    return 0


def cmd_list_signatures(_: argparse.Namespace) -> int:
    for name in sorted(SIGNATURES):
        sig = SIGNATURES[name]
        if sig.get("ssh_full"):
            kind = "ssh-full"
        elif "handler" in sig:
            kind = "handler"
        elif sig.get("raw"):
            kind = "raw"
        else:
            kind = "http"
        tls = " tls" if sig.get("tls") else ""
        print(f"{name:<28} {kind}{tls}")
    return 0


def cmd_show_signature(args: argparse.Namespace) -> int:
    sig = SIGNATURES.get(args.name)
    if sig is None:
        print(f"unknown signature: {args.name}", file=sys.stderr)
        return 1
    print(json.dumps(sig, indent=2, ensure_ascii=False))
    return 0


def cmd_gen_config(args: argparse.Namespace) -> int:
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
    preset["settings"].setdefault(
        "rate_limit_per_ip",
        DEFAULT_RATE_LIMIT,
    )
    preset["settings"].setdefault(
        "rate_window_seconds",
        DEFAULT_RATE_WINDOW,
    )
    preset["settings"].setdefault("read_timeout", DEFAULT_READ_TIMEOUT)
    preset["settings"].setdefault(
        "handler_read_timeout",
        DEFAULT_HANDLER_TIMEOUT,
    )
    preset["settings"].setdefault(
        "ssh_login_timeout",
        DEFAULT_SSH_LOGIN_TIMEOUT,
    )

    preset.setdefault("tls", {})
    preset["tls"].setdefault(
        "cert_file",
        "/opt/mimic/certs/example.com/fullchain.pem",
    )
    preset["tls"].setdefault(
        "key_file",
        "/opt/mimic/certs/example.com/privkey.pem",
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
    parser = argparse.ArgumentParser(
        prog="mimic",
        description="Lightweight port spoofer for disguising servers.",
        epilog=(
            "examples:\n"
            "  mimic run --config /etc/mimic/config.json\n"
            "  mimic list-presets\n"
            "  mimic list-signatures\n"
            "  mimic show-signature nginx-welcome\n"
            "  mimic gen-config --preset ci-cd -o config.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    sub = parser.add_subparsers(dest="cmd", required=False)

    p_run = sub.add_parser("run", help="run the spoofer with a config file")
    p_run.add_argument("--config", "-c", default=str(DEFAULT_CONFIG))
    p_run.set_defaults(func=cmd_run)

    p_lp = sub.add_parser("list-presets", help="list bundled presets")
    p_lp.set_defaults(func=cmd_list_presets)

    p_ls = sub.add_parser(
        "list-signatures", help="list built-in signatures"
    )
    p_ls.set_defaults(func=cmd_list_signatures)

    p_ss = sub.add_parser(
        "show-signature", help="show one signature as JSON"
    )
    p_ss.add_argument("name")
    p_ss.set_defaults(func=cmd_show_signature)

    p_gen = sub.add_parser(
        "gen-config", help="generate a config from a preset"
    )
    p_gen.add_argument("--preset", required=True)
    p_gen.add_argument("--output", "-o", required=True)
    p_gen.add_argument("--force", action="store_true")
    p_gen.set_defaults(func=cmd_gen_config)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argparser()
    args = parser.parse_args(argv)

    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())