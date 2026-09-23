#!/usr/bin/env python3
"""Built-in service signatures and protocol handlers for Mimic.

A signature describes how a port should respond:

HTTP service:
    status   -- HTTP status line, e.g. "200 OK"
    headers  -- dict of HTTP headers
    body     -- response body (str)

Raw service:
    raw      -- True
    body     -- banner sent as-is

Handler service:
    handler  -- name of a protocol handler from HANDLERS

Any signature may also set:
    tls        -- wrap in TLS (requires cert/key in config)
    delay      -- seconds before responding (float)
    keep_open  -- keep connection open after response (bool)
"""

from __future__ import annotations

import struct
from typing import Callable

Handler = Callable[[bytes], bytes]


# ============================================================
# HTTP helpers
# ============================================================

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


def _is_http(data: bytes) -> bool:
    """Return True if data looks like an HTTP request."""
    if not data:
        return False
    upper = data[:16].upper()
    return any(upper.startswith(method) for method in _HTTP_METHODS)


def _is_proxy_like(data: bytes) -> bool:
    """Return True if data looks like an open-proxy probe."""
    if data[:8].upper().startswith(b"CONNECT "):
        return True
    first_line = data.split(b"\r\n", 1)[0]
    parts = first_line.split(b" ", 2)
    return len(parts) >= 2 and b"://" in parts[1]


def _http_400() -> bytes:
    """Minimal 400 Bad Request response with empty body."""
    return (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )


# ============================================================
# Protocol handlers
# ============================================================

def handle_redis(data: bytes) -> bytes:
    """Minimal Redis emulation (auth-required behaviour)."""
    cmd = data.strip().lower()
    if cmd.startswith(b"auth"):
        return b"-ERR invalid password\r\n"
    if cmd.startswith(b"quit"):
        return b""
    return b"-NOAUTH Authentication required.\r\n"


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


def handle_etcd(data: bytes) -> bytes:
    """etcd /version on HTTP; 400 otherwise or on proxy-like probes."""
    if not _is_http(data) or _is_proxy_like(data):
        return _http_400()
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
    if not _is_http(data) or _is_proxy_like(data):
        return _http_400()
    return build_http_response(
        "200 OK",
        {"Content-Type": "application/json"},
        '{"status":"ok","service":"ci-runner","version":"1.2.4"}',
    )


def handle_mysql(_data: bytes) -> bytes:
    """Send a valid MySQL 8.0.x server greeting packet."""
    # Protocol version 10 (0x0a), server version, thread id,
    # auth-plugin-data part 1 (8 bytes), filler, capabilities,
    # charset, status, caps upper, auth len, reserved,
    # auth-plugin-data part 2 (12 + NUL), plugin name.
    payload = (
        b"\x0a"
        + b"8.0.35\x00"
        + struct.pack("<I", 42)
        + b"abcdefgh"
        + b"\x00"
        + struct.pack("<H", 0xFFFF)
        + b"\x21"
        + struct.pack("<H", 0x0002)
        + struct.pack("<H", 0xFFFF)
        + b"\x15"
        + b"\x00" * 10
        + b"ijklmnopqrst\x00"
        + b"mysql_native_password\x00"
    )
    header = struct.pack("<I", len(payload))[:3] + b"\x00"
    return header + payload


def handle_postgres(data: bytes) -> bytes:
    """PostgreSQL: reply with cleartext-password auth request.

    Real PostgreSQL sends nothing until the client sends a
    StartupMessage; we only respond once the client has spoken.
    """
    if not data:
        return b""
    # 'R' message, length 8, auth code 3 (cleartext password).
    return b"R\x00\x00\x00\x08\x00\x00\x00\x03"


def handle_mqtt(data: bytes) -> bytes:
    """MQTT 3.1.1 CONNACK with return code 0 (accepted)."""
    if not data:
        return b""
    return b"\x20\x02\x00\x00"


def handle_amqp(_data: bytes) -> bytes:
    """AMQP 0-9-1 protocol header."""
    return b"AMQP\x00\x00\x09\x01"


def handle_smtp(data: bytes) -> bytes:
    """Minimal SMTP: greeting on empty input, per-command otherwise."""
    if not data:
        return b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"

    cmd = data.strip().upper()
    if cmd.startswith(b"EHLO"):
        return (
            b"250-mail.example.com\r\n"
            b"250-PIPELINING\r\n"
            b"250-SIZE 10240000\r\n"
            b"250-VRFY\r\n"
            b"250-ETRN\r\n"
            b"250-STARTTLS\r\n"
            b"250-ENHANCEDSTATUSCODES\r\n"
            b"250-8BITMIME\r\n"
            b"250-DSN\r\n"
            b"250 SMTPUTF8\r\n"
        )
    if cmd.startswith(b"HELO"):
        return b"250 mail.example.com\r\n"
    if cmd.startswith(b"MAIL FROM"):
        return b"250 2.1.0 Ok\r\n"
    if cmd.startswith(b"RCPT TO"):
        return b"250 2.1.5 Ok\r\n"
    if cmd.startswith(b"DATA"):
        return b"354 End data with <CR><LF>.<CR><LF>\r\n"
    if cmd.startswith(b"QUIT"):
        return b"221 2.0.0 Bye\r\n"
    if cmd.startswith(b"NOOP"):
        return b"250 2.0.0 Ok\r\n"
    return b"502 5.5.2 Error: command not recognized\r\n"


def handle_pop3(data: bytes) -> bytes:
    """Minimal POP3: greeting on empty input, per-command otherwise."""
    if not data:
        return b"+OK Dovecot ready.\r\n"

    cmd = data.strip().upper()
    if cmd.startswith(b"USER"):
        return b"+OK\r\n"
    if cmd.startswith(b"PASS"):
        return b"-ERR [AUTH] Authentication failed.\r\n"
    if cmd.startswith(b"CAPA"):
        return b"+OK\r\nUSER\r\nUIDL\r\nTOP\r\n.\r\n"
    if cmd.startswith(b"QUIT"):
        return b"+OK Logging out.\r\n"
    return b"-ERR Unknown command.\r\n"


def handle_imap(data: bytes) -> bytes:
    """Minimal IMAP: greeting on empty input, per-command otherwise."""
    if not data:
        return (
            b"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS "
            b"ID ENABLE IDLE LITERAL+] Dovecot ready.\r\n"
        )

    cmd = data.strip().upper()
    if cmd.endswith(b"CAPABILITY"):
        return (
            b"* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS "
            b"ID ENABLE IDLE LITERAL+\r\n"
            b"a001 OK Pre-login capabilities listed, post-login "
            b"capabilities have more.\r\n"
        )
    if cmd.endswith(b"LOGOUT"):
        return b"* BYE Logging out\r\na001 OK Logout completed.\r\n"
    return b"a001 NO Unknown command.\r\n"


def handle_ssh(_data: bytes) -> bytes:
    """SSH banner, sent on connect."""
    return b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19\r\n"


HANDLERS: dict[str, Handler] = {
    "redis": handle_redis,
    "memcached": handle_memcached,
    "etcd": handle_etcd,
    "ci-runner": handle_ci_runner,
    "mysql": handle_mysql,
    "postgres": handle_postgres,
    "mqtt": handle_mqtt,
    "amqp": handle_amqp,
    "smtp": handle_smtp,
    "pop3": handle_pop3,
    "imap": handle_imap,
    "ssh": handle_ssh,
}


# ============================================================
# Signature library
# ============================================================

SIGNATURES: dict[str, dict] = {

    # Full SSH handshake (requires asyncssh). Runs a real KEX and
    # rejects all auth — no shell, no exec, no access.
    "ssh-full-handshake": {
        "ssh_full": True,
        "ssh_version": "OpenSSH_9.6p1 Ubuntu-3ubuntu13.19",
    },
    "ssh-full-handshake-debian": {
        "ssh_full": True,
        "ssh_version": "OpenSSH_9.2p1 Debian-2+deb12u2",
    },
    
    # --------------------------------------------------------
    # Web servers
    # --------------------------------------------------------
    "nginx-welcome": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/html",
            "Server": "nginx",
        },
        "body": (
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            "<title>Welcome to nginx!</title>\n"
            "</head>\n"
            "<body>\n"
            "<h1>Welcome to nginx!</h1>\n"
            "<p>If you see this page, the nginx web server "
            "is successfully installed and working.</p>\n"
            "</body>\n"
            "</html>\n"
        ),
    },
    "nginx-404": {
        "status": "404 Not Found",
        "headers": {
            "Content-Type": "text/html",
            "Server": "nginx",
        },
        "body": (
            "<html>\r\n"
            "<head><title>404 Not Found</title></head>\r\n"
            "<body>\r\n"
            "<center><h1>404 Not Found</h1></center>\r\n"
            "<hr><center>nginx</center>\r\n"
            "</body>\r\n"
            "</html>\r\n"
        ),
    },
    "apache-default": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/html; charset=UTF-8",
            "Server": "Apache/2.4.58 (Ubuntu)",
        },
        "body": (
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            "<title>Apache2 Ubuntu Default Page: It works</title>\n"
            "</head>\n"
            "<body>\n"
            "<h1>Apache2 Ubuntu Default Page</h1>\n"
            "<p>It works!</p>\n"
            "</body>\n"
            "</html>\n"
        ),
    },
    "apache-403": {
        "status": "403 Forbidden",
        "headers": {
            "Content-Type": "text/html; charset=iso-8859-1",
            "Server": "Apache/2.4.58 (Ubuntu)",
        },
        "body": (
            "<!DOCTYPE HTML PUBLIC "
            "\"-//IETF//DTD HTML 2.0//EN\">\n"
            "<html><head>\n"
            "<title>403 Forbidden</title>\n"
            "</head><body>\n"
            "<h1>Forbidden</h1>\n"
            "<p>You don't have permission to access this "
            "resource.</p>\n"
            "</body></html>\n"
        ),
    },
    "iis-default": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/html",
            "Server": "Microsoft-IIS/10.0",
            "X-Powered-By": "ASP.NET",
        },
        "body": (
            "<html>\n"
            "<head><title>IIS Windows Server</title></head>\n"
            "<body><h1>IIS Windows Server</h1></body>\n"
            "</html>\n"
        ),
    },
    "caddy": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/html; charset=utf-8",
            "Server": "Caddy",
        },
        "body": (
            "<!DOCTYPE html>\n"
            "<html><body><h1>Caddy</h1></body></html>\n"
        ),
    },
    "tomcat": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/html;charset=UTF-8",
            "Server": "Apache-Coyote/1.1",
        },
        "body": (
            "<!DOCTYPE html>\n"
            "<html><head><title>Apache Tomcat</title></head>\n"
            "<body><h1>It works!</h1></body></html>\n"
        ),
    },

    # --------------------------------------------------------
    # CI/CD and container orchestration
    # --------------------------------------------------------
    "k8s-api": {
        "tls": True,
        "status": "401 Unauthorized",
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-cache, private",
            "X-Content-Type-Options": "nosniff",
        },
        "body": (
            '{"kind":"Status","apiVersion":"v1","metadata":{},'
            '"status":"Failure","message":"Unauthorized",'
            '"reason":"Unauthorized","code":401}'
        ),
    },
    "k8s-kubelet": {
        "status": "403 Forbidden",
        "headers": {"Content-Type": "text/plain; charset=utf-8"},
        "body": "Forbidden",
    },
    "k8s-dashboard": {
        "status": "200 OK",
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": (
            "<html><head><title>Kubernetes Dashboard</title>"
            "</head><body>Kubernetes Dashboard</body></html>"
        ),
    },
    "docker-registry": {
        "tls": True,
        "status": "401 Unauthorized",
        "headers": {
            "Content-Type": "application/json",
            "Docker-Distribution-Api-Version": "registry/2.0",
        },
        "body": (
            '{"errors":[{"code":"UNAUTHORIZED",'
            '"message":"authentication required",'
            '"detail":null}]}'
        ),
    },
    "docker-daemon": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "application/json",
            "Api-Version": "1.43",
        },
        "body": '{"message":"page not found"}',
    },
    "etcd": {"handler": "etcd"},
    "ci-runner": {"handler": "ci-runner"},
    "jenkins": {
        "status": "403 Forbidden",
        "headers": {
            "Content-Type": "text/html;charset=utf-8",
            "X-Jenkins": "2.426.1",
            "X-Hudson": "1.395",
        },
        "body": (
            "<html><head><title>Jenkins</title></head>"
            "<body>Authentication required</body></html>"
        ),
    },
    "gitlab": {
        "status": "302 Found",
        "headers": {
            "Location": "/users/sign_in",
            "Content-Type": "text/html; charset=utf-8",
        },
        "body": (
            "<html><body>You are being "
            "<a href=\"/users/sign_in\">redirected</a>.</body></html>"
        ),
    },
    "gitlab-runner": {
        "status": "200 OK",
        "headers": {"Content-Type": "application/json"},
        "body": '{"status":"ok"}',
    },
    "drone-ci": {
        "status": "200 OK",
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": (
            "<html><head><title>Drone CI</title></head>"
            "<body>Drone</body></html>"
        ),
    },
    "concourse": {
        "status": "200 OK",
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": (
            "<html><head><title>Concourse</title></head>"
            "<body>Concourse CI</body></html>"
        ),
    },
    "teamcity": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/html; charset=UTF-8",
            "Server": "TeamCity",
        },
        "body": (
            "<html><head><title>TeamCity</title></head>"
            "<body>TeamCity</body></html>"
        ),
    },

    # --------------------------------------------------------
    # Monitoring and observability
    # --------------------------------------------------------
    "prometheus": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/html; charset=utf-8",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "deny",
        },
        "body": (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "<title>Prometheus Time Series Collection and "
            "Processing Server</title>\n"
            "</head>\n"
            "<body>\n"
            "<h1>Prometheus</h1>\n"
            "<p>Version 2.45.0 (branch: HEAD, "
            "revision: abc1234)</p>\n"
            "</body>\n"
            "</html>\n"
        ),
    },
    "alertmanager": {
        "status": "200 OK",
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": (
            "<!DOCTYPE html>\n"
            "<html><head><title>Alertmanager</title></head>\n"
            "<body><h1>Alertmanager</h1></body></html>\n"
        ),
    },
    "grafana": {
        "status": "302 Found",
        "headers": {
            "Location": "/login",
            "Content-Type": "text/html; charset=utf-8",
            "X-Content-Type-Options": "nosniff",
        },
        "body": "<a href=\"/login\">Found</a>.\n",
    },
    "kibana": {
        "status": "302 Found",
        "headers": {
            "Location": "/app/login",
            "Content-Type": "text/html; charset=utf-8",
            "kbn-name": "kibana",
            "kbn-version": "8.11.0",
        },
        "body": "<a href=\"/app/login\">Found</a>.\n",
    },
    "elasticsearch": {
        "status": "200 OK",
        "headers": {"Content-Type": "application/json; charset=UTF-8"},
        "body": (
            '{"name":"node-1","cluster_name":"elasticsearch",'
            '"version":{"number":"8.11.0","build_flavor":"default"},'
            '"tagline":"You Know, for Search"}'
        ),
    },
    "zabbix": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/html; charset=UTF-8",
            "Server": "nginx",
        },
        "body": (
            "<html><head><title>Zabbix</title></head>"
            "<body>Zabbix</body></html>"
        ),
    },
    "netdata": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/html; charset=utf-8",
            "Server": "netdata",
        },
        "body": (
            "<html><head><title>netdata dashboard</title></head>"
            "<body>Netdata</body></html>"
        ),
    },
    "victoriametrics": {
        "status": "200 OK",
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": (
            "<html><head><title>VictoriaMetrics</title></head>"
            "<body>VictoriaMetrics</body></html>"
        ),
    },
    "loki": {
        "status": "200 OK",
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": (
            "<html><head><title>Loki</title></head>"
            "<body>Loki</body></html>"
        ),
    },
    "jaeger": {
        "status": "200 OK",
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": (
            "<html><head><title>Jaeger</title></head>"
            "<body>Jaeger</body></html>"
        ),
    },

    # --------------------------------------------------------
    # DevOps tooling
    # --------------------------------------------------------
    "portainer": {
        "status": "200 OK",
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": (
            "<html><head><title>Portainer</title></head>"
            "<body>Portainer</body></html>"
        ),
    },
    "rancher": {
        "status": "302 Found",
        "headers": {
            "Location": "/login",
            "Content-Type": "text/html; charset=utf-8",
        },
        "body": "<a href=\"/login\">Found</a>.\n",
    },
    "consul": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/html; charset=utf-8",
            "X-Consul-Index": "42",
        },
        "body": (
            "<html><head><title>Consul by HashiCorp</title></head>"
            "<body>Consul</body></html>"
        ),
    },
    "vault": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/html; charset=utf-8",
            "X-Vault-Index": "42",
        },
        "body": (
            "<html><head><title>Vault by HashiCorp</title></head>"
            "<body>Vault</body></html>"
        ),
    },
    "nomad": {
        "status": "200 OK",
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": (
            "<html><head><title>Nomad by HashiCorp</title></head>"
            "<body>Nomad</body></html>"
        ),
    },
    "minio": {
        "status": "403 Forbidden",
        "headers": {
            "Content-Type": "application/xml",
            "Server": "MinIO",
        },
        "body": (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<Error><Code>AccessDenied</Code>"
            "<Message>Access Denied.</Message></Error>"
        ),
    },
    "ceph-rgw": {
        "status": "403 Forbidden",
        "headers": {
            "Content-Type": "application/xml",
            "Server": "Ceph Object Gateway",
        },
        "body": (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<Error><Code>AccessDenied</Code>"
            "<Message>Access Denied</Message></Error>"
        ),
    },

    # --------------------------------------------------------
    # Message brokers
    # --------------------------------------------------------
    "rabbitmq-mgmt": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/html; charset=utf-8",
            "Server": "Cowboy",
        },
        "body": (
            "<html><head><title>RabbitMQ Management</title></head>"
            "<body>RabbitMQ</body></html>"
        ),
    },
    "rabbitmq-amqp": {"handler": "amqp"},
    "nats": {
        "raw": True,
        "body": (
            "INFO {\"server_id\":\"ND123\",\"version\":\"2.10.0\","
            "\"go\":\"go1.21\",\"host\":\"0.0.0.0\",\"port\":4222,"
            "\"max_payload\":1048576}\r\n"
        ),
    },
    "mosquitto": {"handler": "mqtt"},
    "beanstalkd": {
        "raw": True,
        "body": "OK 42\r\n",
    },

    # --------------------------------------------------------
    # Data stores
    # --------------------------------------------------------
    "redis": {"handler": "redis"},
    "memcached": {"handler": "memcached"},
    "mysql": {"handler": "mysql"},
    "mariadb": {"handler": "mysql"},
    "postgres": {"handler": "postgres"},
    "clickhouse": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "text/plain; charset=UTF-8",
            "X-ClickHouse-Server-Display-Name": "clickhouse",
        },
        "body": "Ok.\n",
    },
    "couchdb": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "application/json",
            "Server": "CouchDB/3.3.2 (Erlang OTP/24)",
        },
        "body": (
            '{"couchdb":"Welcome","version":"3.3.2",'
            '"vendor":{"name":"The Apache Software Foundation"}}'
        ),
    },
    "influxdb": {
        "status": "404 Not Found",
        "headers": {
            "Content-Type": "application/json",
            "X-Influxdb-Version": "2.7.5",
        },
        "body": '{"code":"not found","message":"not found"}',
    },
    "neo4j": {
        "status": "200 OK",
        "headers": {
            "Content-Type": "application/json; charset=UTF-8",
            "Server": "Neo4j",
        },
        "body": (
            '{"neo4j_version":"5.14.0",'
            '"neo4j_edition":"community"}'
        ),
    },
    "solr": {
        "status": "200 OK",
        "headers": {"Content-Type": "text/html;charset=UTF-8"},
        "body": (
            "<html><head><title>Solr Admin</title></head>"
            "<body>Solr</body></html>"
        ),
    },
    "meilisearch": {
        "status": "200 OK",
        "headers": {"Content-Type": "application/json"},
        "body": '{"message":"Meilisearch is running"}',
    },

    # --------------------------------------------------------
    # Mail servers
    # --------------------------------------------------------
    "smtp-postfix": {"handler": "smtp"},
    "smtp-exim": {
        "raw": True,
        "body": "220 mail.example.com ESMTP Exim 4.96 Ubuntu\r\n",
    },
    "smtps": {
        "tls": True,
        "handler": "smtp",
    },
    "pop3-dovecot": {"handler": "pop3"},
    "imap-dovecot": {"handler": "imap"},

    # --------------------------------------------------------
    # Directory, network services
    # --------------------------------------------------------
    "ldap-openldap": {
        "raw": True,
        "body": b"0\x0c\x02\x01\x01a\x07\x0a\x01\x00\x04\x00\x04\x00",
    },
    "snmp-net-snmp": {
        "raw": True,
        "body": b"\x30\x0d\x02\x01\x01\x04\x06public\xa0\x00",
    },
    "ntp": {
        "raw": True,
        "body": b"\x1c\x01\x00\xe9\x00\x00\x00\x00\x00\x00\x00\x00",
    },
    "rsync": {
        "raw": True,
        "body": "@RSYNCD: 31.0\n",
    },

    # --------------------------------------------------------
    # SSH banners
    # --------------------------------------------------------
    "ssh-openssh-9-ubuntu": {
        "raw": True,
        "body": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19\r\n",
    },
    "ssh-openssh-9-debian": {
        "raw": True,
        "body": "SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n",
    },
    "ssh-openssh-8-ubuntu": {
        "raw": True,
        "body": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    },
    "ssh-openssh-7-ubuntu": {
        "raw": True,
        "body": "SSH-2.0-OpenSSH_7.4\r\n",
    },
    "ssh-dropbear": {
        "raw": True,
        "body": "SSH-2.0-dropbear_2022.83\r\n",
    },

    # --------------------------------------------------------
    # Legacy banners
    # --------------------------------------------------------
    "ftp-vsftpd": {
        "raw": True,
        "body": "220 (vsFTPd 3.0.5)\r\n",
    },
    "ftp-proftpd": {
        "raw": True,
        "body": (
            "220 ProFTPD 1.3.8 Server (Debian) "
            "[::ffff:127.0.0.1]\r\n"
        ),
    },
    "telnet-linux": {
        "raw": True,
        "body": "Ubuntu 24.04 LTS\r\nlogin: ",
    },
    "irc-unrealircd": {
        "raw": True,
        "body": (
            ":irc.example.com NOTICE AUTH :*** "
            "Looking up your hostname...\r\n"
        ),
    },
    "vnc-rfb": {
        "raw": True,
        "body": "RFB 003.008\n",
    },
    "socks5": {
        "raw": True,
        "body": b"\x05\x00",
    },
}