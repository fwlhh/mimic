# Mimic

A lightweight, dependency-free port spoofer. Makes your server look
like something it isn't: a CI/CD platform, a web host, a mail server,
a database cluster, a container host, and more.

## Features

- **Zero dependencies** — Python 3.9+ standard library only.
- **Presets** — ready-to-use configs for common scenarios.
- **60+ signatures** — nginx, Prometheus, Grafana, k8s API, Redis,
  Memcached, MySQL, PostgreSQL, Kafka, SMTP, IMAP, SSH banners, and more.
- **Config file** — pick which ports to emulate, override any field.
- **TLS support** — per-service TLS via any cert/key pair.
- **Multi-domain certificates** — one subdirectory per domain.
- **DoS-resistant** — per-IP connection limit, sane read timeouts.
- **Systemd hardened** — runs as `nobody`, `ProtectSystem=strict`.
- **Automatic TLS renewal** — Certbot deploy hook keeps certificates fresh.

## Quick start

```bash
git clone https://github.com/fwlhh/mimic.git
cd mimic
sudo ./scripts/install.sh

# Edit the config
sudo nano /etc/mimic/config.json

# Start the service
sudo systemctl enable --now mimic
sudo journalctl -u mimic -f
```

That's it. `install.sh` copies binaries, sets up systemd, copies
existing TLS certificates (if any), and installs the Certbot
renewal hook.

## CLI

```text
mimic run --config /etc/mimic/config.json
mimic list-presets
mimic list-signatures
mimic show-signature nginx-welcome
mimic gen-config --preset ci-cd --output /etc/mimic/config.json
```

## Config format

```json
{
  "settings": {
    "log_level": "INFO",
    "max_connections_per_ip": 20,
    "read_timeout": 0.3,
    "handler_read_timeout": 1.0
  },
  "tls": {
    "cert_file": "/opt/mimic/certs/domain/fullchain.pem",
    "key_file": "/opt/mimic/certs/domain/privkey.pem"
  },
  "services": [
    { "port": 2379, "service": "etcd" },
    { "port": 6443, "service": "k8s-api" },
    { "port": 9090, "service": "prometheus" }
  ]
}
```

Each service entry can be one of three forms.

**1. Reference to a built-in signature:**

```json
{ "port": 2379, "service": "etcd" }
```

**2. Reference with overrides:**

```json
{ "port": 2379, "service": "etcd", "body": "custom" }
```

**3. Fully custom spec:**

```json
{
  "port": 9999,
  "status": "200 OK",
  "headers": { "Content-Type": "text/plain" },
  "body": "hello"
}
```

## Presets

- `ci-cd` — k8s + monitoring + registry
- `web-host` — nginx + MySQL + Redis + Jenkins
- `mail-server` — SMTP + IMAP + POP3
- `database-cluster` — PostgreSQL + Redis + Memcached
- `monitoring` — Grafana + Prometheus + Kibana + Elasticsearch
- `dev-server` — mixed developer environment
- `windows-server` — IIS + RDP + WinRM ports
- `container-host` — Docker daemon + k8s + registry + Portainer
- `message-broker` — RabbitMQ + Kafka + NATS + Redis
- `empty` — starting template

Generate a config from a preset:

```bash
sudo mimic gen-config --preset ci-cd --output /etc/mimic/config.json
```

## TLS certificates

Mimic runs as an unprivileged user (`nobody`) and cannot read
`/etc/letsencrypt/` directly — those files are restricted to `root`
by design. Instead, certificates are copied to `/opt/mimic/certs/`,
one subdirectory per domain:

```text
/opt/mimic/certs/
├── domain1/
│   ├── fullchain.pem
│   └── privkey.pem
└── domain2/
    ├── fullchain.pem
    └── privkey.pem
```
## SSH full handshake

Regular SSH signatures (`ssh-openssh-9-ubuntu` and friends) send only
a banner and close the connection. Port scanners like `nmap` see an
SSH server, but deeper fingerprinting tools — Censys, Shodan, custom
HASSH collectors — see that the host key exchange never happens and
flag the host as a honeypot.

For port 22 use the `ssh-full-handshake` signature instead. It runs a
real SSH server (via `asyncssh`) that:

- Sends a plausible SSH banner.
- Performs a full KEX (curve25519-sha256, etc.).
- Presents a real host key (ed25519 + rsa).
- Responds to auth attempts — and rejects **every** one of them.
- Never opens a shell, never executes a command.

To a scanner, it looks exactly like a hardened production SSH server
with password auth disabled. To anyone trying to log in, it looks
like they typed the wrong password.

### Requirements

- `asyncssh` **>= 2.15** (older versions lack post-quantum KEX and
  will not start if `sntrup761x25519-sha512@openssh.com` is in the
  algorithm list).
- Host keys in `/opt/mimic/`:
  - `ssh_host_ed25519_key`
  - `ssh_host_rsa_key`

`install.sh` handles both: it upgrades `asyncssh` via pip if the
system package is older than 2.15, and generates both host keys if
they are missing.

If you install Mimic manually, upgrade asyncssh yourself:

```bash
sudo apt install python3-pip
sudo pip3 install --upgrade --break-system-packages 'asyncssh>=2.15'
```

### Verify

```bash
# Should print the banner, then prompt for a password
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 22 root@your-server

# Should show both host keys
ssh-keyscan -p 22 your-server
```

Any password returns `Permission denied`. No shell is ever opened.

### Key rotation

Do **not** regenerate host keys unless you want to look like a
different server. Censys tracks host key fingerprints — a new key
means a new host in their index.

### Raw banner signatures

The `ssh-openssh-*` signatures (raw banner only) are still useful for
non-standard ports — for example, a fake SSH on port 2222 that
nobody scans deeply. They do **not** survive HASSH fingerprinting.

### Automatic setup

`scripts/install.sh` handles this for you:

1. Copies **every** domain found in `/etc/letsencrypt/live/*/` into
   its own subdirectory under `/opt/mimic/certs/`.
2. Fixes ownership and permissions (`root:nogroup`, `644` for the
   chain, `640` for the key).
3. Installs a Certbot deploy hook at
   `/etc/letsencrypt/renewal-hooks/deploy/mimic-copy-certs.sh`,
   so every renewal refreshes the affected domain and reloads Mimic.

Point `config.json` at the domain you want Mimic to serve:

```json
"tls": {
  "cert_file": "/opt/mimic/certs/domain/fullchain.pem",
  "key_file": "/opt/mimic/certs/domain/privkey.pem"
}
```

### Multiple domains

Each domain lives in its own subdirectory, so you can serve different
certificates on different ports — for example, the k8s API with the
`domain` certificate and the registry with the `beta` certificate.

The deploy hook copies only the domain that was just renewed
(Certbot sets `RENEWED_LINEAGE`), so renewing one domain doesn't
touch the others.

### Verify

```bash
# List copied domains
sudo ls -la /opt/mimic/certs/

# Check nobody can read one domain's certs
sudo -u nobody head -1 /opt/mimic/certs/domain/fullchain.pem
sudo -u nobody head -1 /opt/mimic/certs/domain/privkey.pem

# Dry-run the hook (doesn't touch live certs)
sudo certbot renew --dry-run

# Full sync of all domains (manual re-copy)
sudo /etc/letsencrypt/renewal-hooks/deploy/mimic-copy-certs.sh
```

### Manual setup

```bash
# 1. Create the cert directory
sudo mkdir -p /opt/mimic/certs

# 2. Copy each domain (adjust names)
for domain in domain1 domain2; do
    sudo mkdir -p "/opt/mimic/certs/$domain"
    sudo cp "/etc/letsencrypt/live/$domain/fullchain.pem" \
            "/opt/mimic/certs/$domain/"
    sudo cp "/etc/letsencrypt/live/$domain/privkey.pem" \
            "/opt/mimic/certs/$domain/"
done

# 3. Set permissions
sudo chown -R root:nogroup /opt/mimic/certs
sudo find /opt/mimic/certs -type d -exec chmod 750 {} \;
sudo find /opt/mimic/certs -name fullchain.pem \
     -exec chmod 644 {} \;
sudo find /opt/mimic/certs -name privkey.pem \
     -exec chmod 640 {} \;

# 4. Install the Certbot deploy hook
sudo cp scripts/mimic-copy-certs.sh \
        /etc/letsencrypt/renewal-hooks/deploy/mimic-copy-certs.sh
sudo chmod 755 /etc/letsencrypt/renewal-hooks/deploy/mimic-copy-certs.sh

# 5. Update config.json and restart
sudo systemctl restart mimic
```

### Custom cert path

Override the default cert directory at install time:

```bash
CERT_DIR=/var/lib/mimic/certs ./scripts/install.sh
```

Then update `tls.cert_file` and `tls.key_file` in `config.json`
to match.

### Why not `chmod /etc/letsencrypt/`?

Opening permissions on `/etc/letsencrypt/` would expose the private
key to every user on the system. It also doesn't survive renewal —
Certbot resets permissions on every renewal, so the problem would
return every 60–90 days. Copying to a dedicated directory is the
safe, persistent solution.

## Available signatures

Run `mimic list-signatures` for the full list.

**Web servers:** nginx, apache, iis, caddy, tomcat.

**CI/CD:** k8s-api, k8s-kubelet, k8s-dashboard, docker-registry,
docker-daemon, etcd, ci-runner, jenkins, gitlab, gitlab-runner,
drone-ci, concourse, teamcity.

**Monitoring:** prometheus, alertmanager, grafana, kibana,
elasticsearch, zabbix, netdata, victoriametrics, loki, jaeger.

**DevOps:** portainer, rancher, consul, vault, nomad, minio, ceph-rgw.

**Message brokers:** rabbitmq-mgmt, rabbitmq-amqp, nats, mosquitto,
beanstalkd.

**Data stores:** redis, memcached, mysql, mariadb, postgres,
clickhouse, couchdb, influxdb, neo4j, solr, meilisearch.

**Mail:** smtp-postfix, smtp-exim, smtps, pop3-dovecot, imap-dovecot.

**Network:** ldap-openldap, snmp-net-snmp, ntp, rsync.

**SSH banners:** openssh-9-ubuntu, openssh-9-debian, openssh-8-ubuntu,
openssh-7-ubuntu, dropbear.

**Legacy:** ftp-vsftpd, ftp-proftpd, telnet-linux, irc-unrealircd,
vnc-rfb, socks5.

## Firewall

Open the ports you configured. Example for `ufw`:

```bash
for p in 2379 3000 5000 6379 6443 8080 9090 10250 11211; do
    sudo ufw allow "$p/tcp"
done
```

## Security notes

- Runs as an unprivileged user by default (`nobody`).
- Per-IP connection limit prevents simple DoS.
- No filesystem access beyond the config directory.
- Responses are static — no shell, no `eval`, no dynamic code.
- TLS private keys are readable only by the service group.

## Project layout

```text
mimic/
├── mimic.py              entrypoint and CLI
├── signatures/           protocol handlers and service library
│   ├── __init__.py       public API (HANDLERS, SIGNATURES, ...)
│   ├── _common.py        shared HTTP helpers
│   ├── redis.py          RESP protocol
│   ├── postgres.py       PostgreSQL wire protocol
│   ├── mongodb.py        BSON + isMaster
│   ├── mysql.py          greeting packet
│   ├── memcached.py      text protocol
│   ├── smtp.py           SMTP dialogue
│   ├── pop3.py           POP3 dialogue
│   ├── imap.py           IMAP dialogue
│   ├── http_handlers.py  etcd, CI runner
│   ├── mqtt.py           MQTT, AMQP, SSH banner
│   ├── ssh.py            full SSH handshake (asyncssh)
│   └── library.py        SIGNATURES, KNOWN_PORTS, TLS_ONLY_PORTS
├── presets/              ready-made configs
├── systemd/              systemd unit
└── scripts/              install, uninstall, certbot hook
```

## Adding a new signature

**Simple HTTP or raw banner** — add an entry to the `SIGNATURES`
dict in `signatures/library.py`:

```python
"my-service": {
    "status": "200 OK",
    "headers": {"Content-Type": "text/plain"},
    "body": "hello\n",
},
```

**Stateful protocol** — create a new module in `signatures/`, for
example `signatures/myproto.py`:

```python
def handle_myproto(data: bytes) -> bytes:
    ...
```

Then register it in `signatures/__init__.py`:

```python
from .myproto import handle_myproto

HANDLERS = {
    ...
    "myproto": handle_myproto,
}
```

And reference it from `signatures/library.py`:

```python
"my-service": {"handler": "myproto"},
```

**Shared HTTP helpers** live in `signatures/_common.py`:
`build_http_response`, `build_raw_response`, `is_http`,
`is_proxy_like`, `http_400`.

## Development

```bash
# Install dev dependencies
pip install ruff pytest pytest-asyncio

# Lint
ruff check .

# Format
ruff format .

# Tests
pytest -v
```

## Credits

Mimic was inspired by the following projects:

- [Portspoof](https://github.com/drk1wi/portspoof) by Piotr Duszynski —
  a C++ service emulator that keeps all 65535 TCP ports open and
  generates fake banners to slow down reconnaissance. Mimic borrows
  the core idea of making scanning expensive and unreliable.

- [symfony-fake-server-bundle](https://github.com/tourze/symfony-fake-server-bundle)
  by Tourze — a Symfony bundle that injects fake `Server` headers into
  HTTP responses to deceive scanners. Mimic's HTTP signature approach
  was partly inspired by this bundle.

## License

GNU General Public License v3.0 or later — see [LICENSE](LICENSE).