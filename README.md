# Mimic

A lightweight, dependency-free port spoofer. Makes your server look
like something it isn't: a CI/CD platform, a web host, a mail server,
a database cluster, a container host, and more.

## Features

- **Zero dependencies** — Python 3.9+ standard library only.
- **Presets** — ready-to-use configs for common scenarios.
- **60+ signatures** — nginx, Prometheus, Grafana, k8s API, Redis,
  Memcached, MySQL, PostgreSQL, MongoDB, RabbitMQ, Kafka, SMTP, IMAP,
  SSH banners, and more.
- **Config file** — pick which ports to emulate, override any field.
- **TLS support** — per-service TLS via any cert/key pair.
- **DoS-resistant** — per-IP connection limit, sane read timeouts.
- **Systemd hardened** — runs as `nobody`, `ProtectSystem=strict`.

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

## Quick start

```bash
git clone https://github.com/yourname/mimic.git
cd mimic
sudo ./scripts/install.sh

# Edit the config
sudo nano /etc/mimic/config.json

# Start the service
sudo systemctl enable --now mimic
sudo journalctl -u mimic -f
```

## CLI

```
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
    "cert_file": "/path/to/fullchain.pem",
    "key_file": "/path/to/privkey.pem"
  },
  "services": [
    { "port": 2379, "service": "etcd" },
    { "port": 6443, "service": "k8s-api" },
    { "port": 9090, "service": "prometheus" }
  ]
}
```

Each service entry can be:

1. A reference to a built-in signature: `{ "port": 2379, "service": "etcd" }`.
2. A reference with overrides: `{ "port": 2379, "service": "etcd", "body": "custom" }`.
3. A fully custom spec:
   ```json
   {
     "port": 9999,
     "status": "200 OK",
     "headers": { "Content-Type": "text/plain" },
     "body": "hello"
   }
   ```

## Presets

- `ci-cd` — k8s + monitoring + registry (Alpha Sandbox style)
- `web-host` — nginx + MySQL + Redis + Jenkins
- `mail-server` — SMTP + IMAP + POP3
- `database-cluster` — PostgreSQL + Redis + Memcached + MongoDB
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

## Available signatures

Run `mimic list-signatures` for the full list.

## TLS

Set `"tls": true` on a service and point `tls.cert_file` /
`tls.key_file` to a valid pair. The cert is loaded once at startup.

Auto-reload on renewal:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-mimic.sh > /dev/null <<'EOF'
#!/bin/bash
systemctl reload mimic || true
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-mimic.sh
```

## Firewall

Open the ports you configured. Example for ufw:

```bash
for p in 2379 3000 5000 6379 6443 8080 9090 10250 11211; do
    sudo ufw allow $p/tcp
done
```

## Security notes

- Runs as an unprivileged user by default (`nobody`).
- Per-IP connection limit prevents simple DoS.
- No filesystem access beyond the config directory.
- Responses are static — no shell, no eval, no dynamic code.

## Adding a new signature

Edit `signatures.py`, add an entry to `SIGNATURES`:

```python
"my-service": {
    "status": "200 OK",
    "headers": {"Content-Type": "text/plain"},
    "body": "hello\n",
}
```

For state-aware protocols, add a handler to `HANDLERS` and reference it
with `{ "handler": "my-service" }`.

## License

GNU General Public License v3.0 or later — see [LICENSE](LICENSE).