#!/usr/bin/env python3
"""Signature library: service definitions and port mappings."""

from __future__ import annotations


# Well-known ports for each service.
KNOWN_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2375: "docker-daemon",
    2379: "etcd",
    3000: "grafana",
    3306: "mysql",
    4222: "nats",
    5000: "docker-registry",
    5432: "postgres",
    5601: "kibana",
    5672: "rabbitmq-amqp",
    6379: "redis",
    6443: "k8s-api",
    8080: "http-alt",
    9000: "portainer",
    9090: "prometheus",
    9092: "kafka",
    9093: "alertmanager",
    9200: "elasticsearch",
    10250: "kubelet",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
}

# Ports where TLS is required by protocol convention.
TLS_ONLY_PORTS: set[int] = {465, 636, 993, 995, 8443}


SIGNATURES: dict[str, dict] = {
    # --------------------------------------------------------
    # Web servers
    # --------------------------------------------------------
    "nginx-welcome": {
        "status": "200 OK",
        "headers": {"Content-Type": "text/html", "Server": "nginx"},
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
        "headers": {"Content-Type": "text/html", "Server": "nginx"},
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
    "beanstalkd": {"raw": True, "body": "OK 42\r\n"},

    # --------------------------------------------------------
    # Data stores
    # --------------------------------------------------------
    "redis": {"handler": "redis"},
    "memcached": {"handler": "memcached"},
    "mysql": {"handler": "mysql"},
    "mariadb": {"handler": "mysql"},
    "postgres": {"handler": "postgres"},
    "mongodb": {"handler": "mongodb"},
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
    "smtps": {"tls": True, "handler": "smtp"},
    "pop3-dovecot": {"handler": "pop3"},
    "imap-dovecot": {"handler": "imap"},
    "pop3s-dovecot": {"tls": True, "handler": "pop3"},
    "imaps-dovecot": {"tls": True, "handler": "imap"},

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
    "rsync": {"raw": True, "body": "@RSYNCD: 31.0\n"},

    # --------------------------------------------------------
    # SSH banners (raw, no handshake)
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
    # SSH full handshake (asyncssh)
    # --------------------------------------------------------
    "ssh-full-handshake": {
        "ssh_full": True,
        "ssh_version": "OpenSSH_9.6p1 Ubuntu-3ubuntu13.19",
    },
    "ssh-full-handshake-debian": {
        "ssh_full": True,
        "ssh_version": "OpenSSH_9.2p1 Debian-2+deb12u2",
    },

    # --------------------------------------------------------
    # Legacy banners
    # --------------------------------------------------------
    "ftp-vsftpd": {"raw": True, "body": "220 (vsFTPd 3.0.5)\r\n"},
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
    "vnc-rfb": {"raw": True, "body": "RFB 003.008\n"},
    "socks5": {"raw": True, "body": b"\x05\x00"},
}