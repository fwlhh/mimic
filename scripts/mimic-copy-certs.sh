#!/usr/bin/env bash
# Copy Let's Encrypt certificates to Mimic's cert directory.
# Runs after every successful Certbot renewal.
#
# Copies each domain from /etc/letsencrypt/live/<domain>/ into
# /opt/mimic/certs/<domain>/, preserving one subdirectory per domain.
#
# Installed to: /etc/letsencrypt/renewal-hooks/deploy/mimic-copy-certs.sh

set -euo pipefail

SRC_ROOT="/etc/letsencrypt/live"
DST_ROOT="/opt/mimic/certs"

mkdir -p "$DST_ROOT"

# Certbot sets RENEWED_LINEAGE to the domain that was just renewed.
# We copy that one; for full sync (first install / manual run),
# fall back to copying everything.
if [[ -n "${RENEWED_LINEAGE:-}" && -d "$RENEWED_LINEAGE" ]]; then
    domains=("$RENEWED_LINEAGE")
else
    domains=("$SRC_ROOT"/*/)
fi

copied=0
for lineage in "${domains[@]}"; do
    domain="$(basename "$lineage")"
    src_chain="$lineage/fullchain.pem"
    src_key="$lineage/privkey.pem"

    if [[ ! -f "$src_chain" || ! -f "$src_key" ]]; then
        echo "mimic-copy-certs: skipping $domain (no certs)" >&2
        continue
    fi

    dst_dir="$DST_ROOT/$domain"
    mkdir -p "$dst_dir"

    cp "$src_chain" "$dst_dir/fullchain.pem"
    cp "$src_key"   "$dst_dir/privkey.pem"

    chown root:nogroup "$dst_dir/fullchain.pem" "$dst_dir/privkey.pem"
    chmod 644 "$dst_dir/fullchain.pem"
    chmod 640 "$dst_dir/privkey.pem"

    echo "mimic-copy-certs: updated $domain"
    copied=$((copied + 1))
done

if [[ $copied -eq 0 ]]; then
    echo "mimic-copy-certs: no certificates found" >&2
    exit 1
fi

systemctl reload mimic 2>/dev/null \
    || systemctl restart mimic 2>/dev/null \
    || true

echo "mimic-copy-certs: done ($copied domain(s))"