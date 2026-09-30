#!/bin/sh
set -eu

cert_dir=/etc/nginx/certs
cert_file="$cert_dir/server.crt"
key_file="$cert_dir/server.key"
tls_host="${JOCKY_TLS_HOST:-localhost}"

if [ -s "$cert_file" ] && [ -s "$key_file" ]; then
    exit 0
fi

case "$tls_host" in
    localhost)
        subject_alt_names="DNS:localhost,IP:127.0.0.1"
        ;;
    *[!0-9.]* )
        case "$tls_host" in
            *[!A-Za-z0-9.-]*|"")
                echo "JOCKY_TLS_HOST must be a DNS name or IPv4 address" >&2
                exit 1
                ;;
        esac
        subject_alt_names="DNS:localhost,IP:127.0.0.1,DNS:$tls_host"
        ;;
    *.*)
        subject_alt_names="DNS:localhost,IP:127.0.0.1,IP:$tls_host"
        ;;
    *)
        echo "JOCKY_TLS_HOST must be a DNS name or IPv4 address" >&2
        exit 1
        ;;
esac

mkdir -p "$cert_dir"
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 365 \
    -keyout "$key_file" \
    -out "$cert_file" \
    -subj "/CN=$tls_host" \
    -addext "subjectAltName=$subject_alt_names"
chmod 600 "$key_file"