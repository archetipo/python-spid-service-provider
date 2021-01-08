#!/bin/bash
set -eu

KEY_FILE=sp.key
CRT_FILE=sp.crt

CONFIG_YAML=config.yaml


if [ ! -e $KEY_FILE ] && [ ! -e $CRT_FILE ]; then
    echo "Generating $KEY_FILE and $CRT_FILE..."
    openssl req -x509 \
                -nodes \
                -sha256 \
                -subj '/C=IT' \
                -newkey rsa:2048 \
                -keyout $KEY_FILE \
                -out $CRT_FILE
fi

echo "Using default $CONFIG_YAML..."
cp config.yaml.example $CONFIG_YAML

#echo "0.0.0.0 spid-sp-test" >> /etc/hosts

exec "$@"
