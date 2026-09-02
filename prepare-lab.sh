#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "prepare-lab.sh must run as root inside a disposable VM" >&2
	exit 1
fi

printf '%s\n' 'ESP-ORIGINAL-PAGE-CACHE-FIXTURE' > /dirtyfrag-esp-target
printf '%s\n' 'RXRPC-ORIGINAL-PAGE-CACHE-FIXTURE' > /dirtyfrag-rxrpc-target

chown root:root /dirtyfrag-esp-target /dirtyfrag-rxrpc-target
chmod 0444 /dirtyfrag-esp-target /dirtyfrag-rxrpc-target

echo "prepared root-owned, read-only fixtures:"
ls -l /dirtyfrag-esp-target /dirtyfrag-rxrpc-target
