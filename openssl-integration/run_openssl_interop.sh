#!/usr/bin/env bash
# Mainstream-stack interop: OpenSSL <-> tlslite-ng on migration_support (0xFE4D).
#   Direction A: OpenSSL client   -> tlslite-ng server  (C emits, Py parses)
#   Direction B: tlslite-ng client -> OpenSSL server     (Py emits, C parses)
set -uo pipefail
cd "$(dirname "$0")/.."

OSSL="$(brew --prefix openssl@3)"
PY=.venv/bin/python
CERT=tlslite_poc/cert.pem
KEY=tlslite_poc/key.pem
BIN=openssl-integration/svcaff_openssl
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT

cc -I"$OSSL/include" -L"$OSSL/lib" openssl-integration/svcaff_openssl.c -lssl -lcrypto -o "$BIN" \
    || { echo "build failed"; exit 1; }
echo "built $BIN against $(${OSSL}/bin/openssl version)"
"$PY" tlslite_poc/common.py >/dev/null

wait_port() { local h=${1%:*} p=${1##*:}; for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/$h/$p") 2>/dev/null && { exec 3>&-; return; }; sleep 0.1; done; }

echo "=================================================================="
echo " Direction A: OpenSSL client  ->  tlslite-ng server"
echo "=================================================================="
"$PY" tlslite_poc/interop_server.py 7510 >/tmp/ossl_srv_tls.log 2>&1 & PIDS+=($!)
wait_port 127.0.0.1:7510
"$BIN" client 127.0.0.1 7510 2>/tmp/ossl_cli.log || true
sleep 0.4
grep -iE "migration_support|handshake OK" /tmp/ossl_cli.log /tmp/ossl_srv_tls.log | sed 's/^/  /'

echo "=================================================================="
echo " Direction B: tlslite-ng client  ->  OpenSSL server"
echo "=================================================================="
"$BIN" server 7610 "$CERT" "$KEY" >/tmp/ossl_srv.log 2>&1 & PIDS+=($!)
wait_port 127.0.0.1:7610
"$PY" tlslite_poc/interop_client.py 7610 >/tmp/ossl_tls_cli.log 2>&1 || true
sleep 0.4
grep -iE "observed migration_support|handshake OK|emitted on the wire" /tmp/ossl_srv.log /tmp/ossl_tls_cli.log | sed 's/^/  /'

echo "=================================================================="
echo " RESULT"
A=$(grep -c "migration_support(0xFE4D) from peer = True" /tmp/ossl_srv_tls.log || true)
B=$(grep -c "observed migration_support (0xFE4D)" /tmp/ossl_srv.log || true)
echo "  OpenSSL client  -> tlslite server (Py parses 0xFE4D): $([ "$A" -ge 1 ] && echo PASS || echo FAIL)"
echo "  tlslite client  -> OpenSSL server (C parses 0xFE4D) : $([ "$B" -ge 1 ] && echo PASS || echo FAIL)"
[ "$A" -ge 1 ] && [ "$B" -ge 1 ] && echo "  OPENSSL-INTEROP: PASS (migration_support both directions)" || { echo "  OPENSSL-INTEROP: FAIL"; exit 1; }
