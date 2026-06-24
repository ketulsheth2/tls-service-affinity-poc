#!/usr/bin/env bash
# Cross-stack interop for migration_support (0xFE4D) between picotls (C) and
# tlslite-ng (Python). Requires: picotls built (../picotls/cli with the -M
# patch) and the venv at ../.venv.
#
#   Direction 1: picotls client  -> tlslite-ng server  (C emits, Python parses)
#   Direction 2: tlslite-ng client -> picotls server   (Python emits, C parses)
set -uo pipefail
cd "$(dirname "$0")/.."

CLI=picotls/cli
PY=.venv/bin/python
CERT=tlslite_poc/cert.pem
KEY=tlslite_poc/key.pem
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT

[ -x "$CLI" ] || { echo "build picotls first: (cd picotls && cmake ... && make -j4 cli)"; exit 1; }
"$PY" tlslite_poc/common.py >/dev/null   # ensure cert/key exist

wait_port() { local h=${1%:*} p=${1##*:}; for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/$h/$p")2>/dev/null && { exec 3>&-; return; }; sleep 0.1; done; }

echo "=================================================================="
echo " Direction 1: picotls CLIENT  ->  tlslite-ng SERVER"
echo "   (C emits migration_support; Py server's NST carries migration_allowed,"
echo "    which the C client observes)"
echo "=================================================================="
"$PY" tlslite_poc/interop_server.py 7500 >/tmp/iserver.log 2>&1 & PIDS+=($!)
wait_port 127.0.0.1:7500
"$CLI" -M 127.0.0.1 7500 </dev/null >/tmp/picli.log 2>&1 || true
sleep 0.5
sed 's/^/  /' /tmp/iserver.log
sed 's/^/  /' /tmp/picli.log | grep -i "observed\|received migrate" || true

echo
echo "=================================================================="
echo " Direction 2: tlslite-ng CLIENT  ->  picotls SERVER"
echo "   (Py emits migration_support; C server emits migration_allowed in its"
echo "    NST and sends migrate_request, both observed by the Py client)"
echo "=================================================================="
"$CLI" -M -c "$CERT" -k "$KEY" 127.0.0.1 7600 >/tmp/picotls_srv.log 2>&1 & PIDS+=($!)
wait_port 127.0.0.1:7600
"$PY" tlslite_poc/interop_client.py 7600 >/tmp/iclient.log 2>&1 || true
sed 's/^/  /' /tmp/iclient.log
sleep 0.3
echo "  --- picotls server log ---"
sed 's/^/  /' /tmp/picotls_srv.log

echo
echo "=================================================================="
echo " RESULT"
D1=$(grep -c "migration_support(0xFE4D) from peer = True" /tmp/iserver.log || true)
D1b=$(grep -c "observed migration_allowed (0xFE4E)" /tmp/picli.log || true)
D1c=$(grep -c "received migrate_request (0xFD)" /tmp/picli.log || true)
D2=$(grep -c "observed migration_support (0xFE4D)" /tmp/picotls_srv.log || true)
D2b=$(grep -c "migration_allowed(0xFE4E) observed in picotls NST = True" /tmp/iclient.log || true)
D2c=$(grep -c "migrate_request received from picotls: target=b'tok-B'" /tmp/iclient.log || true)
echo "  Direction 1  (C->Py) migration_support  parsed   by tlslite: $([ "$D1" -ge 1 ] && echo PASS || echo FAIL)"
echo "  Direction 1b (Py->C) migration_allowed  observed by picotls : $([ "$D1b" -ge 1 ] && echo PASS || echo FAIL)"
echo "  Direction 1c (Py->C) migrate_request    received by picotls : $([ "$D1c" -ge 1 ] && echo PASS || echo FAIL)"
echo "  Direction 2  (Py->C) migration_support  observed by picotls : $([ "$D2" -ge 1 ] && echo PASS || echo FAIL)"
echo "  Direction 2b (C->Py) migration_allowed  observed by tlslite : $([ "$D2b" -ge 1 ] && echo PASS || echo FAIL)"
echo "  Direction 2c (C->Py) migrate_request    received by tlslite : $([ "$D2c" -ge 1 ] && echo PASS || echo FAIL)"
ALL=$((D1>=1 && D1b>=1 && D1c>=1 && D2>=1 && D2b>=1 && D2c>=1))
[ "$ALL" = "1" ] && echo "  INTEROP: PASS (all 3 elements, both directions)" || { echo "  INTEROP: FAIL"; exit 1; }
