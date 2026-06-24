# Wire-real interop PoC — draft-wang-tls-service-affinity

This PoC demonstrates the draft's **real TLS wire elements** in independent TLS
stacks, following how the WG validated ECH (real wire bytes + interop, RFC 7942).

It puts the `migration_support` extension on the wire as a genuine TLS
extension and uses real TLS 1.3 cross-instance resumption — not an
application-level model.

## Status (honest)

| Item | Stack | Status |
| --- | --- | --- |
| `migration_support` as a real TLS extension in the ClientHello | tlslite-ng | **DONE, tested** (byte-level evidence) |
| Cross-instance TLS 1.3 ticket resumption (shared ticket key) | tlslite-ng | **DONE, tested** (`conn.resumed == True` on sibling) |
| Fail-closed on a foreign instance (no shared key) | tlslite-ng | **DONE, tested** (`resumed == False` → client aborts) |
| Scope enforcement + application idempotency on relocation | tlslite-ng | **DONE, tested** |
| `migration_allowed` as a real `NewSessionTicket` extension (`0xFE4E`) | tlslite-ng | **DONE, tested** (server emits, client reads; captured + decoded) |
| `migrate_request` as a real **post-handshake message** (type `0xFD`) | tlslite-ng | **DONE, tested** (sent as `ContentType.handshake`, read off the record layer; resumption preserved) |
| Capture artifacts (ClientHello / NST / migrate_request bytes) | tlslite-ng | **DONE** (`captures/`, `make captures`) |
| Independent C TLS 1.3 stack builds + self-tests pass | picotls | **DONE** (17/17 tests, 10k handshakes) |
| **Cross-stack interop — `migration_support`** (both directions) | picotls ↔ tlslite-ng | **DONE, tested** |
| **Cross-stack interop — `migration_allowed`** (both directions) | picotls ↔ tlslite-ng | **DONE, tested** |
| **Cross-stack interop — `migrate_request`** (both directions) | picotls ↔ tlslite-ng | **DONE, tested** |
| **Forward secrecy enforced** (`psk_dhe_ke` required, `psk_ke` refused) | tlslite-ng | **DONE, tested** (`make fs`) |
| **Mainstream-stack interop — `migration_support`** (both directions) | OpenSSL 3.x ↔ tlslite-ng | **DONE, tested** (`make openssl-interop`) |

## Real vs modeled

- **Real on the wire:** TLS 1.3 itself; the `migration_support` extension
  (code point `0xFE4D`) is appended to the live ClientHello and parsed by the
  server (proven by capturing the actual bytes and the server's parsed
  extension-type list); cross-instance resumption via a shared ticket key;
  forward secrecy (TLS 1.3 always uses (EC)DHE = `psk_dhe_ke`).
- **Real on the wire:** `migration_allowed` (`0xFE4E`) is a genuine
  `NewSessionTicket` extension — the server emits it and the client reads it
  back (captured and decoded in `captures/`).
- **Real on the wire:** `migrate_request` (type `0xFD`) is a genuine
  post-handshake handshake message — the server sends it as a
  `ContentType.handshake` record (encrypted under the application traffic
  keys), and the client reads it straight off the record layer, processing
  NewSessionTickets alongside so resumption is preserved. See
  `migrate_request_wire.py` for the focused proof; it is also used in `demo.py`.
- **Modeled:** the opaque target / scope / idempotency ledger
  (application/control-plane concerns, not TLS).

## Code points (experimental; TBD via IANA)

```
migration_support   ClientHello extension       0xFE4D
migration_allowed   NewSessionTicket extension  0xFE4E
migrate_request     post-handshake message      0xFD
```

## Run

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cd tlslite_poc
python demo.py            # all scenarios: success | foreign | unaware | outofscope
python demo.py success    # one scenario, prints byte-level evidence
python _smoke.py          # minimal cross-instance resumption check
python captures.py        # write real wire bytes to ../captures/
python decode.py          # decode + verify the captured artifacts
```

### picotls (independent C stack) + cross-stack interop

```bash
# see picotls-integration/README.md for full steps
git clone --recurse-submodules https://github.com/h2o/picotls.git
git -C picotls apply picotls-integration/cli_svcaff.patch
brew install cmake pkg-config openssl@3
(cd picotls && cmake -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)" . && make -j4 cli test-openssl.t)
bash picotls-integration/run_interop.sh    # picotls <-> tlslite-ng, both directions -> INTEROP: PASS
```

## What the demo proves (success scenario)

```
migration_support_on_wire = True (client A and B)
real ClientHello bytes ...svc.e│xample│ fe4d 0000 │...   (0xFE4D = migration_support)
server parsed CH ext types include 0xfe4d  (independent parse)
B: resumed = True            (cross-instance resumption via shared ticket key)
F: resumed = False           (foreign instance -> client fails closed)
payment replay @ B = deduped (idempotency handled by the app backend, not TLS)
migrate_request codec round-trip = PASS
```

## Files

```
tlslite_poc/common.py          code points, test PKI, shared/foreign ticket keys
tlslite_poc/wire.py            extension inject/observe (CH + NST), MigrateRequest msg + send/recv, byte capture
tlslite_poc/demo.py            end-to-end scenarios + evidence
tlslite_poc/migrate_request_wire.py  focused proof: migrate_request as a real post-handshake message
tlslite_poc/fs_enforcement.py  forward-secrecy enforcement (psk_dhe_ke required)
tlslite_poc/_smoke.py          minimal resumption check
openssl-integration/           OpenSSL custom-ext harness + run script (mainstream stack)
tlslite_poc/interop_server.py  tlslite server for cross-stack interop
tlslite_poc/interop_client.py  tlslite client for cross-stack interop
tlslite_poc/captures.py        write real wire bytes to captures/
tlslite_poc/decode.py          decode + verify the artifacts
picotls-integration/           cli_svcaff.patch + run_interop.sh + notes (independent C stack)
picotls/                       upstream clone (gitignored); apply the patch + build
IMPLEMENTATION_STATUS.md       RFC 7942 text for the draft
APPROACH.md                    why this shape, grounded in WG practice
```

## Limitations

Demonstration only: deterministic/test certs and hard-coded ticket keys, single
host, loopback. Not production code.
