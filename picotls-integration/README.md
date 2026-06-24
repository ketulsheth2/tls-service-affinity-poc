# picotls integration (independent C stack) + cross-stack interop

This shows the `migration_support` extension (code point `0xFE4D`) interoperating
between **picotls** (C) and **tlslite-ng** (Python) — two independent TLS 1.3
stacks, which is the bar the WG used for ECH.

The picotls source is a clone (not committed here). Our change is the small
patch `cli_svcaff.patch`, which touches two files:

- `t/cli.c`: adds a `-M` flag that (as a **client**) emits `migration_support`
  via `ptls_handshake_properties_t.additional_extensions` and observes
  `migration_support`/`migration_allowed` via `ptls_context_t.on_extension`;
  and (as a **server**) emits `migration_allowed` in its NewSessionTicket and
  sends a `migrate_request` after the handshake;
- `lib/picotls.c`: adds `migration_allowed` (0xFE4E) to the server NST emission,
  a `ptls_svcaff_send_migrate_request()` sender (modeled on the KeyUpdate
  sender), and a `0xFD` case to the client post-handshake dispatch so the
  picotls client can **receive** a `migrate_request`.

## Build

```bash
# from wire-interop-poc/
git clone --recurse-submodules https://github.com/h2o/picotls.git
git -C picotls apply ../picotls-integration/cli_svcaff.patch   # or: patch -p1 < ...
brew install cmake pkg-config openssl@3
(cd picotls && cmake -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)" . && make -j4 cli test-openssl.t)
./picotls/test-openssl.t | tail -3      # sanity: 17/17 subtests pass
```

## Run the interop

```bash
bash picotls-integration/run_interop.sh
```

Expected:

```
  Direction 1  (C->Py) migration_support  parsed   by tlslite: PASS
  Direction 1b (Py->C) migration_allowed  observed by picotls : PASS
  Direction 1c (Py->C) migrate_request    received by picotls : PASS
  Direction 2  (Py->C) migration_support  observed by picotls : PASS
  Direction 2b (C->Py) migration_allowed  observed by tlslite : PASS
  Direction 2c (C->Py) migrate_request    received by tlslite : PASS
  INTEROP: PASS (all 3 elements, both directions)
```

All three wire elements interoperate **both directions** between the two
independent stacks (`hstype=1` = ClientHello, `4` = NewSessionTicket;
`0xfe4d`/`0xfe4e`/`0xFD` are migration_support / migration_allowed /
migrate_request).

## Next

- Capture pcaps and exercise the 0-RTT relocation path; demo at an IETF
  Hackathon.
