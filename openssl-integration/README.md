# OpenSSL integration (mainstream stack)

Adds a third, **mainstream** TLS stack (OpenSSL 3.x) to the interop, raising
credibility beyond the two niche stacks. It demonstrates `migration_support`
(`0xFE4D`) emitted and observed via OpenSSL's public `SSL_CTX_add_custom_ext`
API — **no fork**.

`svcaff_openssl.c` is a tiny client/server:
- as a **client** it emits `migration_support` in its ClientHello;
- as a **server** it parses `migration_support` from a peer's ClientHello.

## Run

```bash
brew install openssl@3
bash openssl-integration/run_openssl_interop.sh
```

Expected:

```
Direction A: OpenSSL client  -> tlslite-ng server   (Py parses 0xFE4D): PASS
Direction B: tlslite-ng client -> OpenSSL server    (C parses 0xFE4D) : PASS
OPENSSL-INTEROP: PASS (migration_support both directions)
```

## Scope

OpenSSL's custom-ext API covers ClientHello extensions cleanly, so
`migration_support` interoperates both ways. `migration_allowed` (a
NewSessionTicket extension) and `migrate_request` (a new post-handshake message)
are **not** done in OpenSSL: its public API does not cover NST extensions or new
handshake-message types, which would require OpenSSL state-machine changes.
Those two elements already interoperate between tlslite-ng and picotls; OpenSSL
here provides mainstream-stack evidence for `migration_support`.
