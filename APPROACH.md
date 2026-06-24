# PoC approach for draft-wang-tls-service-affinity (wire-real + interop)

## Why this shape (grounded in TLS WG practice)

New TLS extensions earn credibility by demonstrating the **real wire elements**
and **interop between independent implementations**, surfaced through an
RFC 7942 "Implementation Status" section and an IETF Hackathon. ECH
(`draft-ietf-tls-esni`, now RFC 9849) was approved on exactly that basis:
"Draft versions ... deployed and tested at scale. A number of vendors have
implemented this protocol and tested interoperability" with code in OpenSSL,
BoringSSL, rustls, NSS, and picotls.

No specific stack is mandated (OpenSSL is *not* required). What matters is real
wire bytes + ≥2 independent implementations.

## Stack choice

| Stack | Role | Why |
| --- | --- | --- |
| **tlslite-ng** (Python, Hubert Kario) | primary, real-wire client+server | "focused on interoperability testing"; TLS 1.3 PSK-(EC)DHE + ticket resumption; easy custom extensions; tlsfuzzer integration |
| **picotls** (C, Kazuho Oku; Christian Huitema is a top contributor) | second independent stack | message-level handshake API (built for QUIC); `additional_extensions` / `collect_extension` / `on_extension` hooks; meets a draft reviewer on home ground |
| OpenSSL / BoringSSL | deferred | highest "reference" weight, but a new post-handshake message needs state-machine surgery — wrong first target |

## Wire elements (experimental code points, 0xFE** convention like ECH; TBD via IANA)

- `migration_support`  ClientHello extension      `0xFE4D`
- `migration_allowed`  NewSessionTicket extension  `0xFE4E`
- `migrate_request`    post-handshake message      `0xFD`

## Plan

1. **tlslite-ng (DONE):** real `migration_support` extension on the wire;
   real cross-instance ticket resumption (shared ticket key); fail-closed on a
   foreign instance; scope enforcement; application idempotency; `migrate_request`
   real handshake-message wire format (codec round-trip).
2. **picotls (built + verified):** independent C TLS 1.3 stack compiles and
   passes its self-tests here; integration path identified via
   `additional_extensions` (emit) and `collect_extension`/`collected_extensions`/
   `on_extension` (parse).
3. **Interop (NEXT):** picotls client emitting `migration_support` parsed by the
   tlslite-ng server, and vice versa; capture pcaps; 2x2 matrix.
4. **Package:** RFC 7942 Implementation Status section + Implementations wiki;
   demo at the next IETF Hackathon.

## Honest scope note

A wire PoC removes the "does it work on the wire" objection. It does not by
itself settle "should this live in TLS"; that rests on the protocol-agnostic +
key-governance argument in the draft.
