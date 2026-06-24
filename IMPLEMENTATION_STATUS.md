# Implementation Status (RFC 7942 text for the draft)

> Note to RFC Editor: please remove this section before publication.
>
> This section records the status of known implementations of the protocol
> defined by this specification at the time of posting, per RFC 7942. The
> description of implementations here does not imply endorsement by the IETF.

## Implementation 1: tlslite-ng-based reference PoC

- Organization: (authors)
- Description: Client and two-or-more server "instances" built on tlslite-ng
  (pure-Python TLS 1.3). Demonstrates the `migration_support` extension on the
  wire, authorized cross-instance session resumption via a shared ticket key,
  fail-closed behavior against an instance outside the trust domain, scope
  enforcement, application-level idempotency across relocation, and the
  `migrate_request` handshake-message wire format.
- Level of maturity: research / proof-of-concept.
- Coverage:
  - `migration_support` (ClientHello extension, code point 0xFE4D): IMPLEMENTED;
    emitted on the live ClientHello and parsed by the server (verified at the
    byte level).
  - Authorized resumption on an alternate instance (Section 6): IMPLEMENTED via
    TLS 1.3 ticket resumption with a ticket key shared across instances.
  - Anti-redirection / fail-closed (Section 10.2): IMPLEMENTED; an instance
    without the shared key cannot resume, and the client aborts before sending
    application data.
  - Forward secrecy (`psk_dhe_ke`, Section 10.3): IMPLEMENTED (TLS 1.3 (EC)DHE).
  - `migration_allowed` (NewSessionTicket extension, code point 0xFE4E,
    Section 5.2): IMPLEMENTED as a real NewSessionTicket extension; the server
    emits it and the client reads it back (captured and decoded).
  - `migrate_request` (post-handshake message, type 0xFD, Section 5.3):
    IMPLEMENTED as a real post-handshake handshake message. The server sends it
    as a ContentType.handshake record (encrypted under the application traffic
    keys); the client reads it off the record layer and parses the target,
    while NewSessionTickets are processed alongside so resumption is preserved.
  - Capture artifacts: real ClientHello (with 0xFE4D) and NewSessionTicket
    (with 0xFE4E) bytes are produced and decoded by `captures.py` / `decode.py`.
- Version compatible with: draft-wang-tls-service-affinity-03.
- Licensing: (TBD) intended permissive.
- Contact: (authors)

## Implementation 2: picotls (independent stack)

- Description: picotls (compact C TLS 1.3) is used as a second, independent
  implementation. The library builds and passes its own test suite in this
  environment (17/17 subtests, including 10,000 handshakes, resumption, HPKE).
- Level of maturity: research / proof-of-concept.
- Coverage (via the `picotls-integration/cli_svcaff.patch`, touching `t/cli.c`
  and `lib/picotls.c`):
  - `migration_support` (0xFE4D): emitted (client) via `additional_extensions`;
    observed via `on_extension`.
  - `migration_allowed` (0xFE4E): emitted (server) in the NewSessionTicket;
    observed (client) via `on_extension`.
  - `migrate_request` (0xFD): sent (server) via `ptls_svcaff_send_migrate_request`;
    received (client) via a case in the client post-handshake dispatch.

## Implementation 3: OpenSSL (mainstream stack)

- Description: a small client/server (`openssl-integration/svcaff_openssl.c`)
  using OpenSSL 3.x. It emits and observes `migration_support` (0xFE4D) via the
  public `SSL_CTX_add_custom_ext` API (no fork).
- Coverage: `migration_support` only. `migration_allowed` (NewSessionTicket
  extension) and `migrate_request` (new post-handshake message) are not
  implemented in OpenSSL, as its public API does not cover them.

## Forward secrecy

The tlslite-ng server enforces `psk_dhe_ke` and refuses `psk_ke`
(`fs_enforcement.py`): a psk_dhe_ke client resumes, a psk_ke-only client is
refused resumption. This realizes the draft's forward-secrecy requirement.

## Interoperability

ACHIEVED between tlslite-ng (Python) and picotls (C) for all three wire
elements, BOTH directions, run via `picotls-integration/run_interop.sh`;
additionally OpenSSL 3.x (mainstream) interoperates with tlslite-ng on
`migration_support` both directions (`openssl-integration/run_openssl_interop.sh`):

- `migration_support` (ClientHello extension): picotls<->tlslite both ways.
- `migration_allowed` (NewSessionTicket extension): tlslite server -> picotls
  client, and picotls server -> tlslite client.
- `migrate_request` (post-handshake message, type 0xFD): tlslite server ->
  picotls client, and picotls server -> tlslite client.

This provides genuine two-independent-implementation interop for every wire
element of the draft. Next: capture pcaps, exercise the 0-RTT relocation path,
and demo at an IETF Hackathon.
