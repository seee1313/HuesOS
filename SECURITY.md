# Security Policy

HuesOS is a research operating system and is **not production-ready**. Security
reports are still treated as private until a fix and disclosure plan exist.

## Reporting a vulnerability

Do not open a public issue for suspected vulnerabilities involving privilege
boundaries, key handling, memory safety, filesystem corruption or boot-chain
integrity. Contact the repository owner through GitHub private vulnerability
reporting. If that feature is unavailable, contact `seee1313` through the
address published on the GitHub profile and request a private channel without
including exploit details in the first message.

Include:

- affected commit SHA and build profile;
- QEMU/hardware configuration;
- minimal reproduction or malformed input;
- observed privilege/integrity/confidentiality impact;
- whether the result is deterministic;
- any crash log, excluding live secrets and disk keys.

## Supported versions

Only the current `main` branch receives security fixes. There are no stable
releases or format-compatibility guarantees yet. HxFS v5 is read-compatible but
mutation requires the explicit v6 migration tool.

## Disclosure

The owner will acknowledge a report, reproduce it privately, prepare regression
coverage and coordinate disclosure after a fix is available. Never commit real
volume keys, sealed private blobs, credentials or hardware identifiers that are
not required for reproduction.
