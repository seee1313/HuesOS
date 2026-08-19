# Volume KeyBroker

Status: **implemented and exercised on target**.

## Security boundary

The boot volume key is not ambient syscall state. The kernel may obtain it from
a TPM-sealed blob or an explicit build-time development blob, but only the
isolated `key-broker` process is allowed to move it out of the kernel.

Authority is represented by `ResourceKind::VolumeKey`:

- init is the only process allowed to mint the Resource;
- the handle has no `DUPLICATE` right;
- init moves it into KeyBroker over the bootstrap channel;
- `VolumeKeyTake` validates that Resource and atomically removes the key from
  the kernel slot;
- a second successful take is impossible.

The old unrestricted `VolumeKeyGet` syscall no longer exists.

## Generation-bound grant flow

```text
kernel --VolumeKey Resource--> init --move--> KeyBroker
init --unique manager endpoint--> DriverManager
DriverManager --GrantRequest(generation) + one-shot endpoint--> KeyBroker
DriverManager --peer endpoint + same request--> hxfs-service generation N
KeyBroker --GrantReply(N, key | NotFound)--> hxfs-service
```

Init delegates exactly one manager-channel endpoint. DriverManager never sees
the master key and KeyBroker accepts generation requests only over that unique
endpoint. For each strictly increasing generation, DriverManager creates a new
channel pair. One endpoint is moved to KeyBroker and the peer is moved to that
specific HxFS process. The reply is sent once and the reply endpoint is dropped.

A stale/repeated generation receives `StaleGeneration`. A request without a
transferred reply endpoint observes nothing, including whether a key exists.

## Secret lifetime

- `libcanvas::system::VolumeKey` is neither `Copy`, `Clone`, nor `Debug` and
  clears its bytes on drop.
- `GrantReply` deliberately has no `Debug` implementation and clears its key
  field on drop.
- encoded reply and receive buffers are explicitly cleared after channel I/O.
- HxFS retains the master key only through mount/subkey derivation; mount state
  stores derived metadata and extent subkeys, not the master key.

The kernel restore path is used only if the final recoverable userspace copy
faults after the one-shot take. This prevents an invalid output pointer from
permanently destroying the boot key.

## Failure policy

- Missing key: KeyBroker returns `NotFound`; plain volumes remain mountable and
  encrypted volumes fail closed.
- Missing broker authority or manager channel: DriverManager refuses to launch
  HxFS.
- Generation mismatch, stale request, malformed reply: HxFS refuses the grant.
- KeyBroker manager-channel closure: KeyBroker exits rather than accepting a
  replacement ambient authority.

## Verification

Host coverage lives in `huesos-abi::key_broker` and covers request/reply wire
validation, generation zero, malformed records, and rejection of secret bytes
in non-granted replies.

QEMU serial requirements:

```text
[key-broker] kernel key moved; state=plain-only
[driver-manager] received unique KeyBroker generation authority
```

Encrypted NVMe runs additionally require:

```text
[key-broker] one-shot handoff verified
[driver-manager] issued one-shot Hxfs key grant generation 1
[hxfs] accepted generation-bound key grant 1 (key)
```
