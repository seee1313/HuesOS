# Asynchronous Ring-3 USB 3.x (`xHCI`) Stack (`huesos-usb` & `driver-host-xhci`)

HuesOS implements its USB 3.x / 2.0 / 1.x host stack entirely in unprivileged
Ring-3 userspace (`crates/huesos-usb` + `crates/huesos-userspace/driver-host-xhci`),
isolated by capability handles and Intel VT-d second-stage DMA translation
([`IOMMU_VTD.md`](IOMMU_VTD.md)).

## Trust, Safety, and Zero-Heap Boundary

Following the microkernel policy-crate architecture enforced by
`tools/check-policy-crates.py` and `tools/check-hues-async-noalloc.py`:

1. **`crates/huesos-usb` (`#![no_std]`, `#![forbid(unsafe_code)]`)** owns all
   protocol codecs, ring cursors, and asynchronous completion state machines:
   - **`xhci`**: xHCI 1.x Capability/Operational/Runtime/Doorbell offsets,
     `HCCPARAMS1` (`CSZ` 32B/64B context size, `XECP` extended capabilities),
     `USBLEGSUP` BIOS-to-OS handoff helpers, `Supported Protocol` (`"USB "`)
     port-range decoding, `portsc_preserve_rw` RW1C-safe port masks, 16-byte
     `Trb` codecs, zero-shadow `ProducerRing` (`enqueue` -> `EnqueuedTrb` with
     `ToggleCycle` Link TRBs) and `EventRingConsumer` (`try_consume` with
     Consumer Cycle State tracking), and `SlotContext` / `EndpointContext` /
     `InputControlContext` builders.
   - **`ch9`**: USB 2.0/3.x standard `SetupPacket`, Device/Configuration/Interface/
     Endpoint/SS-Companion/String UTF-16LE descriptor walkers (`walk_configuration`).
   - **`hub`**: USB 2.0 (`0x29`) & SuperSpeed (`0x2A`) Hub descriptors,
     downstream port status/change decoders, and 20-bit xHCI `Route String` +
     High-Speed Transaction Translator (`TT`) propagation.
   - **`hid`**: HID Boot Keyboard 8-byte report diffing (`HidKeyboardState` ->
     HuesOS `[b'k', pressed, key]` events) and Boot Mouse report decoding
     (`[b'm', buttons, dx, dy, wheel]`).
   - **`bot`**: USB Mass Storage Bulk-Only Transport (`CBW` `USBC`, `CSW` `USBS`)
     and SCSI `INQUIRY`, `TEST UNIT READY`, `REQUEST SENSE`, `READ CAPACITY(10)`,
     `READ(10)`, `WRITE(10)`, and `SYNCHRONIZE CACHE(10)` CDB builders.
   - **`async_io`**: `TrbCompletionTable<N>` + `TrbWaitFuture` providing
     allocation-free `core::future::Future` waker registration and RAII drop
     cancellation over `hues-async`.

2. **`crates/huesos-userspace/driver-host-xhci` (`#![no_std]`, `NoHeapAllocator`)**
   owns the isolated Ring-3 hardware runtime:
   - Installs a `GlobalAlloc` that unconditionally returns null so zero heap
     allocations occur at bring-up or steady state; `XhciController` (`< 11 KiB`)
     lives inline in `.bss` with zero shadow ring arrays.
   - Receives `BAR0` `Mmio`, MSI-X/MSI `Irq` (vector `0xE0`), a dedicated `4 MiB`
     `< 4 GiB` `DmaPool` (`[72..76 MiB)` in `BOOT_DMA_POOL_LEN = 76 MiB`), and a
     read-only `DeviceLease` (`DEVICE_LEASE_XHCI_RO_LABEL`).
   - `driver-manager` attaches the `4 MiB` `DmaPool` to `xhci_lease_rw` via
     `DeviceLease::attach_dma` before forwarding `resource:transfer-complete`,
     programming Intel VT-d second-stage page tables prior to `USBCMD.RS = 1`,
     and revokes the lease on failure or `PORT_PACKET_DEVICE_GONE`.

3. **`crates/huesos-abi/src/usb.rs` (`HUSB` v1)** defines the FNV-1a-checksummed
   read-only VMO snapshot published to `driver-manager` (`service:usb:inventory-vmo`)
   so `lsusb` and `lsusb -v` inspect controller and downstream device state with
   zero live USB or PCI bus traffic.

## Static 4 MiB DMA Window Layout

| Offset | Size | Purpose |
| --- | --- | --- |
| `0x00_0000` | `4 KiB` | `DCBAA` (Device Context Base Address Array, up to 32 slots + scratchpad ptr) |
| `0x00_1000` | `4 KiB` | Scratchpad Buffer Pointer Array (up to 32 entries) |
| `0x00_2000` | `128 KiB` | 32 x `4 KiB` Scratchpad pages (`Max Scratchpad Bufs`) |
| `0x02_2000` | `4 KiB` | Command Ring (`64` TRBs, Link TRB at slot `63`) |
| `0x02_3000` | `4 KiB` | Event Ring Segment 0 (`256` TRBs) |
| `0x02_4000` | `4 KiB` | `ERST` (Event Ring Segment Table, 1 segment) |
| `0x02_5000` | `128 KiB` | `32` x `4 KiB` Output Device Contexts (`CSZ` 32B/64B aware) |
| `0x04_5000` | `128 KiB` | `32` x `4 KiB` Input Contexts (`A0 = 1, A1 = 0` on `Configure Endpoint`) |
| `0x06_5000` | `256 KiB` | `64` x `4 KiB` Transfer Rings (`64` TRBs each: `EP0`, HID IN, Hub IN, BOT Bulk IN/OUT) |
| `0x0A_5000` | `128 KiB` | `32` x `4 KiB` per-slot Control/Descriptor/HID/CBW/CSW DMA scratch pages |
| `0x10_0000` | `256 KiB` | BOT Bulk data window (`BOT_DATA_OFF`, chunked `AsyncBlockRequest` transfers) |

## Services, Multiplexing, and Userland Diagnostics

- **Dual Keyboard Multiplexing (`driver-manager`)**: `Supervisor` multiplexes
  3-byte `[b'k', pressed, key]` frames concurrently from both `driver-host-input`
  (PS/2 `IRQ1`) and `driver-host-xhci` (USB HID Boot Keyboard, including
  hot-attached keyboards behind USB Hubs) into the active `terminal` / `doom` /
  `snake` client channel.
- **Mouse & Block Services**: `open:mouse` streams 5-byte `[b'm', buttons, dx, dy, wheel]`
  packets; `open:block:usb` and DevFS `OPEN /dev/block/usb0` expose standard
  `AsyncBlockRequest` (`Info`, `Read`, `Write`, `Flush`) backed by SCSI BOT.
- **`/bin/lsusb.elf`**:
  - `lsusb`: queries `driver-manager` (`query:usb`) for an aligned TSV summary
    compatible with `hsh` structured pipelines (`lsusb | count`).
  - `lsusb -v`: maps and validates the read-only `HUSB` v1 VMO (`query:usb:vmo`).
  - `lsusb --bot-smoke`: opens `open:block:usb`, executes `AsyncBlockOp::Info` +
    `AsyncBlockOp::Read` (`LBA 0`), and verifies sector contents end-to-end.

## Verification

- **Host & ASan suites**: `cargo test -p huesos-abi -p huesos-usb` (also run
  under AddressSanitizer in `.github/workflows/sanitizers.yml`).
- **Live QEMU VT-d + Hub + HID + BOT gate**: `scripts/ci-qemu-usb-xhci-smoke.sh`
  boots Q35 with `intel-iommu,intremap=off,caching-mode=on`, `qemu-xhci`, a
  downstream `usb-hub` hosting both `usb-kbd` and `usb-mouse`, plus a root-port
  `usb-storage` disk, injects `lsusb -v --bot-smoke --log-serial` via QMP
  `input-send-event` exclusively into the Hub-attached `usb-kbd`, and verifies
  `HUSB v1` `iommu=isolated`, all 4 USB slots (`usb-hub`, `hid-kbd`, `hid-mouse`,
  `usb-bot`), live `USB_BOT_SMOKE_OK` sector readback, and zero IOMMU faults.
