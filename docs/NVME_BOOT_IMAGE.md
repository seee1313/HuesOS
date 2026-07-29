# NVMe DriverHost HBI `.img` Bootstrap Contract

Status: **Stage A wiring landed; controller I/O remains next**.

HuesOS keeps storage-critical userspace drivers out of the disk they are needed
to read. The bootloader provides an HBI image containing a small immutable
bootstrap set:

- `init` and DriverManager;
- `driver-host-nvme` ELF;
- the NVMe driver manifest;
- `/storage/boot-drivers.manifest` naming storage-critical DriverHosts;
- kernel-produced storage boot-info metadata for BAR/MMIO, IRQ/MSI/MSI-X policy,
  and the 64 MiB `DmaPool`;
- optional recovery/diagnostic tools.

## Why this exists

NVMe is a userspace DriverHost, but the system may need NVMe before BlobFS/Hxfs
or a user volume is available. The HBI `.img` solves the chicken-and-egg problem:
all drivers required to reach persistent storage are already in the boot image.

## Contract

The HBI BOOTFS namespace reserves:

```text
/drivers/driver-host-nvme.elf
/manifests/nvme.hdriver
/storage/boot-drivers.manifest
```

`/storage/boot-drivers.manifest` is a small fixed-record table described by
`huesos_abi::hbi_boot`. It names each storage-critical DriverHost ELF and its
manifest path. Stage A currently emits one entry:

```text
elf      = /drivers/driver-host-nvme.elf
manifest = /manifests/nvme.hdriver
```

The `.hdriver` does **not** hard-code BAR/IRQ/DMA resources, because those are
discovered dynamically. Instead, the kernel installs a read-only storage
boot-info VMO (`huesos_abi::storage_boot`) into init. Init reads that metadata,
mints the root-only Resource handles, and forwards them to DriverManager before
signalling `manifest:grants-complete:driver-host-nvme`.

## Resource labels

When init/DriverManager transfers resources to `driver-host-nvme`, labels use
the existing format:

```text
resource:<driver>:<kind>:0x<base>:0x<len>:<mode>
```

Stage A sends, when hardware is present:

```text
resource:driver-host-nvme:mmio:0x<bar0_phys>:0x<bar0_len>:excl
resource:driver-host-nvme:irq:0x<irq_or_metadata>:0x1:excl
resource:driver-host-nvme:dma:0x<dma_pool_phys>:0x4000000:excl
```

`driver-host-nvme` validates labels strictly and logs either:

```text
[driver-host:nvme] resources: mmio OK, irq OK, dma OK
```

or the exact missing kind.

## Still not part of Stage A

Stage A intentionally does not yet:

- map BAR0 into the DriverHost VMAR;
- map the DMA pool into the DriverHost VMAR;
- program MSI-X/MSI or bind completions to Ports;
- initialize NVMe admin queues;
- register a real async BlockDevice channel.

Those are Stage B/C tasks.
