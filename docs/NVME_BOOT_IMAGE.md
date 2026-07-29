# NVMe DriverHost HBI `.img` Bootstrap Contract

Status: **contract landed; kernel/DriverManager wiring remains next**.

HuesOS keeps storage-critical userspace drivers out of the disk they are needed
to read. The bootloader provides an HBI image containing a small immutable
bootstrap set:

- `init` and DriverManager;
- `driver-host-nvme` ELF;
- the NVMe driver manifest;
- resource metadata for BAR/MMIO, IRQ/MSI/MSI-X policy, and a 64 MiB `DmaPool`;
- optional recovery/diagnostic tools.

## Why this exists

NVMe is a userspace DriverHost, but the system may need NVMe before BlobFS/Hxfs
or a user volume is available. The HBI `.img` solves the chicken-and-egg problem:
all drivers required to reach persistent storage are already in the boot image.

## Contract

The HBI BOOTFS namespace reserves:

```text
/bin/driver-host-nvme.elf
/manifests/nvme.hdriver
/storage/boot-drivers.manifest
```

`/storage/boot-drivers.manifest` is a small fixed-record table described by
`huesos_abi::hbi_boot`. It names each storage-critical DriverHost and its
manifest path. The manifest then declares fine-grained Resource grants, including
`resource=dma:<phys-base>:0x4000000:excl` for the preallocated 64 MiB DMA pool.

## Resource labels

When init/DriverManager transfers resources to `driver-host-nvme`, labels use
the existing `resource:<driver>:<kind>:0x<base>:0x<len>:<mode>` format. `kind`
for the DMA pool is `dma`.

## Non-goals in this slice

This contract does not yet:

- allocate/map the actual DMA pool;
- discover the NVMe PCI BAR;
- configure MSI-X/MSI;
- launch `driver-host-nvme` during boot.

Those are the next on-target slices.
