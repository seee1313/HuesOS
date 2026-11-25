#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use huesos_abi::pci::ConfigBackend;
use huesos_abi::pci_inventory::{
    self, InventoryBarClass, InventoryIrqMode, InventoryParentKind, BAR_SLOTS_PER_FUNCTION,
};
use huesos_abi::pci_iommu::{self, IommuMode};
use huesos_coreutils as cu;
use libcanvas::{ErrorCode, Vmo};

cu::coreutil_entry!(run);

const QUERY_WAIT_TICKS: u64 = 250;

fn run() -> i32 {
    let args = cu::collect_args();
    if args.is_empty() {
        return cu::run_registry_query("pci", b"query:pci");
    }

    let mut show_iommu = false;
    let mut show_functions = false;
    let mut show_bars = false;

    for arg in &args {
        match arg.as_str() {
            "-v" | "--verbose" => {
                show_iommu = true;
                show_functions = true;
                show_bars = true;
            }
            "--bars" => {
                show_functions = true;
                show_bars = true;
            }
            "--iommu" => {
                show_iommu = true;
            }
            "-h" | "--help" => {
                cu::outln("usage: pci [-v|--verbose] [--bars] [--iommu]");
                return 0;
            }
            other => {
                cu::errln(&format!("pci: unknown option '{other}'"));
                return 2;
            }
        }
    }

    run_hpin_report(show_iommu, show_functions, show_bars)
}

fn fetch_inventory_vmo() -> Result<Vmo, i32> {
    if let Err(code) = cu::check_query_ro() {
        return Err(code);
    }
    let Some(reg) = cu::take_registry() else {
        cu::errln("pci: DriverManager query channel unavailable");
        return Err(1);
    };
    if let Err(e) = reg.write(b"query:pci:vmo") {
        cu::errln(&format!("pci: query write failed: {}", e.as_str()));
        return Err(1);
    }
    let mut buf = [0u8; 128];
    for _ in 0..6 {
        match reg.read_optional_handle_timeout(&mut buf, QUERY_WAIT_TICKS) {
            Ok((_len, Some(handle))) => return Ok(Vmo::from_handle(handle)),
            Ok((len, None)) => {
                let msg = core::str::from_utf8(&buf[..len]).unwrap_or("err:pci-inventory");
                cu::errln(&format!("pci: inventory VMO unavailable ({msg})"));
                return Err(1);
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(e) => {
                cu::errln(&format!("pci: query read failed: {}", e.as_str()));
                return Err(1);
            }
        }
    }
    cu::errln("pci: inventory VMO query timed out");
    Err(1)
}

fn run_hpin_report(show_iommu: bool, show_functions: bool, show_bars: bool) -> i32 {
    let vmo = match fetch_inventory_vmo() {
        Ok(v) => v,
        Err(code) => return code,
    };

    let mut hdr_bytes = [0u8; pci_inventory::HEADER_BYTES];
    if vmo.read(0, &mut hdr_bytes) != Ok(pci_inventory::HEADER_BYTES) {
        cu::errln("pci: short HPIN header read");
        return 1;
    }
    let Ok(declared) = pci_inventory::declared_size(&hdr_bytes) else {
        cu::errln("pci: invalid HPIN header");
        return 1;
    };
    let mut raw = alloc::vec![0u8; declared];
    if vmo.read(0, &mut raw) != Ok(declared) {
        cu::errln("pci: short HPIN body read");
        return 1;
    }
    let Ok(hdr) = pci_inventory::validate_and_decode_header(&raw) else {
        cu::errln("pci: HPIN checksum or format validation failed");
        return 1;
    };

    let backend = match hdr.backend {
        ConfigBackend::Ecam => "ecam",
        ConfigBackend::LegacyIo => "legacy-io",
    };
    let live_sized = (hdr.flags & pci_inventory::INVENTORY_FLAG_LIVE_SIZED) != 0;
    let bound = (hdr.flags & pci_inventory::INVENTORY_FLAG_BINDING_COMPLETE) != 0;
    cu::outln(&format!(
        "HPIN v1 snapshot=0x{:016x} pci_gen={} topo_gen={} functions={} backend={} live_sized={} bound={}",
        hdr.firmware_snapshot_id,
        hdr.manager_generation,
        hdr.topology_generation,
        hdr.function_count,
        backend,
        live_sized,
        bound
    ));

    if show_iommu {
        let dma = match hdr.active_dma_isolation {
            IommuMode::Trusted => "trusted",
            IommuMode::Isolated => "isolated",
        };
        let intr_hw = (hdr.iommu_flags & pci_iommu::FLAG_INTR_REMAP_HW_SUPPORTED) != 0;
        let intr_active = (hdr.iommu_flags & pci_iommu::FLAG_INTR_REMAP_ACTIVE) != 0;
        cu::outln(&format!(
            "IOMMU hw={} status={} units={} dma_isolation={} intr_remap_hw={} intr_remap_active={}",
            hdr.iommu_hw.label(),
            hdr.iommu_status.label(),
            hdr.iommu_unit_count,
            dma,
            intr_hw,
            intr_active
        ));
    }

    if show_functions {
        for idx in 0..usize::from(hdr.function_count) {
            let Ok(rec) = pci_inventory::decode_record(&raw, idx) else {
                break;
            };
            let irq = match rec.irq_mode {
                InventoryIrqMode::None | InventoryIrqMode::Polling => {
                    String::from(rec.irq_mode.label())
                }
                InventoryIrqMode::Intx | InventoryIrqMode::Msi | InventoryIrqMode::Msix => {
                    format!("{}({})", rec.irq_mode.label(), rec.irq_vector_or_gsi)
                }
            };
            let parent = match rec.parent_kind {
                InventoryParentKind::Root => format!("root({})", rec.root_id),
                InventoryParentKind::Bridge => format!(
                    "{:02x}:{:02x}.{}",
                    rec.parent_bus, rec.parent_device, rec.parent_function
                ),
            };
            let caps = format_caps(rec.cap_flags);
            let cls_name =
                pci_inventory::class_short_name(rec.class_code, rec.subclass, rec.prog_if);
            cu::outln(&format!(
                "{:04x}:{:02x}:{:02x}.{} {:04x}:{:04x} {} ({:02x}:{:02x}:{:02x}) rev={:02x} parent={} depth={} caps=[{}] irq={} reloc={} lease={}",
                rec.segment,
                rec.bus,
                rec.device,
                rec.function,
                rec.vendor_id,
                rec.device_id,
                cls_name,
                rec.class_code,
                rec.subclass,
                rec.prog_if,
                rec.revision_id,
                parent,
                rec.depth,
                caps,
                irq,
                rec.relocation_class.label(),
                rec.lease_state.label()
            ));
            if rec.header_type == 1 {
                cu::outln(&format!(
                    "  bridge sec_bus={:02x} sub_bus={:02x}",
                    rec.secondary_bus, rec.subordinate_bus
                ));
            }
            if show_bars {
                for b_idx in 0..BAR_SLOTS_PER_FUNCTION {
                    let bar = rec.bars[b_idx];
                    if bar.class == InventoryBarClass::Unused {
                        continue;
                    }
                    let slot_lbl = if rec.header_type == 1 {
                        format!("WIN{b_idx}")
                    } else {
                        format!("BAR{b_idx}")
                    };
                    cu::outln(&format!(
                        "  {} {} base=0x{:x} size=0x{:x} status={}",
                        slot_lbl,
                        bar.class.label(),
                        bar.base,
                        bar.len,
                        bar.status.label()
                    ));
                }
            }
        }
    }

    0
}

fn format_caps(flags: u16) -> String {
    let mut parts = Vec::new();
    if (flags & pci_inventory::CAP_FLAG_PCIE) != 0 {
        parts.push("pcie");
    }
    if (flags & pci_inventory::CAP_FLAG_MSIX) != 0 {
        parts.push("msix");
    }
    if (flags & pci_inventory::CAP_FLAG_MSI) != 0 {
        parts.push("msi");
    }
    if (flags & pci_inventory::CAP_FLAG_PM) != 0 {
        parts.push("pm");
    }
    if (flags & pci_inventory::CAP_FLAG_VENDOR) != 0 {
        parts.push("vendor");
    }
    if (flags & pci_inventory::CAP_FLAG_AER) != 0 {
        parts.push("aer");
    }
    if (flags & pci_inventory::CAP_FLAG_HOTPLUG) != 0 {
        parts.push("hotplug");
    }
    if parts.is_empty() {
        String::from("-")
    } else {
        parts.join(",")
    }
}
