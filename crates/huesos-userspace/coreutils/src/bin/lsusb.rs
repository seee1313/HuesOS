#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use huesos_abi::block::{AsyncBlockInfo, AsyncBlockOp, AsyncBlockRequest, AsyncBlockStatus};
use huesos_abi::pci_lease::unpack_pci_address;
use huesos_abi::rights;
use huesos_abi::usb;
use huesos_coreutils as cu;
use libcanvas::{
    wait_any, Channel, ErrorCode, Port, Signals, Vmo, WaitItem, PORT_PACKET_BLOCK_COMPLETION,
};

cu::coreutil_entry!(run);

const QUERY_WAIT_TICKS: u64 = 250;

fn emit_line(line: &str, log_serial: bool) {
    cu::outln(line);
    if log_serial {
        libcanvas::println!("{line}");
    }
}

fn run() -> i32 {
    let args = cu::collect_args();
    if args.is_empty() {
        return cu::run_registry_query("lsusb", b"query:usb");
    }

    let mut verbose = false;
    let mut bot_smoke = false;
    let mut log_serial = false;

    for arg in &args {
        match arg.as_str() {
            "-v" | "--verbose" => verbose = true,
            "--bot-smoke" => bot_smoke = true,
            "--log-serial" => log_serial = true,
            "-h" | "--help" => {
                cu::outln("usage: lsusb [-v|--verbose] [--bot-smoke] [--log-serial]");
                return 0;
            }
            other => {
                cu::errln(&format!("lsusb: unknown option '{other}'"));
                return 2;
            }
        }
    }

    if let Err(code) = cu::check_query_ro() {
        return code;
    }
    let Some(reg) = cu::take_registry() else {
        cu::errln("lsusb: DriverManager query channel unavailable");
        return 1;
    };

    if verbose || !bot_smoke {
        if let Err(code) = report_husb_vmo(&reg, verbose, log_serial) {
            return code;
        }
    }
    if bot_smoke {
        if let Err(code) = run_bot_smoke(&reg, log_serial) {
            return code;
        }
    }
    0
}

fn fetch_husb_vmo(reg: &Channel) -> Result<Vmo, i32> {
    if let Err(e) = reg.write(b"query:usb:vmo") {
        cu::errln(&format!("lsusb: query write failed: {}", e.as_str()));
        return Err(1);
    }
    let mut buf = [0u8; 128];
    for _ in 0..6 {
        match reg.read_optional_handle_timeout(&mut buf, QUERY_WAIT_TICKS) {
            Ok((_len, Some(handle))) => return Ok(Vmo::from_handle(handle)),
            Ok((len, None)) => {
                let msg = core::str::from_utf8(&buf[..len]).unwrap_or("err:usb-inventory");
                cu::errln(&format!("lsusb: inventory VMO unavailable ({msg})"));
                return Err(1);
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(e) => {
                cu::errln(&format!("lsusb: query read failed: {}", e.as_str()));
                return Err(1);
            }
        }
    }
    cu::errln("lsusb: inventory VMO query timed out");
    Err(1)
}

fn report_husb_vmo(reg: &Channel, verbose: bool, log_serial: bool) -> Result<(), i32> {
    let vmo = fetch_husb_vmo(reg)?;
    let mut raw = [0u8; usb::MAX_BYTES];
    let Ok(read_len) = vmo.read(0, &mut raw) else {
        cu::errln("lsusb: failed reading HUSB VMO");
        return Err(1);
    };
    let slice = &raw[..read_len];
    let Ok(hdr) = usb::validate_and_decode_header(slice) else {
        cu::errln("lsusb: HUSB checksum or format validation failed");
        return Err(1);
    };

    let (seg, bus, dev, func) =
        unpack_pci_address(u64::from(hdr.controller_bdf_packed)).unwrap_or((0, 0, 0, 0));
    let iommu = if (hdr.flags & usb::USB_FLAG_IOMMU_ISOLATED) != 0 {
        "isolated"
    } else {
        "trusted"
    };
    let msi = (hdr.flags & usb::USB_FLAG_MSI_ACTIVE) != 0;
    let bios_handoff = (hdr.flags & usb::USB_FLAG_BIOS_HANDOFF_DONE) != 0;
    emit_line(
        &format!(
            "HUSB v1 bdf={seg:04x}:{bus:02x}:{dev:02x}.{func} hci={:#06x} gen={} slots={} ports={} iommu={} msi={} bios_handoff={} trbs={} hid_ev={} bot_io={} devices={}",
            hdr.hci_version,
            hdr.generation,
            hdr.max_slots,
            hdr.max_ports,
            iommu,
            msi,
            bios_handoff,
            hdr.completed_trbs,
            hdr.hid_events,
            hdr.bot_blocks_io,
            hdr.device_count
        ),
        log_serial,
    );

    for idx in 0..usize::from(hdr.device_count) {
        let Ok(rec) = usb::decode_device(slice, idx) else {
            continue;
        };
        let product = rec.product_str();
        let prod_disp = if product.is_empty() { "-" } else { product };
        if verbose {
            emit_line(
                &format!(
                    "  slot {:02} port {} parent {}:{} speed {} id {:04x}:{:04x} if {:02x}:{:02x}:{:02x} drv {} eps {} hub_ports {} blk {}x{} prod \"{}\"",
                    rec.slot_id,
                    rec.root_port,
                    rec.parent_slot_id,
                    rec.parent_port,
                    rec.speed.rate_label(),
                    rec.vendor_id,
                    rec.product_id,
                    rec.interface_class,
                    rec.interface_subclass,
                    rec.interface_protocol,
                    rec.role.label(),
                    rec.endpoint_count,
                    rec.hub_ports,
                    rec.bot_total_blocks,
                    rec.bot_block_size,
                    prod_disp
                ),
                log_serial,
            );
        } else {
            emit_line(
                &format!(
                    "Bus 001 Port {:02} Dev {:03}: ID {:04x}:{:04x} {} ({}) \"{}\"",
                    rec.root_port,
                    rec.slot_id,
                    rec.vendor_id,
                    rec.product_id,
                    rec.role.label(),
                    rec.speed.rate_label(),
                    prod_disp
                ),
                log_serial,
            );
        }
    }
    Ok(())
}

fn run_bot_smoke(reg: &Channel, log_serial: bool) -> Result<(), i32> {
    if reg.write(b"open:block:usb").is_err() {
        cu::errln("lsusb: failed sending open:block:usb");
        return Err(1);
    }
    let mut buf = [0u8; 128];
    let mut blk_ch: Option<Channel> = None;
    for _ in 0..6 {
        match reg.read_optional_handle_timeout(&mut buf, QUERY_WAIT_TICKS) {
            Ok((_n, Some(handle))) => {
                blk_ch = Some(Channel::from_handle(handle));
                break;
            }
            Ok((n, None)) => {
                let msg = core::str::from_utf8(&buf[..n]).unwrap_or("err:block:usb");
                cu::errln(&format!("lsusb: USB BOT unavailable ({msg})"));
                return Err(1);
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(_) => return Err(1),
        }
    }
    let Some(blk) = blk_ch else {
        cu::errln("lsusb: open:block:usb timed out");
        return Err(1);
    };

    let Ok(port) = Port::create() else {
        return Err(1);
    };
    let Ok(port_dup) = port.handle().duplicate(rights::WRITE | rights::TRANSFER) else {
        return Err(1);
    };
    if blk
        .write_handle(b"block:completion-port", port_dup)
        .is_err()
    {
        return Err(1);
    }

    let info_req = AsyncBlockRequest {
        op: AsyncBlockOp::Info,
        request_id: 1,
        namespace_id: 1,
        lba: 0,
        block_count: 0,
        buffer_id: 0,
    };
    if blk.write(&info_req.encode()).is_err() {
        return Err(1);
    }
    let mut info_raw = [0u8; 96];
    let mut info_opt: Option<AsyncBlockInfo> = None;
    for _ in 0..8 {
        match blk.read_optional_handle_timeout(&mut info_raw, QUERY_WAIT_TICKS) {
            Ok((n, None)) => {
                info_opt = AsyncBlockInfo::decode(&info_raw[..n]);
                break;
            }
            Ok((_n, Some(h))) => drop(h),
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(_) => return Err(1),
        }
    }
    let Some(info) = info_opt else {
        cu::errln("lsusb: AsyncBlockOp::Info failed");
        return Err(1);
    };
    let _ = wait_port_completion(&port, 1)?;

    let bsz = (info.block_size as usize).max(512);
    let Ok(vmo) = Vmo::create(bsz as u64) else {
        return Err(1);
    };
    let Ok(vmo_dup) = vmo.duplicate(rights::READ | rights::WRITE | rights::TRANSFER) else {
        return Err(1);
    };
    if blk
        .write_handle(b"block:buffer:0x1", vmo_dup.into_handle())
        .is_err()
    {
        return Err(1);
    }

    let rd_req = AsyncBlockRequest {
        op: AsyncBlockOp::Read,
        request_id: 2,
        namespace_id: 1,
        lba: 0,
        block_count: 1,
        buffer_id: 1,
    };
    if blk.write(&rd_req.encode()).is_err() {
        return Err(1);
    }
    let xfer = wait_port_completion(&port, 2)?;
    let mut sector0 = [0u8; 64];
    if vmo.read(0, &mut sector0) != Ok(sector0.len()) {
        return Err(1);
    }
    let prefix_end = sector0
        .iter()
        .position(|&b| b == 0 || b == b'\n')
        .unwrap_or(24)
        .min(32);
    let tag = core::str::from_utf8(&sector0[..prefix_end]).unwrap_or("binary");
    emit_line(
        &format!(
            "USB_BOT_SMOKE_OK block_size={} blocks={} xfer={} lba0_tag=\"{}\"",
            info.block_size, info.block_count, xfer, tag
        ),
        log_serial,
    );
    Ok(())
}

fn wait_port_completion(port: &Port, expected_id: u64) -> Result<u64, i32> {
    let items = [WaitItem::new(
        port.handle().raw(),
        Signals::READABLE,
        expected_id,
    )];
    for _ in 0..20 {
        let _ = wait_any(&items, 25);
        loop {
            match port.read() {
                Ok(pkt)
                    if pkt.packet_type == PORT_PACKET_BLOCK_COMPLETION
                        && pkt.data[0] == expected_id =>
                {
                    if pkt.data[1] != AsyncBlockStatus::Ok as u64 {
                        cu::errln(&format!(
                            "lsusb: block completion status={} for req={}",
                            pkt.data[1], expected_id
                        ));
                        return Err(1);
                    }
                    return Ok(pkt.data[2]);
                }
                Ok(_) => {}
                Err(ErrorCode::ShouldWait) => break,
                Err(_) => return Err(1),
            }
        }
    }
    cu::errln("lsusb: block completion timed out");
    Err(1)
}
