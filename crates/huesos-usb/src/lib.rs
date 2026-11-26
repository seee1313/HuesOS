//! `#![no_std]` `#![forbid(unsafe_code)]` USB 3.x (`xHCI` 1.x), Chapter 9, Hub, HID,
//! Mass Storage Bulk-Only Transport (`BOT` / SCSI), and `hues-async` TRB completion
//! futures crate for HuesOS Ring-3 drivers.

#![no_std]
#![forbid(unsafe_code)]

pub mod async_io;
pub mod bot;
pub mod ch9;
pub mod hid;
pub mod hub;
pub mod xhci;

#[cfg(test)]
mod tests {
    use super::async_io::{TrbCompletionTable, TrbOutcome};
    use super::bot::{
        CommandBlockWrapper, CommandStatusWrapper, CswStatus, ScsiCapacity, CBW_BYTES,
        CBW_SIGNATURE, CSW_SIGNATURE,
    };
    use super::ch9::{
        decode_usb_string_ascii, ConfigurationDescriptor, DescriptorIter, DeviceDescriptor,
        ParsedDescriptor, SetupPacket, DESC_CONFIGURATION, DESC_DEVICE, DESC_ENDPOINT,
        DESC_INTERFACE, DESC_SS_EP_COMPANION, DESC_STRING, USB_CLASS_HID, USB_CLASS_MASS_STORAGE,
    };
    use super::hid::{HidBootKeyboard, HidKeyEvent, HidMouseEvent, KEY_ARROW_UP, MAX_HID_KEY_EVENTS};
    use super::hub::{append_route_port, HubDescriptor, HubPortStatus};
    use super::xhci::{
        init_input_context, portsc_preserve_rw, set_input_endpoint_context, usb_interval_to_xhci,
        CompletionCode, DecodedEvent, EndpointContextParams, EventRingConsumer, ProducerRing,
        SlotContextParams, Trb, XhciCapabilities, XhciEndpointType, PORTSC_PED, PORTSC_PP,
        PORTSC_PR, TRB_TYPE_CMD_COMPLETION, TRB_TYPE_PORT_STATUS_CHANGE,
    };
    use core::cell::Cell;
    use hues_async::{block_on, Executor, TaskId};
    use huesos_abi::usb::UsbSpeedAbi;

    #[test]
    fn portsc_w1c_mask_never_clears_ped_or_change_flags() {
        let raw = PORTSC_PP | PORTSC_PED | (4 << 10) | (1 << 17) | (1 << 21);
        let preserved = portsc_preserve_rw(raw);
        assert_eq!(preserved & PORTSC_PP, PORTSC_PP);
        assert_eq!(preserved & PORTSC_PED, 0);
        assert_eq!(preserved & (1 << 17), 0);
        assert_eq!(preserved & (1 << 21), 0);
        let reset_cmd = preserved | PORTSC_PR;
        assert_eq!(reset_cmd & PORTSC_PED, 0);
        assert_eq!(reset_cmd & PORTSC_PR, PORTSC_PR);
    }

    #[test]
    fn producer_ring_wraps_with_link_trb_and_toggles_pcs() {
        let mut ring = ProducerRing::new(0x1000_0000, 4);
        let e0 = ring.enqueue(Trb::cmd_enable_slot());
        let e1 = ring.enqueue(Trb::cmd_enable_slot());
        let e2 = ring.enqueue(Trb::cmd_enable_slot());
        assert_eq!(e0.trb_iova, 0x1000_0000);
        assert!(e0.wrap_link.is_none());
        assert_eq!(e1.trb_iova, 0x1000_0010);
        assert_eq!(e2.trb_iova, 0x1000_0020);

        // Enqueueing when at slot 3 emits the Link TRB at index 3 (cycle=true) and wraps to 0 (cycle=false).
        let e3 = ring.enqueue(Trb::cmd_disable_slot(2));
        let Some((link_idx, link_trb)) = e3.wrap_link else {
            assert!(false);
            return;
        };
        assert_eq!(link_idx, 3);
        assert_eq!(link_trb.param_u64(), 0x1000_0000);
        assert!(link_trb.cycle());
        assert_eq!(e3.slot_index, 0);
        assert_eq!(e3.trb_iova, 0x1000_0000);
        assert!(!e3.trb.cycle());
    }

    #[test]
    fn event_ring_consumer_tracks_ccs_across_wrap() {
        let mut consumer = EventRingConsumer::new(0x2000_0000, 2);
        assert!(consumer.try_consume(Trb::ZERO).is_none());

        let trb0 = Trb {
            d0: 0x1000_0000,
            d1: 0,
            d2: 1 << 24,
            d3: ((TRB_TYPE_CMD_COMPLETION as u32) << 10) | (3 << 24) | 1,
        };
        let trb1 = Trb {
            d0: 4 << 24,
            d1: 0,
            d2: 1 << 24,
            d3: ((TRB_TYPE_PORT_STATUS_CHANGE as u32) << 10) | 1,
        };
        let Some(ev0) = consumer.try_consume(trb0) else {
            assert!(false);
            return;
        };
        assert_eq!(
            ev0,
            DecodedEvent::CommandCompletion {
                cmd_trb_iova: 0x1000_0000,
                code: CompletionCode::Success,
                slot_id: 3,
            }
        );
        assert_eq!(consumer.erdp_with_ehb(), 0x2000_0018);

        let Some(ev1) = consumer.try_consume(trb1) else {
            assert!(false);
            return;
        };
        assert_eq!(
            ev1,
            DecodedEvent::PortStatusChange {
                port_id: 4,
                code: CompletionCode::Success,
            }
        );
        assert_eq!(consumer.erdp_with_ehb(), 0x2000_0008);
        assert!(!consumer.cycle());
        assert!(consumer.try_consume(trb0).is_none());
    }

    #[test]
    fn context_builders_and_route_string_encode_64byte_csz_cleanly() {
        let Some(caps) = XhciCapabilities::parse(
            0x0100_0040,
            (8 << 24) | 64,
            0,
            (0x200 << 16) | (1 << 2) | 1,
            0x1000,
            0x2000,
        ) else {
            assert!(false);
            return;
        };
        assert_eq!(caps.context_size, 64);

        let mut buf = [0u8; 33 * 64];
        let route = append_route_port(0, 2).unwrap_or(0);
        let route2 = append_route_port(route, 5).unwrap_or(0);
        assert_eq!(route2, 0x52);

        let slot = SlotContextParams {
            route_string: route2,
            speed: UsbSpeedAbi::Super,
            context_entries: 3,
            root_hub_port: 1,
            is_hub: false,
            num_ports: 0,
            tt_hub_slot_id: 0,
            tt_port_number: 0,
        };
        assert!(init_input_context(&mut buf, 64, 0, 0x9, &slot));
        let d0 = u32::from_le_bytes([buf[64], buf[65], buf[66], buf[67]]);
        assert_eq!(d0 & 0x000F_FFFF, 0x52);
        assert_eq!((d0 >> 20) & 0xF, 4);
        assert_eq!((d0 >> 27) & 0x1F, 3);

        let ep = EndpointContextParams {
            dci: 3,
            ep_type: XhciEndpointType::InterruptIn,
            max_packet_size: 8,
            max_burst: 0,
            interval: usb_interval_to_xhci(UsbSpeedAbi::High, 4, true),
            tr_dequeue_ptr_with_dcs: 0x7000_1001,
            avg_trb_len: 8,
        };
        assert!(set_input_endpoint_context(&mut buf, 64, &ep));
        let ep_d2 = u32::from_le_bytes([buf[264], buf[265], buf[266], buf[267]]);
        assert_eq!(ep_d2, 0x7000_1001);
    }

    #[test]
    fn ch9_descriptors_and_utf16_strings_parse_cleanly() {
        let setup = SetupPacket::get_descriptor(DESC_DEVICE, 0, 0, 18);
        assert_eq!(setup.to_le_u64(), 0x0012_0000_0100_0680);

        let dev_raw = [
            18,
            DESC_DEVICE,
            0x00,
            0x03,
            0,
            0,
            0,
            9,
            0xF4,
            0x46,
            0x01,
            0x00,
            0x00,
            0x02,
            1,
            2,
            3,
            1,
        ];
        let Some(dev) = DeviceDescriptor::parse(&dev_raw) else {
            assert!(false);
            return;
        };
        assert_eq!(dev.ep0_max_packet_size(), 512);
        assert_eq!(dev.vendor_id, 0x46F4);
        assert_eq!(dev.product_id, 0x0001);

        let cfg_blob = [
            9,
            DESC_CONFIGURATION,
            31,
            0,
            1,
            1,
            0,
            0x80,
            250,
            9,
            DESC_INTERFACE,
            0,
            0,
            1,
            USB_CLASS_HID,
            1,
            1,
            0,
            7,
            DESC_ENDPOINT,
            0x81,
            0x03,
            8,
            0,
            10,
            6,
            DESC_SS_EP_COMPANION,
            3,
            0,
            0,
            0,
        ];
        let Some(hdr) = ConfigurationDescriptor::parse_header(&cfg_blob) else {
            assert!(false);
            return;
        };
        assert_eq!(hdr.configuration_value, 1);
        let mut it = DescriptorIter::new(&cfg_blob);
        assert!(matches!(it.next(), Some(ParsedDescriptor::Interface(_))));
        let Some(ParsedDescriptor::Endpoint(ep)) = it.next() else {
            assert!(false);
            return;
        };
        assert_eq!(ep.xhci_dci(), Some(3));
        assert_eq!(ep.xhci_ep_type(), Some(XhciEndpointType::InterruptIn));
        assert_eq!(
            it.next(),
            Some(ParsedDescriptor::SsCompanion { max_burst: 3 })
        );
        assert_eq!(it.next(), None);

        let str_raw = [10, DESC_STRING, b'Q', 0, b'E', 0, b'M', 0, b'U', 0];
        let mut ascii = [0u8; 16];
        let n = decode_usb_string_ascii(&str_raw, &mut ascii);
        assert_eq!(&ascii[..n], b"QEMU");
        assert_eq!(USB_CLASS_MASS_STORAGE, 0x08);
    }

    #[test]
    fn hub_hid_and_bot_protocols_encode_and_decode() {
        let hub_raw = [9, 0x29, 4, 0x09, 0x00, 50, 0, 0, 0xFF];
        let Some(hub) = HubDescriptor::parse(&hub_raw) else {
            assert!(false);
            return;
        };
        assert_eq!(hub.num_ports, 4);
        assert!(!hub.is_superspeed);
        let ps = HubPortStatus::decode([0x03, 0x02, 0x01, 0x00], false);
        assert!(ps.connected);
        assert!(ps.enabled);
        assert_eq!(ps.speed, UsbSpeedAbi::Low);

        let mut kbd = HidBootKeyboard::new();
        let mut evs = [HidKeyEvent {
            key: 0,
            pressed: false,
        }; MAX_HID_KEY_EVENTS];
        let n1 = kbd.feed_report(&[0x02, 0, 0x04, 0x52, 0, 0, 0, 0], &mut evs);
        assert_eq!(n1, 2);
        assert_eq!(evs[0].to_wire(), [b'k', 1, b'A']);
        assert_eq!(evs[1].to_wire(), [b'k', 1, KEY_ARROW_UP]);
        let n2 = kbd.feed_report(&[0, 0, 0, 0, 0, 0, 0, 0], &mut evs);
        assert_eq!(n2, 2);
        assert_eq!(evs[0].to_wire(), [b'k', 0, b'A']);

        let Some(mouse) = HidMouseEvent::decode(&[0x01, 0xFB, 0x05, 0xFF]) else {
            assert!(false);
            return;
        };
        assert_eq!(mouse.buttons, 1);
        assert_eq!(mouse.dx, -5);
        assert_eq!(mouse.dy, 5);
        assert_eq!(mouse.wheel, -1);

        let Some(cbw) = CommandBlockWrapper::scsi_read10(0xCAFE_BABE, 0, 64, 8, 512) else {
            assert!(false);
            return;
        };
        let cbw_bytes = cbw.to_bytes();
        assert_eq!(cbw_bytes.len(), CBW_BYTES);
        assert_eq!(
            u32::from_le_bytes([cbw_bytes[0], cbw_bytes[1], cbw_bytes[2], cbw_bytes[3]]),
            CBW_SIGNATURE
        );

        let mut csw_raw = [0u8; 13];
        csw_raw[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        csw_raw[4..8].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());
        let Some(csw) = CommandStatusWrapper::decode(&csw_raw, 0xCAFE_BABE) else {
            assert!(false);
            return;
        };
        assert_eq!(csw.status, CswStatus::Passed);

        let Some(cap) = ScsiCapacity::from_read_capacity10(&[0, 0, 0x0F, 0xFF, 0, 0, 0x02, 0])
        else {
            assert!(false);
            return;
        };
        assert_eq!(cap.total_blocks, 4096);
        assert_eq!(cap.block_size, 512);
    }

    #[test]
    fn trb_completion_table_wakes_hues_async_tasks_zero_heap() {
        let table: TrbCompletionTable<8> = TrbCompletionTable::new();
        let completed_ok = Cell::new(false);
        let Some(ticket) = table.register(0xDEAD_1000, 2) else {
            assert!(false);
            return;
        };
        let parked = Cell::new(0u32);

        block_on(
            async {
                if let Some(outcome) = table.wait(ticket).await {
                    completed_ok.set(outcome.code == CompletionCode::ShortPacket);
                }
            },
            || {
                parked.set(parked.get() + 1);
                let woke = table.complete_by_trb(
                    0xDEAD_1000,
                    TrbOutcome {
                        code: CompletionCode::ShortPacket,
                        residual_len: 4,
                        slot_id: 2,
                        dci: 3,
                    },
                );
                assert!(woke);
            },
        );
        assert_eq!(parked.get(), 1);
        assert!(completed_ok.get());

        let exec: Executor<4, 128> = Executor::new();
        let tid = exec.spawn(hues_async::yield_now()).unwrap_or(TaskId::INVALID);
        assert_ne!(tid, TaskId::INVALID);
        assert_eq!(exec.poll(), 2);
        assert!(exec.is_empty());
    }
}
