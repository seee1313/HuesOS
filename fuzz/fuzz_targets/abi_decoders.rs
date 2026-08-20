#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = huesos_abi::acpi_archive::decode(data);
    let _ = huesos_abi::storage_boot::decode(data);
    let _ = huesos_abi::pci::decode(data);
    let _ = huesos_abi::key_broker::GrantRequest::decode(data);
    let _ = huesos_abi::key_broker::GrantReply::decode(data);
});
