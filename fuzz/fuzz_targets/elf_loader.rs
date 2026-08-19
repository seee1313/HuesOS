#![no_main]

use huesos_elf::{Loader, SegmentFlags};
use libfuzzer_sys::fuzz_target;

struct RejectMappings;

impl Loader for RejectMappings {
    type Error = ();

    fn map_zeroed_page(
        &mut self,
        _vaddr: u64,
        _flags: SegmentFlags,
    ) -> Result<*mut u8, Self::Error> {
        Err(())
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = huesos_elf::load(data, &mut RejectMappings);
});
