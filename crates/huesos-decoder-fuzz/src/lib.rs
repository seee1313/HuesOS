//! Fuzzing / robustness harness for the HuesOS ACPI decoders.
//!
//! A host-testable, `no_std`, zero-dependency (besides `huesos-abi`) crate
//! that hammers the on-wire ACPI decoders with large volumes of randomized
//! input and asserts they never panic and always return a well-formed
//! `Result`. This is the first line of the Task #12 fuzzing/sanitizer effort:
//! it runs today via `cargo test -p huesos-decoder-fuzz` and is wired into
//! the AddressSanitizer CI job so the decoders are also exercised under
//! memory instrumentation.
//!
//! The decoders deliberately return `Result` rather than panicking on hostile
//! input, so the valuable property being checked is simply "no panic / no
//! out-of-bounds / no overflow" across the whole input space we can reach.

#![no_std]

#[cfg(test)]
mod tests {
    use huesos_abi::acpi_archive;
    use huesos_abi::acpi_broker::{Opcode, Request, TABLE_ARCHIVE_MAGIC};

    /// Small deterministic PRNG (Numerical Recipes LCG) so fuzz runs are
    /// reproducible across machines and CI without pulling in a random
    /// dependency or `std`.
    struct Lcg(u64);

    impl Lcg {
        fn new(seed: u64) -> Self {
            Lcg(seed)
        }

        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }

        fn byte(&mut self) -> u8 {
            (self.next() & 0xff) as u8
        }

        fn word(&mut self) -> u16 {
            (self.next() & 0xffff) as u16
        }

        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.byte();
            }
        }
    }

    #[test]
    fn fuzz_archive_decode_never_panics() {
        let mut rng = Lcg::new(0x9E37_79B9_7F4A_7C15);
        let mut buf = [0u8; 512];
        for _ in 0..10_000u32 {
            let len = (rng.next() as usize) % (buf.len() + 1);
            rng.fill(&mut buf);
            // decode returns a Result; reaching the next iteration proves it
            // did not panic on arbitrary bytes.
            if let Ok(decoded) = acpi_archive::decode(&buf[..len]) {
                // A successful decode must report the magic it validated.
                assert_eq!(decoded.header.magic, TABLE_ARCHIVE_MAGIC);
            }
        }
    }

    #[test]
    fn fuzz_request_validate_never_panics() {
        let mut rng = Lcg::new(0x1234_5678_90AB_CDEF);
        for _ in 0..10_000u32 {
            let req = Request {
                version: rng.word(),
                opcode: rng.word(),
                width: rng.byte(),
                reserved: [rng.byte(), rng.byte(), rng.byte()],
                request_id: rng.next(),
                address: rng.next(),
                value: rng.next(),
                argument: rng.next(),
            };
            // validate returns a Result; must not panic.
            let _ = req.validate();
        }
    }

    #[test]
    fn fuzz_opcode_from_raw_never_panics() {
        let mut rng = Lcg::new(0xFEED_FACE_CAFE_BEEF);
        for _ in 0..5_000u32 {
            // from_raw returns an Option for every u16; must not panic.
            let _ = Opcode::from_raw(rng.word());
        }
    }
}
