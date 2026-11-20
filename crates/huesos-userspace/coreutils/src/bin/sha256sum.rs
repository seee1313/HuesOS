//! `/bin/sha256sum.elf` — SHA-256 digests (FIPS 180-4).
//!
//! `sha256sum [-c] [<path>...]`
//!
//! Prints `<hex>  <path>` per input, the format `sha256sum -c` reads back. With
//! `-c` the inputs are checksum lists: each `hex  path` line is verified and a
//! per-file `OK`/`FAILED` line is printed. No path (or `-`) hashes standard
//! input, labelled `-`.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;

use huesos_std::prelude::*;

huesos_std::entry!(run);

/// SHA-256 as specified in FIPS 180-4: 64 rounds over a 32-byte state.
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length_bits: u64,
}

/// First 32 bits of the fractional parts of the square roots of the first
/// eight primes.
const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// First 32 bits of the fractional parts of the cube roots of the first
/// sixty-four primes.
const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256 {
    fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            buffer: [0u8; 64],
            buffered: 0,
            length_bits: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.length_bits = self.length_bits.wrapping_add((data.len() as u64) * 8);
        while !data.is_empty() {
            let room = 64 - self.buffered;
            let take = room.min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
    }

    fn finish(mut self) -> [u8; 32] {
        // The 0x80 terminator, zero padding to 56 mod 64, then the bit length
        // big-endian -- exactly FIPS 180-4 section 5.1.1.
        let length_bits = self.length_bits;
        self.update(&[0x80]);
        while self.buffered != 56 {
            self.update(&[0x00]);
        }
        // `update` would count these eight bytes as message; the length is
        // already recorded, so compress the final block directly.
        self.buffer[56..64].copy_from_slice(&length_bits.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut digest = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut schedule = [0u32; 64];
        for (index, word) in schedule.iter_mut().take(16).enumerate() {
            let start = index * 4;
            *word = u32::from_be_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(ROUND_CONSTANTS[index])
                .wrapping_add(schedule[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

fn hex(digest: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::new();
    for byte in digest {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    text
}

fn run() -> i32 {
    let args = args();
    let mut check = false;
    let mut operands: Vec<String> = Vec::new();
    for arg in &args {
        match arg.as_str() {
            "-c" | "--check" => check = true,
            "-h" | "--help" => {
                println!("usage: sha256sum [-c] [<path>...]");
                println!("  no path (or `-`) hashes standard input");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 && other != "-" => {
                eprintln!("sha256sum: unknown option '{other}'");
                return 2;
            }
            other => operands.push(String::from(other)),
        }
    }
    if operands.is_empty() {
        operands.push(String::from("-"));
    }
    if check {
        verify(&operands)
    } else {
        hash(&operands)
    }
}

fn hash(operands: &[String]) -> i32 {
    let mut failures = 0u32;
    for operand in operands {
        match digest_of(operand) {
            Ok(digest) => println!("{}  {}", hex(&digest), operand),
            Err(error) => {
                eprintln!("sha256sum: {operand}: {error}");
                failures += 1;
            }
        }
    }
    if failures > 0 {
        1
    } else {
        0
    }
}

fn verify(operands: &[String]) -> i32 {
    let mut failures = 0u32;
    let mut checked = 0u32;
    for operand in operands {
        let list = match read_operand(operand) {
            Ok(data) => String::from_utf8_lossy(&data).into_owned(),
            Err(error) => {
                eprintln!("sha256sum: {operand}: {error}");
                failures += 1;
                continue;
            }
        };
        for line in list.lines() {
            let Some((expected, name)) = parse_check_line(line) else {
                if !line.trim().is_empty() {
                    eprintln!("sha256sum: {operand}: malformed line '{line}'");
                    failures += 1;
                }
                continue;
            };
            checked += 1;
            match digest_of(name) {
                Ok(digest) => {
                    let actual = hex(&digest);
                    if actual == expected {
                        println!("{name}: OK");
                    } else {
                        println!("{name}: FAILED");
                        failures += 1;
                    }
                }
                Err(error) => {
                    println!("{name}: FAILED open or read ({error})");
                    failures += 1;
                }
            }
        }
    }
    if checked == 0 && failures == 0 {
        eprintln!("sha256sum: no checksums found");
        return 1;
    }
    if failures > 0 {
        println!("sha256sum: WARNING: {failures} computed checksum(s) did NOT match");
        1
    } else {
        0
    }
}

/// Split a `hex  name` line (two spaces, or one space plus `*`).
fn parse_check_line(line: &str) -> Option<(String, &str)> {
    let bytes = line.as_bytes();
    if bytes.len() < 67 {
        return None;
    }
    let expected = &line[..64];
    if !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut rest = &line[64..];
    rest = rest.strip_prefix("  ").or_else(|| rest.strip_prefix(" *"))?;
    if rest.is_empty() {
        return None;
    }
    // A checksum list written by `sha256sum` names files relative to the list,
    // so keep the name exactly as written.
    Some((String::from(expected), rest))
}

fn digest_of(operand: &str) -> Result<[u8; 32]> {
    let data = read_operand(operand)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hasher.finish())
}

fn read_operand(operand: &str) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    if operand == "-" {
        io::read_to_end(&mut io::stdin(), &mut data)?;
    } else {
        let mut file = fs::File::open(&path::normalize(operand))?;
        io::read_to_end(&mut file, &mut data)?;
    }
    Ok(data)
}
