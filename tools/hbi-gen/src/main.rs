use clap::Parser;
use crc32fast::Hasher;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "HuesOS signed Boot Image Generator v2.2")]
struct Args {
    #[arg(short, long)]
    kernel: PathBuf,
    #[arg(short, long)]
    bootfs: PathBuf,
    #[arg(short, long)]
    cmdline: PathBuf,
    #[arg(short, long)]
    platform: PathBuf,
    #[arg(short, long)]
    output: PathBuf,
    /// PKCS#8 PEM Ed25519 private key. Production keys must live outside the repository.
    #[arg(long)]
    signing_key: PathBuf,
    /// Optional signed TPM sealed-key module produced after PCR provisioning.
    #[arg(long)]
    sealed_key: Option<PathBuf>,
}

#[derive(Clone, Copy)]
struct DirectoryEntry {
    type_id: u32,
    offset: u32,
    length: u32,
    flags: u32,
}

const GLOBAL_HEADER_BYTES: usize = 72;
const DIRECTORY_ENTRY_BYTES: usize = 16;
const ENTRY_HEADER_BYTES: usize = 24;
const SIGNATURE_TRAILER_BYTES: usize = 72;
const HBI_VERSION: u32 = 0x0002_0002;
const HBI_FLAG_SIGNED: u32 = 1;
const SIGNATURE_ALGORITHM_ED25519: u32 = 1;
const SIGNATURE_MAGIC: &[u8; 8] = b"HUESIG1\0";

const TYPE_KERNEL: u32 = 1;
const TYPE_BOOTFS: u32 = 2;
const TYPE_CMDLINE: u32 = 3;
const TYPE_PLATFORM: u32 = 4;
const TYPE_SEALED_KEY: u32 = 5;

const FLAG_REQUIRED: u32 = 0x8000_0000;
const FLAG_CRITICAL: u32 = 0x4000_0000;
const FLAG_EXECUTABLE: u32 = 0x0000_0004;

fn align_up(value: usize, align: usize) -> Result<usize, &'static str> {
    value
        .checked_add(align - 1)
        .map(|sum| sum & !(align - 1))
        .ok_or("HBI offset overflow")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let private_pem = fs::read_to_string(&args.signing_key)?;
    let signing_key = SigningKey::from_pkcs8_pem(&private_pem)?;

    let mut payloads: Vec<(u32, Vec<u8>, u32, u32)> = vec![
        (
            TYPE_KERNEL,
            fs::read(&args.kernel)?,
            FLAG_REQUIRED | FLAG_CRITICAL | FLAG_EXECUTABLE,
            0,
        ),
        (
            TYPE_BOOTFS,
            fs::read(&args.bootfs)?,
            FLAG_REQUIRED | FLAG_CRITICAL,
            0,
        ),
        (TYPE_CMDLINE, fs::read(&args.cmdline)?, 0, 0),
        (
            TYPE_PLATFORM,
            fs::read(&args.platform)?,
            FLAG_REQUIRED | FLAG_CRITICAL,
            0,
        ),
    ];
    if let Some(path) = &args.sealed_key {
        payloads.push((
            TYPE_SEALED_KEY,
            fs::read(path)?,
            FLAG_REQUIRED | FLAG_CRITICAL,
            0,
        ));
    }

    let header_size = GLOBAL_HEADER_BYTES
        .checked_add(payloads.len() * DIRECTORY_ENTRY_BYTES)
        .ok_or("HBI header overflow")?;
    let mut current_offset = align_up(header_size, 8)?;
    let mut directory = Vec::with_capacity(payloads.len());
    for (type_id, data, flags, _) in &payloads {
        let length = u32::try_from(data.len()).map_err(|_| "HBI payload exceeds u32")?;
        directory.push(DirectoryEntry {
            type_id: *type_id,
            offset: u32::try_from(current_offset).map_err(|_| "HBI offset exceeds u32")?,
            length,
            flags: *flags,
        });
        current_offset = current_offset
            .checked_add(ENTRY_HEADER_BYTES)
            .and_then(|value| value.checked_add(align_up(data.len(), 8).ok()?))
            .ok_or("HBI image overflow")?;
    }
    let signed_len = current_offset;
    let image_size = signed_len
        .checked_add(SIGNATURE_TRAILER_BYTES)
        .ok_or("HBI signature trailer overflow")?;

    let mut image = Vec::new();
    image
        .try_reserve_exact(image_size)
        .map_err(|_| "cannot allocate HBI image")?;
    write_global_header(
        &mut image,
        payloads.len(),
        header_size,
        image_size,
        signed_len,
    )?;
    for entry in &directory {
        push_u32(&mut image, entry.type_id);
        push_u32(&mut image, entry.offset);
        push_u32(&mut image, entry.length);
        push_u32(&mut image, entry.flags);
    }
    image.resize(align_up(image.len(), 8)?, 0);

    for (type_id, data, flags, extra) in &payloads {
        if image.len() != directory
            .iter()
            .find(|entry| entry.type_id == *type_id)
            .map(|entry| entry.offset as usize)
            .ok_or("directory entry missing")?
        {
            return Err("directory/payload offset drift".into());
        }
        let mut hasher = Hasher::new();
        hasher.update(data);
        push_u32(&mut image, *type_id);
        push_u32(&mut image, *flags);
        push_u32(
            &mut image,
            u32::try_from(data.len()).map_err(|_| "payload length overflow")?,
        );
        push_u32(&mut image, *extra);
        push_u32(&mut image, hasher.finalize());
        push_u32(&mut image, 0);
        image.extend_from_slice(data);
        image.resize(align_up(image.len(), 8)?, 0);
    }
    if image.len() != signed_len {
        return Err("signed length drift".into());
    }

    let signature = signing_key.sign(&image);
    image.extend_from_slice(SIGNATURE_MAGIC);
    image.extend_from_slice(&signature.to_bytes());
    if image.len() != image_size {
        return Err("final image size drift".into());
    }
    fs::write(&args.output, &image)?;
    println!("Signed HBI v2.2 image created at {:?}", args.output);
    println!("Signed bytes: {signed_len}; total bytes: {image_size}");
    Ok(())
}

fn write_global_header(
    out: &mut Vec<u8>,
    entries: usize,
    header_size: usize,
    image_size: usize,
    signed_len: usize,
) -> Result<(), &'static str> {
    out.extend_from_slice(b"HUESOS_H");
    push_u32(out, HBI_VERSION);
    push_u32(out, HBI_FLAG_SIGNED);
    push_u32(out, u32::try_from(entries).map_err(|_| "entry count overflow")?);
    push_u32(
        out,
        u32::try_from(header_size).map_err(|_| "header size overflow")?,
    );
    push_u64(
        out,
        u64::try_from(image_size).map_err(|_| "image size overflow")?,
    );
    push_u32(out, 0); // x86_64 architecture id
    let mut reserved = [0u8; 36];
    reserved[0..4].copy_from_slice(&SIGNATURE_ALGORITHM_ED25519.to_le_bytes());
    reserved[4..8].copy_from_slice(&(SIGNATURE_TRAILER_BYTES as u32).to_le_bytes());
    reserved[8..16].copy_from_slice(
        &u64::try_from(signed_len)
            .map_err(|_| "signed size overflow")?
            .to_le_bytes(),
    );
    out.extend_from_slice(&reserved);
    if out.len() != GLOBAL_HEADER_BYTES {
        return Err("global header layout drift");
    }
    Ok(())
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
