//! Host-side synthetic boot image builder shared by the
//! `hxfs-seed` image tool and the Stage B.5 host tests.
//!
//! The writer (`FixedHxfsWriter`) mounts an existing volume image;
//! it does not create volumes from scratch. This module builds the
//! minimal 8-block v5 boot image the writer needs: superblock,
//! checkpoint, volume table (optionally encrypted under a given
//! policy id, optionally carrying an LZ4 volume compression
//! policy), object table (root directory + an empty `seed.bin`),
//! a root dirent block, and an empty extent table. The writer then
//! overwrites `seed.bin` through the normal mutation API and
//! publishes a fresh checkpoint.
//!
//! **Test wiring only**: the layout is tailored to the synthetic
//! key context (`crate::synthetic_key`); the production install
//! path builds volumes through the streaming `mkhxfs` tooling.

use crate::crc32c::metadata_crc32c;
use crate::format::*;
use alloc::vec;
use alloc::vec::Vec;

/// Number of blocks in the boot image (LBAs 0..8).
pub const BOOT_IMAGE_BLOCKS: usize = 8;

/// Build the 8-block synthetic boot image.
///
/// `encrypted` sets `VOLUME_FLAG_ENCRYPTED` and stores
/// `encryption_policy_id`; `compression_policy_id` is stored in
/// the volume record (0 = none). The image contains the root
/// directory and an empty `seed.bin` file entry (object 2,
/// `record_count 0`) that the writer overwrites.
pub fn build_boot_image(
    instance_uuid: Uuid,
    volume_uuid: Uuid,
    encrypted: bool,
    encryption_policy_id: u32,
    compression_policy_id: u32,
) -> Vec<u8> {
    fn mk(bt: u32, owner: u64, lba: u64, payload: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        block[0..4].copy_from_slice(&bt.to_le_bytes());
        block[4..6].copy_from_slice(&1u16.to_le_bytes());
        block[6..8].copy_from_slice(&(crate::HEADER_BYTES as u16).to_le_bytes());
        block[8..16].copy_from_slice(&1u64.to_le_bytes());
        block[16..24].copy_from_slice(&owner.to_le_bytes());
        block[24..32].copy_from_slice(&lba.to_le_bytes());
        block[36..40].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        block[crate::HEADER_BYTES..crate::HEADER_BYTES + payload.len()].copy_from_slice(payload);
        let crc = metadata_crc32c(&block);
        block[32..36].copy_from_slice(&crc.to_le_bytes());
        block
    }
    fn write_object(
        out: &mut [u8],
        offset: usize,
        object_id: u64,
        object_type: u32,
        size: u64,
        tree_lba: u64,
        record_count: u32,
    ) {
        out[offset..offset + 8].copy_from_slice(&object_id.to_le_bytes());
        out[offset + 8..offset + 12].copy_from_slice(&object_type.to_le_bytes());
        out[offset + 12..offset + 16].copy_from_slice(&1u32.to_le_bytes());
        out[offset + 16..offset + 24].copy_from_slice(&size.to_le_bytes());
        out[offset + 24..offset + 32].copy_from_slice(&0i64.to_le_bytes());
        out[offset + 40..offset + 48].copy_from_slice(&tree_lba.to_le_bytes());
        out[offset + 48..offset + 52].copy_from_slice(&record_count.to_le_bytes());
    }
    let mut image: Vec<u8> = vec![0u8; BLOCK_SIZE * BOOT_IMAGE_BLOCKS];
    let mut sp = [0u8; 120];
    sp[0..16].copy_from_slice(&FORMAT_GUID);
    sp[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    sp[20..24].copy_from_slice(&TYPE_SYSTEM_VERSION.to_le_bytes());
    sp[24..40].copy_from_slice(&instance_uuid);
    sp[40..48].copy_from_slice(&1u64.to_le_bytes());
    sp[48..52].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
    sp[56..64].copy_from_slice(&1u64.to_le_bytes());
    sp[104..112].copy_from_slice(&BASE_INCOMPAT_FEATURES.to_le_bytes());
    sp[112..116].copy_from_slice(&ROOT_STATE_CLEAN.to_le_bytes());
    image[0..BLOCK_SIZE].copy_from_slice(&mk(BLOCK_TYPE_SUPERBLOCK, 0, 0, &sp));
    let mut cp = [0u8; 128];
    cp[0..8].copy_from_slice(&1u64.to_le_bytes());
    cp[8..16].copy_from_slice(&2u64.to_le_bytes());
    cp[16..20].copy_from_slice(&1u32.to_le_bytes());
    cp[24..40].copy_from_slice(&volume_uuid);
    image[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&mk(BLOCK_TYPE_CHECKPOINT, 0, 1, &cp));
    let mut vp = [0u8; 16 + crate::VOLUME_RECORD_BYTES];
    vp[0..4].copy_from_slice(&1u32.to_le_bytes());
    vp[16..32].copy_from_slice(&volume_uuid);
    vp[32..40].copy_from_slice(&1u64.to_le_bytes());
    vp[40..48].copy_from_slice(&3u64.to_le_bytes());
    vp[48..52].copy_from_slice(&2u32.to_le_bytes());
    let flags = if encrypted {
        VOLUME_FLAG_SYSTEM | VOLUME_FLAG_ENCRYPTED
    } else {
        VOLUME_FLAG_SYSTEM
    };
    vp[52..56].copy_from_slice(&flags.to_le_bytes());
    vp[56..60].copy_from_slice(&encryption_policy_id.to_le_bytes());
    vp[60..64].copy_from_slice(&compression_policy_id.to_le_bytes());
    image[BLOCK_SIZE * 2..BLOCK_SIZE * 3].copy_from_slice(&mk(BLOCK_TYPE_VOLUME_TABLE, 0, 2, &vp));
    let mut op = [0u8; 16 + 2 * crate::OBJECT_RECORD_BYTES];
    op[0..4].copy_from_slice(&2u32.to_le_bytes());
    write_object(&mut op, 16, 1, OBJECT_TYPE_DIRECTORY, 0, 4, 1);
    write_object(
        &mut op,
        16 + crate::OBJECT_RECORD_BYTES,
        2,
        OBJECT_TYPE_FILE,
        0,
        5,
        0,
    );
    image[BLOCK_SIZE * 3..BLOCK_SIZE * 4].copy_from_slice(&mk(BLOCK_TYPE_OBJECT_TABLE, 1, 3, &op));
    let mut dp = [0u8; 16 + crate::DIR_RECORD_BYTES];
    dp[0..8].copy_from_slice(&1u64.to_le_bytes());
    dp[8..12].copy_from_slice(&1u32.to_le_bytes());
    dp[16..24].copy_from_slice(&2u64.to_le_bytes());
    dp[24..26].copy_from_slice(&8u16.to_le_bytes());
    dp[26..34].copy_from_slice(b"seed.bin");
    image[BLOCK_SIZE * 4..BLOCK_SIZE * 5].copy_from_slice(&mk(BLOCK_TYPE_DIRECTORY, 1, 4, &dp));
    // Empty extent table for the empty seed.bin (record_count 0);
    // the writer never reads it, but the block keeps the image
    // self-consistent for inspectors.
    let mut ep = [0u8; 16];
    ep[0..8].copy_from_slice(&2u64.to_le_bytes());
    ep[8..12].copy_from_slice(&0u32.to_le_bytes());
    image[BLOCK_SIZE * 5..BLOCK_SIZE * 6].copy_from_slice(&mk(BLOCK_TYPE_EXTENT_TABLE, 2, 5, &ep));
    image
}
