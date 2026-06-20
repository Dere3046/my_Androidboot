use anyhow::Result;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use crate::constants::*;

const BOOT_SIGNATURE_MAGIC: &[u8] = b"Brsgn";
const BOOT_SIGNATURE_SIZE: usize = 32 * 1024;

pub fn sha1_hash(data: &[u8]) -> [u8; SHA1_DIGEST_SIZE] {
    use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
    let d = digest(&SHA1_FOR_LEGACY_USE_ONLY, data);
    let mut out = [0u8; SHA1_DIGEST_SIZE];
    out.copy_from_slice(d.as_ref());
    out
}

pub fn sha256_hash(data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    use ring::digest::{digest, SHA256};
    let d = digest(&SHA256, data);
    let mut out = [0u8; SHA256_DIGEST_SIZE];
    out.copy_from_slice(d.as_ref());
    out
}

pub fn compute_id(
    kernel: &[u8],
    kernel_size: u32,
    ramdisk: &[u8],
    ramdisk_size: u32,
    second: &[u8],
    second_size: u32,
    extra: &[u8],
    extra_size: u32,
    recovery_dtbo_data: Option<&[u8]>,
    recovery_dtbo_size: u32,
    dtb_data: Option<&[u8]>,
    dtb_size: u32,
    use_sha1: bool,
) -> Vec<u8> {
    let digest_size = if use_sha1 { SHA1_DIGEST_SIZE } else { SHA256_DIGEST_SIZE };
    let mut out = vec![0u8; digest_size];

    if use_sha1 {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
        ctx.update(kernel);
        ctx.update(&kernel_size.to_le_bytes());
        ctx.update(ramdisk);
        ctx.update(&ramdisk_size.to_le_bytes());
        ctx.update(second);
        ctx.update(&second_size.to_le_bytes());
        if extra_size > 0 {
            ctx.update(extra);
            ctx.update(&extra_size.to_le_bytes());
        }
        if let Some(data) = recovery_dtbo_data {
            ctx.update(data);
            ctx.update(&recovery_dtbo_size.to_le_bytes());
        }
        if let Some(data) = dtb_data {
            ctx.update(data);
            ctx.update(&dtb_size.to_le_bytes());
        }
        let digest = ctx.finish();
        out.copy_from_slice(digest.as_ref());
    } else {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        ctx.update(kernel);
        ctx.update(&kernel_size.to_le_bytes());
        ctx.update(ramdisk);
        ctx.update(&ramdisk_size.to_le_bytes());
        ctx.update(second);
        ctx.update(&second_size.to_le_bytes());
        if extra_size > 0 {
            ctx.update(extra);
            ctx.update(&extra_size.to_le_bytes());
        }
        if let Some(data) = recovery_dtbo_data {
            ctx.update(data);
            ctx.update(&recovery_dtbo_size.to_le_bytes());
        }
        if let Some(data) = dtb_data {
            ctx.update(data);
            ctx.update(&dtb_size.to_le_bytes());
        }
        let digest = ctx.finish();
        out.copy_from_slice(digest.as_ref());
    }

    out
}

pub fn sign_boot_image(payload: &[u8], pk8_bytes: &[u8]) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pk8_bytes, &rng)
        .map_err(|e| anyhow::anyhow!("failed to load key: {}", e))?;

    let signature = key_pair.sign(&rng, payload)
        .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;
    let sig_bytes = signature.as_ref();

    let mut sig_block = Vec::with_capacity(BOOT_SIGNATURE_SIZE);
    sig_block.extend_from_slice(BOOT_SIGNATURE_MAGIC);
    sig_block.extend_from_slice(&(sig_bytes.len() as u32).to_le_bytes());
    sig_block.extend_from_slice(sig_bytes);

    while sig_block.len() < BOOT_SIGNATURE_SIZE {
        sig_block.push(0);
    }

    Ok(sig_block)
}

pub fn verify_boot_image(payload: &[u8]) -> bool {
    if payload.len() < BOOT_SIGNATURE_SIZE {
        return false;
    }
    let sig_start = payload.len() - BOOT_SIGNATURE_SIZE;
    let sig_data = &payload[sig_start..];
    sig_data.starts_with(BOOT_SIGNATURE_MAGIC)
}
