use crate::compress::{CompressFormat, get_encoder, is_compressed, parse_compress_format};
use crate::constants::*;
use crate::layouts::mod_offsets_AvbFooterLayout;
use crate::parser::{BootImage, RamdiskEntry};
use crate::sign::compute_id;
use crate::utils::{align_padding, WriteExt};
use anyhow::{bail, Result};
use std::io::{Seek, SeekFrom, Write};

pub struct BootImagePatchOption<'a> {
    source: &'a BootImage<'a>,
    replace_kernel: Option<Vec<u8>>,
    replace_ramdisk: Option<Vec<u8>>,
    replace_second: Option<Vec<u8>>,
    replace_extra: Option<Vec<u8>>,
    replace_recovery_dtbo: Option<Vec<u8>>,
    replace_dtb: Option<Vec<u8>>,
    replace_kernel_dtb: Option<Vec<u8>>,
    replace_bootconfig: Option<Vec<u8>>,
    replace_vendor_ramdisk: Vec<(usize, Vec<u8>)>,
    override_cmdline: Option<Vec<u8>>,
    override_os_version: Option<(u32, u32)>,
    no_compress: bool,
    patch_vbmeta_flags: bool,
}

impl<'a> BootImagePatchOption<'a> {
    pub fn new(source: &'a BootImage<'a>) -> Self {
        Self {
            source,
            replace_kernel: None,
            replace_ramdisk: None,
            replace_second: None,
            replace_extra: None,
            replace_recovery_dtbo: None,
            replace_dtb: None,
            replace_kernel_dtb: None,
            replace_bootconfig: None,
            replace_vendor_ramdisk: Vec::new(),
            override_cmdline: None,
            override_os_version: None,
            no_compress: false,
            patch_vbmeta_flags: false,
        }
    }

    pub fn replace_kernel(&mut self, data: Vec<u8>) -> &mut Self {
        self.replace_kernel = Some(data);
        self
    }

    pub fn replace_ramdisk(&mut self, data: Vec<u8>) -> &mut Self {
        self.replace_ramdisk = Some(data);
        self
    }

    pub fn replace_second(&mut self, data: Vec<u8>) -> &mut Self {
        self.replace_second = Some(data);
        self
    }

    pub fn replace_extra(&mut self, data: Vec<u8>) -> &mut Self {
        self.replace_extra = Some(data);
        self
    }

    pub fn replace_recovery_dtbo(&mut self, data: Vec<u8>) -> &mut Self {
        self.replace_recovery_dtbo = Some(data);
        self
    }

    pub fn replace_dtb(&mut self, data: Vec<u8>) -> &mut Self {
        self.replace_dtb = Some(data);
        self
    }

    pub fn replace_kernel_dtb(&mut self, data: Vec<u8>) -> &mut Self {
        self.replace_kernel_dtb = Some(data);
        self
    }

    pub fn replace_bootconfig(&mut self, data: Vec<u8>) -> &mut Self {
        self.replace_bootconfig = Some(data);
        self
    }

    pub fn replace_vendor_ramdisk(&mut self, index: usize, data: Vec<u8>) -> &mut Self {
        self.replace_vendor_ramdisk.push((index, data));
        self
    }

    pub fn override_cmdline(&mut self, cmdline: Vec<u8>) -> &mut Self {
        self.override_cmdline = Some(cmdline);
        self
    }

    pub fn override_os_version(&mut self, ver: u32, patch: u32) -> &mut Self {
        self.override_os_version = Some((ver, patch));
        self
    }

    pub fn no_compress(&mut self, v: bool) -> &mut Self {
        self.no_compress = v;
        self
    }

    pub fn patch_vbmeta_flags(&mut self, v: bool) -> &mut Self {
        self.patch_vbmeta_flags = v;
        self
    }

    pub fn patch<W: Write + Seek>(self, output: &mut W) -> Result<()> {
        let src = self.source;
        let header = &src.header;
        let page_sz = header.page_size_val() as usize;
        let hdr_space = header.hdr_space();

        output.seek(SeekFrom::Start(0))?;

        if src.is_dhtb {
            output.write_all(&src.data[..512])?;
        } else if src.is_blob {
            output.write_all(&src.data[..80])?;
        } else if src.is_nookhd {
            output.write_all(&src.data[src.payload_offset..src.payload_offset + NOOKHD_PRE_HEADER_SZ])?;
        } else if src.is_acclaim {
            output.write_all(&src.data[src.payload_offset..src.payload_offset + ACCLAIM_PRE_HEADER_SZ])?;
        }

        let header_off = output.seek(SeekFrom::Current(0))?;

        output.write_all(&header.data[..hdr_space.min(header.data.len())])?;

        if let Some(ref cmdline) = self.override_cmdline {
            let off = header_off + header.layout.offset_cmdline as u64;
            let max_sz = header.layout.size_cmdline as usize;
            if cmdline.len() > max_sz {
                bail!("cmdline too long: max={}, got={}", max_sz, cmdline.len());
            }
            output.seek(SeekFrom::Start(off))?;
            output.write_all(cmdline)?;
            output.write_zeros(max_sz - cmdline.len())?;
        }

        if let Some((ver, patch)) = self.override_os_version {
            if header.has_os_version_raw() {
                let off = header_off + header.layout.offset_os_version as u64;
                let os_ver = ((ver & 0x7f) << 14) | ((ver >> 8) & 0x7f) << 7;
                let patch_val = (patch & 0x7f) << 4 | (0 & 0xf);
                output.seek(SeekFrom::Start(off))?;
                output.write_all(&(os_ver << 11 | patch_val).to_le_bytes())?;
            }
        }

        output.seek(SeekFrom::Start(header_off + hdr_space as u64))?;

        let mut kernel_sz = 0u32;
        let mut ramdisk_sz = 0u32;
        let mut second_sz = 0u32;
        let mut extra_sz = 0u32;
        let mut recovery_dtbo_sz = 0u32;
        let mut recovery_dtbo_off = 0u64;
        let mut dtb_sz = 0u32;

        let _kernel_off = output.seek(SeekFrom::Current(0))?;
        let k_fmt = src.blocks.kernel.as_ref().map_or(CompressFormat::UNKNOWN, |k| k.compress_format);
        kernel_sz = write_block_optional(output, &self, &self.replace_kernel, src.blocks.kernel.as_ref().map(|k| k.data), k_fmt)?;

        let k_dtb_sz = if let Some(ref data) = self.replace_kernel_dtb {
            output.write_all(data)?;
            data.len() as u32
        } else if let Some(data) = src.blocks.kernel_dtb {
            output.write_all(data)?;
            data.len() as u32
        } else {
            0
        };
        kernel_sz += k_dtb_sz;

        let kernel_end = output.seek(SeekFrom::Current(0))?;
        let pad = align_padding(kernel_end - header_off, page_sz as u64) as usize;
        if pad > 0 {
            output.write_zeros(pad)?;
        }

        let ramdisk_off = output.seek(SeekFrom::Current(0))?;

        if let Some(ref ramdisk) = src.blocks.ramdisk {
            if let Some(ref entries) = ramdisk.vendor_entries {
                let mut new_entries: Vec<RamdiskEntry> = entries.iter().map(|e| {
                    RamdiskEntry {
                        data: e.data,
                        offset: 0,
                        size: e.size,
                        entry_type: e.entry_type,
                        compress_format: e.compress_format,
                        name: e.name,
                    }
                }).collect();

                for (idx, data) in &self.replace_vendor_ramdisk {
                    if let Some(entry) = new_entries.get_mut(*idx) {
                        let e_fmt = entry.compress_format;
                        let pos_before = output.seek(SeekFrom::Current(0))?;
                        if !self.no_compress && !is_compressed(crate::compress::parse_compress_format(data)) && is_compressed(e_fmt) {
                            let mut enc = get_encoder(e_fmt, output.by_ref())?;
                            enc.write_all(data)?;
                            enc.finish()?;
                        } else {
                            output.write_all(data)?;
                        }
                        let pos_after = output.seek(SeekFrom::Current(0))?;
                        entry.offset = (pos_before - ramdisk_off) as u32;
                        entry.size = (pos_after - pos_before) as u32;
                    }
                }

                let indices: Vec<usize> = (0..new_entries.len()).filter(|&i| {
                    !self.replace_vendor_ramdisk.iter().any(|(idx, _)| *idx == i)
                }).collect();
                for i in indices {
                    let entry = &new_entries[i];
                    let pos_before = output.seek(SeekFrom::Current(0))?;
                    output.write_all(entry.data)?;
                    let pos_after = output.seek(SeekFrom::Current(0))?;
                    let e = &mut new_entries[i];
                    e.offset = (pos_before - ramdisk_off) as u32;
                    e.size = (pos_after - pos_before) as u32;
                }

                ramdisk_sz = (output.seek(SeekFrom::Current(0))? - ramdisk_off) as u32;
            } else {
                let r_fmt = ramdisk.compress_format;
                ramdisk_sz = write_block_optional(output, &self, &self.replace_ramdisk, Some(ramdisk.data), r_fmt)?;
            }
        } else {
            ramdisk_sz = write_block_optional(output, &self, &self.replace_ramdisk, Option::<&[u8]>::None, CompressFormat::UNKNOWN)?;
        }

        let ramdisk_end = output.seek(SeekFrom::Current(0))?;
        let pad = align_padding(ramdisk_end - header_off, page_sz as u64) as usize;
        if pad > 0 {
            output.write_zeros(pad)?;
        }

        second_sz = write_block_optional(output, &self, &self.replace_second, src.blocks.second, CompressFormat::UNKNOWN)?;
        align_block(output, header_off, page_sz)?;

        extra_sz = write_block_optional(output, &self, &self.replace_extra, src.blocks.extra, CompressFormat::UNKNOWN)?;
        align_block(output, header_off, page_sz)?;

        let recovery_dtbo_pos = output.seek(SeekFrom::Current(0))?;
        recovery_dtbo_off = recovery_dtbo_pos - header_off;
        recovery_dtbo_sz = write_block_optional(output, &self, &self.replace_recovery_dtbo, src.blocks.recovery_dtbo, CompressFormat::UNKNOWN)?;
        align_block(output, header_off, page_sz)?;

        let _dtb_pos = output.seek(SeekFrom::Current(0))?;
        dtb_sz = write_block_optional(output, &self, &self.replace_dtb, src.blocks.dtb, CompressFormat::UNKNOWN)?;
        align_block(output, header_off, page_sz)?;

        if let Some(ref data) = src.blocks.signature {
            output.write_all(data)?;
            align_block(output, header_off, page_sz)?;
        }

        let _vendor_ramdisk_table_off = output.seek(SeekFrom::Current(0))?;
        let vendor_ramdisk_table_sz = if let Some(ref ramdisk) = src.blocks.ramdisk {
            if let Some(ref entries) = ramdisk.vendor_entries {
                for entry in entries {
                    let e_bytes = VendorRamdiskTableEntryPatch::serialize(entry.offset, entry.size, entry.entry_type.to_u32(), entry.name);
                    output.write_all(&e_bytes)?;
                }
                align_block(output, header_off, page_sz)?;
                entries.len() as u32 * 108
            } else {
                0
            }
        } else {
            0
        };

        let bootconfig_sz = write_block_optional(output, &self, &self.replace_bootconfig, src.blocks.bootconfig, CompressFormat::UNKNOWN)?;
        align_block(output, header_off, page_sz)?;

        let payload_end = output.seek(SeekFrom::Current(0))?;

        let mut avb_vbmeta_off = 0u64;
        let aosp_img_size = payload_end - header_off;

        if let Some(ref avb) = src.avb_info {
            align_block_size(output, 4096)?;
            avb_vbmeta_off = output.seek(SeekFrom::Current(0))?;
            output.write_all(avb.header_data)?;

            let footer_pos = output.seek(SeekFrom::Current(0))?;

            if footer_pos + AVB_FOOTER_SIZE as u64 > src.data.len() as u64 {
                output.write_all(&src.data[payload_end as usize..(src.data.len() - AVB_FOOTER_SIZE)])?;
                output.seek(SeekFrom::Start((src.data.len() - AVB_FOOTER_SIZE) as u64))?;
            } else {
                output.seek(SeekFrom::Start((src.data.len() - AVB_FOOTER_SIZE) as u64))?;
            }

            let mut footer = avb.footer_data.to_vec();
            let vbmeta_off_idx = mod_offsets_AvbFooterLayout::offset_vbmeta_offset as usize;
            let orig_sz_idx = mod_offsets_AvbFooterLayout::offset_original_image_size as usize;
            footer[vbmeta_off_idx..vbmeta_off_idx + 8].copy_from_slice(&avb_vbmeta_off.to_be_bytes());
            footer[orig_sz_idx..orig_sz_idx + 8].copy_from_slice(&aosp_img_size.to_be_bytes());
            output.write_all(&footer)?;
        } else {
            let end = output.seek(SeekFrom::Current(0))?;
            if (end as usize) < src.data.len() {
                output.write_zeros(src.data.len() - end as usize)?;
            }
        }

        let size_off = header_off + header.layout.offset_kernel_size as u64;
        output.seek(SeekFrom::Start(size_off))?;
        output.write_all(&kernel_sz.to_le_bytes())?;

        if header.has_ramdisk_size() {
            let off = header_off + header.layout.offset_ramdisk_size as u64;
            output.seek(SeekFrom::Start(off))?;
            output.write_all(&ramdisk_sz.to_le_bytes())?;
        }

        if header.has_second_size() {
            let off = header_off + header.layout.offset_second_size as u64;
            output.seek(SeekFrom::Start(off))?;
            output.write_all(&second_sz.to_le_bytes())?;
        }

        if header.has_extra_size() {
            let off = header_off + header.layout.offset_extra_size as u64;
            output.seek(SeekFrom::Start(off))?;
            output.write_all(&extra_sz.to_le_bytes())?;
        }

        if header.has_recovery_dtbo_size() {
            let off = header_off + header.layout.offset_recovery_dtbo_size as u64;
            output.seek(SeekFrom::Start(off))?;
            output.write_all(&recovery_dtbo_sz.to_le_bytes())?;

            let off_off = header_off + header.layout.offset_recovery_dtbo_offset as u64;
            output.seek(SeekFrom::Start(off_off))?;
            output.write_all(&recovery_dtbo_off.to_le_bytes())?;
        }

        if header.has_dtb_size() {
            let off = header_off + header.layout.offset_dtb_size as u64;
            output.seek(SeekFrom::Start(off))?;
            output.write_all(&dtb_sz.to_le_bytes())?;
        }

        if header.has_header_size() {
            let hsz = header.layout.total_size as u32;
            let off = header_off + header.layout.offset_header_size as u64;
            output.seek(SeekFrom::Start(off))?;
            output.write_all(&hsz.to_le_bytes())?;
        }

        if header.has_vendor_ramdisk_table_size() && vendor_ramdisk_table_sz > 0 {
            let off = header_off + header.layout.offset_vendor_ramdisk_table_size as u64;
            output.seek(SeekFrom::Start(off))?;
            output.write_all(&vendor_ramdisk_table_sz.to_le_bytes())?;
        }

        if header.has_bootconfig_size() {
            let off = header_off + header.layout.offset_bootconfig_size as u64;
            output.seek(SeekFrom::Start(off))?;
            output.write_all(&bootconfig_sz.to_le_bytes())?;
        }

        if header.has_id() {
            let empty = vec![0u8; 0];
            let mut id = compute_id(
                &empty,
                kernel_sz,
                &empty,
                ramdisk_sz,
                &empty,
                second_sz,
                &empty,
                extra_sz,
                None,
                recovery_dtbo_sz,
                if dtb_sz > 0 { Some(&empty[..]) } else { None },
                dtb_sz,
                !src.sha256_id,
            );
            id.resize(BOOT_ID_SIZE, 0);
            let off = header_off + header.layout.offset_id as u64;
            output.seek(SeekFrom::Start(off))?;
            output.write_all(&id)?;
        }

        if src.is_dhtb {
            output.seek(SeekFrom::Start(0))?;
            let dhtb_sz = (aosp_img_size + 16 + 4) as u32;
            let sz_off = 48;
            output.seek(SeekFrom::Start(sz_off))?;
            output.write_all(&dhtb_sz.to_le_bytes())?;
        } else if src.is_blob {
            let sz_off = 72;
            output.seek(SeekFrom::Start(sz_off))?;
            output.write_all(&(aosp_img_size as u32).to_le_bytes())?;
        }

        output.flush()?;
        Ok(())
    }
}

fn write_block_optional<W: Write + Seek>(
    output: &mut W,
    opts: &BootImagePatchOption,
    replacement: &Option<Vec<u8>>,
    orig: Option<&[u8]>,
    orig_fmt: CompressFormat,
) -> Result<u32> {
    if let Some(data) = replacement {
        let pos_before = output.seek(SeekFrom::Current(0))?;
        if !opts.no_compress
            && !is_compressed(parse_compress_format(data))
            && is_compressed(orig_fmt)
        {
            let mut enc = get_encoder(orig_fmt, output)?;
            enc.write_all(data)?;
            enc.finish()?;
        } else {
            output.write_all(data)?;
        }
        let pos_after = output.seek(SeekFrom::Current(0))?;
        Ok((pos_after - pos_before) as u32)
    } else if let Some(orig_data) = orig {
        output.write_all(orig_data)?;
        Ok(orig_data.len() as u32)
    } else {
        Ok(0u32)
    }
}

fn align_block<W: Write + Seek>(output: &mut W, header_off: u64, page_sz: usize) -> Result<()> {
    let pos = output.seek(SeekFrom::Current(0))?;
    let pad = align_padding(pos - header_off, page_sz as u64) as usize;
    if pad > 0 {
        output.write_zeros(pad)?;
    }
    Ok(())
}

fn align_block_size<W: Write + Seek>(output: &mut W, align: usize) -> Result<()> {
    let pos = output.seek(SeekFrom::Current(0))?;
    let pad = align_padding(pos, align as u64) as usize;
    if pad > 0 {
        output.write_zeros(pad)?;
    }
    Ok(())
}

struct VendorRamdiskTableEntryPatch;

impl VendorRamdiskTableEntryPatch {
    fn serialize(offset: u32, size: u32, entry_type: u32, name: &[u8]) -> [u8; 108] {
        let mut buf = [0u8; 108];
        buf[0..4].copy_from_slice(&size.to_le_bytes());
        buf[4..8].copy_from_slice(&offset.to_le_bytes());
        buf[8..12].copy_from_slice(&entry_type.to_le_bytes());
        let name_len = name.len().min(32);
        buf[12..12 + name_len].copy_from_slice(&name[..name_len]);
        buf
    }
}
