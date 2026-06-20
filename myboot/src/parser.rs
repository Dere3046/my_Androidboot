use crate::compress::{CompressFormat, parse_compress_format};
use crate::constants::*;
use crate::layouts::{
    BootHeaderLayout, BOOT_HEADER_V0, BOOT_HEADER_V1, BOOT_HEADER_V2, BOOT_HEADER_V3, BOOT_HEADER_V4,
    VENDOR_BOOT_HEADER_V3, VENDOR_BOOT_HEADER_V4, PXA_HEADER_LAYOUT,
    mod_offsets_AvbFooterLayout,
    mod_offsets_VendorRamdiskTableEntryV4,
};
use crate::utils::{SliceExt, align_to, trim_end};
use anyhow::{bail, Result};
use paste::paste;
use std::fmt::{Display, Formatter};

#[derive(Debug, Copy, Clone)]
pub enum BootImageVersion {
    Android(u32),
    Vendor(u32),
}

impl Display for BootImageVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BootImageVersion::Android(v) => write!(f, "Android v{}", v),
            BootImageVersion::Vendor(v) => write!(f, "Vendor v{}", v),
        }
    }
}

pub struct OsVersion {
    pub a: u32,
    pub b: u32,
    pub c: u32,
}

impl Display for OsVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.a, self.b, self.c)
    }
}

pub struct PatchLevel {
    pub year: u32,
    pub month: u32,
}

impl Display for PatchLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{:02}", self.year, self.month)
    }
}

#[derive(Debug, Copy, Clone)]
pub enum VendorRamdiskType {
    None,
    Platform,
    Recovery,
    Dlkm,
    Unknown(u32),
}

impl VendorRamdiskType {
    pub fn to_u32(&self) -> u32 {
        match self {
            VendorRamdiskType::None => 0,
            VendorRamdiskType::Platform => 1,
            VendorRamdiskType::Recovery => 2,
            VendorRamdiskType::Dlkm => 3,
            VendorRamdiskType::Unknown(v) => *v,
        }
    }
}

impl Display for VendorRamdiskType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VendorRamdiskType::None => write!(f, "none"),
            VendorRamdiskType::Platform => write!(f, "platform"),
            VendorRamdiskType::Recovery => write!(f, "recovery"),
            VendorRamdiskType::Dlkm => write!(f, "dlkm"),
            VendorRamdiskType::Unknown(v) => write!(f, "unknown({})", v),
        }
    }
}

#[derive(Copy, Clone)]
pub struct VendorRamdiskTableEntry<'a> {
    pub data: &'a [u8],
}

impl<'a> VendorRamdiskTableEntry<'a> {
    pub fn get_ramdisk_size(&self) -> u32 {
        u32::from_le_bytes(
            self.data[mod_offsets_VendorRamdiskTableEntryV4::offset_ramdisk_size
                ..mod_offsets_VendorRamdiskTableEntryV4::offset_ramdisk_size + 4]
                .try_into()
                .unwrap(),
        )
    }

    pub fn get_ramdisk_offset(&self) -> u32 {
        u32::from_le_bytes(
            self.data[mod_offsets_VendorRamdiskTableEntryV4::offset_ramdisk_offset
                ..mod_offsets_VendorRamdiskTableEntryV4::offset_ramdisk_offset + 4]
                .try_into()
                .unwrap(),
        )
    }

    pub fn get_ramdisk_type(&self) -> VendorRamdiskType {
        let raw = u32::from_le_bytes(
            self.data[mod_offsets_VendorRamdiskTableEntryV4::offset_ramdisk_type
                ..mod_offsets_VendorRamdiskTableEntryV4::offset_ramdisk_type + 4]
                .try_into()
                .unwrap(),
        );
        match raw {
            VENDOR_RAMDISK_TYPE_NONE => VendorRamdiskType::None,
            VENDOR_RAMDISK_TYPE_PLATFORM => VendorRamdiskType::Platform,
            VENDOR_RAMDISK_TYPE_RECOVERY => VendorRamdiskType::Recovery,
            VENDOR_RAMDISK_TYPE_DLKM => VendorRamdiskType::Dlkm,
            _ => VendorRamdiskType::Unknown(raw),
        }
    }

    pub fn get_ramdisk_name(&self) -> &[u8] {
        let off = mod_offsets_VendorRamdiskTableEntryV4::offset_ramdisk_name;
        let sz = mod_offsets_VendorRamdiskTableEntryV4::size_ramdisk_name;
        &self.data[off..off + sz]
    }

    pub fn get_board_id(&self) -> &[u8] {
        let off = mod_offsets_VendorRamdiskTableEntryV4::offset_board_id;
        let sz = mod_offsets_VendorRamdiskTableEntryV4::size_board_id;
        &self.data[off..off + sz]
    }

    pub const SIZE: usize = mod_offsets_VendorRamdiskTableEntryV4::total_size;

    pub fn patch(&self, ramdisk_size: u32, ramdisk_offset: u32) -> Vec<u8> {
        let mut v = self.data.to_owned();
        v[mod_offsets_VendorRamdiskTableEntryV4::offset_ramdisk_size
            ..mod_offsets_VendorRamdiskTableEntryV4::offset_ramdisk_size + 4]
            .copy_from_slice(&ramdisk_size.to_le_bytes());
        v[mod_offsets_VendorRamdiskTableEntryV4::offset_ramdisk_offset
            ..mod_offsets_VendorRamdiskTableEntryV4::offset_ramdisk_offset + 4]
            .copy_from_slice(&ramdisk_offset.to_le_bytes());
        v
    }
}

pub struct BootHeader<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) layout: &'static BootHeaderLayout,
    pub(crate) version: BootImageVersion,
}

macro_rules! impl_ifield_accessor {
    ($vis:vis, $t:ty, $name:ident $(,$suffix:ident)?) => {
        paste! {
            $vis fn [<has_ $name $($suffix)?>](&self) -> bool {
                self.layout.[<offset_ $name>] != 0
            }
            $vis fn [<get_ $name $($suffix)?>](&self) -> $t {
                let offset = self.layout.[<offset_ $name>] as usize;
                <$t>::from_le_bytes(self.data[offset..offset + std::mem::size_of::<$t>()].try_into().unwrap())
            }
        }
    };
}

macro_rules! impl_sfield_accessor {
    ($vis:vis, $name:ident $(,$suffix:ident)?) => {
        paste! {
            $vis fn [<has_ $name $($suffix)?>](&self) -> bool {
                self.layout.[<offset_ $name>] != 0
            }
            $vis fn [<get_ $name $($suffix)?>](&self) -> &[u8] {
                let offset = self.layout.[<offset_ $name>] as usize;
                let sz = self.layout.[<size_ $name>] as usize;
                &self.data[offset..offset + sz]
            }
        }
    };
}

impl<'a> BootHeader<'a> {
    impl_ifield_accessor! { pub, u32, kernel_size }
    impl_ifield_accessor! { pub, u32, ramdisk_size }
    impl_ifield_accessor! { pub, u32, second_size }
    impl_ifield_accessor! { pub, u32, page_size }
    impl_ifield_accessor! { pub, u32, header_version }
    impl_ifield_accessor! { pub, u32, os_version, _raw }
    impl_ifield_accessor! { pub, u32, extra_size }
    impl_ifield_accessor! { pub, u32, recovery_dtbo_size }
    impl_ifield_accessor! { pub, u64, recovery_dtbo_offset }
    impl_ifield_accessor! { pub, u32, header_size }
    impl_ifield_accessor! { pub, u32, dtb_size }
    impl_ifield_accessor! { pub, u32, signature_size }
    impl_ifield_accessor! { pub, u32, vendor_ramdisk_table_size }
    impl_ifield_accessor! { pub, u32, vendor_ramdisk_table_entry_num }
    impl_ifield_accessor! { pub, u32, vendor_ramdisk_table_entry_size }
    impl_ifield_accessor! { pub, u32, bootconfig_size }
    impl_sfield_accessor! { pub, name }
    impl_sfield_accessor! { pub, cmdline }
    impl_sfield_accessor! { pub, id }
    impl_sfield_accessor! { pub, extra_cmdline }

    pub fn get_layout(&self) -> &'static BootHeaderLayout {
        self.layout
    }

    pub fn get_version(&self) -> BootImageVersion {
        self.version
    }

    pub fn get_os_version(&self) -> Option<(OsVersion, PatchLevel)> {
        let version = self.get_os_version_raw();
        if version == 0 {
            return None;
        }
        let os_ver = version >> 11;
        let patch_level = version & 0x7ff;
        let a = (os_ver >> 14) & 0x7f;
        let b = (os_ver >> 7) & 0x7f;
        let c = os_ver & 0x7f;
        let y = (patch_level >> 4) + 2000;
        let m = patch_level & 0xf;
        Some((OsVersion { a, b, c }, PatchLevel { year: y, month: m }))
    }

    pub fn page_size_val(&self) -> u32 {
        match self.version {
            BootImageVersion::Android(v) if v >= 3 => 4096,
            _ => self.get_page_size(),
        }
    }

    pub fn hdr_space(&self) -> usize {
        align_to(self.layout.total_size as usize, self.page_size_val() as usize)
    }

    pub fn is_vendor(&self) -> bool {
        matches!(self.version, BootImageVersion::Vendor(_))
    }

    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < BOOT_MAGIC_SIZE + 4 {
            bail!("data too small for boot image header");
        }
        if data.starts_with(BOOT_MAGIC) {
            let ver = data.u32_at(0x28).unwrap_or(0);
            let layout = match ver {
                0 => &BOOT_HEADER_V0,
                1 => &BOOT_HEADER_V1,
                2 => &BOOT_HEADER_V2,
                3 => &BOOT_HEADER_V3,
                4 => &BOOT_HEADER_V4,
                _ => &BOOT_HEADER_V0,
            };
            let total_sz = layout.total_size as usize;
            if data.len() < total_sz {
                bail!("data truncated for boot header v{}", ver);
            }
            Ok(Self {
                data: &data[..total_sz],
                layout,
                version: BootImageVersion::Android(ver),
            })
        } else if data.starts_with(VENDOR_BOOT_MAGIC) {
            let ver = data.u32_at(VENDOR_BOOT_HEADER_V3.offset_header_version as usize).unwrap_or(3);
            let layout = match ver {
                4 => &VENDOR_BOOT_HEADER_V4,
                _ => &VENDOR_BOOT_HEADER_V3,
            };
            let total_sz = layout.total_size as usize;
            if data.len() < total_sz {
                bail!("data truncated for vendor boot header v{}", ver);
            }
            Ok(Self {
                data: &data[..total_sz],
                layout,
                version: BootImageVersion::Vendor(ver),
            })
        } else {
            bail!("not a boot image (magic mismatch)")
        }
    }
}

pub fn is_pxa_header(data: &[u8]) -> bool {
    if data.len() < PXA_HEADER_LAYOUT.total_size as usize {
        return false;
    }
    if !data.starts_with(BOOT_MAGIC) {
        return false;
    }
    let page_sz = u32::from_le_bytes(
        data[PXA_HEADER_LAYOUT.offset_page_size as usize
            ..PXA_HEADER_LAYOUT.offset_page_size as usize + 4]
            .try_into()
            .unwrap(),
    );
    page_sz >= 0x02000000
}

pub struct ZImageInfo {
    pub hdr_size: usize,
    pub tail: Vec<u8>,
}

pub struct KernelImage<'a> {
    pub data: &'a [u8],
    pub compress_format: CompressFormat,
    pub zimage_info: Option<ZImageInfo>,
}

pub struct RamdiskEntry<'a> {
    pub data: &'a [u8],
    pub offset: u32,
    pub size: u32,
    pub entry_type: VendorRamdiskType,
    pub compress_format: CompressFormat,
    pub name: &'a [u8],
}

pub struct RamdiskImage<'a> {
    pub data: &'a [u8],
    pub compress_format: CompressFormat,
    pub vendor_entries: Option<Vec<RamdiskEntry<'a>>>,
}

pub struct BootImageBlocks<'a> {
    pub kernel: Option<KernelImage<'a>>,
    pub ramdisk: Option<RamdiskImage<'a>>,
    pub second: Option<&'a [u8]>,
    pub extra: Option<&'a [u8]>,
    pub recovery_dtbo: Option<&'a [u8]>,
    pub dtb: Option<&'a [u8]>,
    pub signature: Option<&'a [u8]>,
    pub bootconfig: Option<&'a [u8]>,
    pub kernel_dtb: Option<&'a [u8]>,
}

pub struct AvbInfo<'a> {
    pub footer_data: &'a [u8],
    pub header_data: &'a [u8],
    pub tail_data: Option<&'a [u8]>,
}

impl AvbInfo<'_> {
    pub fn get_original_image_size(&self) -> u64 {
        u64::from_be_bytes(
            self.footer_data[mod_offsets_AvbFooterLayout::offset_original_image_size as usize
                ..mod_offsets_AvbFooterLayout::offset_original_image_size as usize + 8]
                .try_into()
                .unwrap(),
        )
    }

    pub fn get_vbmeta_offset(&self) -> u64 {
        u64::from_be_bytes(
            self.footer_data[mod_offsets_AvbFooterLayout::offset_vbmeta_offset as usize
                ..mod_offsets_AvbFooterLayout::offset_vbmeta_offset as usize + 8]
                .try_into()
                .unwrap(),
        )
    }

    pub fn get_vbmeta_size(&self) -> u64 {
        u64::from_be_bytes(
            self.footer_data[mod_offsets_AvbFooterLayout::offset_vbmeta_size as usize
                ..mod_offsets_AvbFooterLayout::offset_vbmeta_size as usize + 8]
                .try_into()
                .unwrap(),
        )
    }
}

pub struct BootImage<'a> {
    pub data: &'a [u8],
    pub header: BootHeader<'a>,
    pub blocks: BootImageBlocks<'a>,
    pub avb_info: Option<AvbInfo<'a>>,
    pub is_chromeos: bool,
    pub is_dhtb: bool,
    pub is_blob: bool,
    pub is_seandroid: bool,
    pub is_lg_bump: bool,
    pub is_nookhd: bool,
    pub is_acclaim: bool,
    pub is_amonet: bool,
    pub mtk_kernel: bool,
    pub mtk_ramdisk: bool,
    pub sha256_id: bool,
    pub tail_offset: usize,
    pub payload_offset: usize,
}

fn find_dtb_in_data(buf: &[u8]) -> Option<usize> {
    if buf.len() < 32 {
        return None;
    }
    let mut pos = 0;
    while pos + 32 <= buf.len() {
        let found = buf[pos..]
            .windows(4)
            .position(|w| w == DTB_MAGIC);
        let found = match found {
            Some(f) => pos + f,
            None => return None,
        };

        if found + 40 > buf.len() {
            return None;
        }

        let totalsize = u32::from_be_bytes(
            buf[found + 4..found + 8].try_into().unwrap(),
        ) as usize;
        if totalsize > buf.len() - found || totalsize <= 0x48 {
            pos = found + 4;
            continue;
        }

        let off_dt_struct = u32::from_be_bytes(
            buf[found + 8..found + 12].try_into().unwrap(),
        ) as usize;
        if off_dt_struct > buf.len() - found {
            pos = found + 4;
            continue;
        }

        let tag = u32::from_be_bytes(
            buf[found + off_dt_struct..found + off_dt_struct + 4]
                .try_into()
                .unwrap(),
        );
        if tag != 1 {
            pos = found + 4;
            continue;
        }

        return Some(found);
    }
    None
}



impl ZImageInfo {
    fn parse(raw: &[u8], kernel_size: usize) -> Option<Self> {
        if raw.len() < 0x30 {
            return None;
        }
        let magic = u32::from_le_bytes(raw[0x24..0x28].try_into().unwrap());
        if magic != 0x18286f01 {
            return None;
        }
        let start = u32::from_le_bytes(raw[0x28..0x2c].try_into().unwrap());
        let end = u32::from_le_bytes(raw[0x2c..0x30].try_into().unwrap());
        let piggy_size = (end - start) as usize;
        if piggy_size >= raw.len() {
            return None;
        }

        let mut piggy_end = piggy_size;
        if piggy_size >= 64 {
            let off_bytes = &raw[piggy_size - 64..piggy_size];
            for i in (0..16).rev() {
                let val = u32::from_le_bytes(off_bytes[i * 4..(i + 1) * 4].try_into().unwrap()) as usize;
                if val > piggy_size - 0xff && val < piggy_size {
                    piggy_end = val;
                    break;
                }
            }
        }

        let tail = raw[piggy_end..kernel_size].to_vec();
        Some(ZImageInfo {
            hdr_size: 0,
            tail,
        })
    }

    fn tail_start(&self) -> usize {
        0
    }
}

fn parse_lz4_legacy_blocks(buf: &[u8]) -> bool {
    let sz = buf.len();
    if sz < 8 {
        return false;
    }
    let mut off = 4usize;
    while off + 4 <= sz {
        let block_sz = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if off + block_sz > sz {
            return false;
        }
        off += block_sz;
    }
    true
}

fn check_fmt_lg(buf: &[u8]) -> CompressFormat {
    let fmt = parse_compress_format(buf);
    if fmt == CompressFormat::LZ4_LEGACY {
        if !parse_lz4_legacy_blocks(buf) {
            return CompressFormat::LZ4_LG;
        }
    }
    fmt
}

impl<'a> BootImage<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let mut chromeos = false;
        let mut dhtb = false;
        let mut blob = false;
        let mut nookhd = false;
        let mut acclaim = false;
        let mut amonet = false;
        let mut payload_offset = 0usize;
        let mut payload_data = data;

        let mut curs = 0usize;
        while curs < data.len() {
            let rem = &data[curs..];
            let _rem_len = data.len() - curs;

            if rem.starts_with(CHROMEOS_MAGIC) {
                chromeos = true;
                curs += 65536;
                continue;
            }
            if rem.starts_with(DHTB_MAGIC) {
                dhtb = true;
                curs += 512;
                continue;
            }
            if rem.starts_with(BLOB_MAGIC) {
                blob = true;
                curs += 80;
                continue;
            }
            if rem.starts_with(BOOT_MAGIC) || rem.starts_with(VENDOR_BOOT_MAGIC) {
                payload_offset = curs;

                if curs + BOOT_MAGIC_SIZE <= data.len() && rem.starts_with(BOOT_MAGIC) {
                    if rem.len() >= PXA_HEADER_LAYOUT.total_size as usize
                        && rem.len() >= BOOT_ARGS_SIZE + BOOT_MAGIC_SIZE
                    {
                        if rem.len() >= 0x28 + 4 {
                            let cmdline_start = 148;
                            if rem[cmdline_start..].len() >= NOOKHD_RL_MAGIC.len() {
                                let cmds = [
                                    NOOKHD_RL_MAGIC, NOOKHD_GL_MAGIC,
                                    NOOKHD_GR_MAGIC, NOOKHD_EB_MAGIC, NOOKHD_ER_MAGIC,
                                ];
                                if cmds.iter().any(|c| rem[cmdline_start..].starts_with(c)) {
                                    nookhd = true;
                                    payload_offset += NOOKHD_PRE_HEADER_SZ;
                                } else if rem.len() > BOOT_NAME_SIZE
                                    && rem[64..64 + ACCLAIM_MAGIC.len()].starts_with(ACCLAIM_MAGIC)
                                {
                                    acclaim = true;
                                    payload_offset += ACCLAIM_PRE_HEADER_SZ;
                                }
                            }
                        }
                        if !nookhd && !acclaim && is_pxa_header(rem) {
                        } else if !nookhd && !acclaim && rem.len() > AMONET_MICROLOADER_SZ + BOOT_MAGIC_SIZE
                            && rem[..AMONET_MICROLOADER_MAGIC.len()].starts_with(AMONET_MICROLOADER_MAGIC)
                            && rem[AMONET_MICROLOADER_SZ..].starts_with(BOOT_MAGIC)
                        {
                            amonet = true;
                            payload_offset = 0;
                        }
                    }
                }

                payload_data = &data[payload_offset..];
                break;
            }
            curs += 1;
        }

        if payload_data.is_empty() {
            bail!("no boot image header found");
        }

        let header = BootHeader::parse(payload_data)?;
        let (blocks, tail_off) = BootImageBlocks::parse(payload_data, &header)?;

        let mut seandroid = false;
        let mut lg_bump = false;
        let mut avb_info = None;

        let tail_data = &payload_data[tail_off..];
        let tail_end = tail_data.len();

        if tail_end >= 16 {
            if tail_data.starts_with(SEANDROID_MAGIC) {
                seandroid = true;
            } else if tail_data[..16].starts_with(LG_BUMP_MAGIC) {
                lg_bump = true;
            }
        }

        if tail_end >= AVB_FOOTER_SIZE {
            let footer_start = tail_end - AVB_FOOTER_SIZE;
            let footer = &tail_data[footer_start..];
            if footer.starts_with(AVB_FOOTER_MAGIC) {
                let vbmeta_off = u64::from_be_bytes(
                    footer[mod_offsets_AvbFooterLayout::offset_vbmeta_offset as usize
                        ..mod_offsets_AvbFooterLayout::offset_vbmeta_offset as usize + 8]
                        .try_into()
                        .unwrap(),
                ) as usize;
                if vbmeta_off < payload_data.len()
                    && payload_data[vbmeta_off..].starts_with(AVB_MAGIC)
                {
                    let vbmeta_sz = u64::from_be_bytes(
                        footer[mod_offsets_AvbFooterLayout::offset_vbmeta_size as usize
                            ..mod_offsets_AvbFooterLayout::offset_vbmeta_size as usize + 8]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    let vbmeta_data = &payload_data[vbmeta_off..vbmeta_off + vbmeta_sz];
                    let orig_sz = u64::from_be_bytes(
                        footer[mod_offsets_AvbFooterLayout::offset_original_image_size as usize
                            ..mod_offsets_AvbFooterLayout::offset_original_image_size as usize + 8]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    let avb_tail = if orig_sz > tail_off {
                        Some(&payload_data[tail_off..orig_sz])
                    } else if orig_sz == tail_off {
                        None
                    } else {
                        None
                    };
                    avb_info = Some(AvbInfo {
                        footer_data: footer,
                        header_data: vbmeta_data,
                        tail_data: avb_tail,
                    });
                }
            }
        }

        let sha256 = if header.has_id() {
            let id = header.get_id();
            id.len() > SHA1_DIGEST_SIZE + 4 && id[SHA1_DIGEST_SIZE + 4..].iter().any(|&b| b != 0)
        } else {
            false
        };

        Ok(BootImage {
            data,
            header,
            blocks,
            avb_info,
            is_chromeos: chromeos,
            is_dhtb: dhtb,
            is_blob: blob,
            is_seandroid: seandroid,
            is_lg_bump: lg_bump,
            is_nookhd: nookhd,
            is_acclaim: acclaim,
            is_amonet: amonet,
            mtk_kernel: false,
            mtk_ramdisk: false,
            sha256_id: sha256,
            tail_offset: payload_offset + tail_off,
            payload_offset,
        })
    }
}

impl<'a> BootImageBlocks<'a> {
    pub fn parse(data: &'a [u8], header: &BootHeader) -> Result<(Self, usize)> {
        let mut off = header.hdr_space();
        let page_sz = header.page_size_val() as usize;

        let kernel = get_block_impl(header, data, &mut off, page_sz, |h| h.has_kernel_size(), |h| h.get_kernel_size() as usize)?;
        let ramdisk = get_block_impl(header, data, &mut off, page_sz, |h| h.has_ramdisk_size(), |h| h.get_ramdisk_size() as usize)?;
        let second = get_block_impl(header, data, &mut off, page_sz, |h| h.has_second_size(), |h| h.get_second_size() as usize)?;
        let extra = get_block_impl(header, data, &mut off, page_sz, |h| h.has_extra_size(), |h| h.get_extra_size() as usize)?;
        let recovery_dtbo = get_block_impl(header, data, &mut off, page_sz, |h| h.has_recovery_dtbo_size(), |h| h.get_recovery_dtbo_size() as usize)?;
        let dtb = get_block_impl(header, data, &mut off, page_sz, |h| h.has_dtb_size(), |h| h.get_dtb_size() as usize)?;
        let signature = get_block_impl(header, data, &mut off, page_sz, |h| h.has_signature_size(), |h| h.get_signature_size() as usize)?;
        let vendor_ramdisk_table = get_block_impl(header, data, &mut off, page_sz, |h| h.has_vendor_ramdisk_table_size(), |h| h.get_vendor_ramdisk_table_size() as usize)?;
        let bootconfig = get_block_impl(header, data, &mut off, page_sz, |h| h.has_bootconfig_size(), |h| h.get_bootconfig_size() as usize)?;

        fn get_block_impl<'a, F, G>(header: &BootHeader, data: &'a [u8], off: &mut usize, page_sz: usize, has: F, get: G) -> Result<Option<&'a [u8]>>
        where
            F: Fn(&BootHeader) -> bool,
            G: Fn(&BootHeader) -> usize,
        {
            if !has(header) {
                return Ok(None);
            }
            let sz = get(header);
            if sz == 0 {
                return Ok(None);
            }
            let blk = data.get(*off..*off + sz).ok_or_else(|| {
                anyhow::anyhow!("block out of bounds off={} size={}", *off, sz)
            })?;
            *off += align_to(sz, page_sz);
            Ok(Some(blk))
        }

        let _mtk_k = false;
        let _zimage = false;

        let kernel = kernel.map(|k| {
            let (k, mtk, zinfo) = Self::parse_kernel_block(k);
            if mtk { } // will be set by caller
            if zinfo.is_some() { } // will be set by caller
            let fmt = if zinfo.is_some() { CompressFormat::ZIMAGE } else { check_fmt_lg(k) };
            KernelImage {
                data: k,
                compress_format: fmt,
                zimage_info: None,
            }
        });

        let (ramdisk, _vendor_entries) = if let Some(r) = ramdisk {
            let (r, _mtk) = Self::maybe_strip_mtk(r);
            if let Some(vt) = vendor_ramdisk_table {
                let entry_sz = header.get_vendor_ramdisk_table_entry_size() as usize;
                if entry_sz != VendorRamdiskTableEntry::SIZE {
                    bail!("invalid vendor ramdisk table entry size: {}", entry_sz);
                }
                let entry_num = header.get_vendor_ramdisk_table_entry_num() as usize;
                let expected = entry_num * entry_sz;
                if vt.len() < expected {
                    bail!("truncated vendor ramdisk table");
                }
                let mut entries = Vec::new();
                for i in 0..entry_num {
                    let e = &vt[i * entry_sz..(i + 1) * entry_sz];
                    let entry = VendorRamdiskTableEntry { data: e };
                    let e_off = entry.get_ramdisk_offset() as usize;
                    let e_sz = entry.get_ramdisk_size() as usize;
                    let e_data = r.get(e_off..e_off + e_sz).ok_or_else(|| {
                        anyhow::anyhow!("vendor ramdisk entry {} out of bounds", i)
                    })?;
                    let name_start = mod_offsets_VendorRamdiskTableEntryV4::offset_ramdisk_name;
                    let name_sz = mod_offsets_VendorRamdiskTableEntryV4::size_ramdisk_name;
                    let name = trim_end(&e[name_start..name_start + name_sz]);
                    entries.push(RamdiskEntry {
                        data: e_data,
                        offset: entry.get_ramdisk_offset(),
                        size: entry.get_ramdisk_size(),
                        entry_type: entry.get_ramdisk_type(),
                        compress_format: check_fmt_lg(e_data),
                        name,
                    });
                }
                let ri = RamdiskImage {
                    data: r,
                    compress_format: CompressFormat::UNKNOWN,
                    vendor_entries: Some(entries),
                };
                (Some(ri), None::<bool>)
            } else {
                let fmt = check_fmt_lg(r);
                let ri = RamdiskImage {
                    data: r,
                    compress_format: fmt,
                    vendor_entries: None,
                };
                (Some(ri), None::<bool>)
            }
        } else {
            (None, None::<bool>)
        };

        let mut kernel_dtb = None;
        let kernel = kernel.map(|mut k| {
            if let Some(dtb_off) = find_dtb_in_data(k.data) {
                if dtb_off > 0 {
                    kernel_dtb = Some(&k.data[dtb_off..]);
                    k.data = &k.data[..dtb_off];
                    k.compress_format = check_fmt_lg(k.data);
                }
            }
            k
        });

        Ok((
            BootImageBlocks {
                kernel,
                ramdisk,
                second,
                extra,
                recovery_dtbo,
                dtb,
                signature,
                bootconfig,
                kernel_dtb,
            },
            off,
        ))
    }

    fn parse_kernel_block(data: &'a [u8]) -> (&'a [u8], bool, Option<ZImageInfo>) {
        if data.len() < 4 {
            return (data, false, None);
        }
        let mut d = data;
        let mut mtk = false;
        if d.starts_with(MTK_MAGIC) && d.len() > 512 {
            mtk = true;
            d = &d[512..];
        }
        let fmt = check_fmt_lg(d);
        if fmt == CompressFormat::ZIMAGE {
            let zinfo = {
                if d.len() < 0x30 {
                    None
                } else {
                    let magic = u32::from_le_bytes(d[0x24..0x28].try_into().unwrap());
                    if magic != 0x18286f01 {
                        None
                    } else {
                        let start = u32::from_le_bytes(d[0x28..0x2c].try_into().unwrap());
                        let end = u32::from_le_bytes(d[0x2c..0x30].try_into().unwrap());
                        let piggy_sz = (end - start) as usize;
                        if piggy_sz >= d.len() {
                            None
                        } else {
                            let mut piggy_off = None;
                            for i in 0x28..d.len() {
                                let f = parse_compress_format(&d[i..]);
                                if f != CompressFormat::UNKNOWN && f != CompressFormat::DTB {
                                    piggy_off = Some(i);
                                    break;
                                }
                            }
                            piggy_off.map(|off| {
                                let mut piggy_end = piggy_sz;
                                if piggy_sz >= 64 {
                                    let ob = &d[piggy_sz - 64..piggy_sz];
                                    for i in (0..16).rev() {
                                        let val = u32::from_le_bytes(
                                            ob[i * 4..(i + 1) * 4].try_into().unwrap(),
                                        ) as usize;
                                        if val > piggy_sz - 0xff && val < piggy_sz {
                                            piggy_end = val;
                                            break;
                                        }
                                    }
                                }
                                ZImageInfo {
                                    hdr_size: off,
                                    tail: d[piggy_end..].to_vec(),
                                }
                            })
                        }
                    }
                }
            };
            (d, mtk, zinfo)
        } else {
            (d, mtk, None)
        }
    }

    fn maybe_strip_mtk(data: &'a [u8]) -> (&'a [u8], bool) {
        if data.len() > 512 && data.starts_with(MTK_MAGIC) {
            (&data[512..], true)
        } else {
            (data, false)
        }
    }
}
