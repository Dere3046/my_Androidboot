use anyhow::{Result, bail};
use crate::constants::DTB_MAGIC;

const FDT_BEGIN_NODE: u32 = 0x00000001;
const FDT_END_NODE: u32 = 0x00000002;
const FDT_PROP: u32 = 0x00000003;
const FDT_END: u32 = 0x00000009;

pub struct FdtHeader {
    pub magic: u32,
    pub totalsize: u32,
    pub off_dt_struct: u32,
    pub off_dt_strings: u32,
    pub off_mem_rsvmap: u32,
    pub version: u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys: u32,
    pub size_dt_strings: u32,
    pub size_dt_struct: u32,
}

fn be32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(buf[off..off + 4].try_into().unwrap())
}

fn parse_fdt_header(data: &[u8]) -> Result<(FdtHeader, usize)> {
    if data.len() < 40 {
        bail!("data too small for fdt header");
    }
    Ok((
        FdtHeader {
            magic: be32(data, 0),
            totalsize: be32(data, 4),
            off_dt_struct: be32(data, 8),
            off_dt_strings: be32(data, 12),
            off_mem_rsvmap: be32(data, 16),
            version: be32(data, 20),
            last_comp_version: be32(data, 24),
            boot_cpuid_phys: be32(data, 28),
            size_dt_strings: be32(data, 32),
            size_dt_struct: be32(data, 36),
        },
        40,
    ))
}

fn copy_be32(data: &mut [u8], off: usize, val: u32) {
    data[off..off + 4].copy_from_slice(&val.to_be_bytes());
}

pub fn dtb_patch_verity(data: &mut Vec<u8>) -> Result<bool> {
    let mut modified = false;
    let mut pos = 0;

    while pos + 40 <= data.len() {
        if &data[pos..pos + 4] != DTB_MAGIC {
            pos += 4;
            continue;
        }

        let totalsize = be32(data, pos + 4) as usize;
        if totalsize > data.len() - pos || totalsize <= 0x48 {
            pos += 4;
            continue;
        }

        let off_dt_struct = be32(data, pos + 8) as usize;
        let off_dt_strings = be32(data, pos + 12) as usize;
        let _size_dt_strings = be32(data, pos + 32) as usize;

        let dt_struct = pos + off_dt_struct;
        let dt_strings = pos + off_dt_strings;

        let mut so = 0;
        while so + 12 <= off_dt_struct {
            let tag = be32(data, dt_struct + so);
            so += 4;
            if tag == FDT_BEGIN_NODE {
                let name_end = data[dt_struct + so..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(0);
                so += align(name_end + 1, 4);
            } else if tag == FDT_END_NODE {
            } else if tag == FDT_PROP {
                let len = be32(data, dt_struct + so) as usize;
                let nameoff = be32(data, dt_struct + so + 4) as usize;
                so += 8;

                let prop_name = &data[dt_strings + nameoff..];
                let prop_name = prop_name.split(|&b| b == 0).next().unwrap_or(prop_name);
                let prop_name = std::str::from_utf8(prop_name).unwrap_or("");

                let prop_data = &data[dt_struct + so..dt_struct + so + len];

                if prop_name == "fstab" && prop_data.iter().any(|&b| b == b',') {
                    let mut new_val = Vec::new();
                    for part in prop_data.split(|&b| b == b',') {
                        let part = std::str::from_utf8(part).unwrap_or("");
                        if part.contains("verify") || part.contains("avb") {
                            modified = true;
                            continue;
                        }
                        if !new_val.is_empty() {
                            new_val.push(b',');
                        }
                        new_val.extend_from_slice(part.as_bytes());
                    }
                    if modified {
                        data[dt_struct + so..dt_struct + so + len].fill(0);
                        let copy_len = std::cmp::min(new_val.len(), len);
                        data[dt_struct + so..dt_struct + so + copy_len]
                            .copy_from_slice(&new_val[..copy_len]);
                    }
                }

                so += align(len, 4);
            } else if tag == FDT_END {
                break;
            } else {
                break;
            }
        }

        pos += align(totalsize, 4);
    }

    Ok(modified)
}

pub fn dtb_patch_initramfs(data: &mut Vec<u8>) -> Result<bool> {
    let mut modified = false;
    let mut pos = 0;

    while pos + 40 <= data.len() {
        if &data[pos..pos + 4] != DTB_MAGIC {
            pos += 4;
            continue;
        }

        let totalsize = be32(data, pos + 4) as usize;
        if totalsize > data.len() - pos || totalsize <= 0x48 {
            pos += 4;
            continue;
        }

        let off_dt_struct = be32(data, pos + 8) as usize;
        let off_dt_strings = be32(data, pos + 12) as usize;

        let dt_struct = pos + off_dt_struct;
        let dt_strings = pos + off_dt_strings;

        let mut so = 0;
        while so + 12 <= off_dt_struct {
            let tag = be32(data, dt_struct + so);
            so += 4;
            if tag == FDT_BEGIN_NODE {
                let name_end = data[dt_struct + so..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(0);
                so += align(name_end + 1, 4);
            } else if tag == FDT_END_NODE {
            } else if tag == FDT_PROP {
                let len = be32(data, dt_struct + so) as usize;
                let nameoff = be32(data, dt_struct + so + 4) as usize;
                so += 8;

                let prop_name = &data[dt_strings + nameoff..];
                let prop_name = prop_name.split(|&b| b == 0).next().unwrap_or(prop_name);
                let prop_name = std::str::from_utf8(prop_name).unwrap_or("");

                let prop_off = dt_struct + so;

                if prop_name == "linux,initrd-start" || prop_name == "linux,initrd-end" {
                    if len == 4 {
                        let _val = be32(data, prop_off);
                        copy_be32(data, prop_off, 0);
                        modified = true;
                    } else if len == 8 {
                        data[prop_off..prop_off + 8].fill(0);
                        modified = true;
                    }
                }

                so += align(len, 4);
            } else if tag == FDT_END {
                break;
            } else {
                break;
            }
        }

        pos += align(totalsize, 4);
    }

    Ok(modified)
}

fn align(v: usize, a: usize) -> usize {
    (v + a - 1) / a * a
}
