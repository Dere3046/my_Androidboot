use crate::utils::{align_to, align_padding};
use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter, Write as FmtWrite};
use std::io::Write;

const CPIO_MAGIC: &[u8] = b"070701";
const CPIO_TRAILER: &[u8] = b"TRAILER!!!";

const TYPE_DIR: u32 = 0o040000;
const TYPE_REGULAR: u32 = 0o100000;
const TYPE_SYMLINK: u32 = 0o120000;
const TYPE_BLOCK: u32 = 0o060000;
const TYPE_CHAR: u32 = 0o020000;
const TYPE_FIFO: u32 = 0o010000;
const TYPE_SOCKET: u32 = 0o140000;

pub fn type_name(mode: u32) -> &'static str {
    match mode & 0o170000 {
        TYPE_DIR => "dir",
        TYPE_REGULAR => "reg",
        TYPE_SYMLINK => "sym",
        TYPE_BLOCK => "blk",
        TYPE_CHAR => "chr",
        TYPE_FIFO => "fifo",
        TYPE_SOCKET => "sock",
        _ => "???",
    }
}

pub fn perm_string(mode: u32) -> String {
    let mut s = String::with_capacity(10);
    s.push(if mode & TYPE_DIR != 0 { 'd' } else if mode & TYPE_SYMLINK != 0 { 'l' } else { '-' });
    s.push(if mode & 0o400 != 0 { 'r' } else { '-' });
    s.push(if mode & 0o200 != 0 { 'w' } else { '-' });
    s.push(if mode & 0o100 != 0 {
        if mode & 0o4000 != 0 { 's' } else { 'x' }
    } else {
        if mode & 0o4000 != 0 { 'S' } else { '-' }
    });
    s.push(if mode & 0o040 != 0 { 'r' } else { '-' });
    s.push(if mode & 0o020 != 0 { 'w' } else { '-' });
    s.push(if mode & 0o010 != 0 {
        if mode & 0o2000 != 0 { 's' } else { 'x' }
    } else {
        if mode & 0o2000 != 0 { 'S' } else { '-' }
    });
    s.push(if mode & 0o004 != 0 { 'r' } else { '-' });
    s.push(if mode & 0o002 != 0 { 'w' } else { '-' });
    s.push(if mode & 0o001 != 0 {
        if mode & 0o1000 != 0 { 't' } else { 'x' }
    } else {
        if mode & 0o1000 != 0 { 'T' } else { '-' }
    });
    s
}

#[derive(Clone)]
pub struct CpioEntry {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub data: Option<Vec<u8>>,
    pub symlink: Option<Vec<u8>>,
}

impl Display for CpioEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let sz = self.data.as_ref().map_or(0, |d| d.len());
        write!(
            f,
            "{} {:>4} {:>4} {:>8}",
            perm_string(self.mode),
            self.uid,
            self.gid,
            sz
        )?;
        if self.rdev_major != 0 || self.rdev_minor != 0 {
            write!(f, " {:>3},{:>3}", self.rdev_major, self.rdev_minor)?;
        }
        Ok(())
    }
}

pub struct Cpio {
    entries: BTreeMap<String, Box<CpioEntry>>,
}

fn parse_hex(s: &[u8], len: usize) -> Result<u32> {
    let s = std::str::from_utf8(s)?;
    u32::from_str_radix(&s[..len], 16).map_err(|e| anyhow::anyhow!("hex parse error: {}", e))
}

impl Cpio {
    pub fn new() -> Self {
        Cpio {
            entries: BTreeMap::new(),
        }
    }

    pub fn load_from_data(data: &[u8]) -> Result<Self> {
        let mut cpio = Cpio::new();
        let mut pos = 0;
        let _inode = 300000u32;

        loop {
            if pos + 110 > data.len() {
                break;
            }

            if &data[pos..pos + 6] != CPIO_MAGIC {
                bail!("invalid cpio magic at offset {}", pos);
            }

            let namesize = parse_hex(&data[pos + 94..pos + 102], 8)? as usize;
            let filesize = parse_hex(&data[pos + 54..pos + 62], 8)? as usize;
            let mode = parse_hex(&data[pos + 14..pos + 22], 8)?;
            let uid = parse_hex(&data[pos + 30..pos + 38], 8)?;
            let gid = parse_hex(&data[pos + 38..pos + 46], 8)?;
            let rdev_major = parse_hex(&data[pos + 46..pos + 54], 8)?;
            let rdev_minor = parse_hex(&data[pos + 62..pos + 70], 8)?;

            let hdr_end = pos + 110;
            let name_start = hdr_end;
            let name_end = name_start + namesize;
            if name_end > data.len() {
                bail!("cpio header truncated");
            }

            let raw_name = &data[name_start..name_end];
            let name = std::str::from_utf8(trim_nul(raw_name))?.to_string();

            if name == "TRAILER!!!" {
                break;
            }

            let data_off = align_to(name_end, 4);
            let data_end = data_off + filesize;
            if data_end > data.len() {
                bail!("cpio file data truncated for {}", name);
            }

            let file_data = if filesize > 0 {
                Some(data[data_off..data_end].to_vec())
            } else {
                None
            };

            let symlink = if mode & TYPE_SYMLINK != 0 {
                file_data.clone()
            } else {
                None
            };

            cpio.entries.insert(
                name,
                Box::new(CpioEntry {
                    mode,
                    uid,
                    gid,
                    rdev_major,
                    rdev_minor,
                    data: if mode & TYPE_SYMLINK != 0 { None } else { file_data },
                    symlink,
                }),
            );

            pos = align_to(data_end, 4);
        }

        Ok(cpio)
    }

    pub fn dump(&self, writer: &mut dyn Write) -> Result<()> {
        let mut entries: Vec<(&String, &Box<CpioEntry>)> = self.entries.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        let mut inode = 300000u32;

        for (name, entry) in entries.iter() {
            write_entry(writer, name, entry, inode)?;
            inode += 1;
        }

        write_entry(
            writer,
            "TRAILER!!!",
            &CpioEntry {
                mode: 0,
                uid: 0,
                gid: 0,
                rdev_major: 0,
                rdev_minor: 0,
                data: None,
                symlink: None,
            },
            0,
        )?;

        let pos_after = 0u64;
        let pad = align_padding(pos_after, 512);
        if pad > 0 {
            writer.write_all(&vec![0u8; pad as usize])?;
        }

        Ok(())
    }

    pub fn exists(&self, path: &str) -> bool {
        let path = normalize_path(path);
        self.entries.contains_key(&path)
    }

    pub fn add(&mut self, path: &str, entry: CpioEntry) {
        let path = normalize_path(path);
        self.entries.insert(path, Box::new(entry));
    }

    pub fn rm(&mut self, path: &str, recursive: bool) -> Result<()> {
        let path = normalize_path(path);
        if !recursive {
            self.entries.remove(&path);
            let dir_prefix = if path.ends_with('/') {
                path.clone()
            } else {
                format!("{}/", path)
            };
            self.entries.remove(&dir_prefix);
            return Ok(());
        }
        let prefix = if path.ends_with('/') {
            path.clone()
        } else {
            format!("{}/", path)
        };
        let keys: Vec<String> = self
            .entries
            .keys()
            .filter(|k| *k == &path || k.starts_with(&prefix))
            .cloned()
            .collect();
        for k in keys {
            self.entries.remove(&k);
        }
        Ok(())
    }

    pub fn mv(&mut self, from: &str, to: &str) -> Result<()> {
        let from = normalize_path(from);
        let to = normalize_path(to);
        if let Some(entry) = self.entries.remove(&from) {
            self.entries.insert(to, entry);
        }
        Ok(())
    }

    pub fn ls(&self, path: &str, recursive: bool) -> Result<()> {
        let path = normalize_path(path);
        let prefix = if path.ends_with('/') {
            path.clone()
        } else if path.is_empty() {
            String::new()
        } else {
            format!("{}/", path)
        };

        for (name, entry) in &self.entries {
            if !name.starts_with(&prefix) {
                continue;
            }
            let rel = &name[prefix.len()..];
            if !recursive && rel.contains('/') {
                continue;
            }
            if rel.is_empty() {
                println!("{} {}", entry, name);
            } else {
                println!("{} {}", entry, rel);
            }
            if entry.symlink.is_some() {
                let target = std::str::from_utf8(entry.symlink.as_ref().unwrap()).unwrap_or("???");
                println!(" -> {}", target);
            }
        }
        Ok(())
    }

    pub fn entries(&self) -> &BTreeMap<String, Box<CpioEntry>> {
        &self.entries
    }

    pub fn entries_mut(&mut self) -> &mut BTreeMap<String, Box<CpioEntry>> {
        &mut self.entries
    }

    pub fn is_magisk_patched(&self) -> bool {
        let markers = [
            ".backup/.magisk",
            "init.magisk.rc",
            "overlay/init.magisk.rc",
        ];
        markers.iter().any(|m| self.exists(m))
    }
}

fn normalize_path(path: &str) -> String {
    let path = path.trim_start_matches('/');
    let path = path.trim_start_matches("./");
    if path.is_empty() {
        return String::new();
    }
    let mut result = String::new();
    for c in path.bytes() {
        if c == 0 {
            break;
        }
        result.push(c as char);
    }
    result
}

fn trim_nul(buf: &[u8]) -> &[u8] {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..end]
}

fn write_entry(writer: &mut dyn Write, name: &str, entry: &CpioEntry, inode: u32) -> Result<()> {
    let namesize = name.len() + 1;
    let filesize = entry.data.as_ref().map_or(0, |d| d.len());

    let mut hdr = String::with_capacity(110);
    write!(&mut hdr, "070701")?;
    write!(&mut hdr, "{:08x}", inode)?;
    write!(&mut hdr, "{:08x}", entry.mode)?;
    write!(&mut hdr, "{:08x}", entry.uid)?;
    write!(&mut hdr, "{:08x}", entry.gid)?;
    write!(&mut hdr, "{:08x}", 1u32)?;
    write!(&mut hdr, "{:08x}", 0u32)?;
    write!(&mut hdr, "{:08x}", filesize)?;
    write!(&mut hdr, "{:08x}", 0u32)?;
    write!(&mut hdr, "{:08x}", 0u32)?;
    write!(&mut hdr, "{:08x}", entry.rdev_major)?;
    write!(&mut hdr, "{:08x}", entry.rdev_minor)?;
    write!(&mut hdr, "{:08x}", namesize)?;
    write!(&mut hdr, "{:08x}", 0u32)?;

    writer.write_all(hdr.as_bytes())?;
    writer.write_all(name.as_bytes())?;
    writer.write_all(&[0u8])?;

    let hdr_total = 110 + namesize;
    let pad = align_padding(hdr_total, 4) as usize;
    if pad > 0 {
        writer.write_all(&vec![0u8; pad])?;
    }

    if filesize > 0 {
        if let Some(data) = &entry.data {
            writer.write_all(data)?;
        }
        let data_pad = align_padding(filesize, 4) as usize;
        if data_pad > 0 {
            writer.write_all(&vec![0u8; data_pad])?;
        }
    }

    Ok(())
}
