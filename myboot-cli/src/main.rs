/*
 * myboot-cli — Android boot image manipulation tool
 *
 * Copyright (C) 2026 dere3046
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use memmap2::Mmap;
use myboot::compress::{CompressFormat, fmt2name, get_decoder, get_encoder, is_compressed, parse_compress_format};
use myboot::cpio::Cpio;
use myboot::dtb;
use myboot::hexpatch::hexpatch;
use myboot::parser::BootImage;
use myboot::patcher::BootImagePatchOption;
use myboot::sign;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};

#[derive(Parser)]
#[command(name = "myboot")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Unpack boot image components")]
    Unpack {
        #[arg(short = 'n', long = "no-decompress")]
        no_decompress: bool,
        #[arg(short = 'H', long = "dump-header")]
        dump_header: bool,
        file: String,
    },
    #[command(about = "Repack boot image from current directory files")]
    Repack {
        #[arg(short = 'n', long = "no-compress")]
        no_compress: bool,
        src: String,
        #[arg(default_value = "new-boot.img")]
        out: String,
    },
    #[command(about = "Verify AVB 1.0 signature on boot image")]
    Verify {
        file: String,
    },
    #[command(about = "Sign boot image with AVB 1.0 signature")]
    Sign {
        file: String,
        key: Option<String>,
    },
    #[command(about = "List CPIO archive contents")]
    CpioLs {
        file: String,
    },
    #[command(about = "Search and replace hex patterns in a file")]
    HexPatch {
        file: String,
        from: String,
        to: String,
    },
    #[command(about = "Patch DTB (remove verity / toggle initramfs)")]
    DtbPatch {
        file: String,
        #[arg(short = 'v', long = "no-verity")]
        no_verity: bool,
        #[arg(short = 'i', long = "want-initramfs")]
        want_initramfs: bool,
    },
    #[command(about = "Split kernel+DTB into kernel and kernel_dtb")]
    Split {
        #[arg(short = 'n', long = "no-decompress")]
        no_decompress: bool,
        file: String,
    },
    #[command(about = "Print SHA1 of a file")]
    Sha1 {
        file: String,
    },
    #[command(about = "Compress a file")]
    Compress {
        #[arg(short = 'f', long = "format", default_value = "gzip")]
        format: String,
        file: String,
        #[arg(default_value = "-")]
        out: String,
    },
    #[command(about = "Decompress a file")]
    Decompress {
        file: String,
        #[arg(default_value = "-")]
        out: String,
    },
    #[command(about = "Print boot image info")]
    Info {
        file: String,
    },
}

fn map_file(path: &str) -> Result<(Mmap, File)> {
    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    Ok((mmap, file))
}

fn dump_block(data: &[u8], filename: &str, decompress: bool) -> Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(filename)?;
    if decompress {
        let fmt = parse_compress_format(data);
        if is_compressed(fmt) {
            let mut decoder = get_decoder(fmt, data)?;
            std::io::copy(&mut decoder, &mut output)?;
            return Ok(());
        }
    }
    output.write_all(data)?;
    Ok(())
}

fn cmd_unpack(file: &str, no_decompress: bool, dump_header: bool) -> Result<()> {
    let (mmap, _f) = map_file(file)?;
    let boot = BootImage::parse(&mmap)?;
    let header = &boot.header;
    let blocks = &boot.blocks;

    eprintln!("{:>15} [{}]", "HEADER_VER", match header.get_version() {
        myboot::parser::BootImageVersion::Android(v) => v.to_string(),
        myboot::parser::BootImageVersion::Vendor(v) => v.to_string(),
    });

    if header.has_kernel_size() && !header.is_vendor() {
        eprintln!("{:>15} [{}]", "KERNEL_SZ", header.get_kernel_size());
    }
    if header.has_ramdisk_size() {
        eprintln!("{:>15} [{}]", "RAMDISK_SZ", header.get_ramdisk_size());
    }
    if header.has_second_size() && !matches!(header.get_version(), myboot::parser::BootImageVersion::Android(v) if v >= 3) {
        eprintln!("{:>15} [{}]", "SECOND_SZ", header.get_second_size());
    }
    if header.has_extra_size() {
        eprintln!("{:>15} [{}]", "EXTRA_SZ", header.get_extra_size());
    }
    if header.has_recovery_dtbo_size() && header.get_recovery_dtbo_size() > 0 {
        eprintln!("{:>15} [{}]", "RECOV_DTBO_SZ", header.get_recovery_dtbo_size());
    }
    if header.has_dtb_size() && header.get_dtb_size() > 0 {
        eprintln!("{:>15} [{}]", "DTB_SZ", header.get_dtb_size());
    }
    if header.has_bootconfig_size() && header.get_bootconfig_size() > 0 {
        eprintln!("{:>15} [{}]", "BOOTCONFIG_SZ", header.get_bootconfig_size());
    }
    if let Some((os_ver, patch)) = header.get_os_version() {
        eprintln!("{:>15} [{}]", "OS_VERSION", os_ver);
        eprintln!("{:>15} [{}]", "OS_PATCH_LEVEL", patch);
    }
    eprintln!("{:>15} [{}]", "PAGESIZE", header.page_size_val());

    if header.has_name() {
        let name = std::str::from_utf8(
            myboot::utils::trim_end(header.get_name()),
        ).unwrap_or("???");
        eprintln!("{:>15} [{}]", "NAME", name);
    }

    let cmdline = std::str::from_utf8(header.get_cmdline()).unwrap_or("");
    let extra = std::str::from_utf8(header.get_extra_cmdline()).unwrap_or("");
    eprintln!("{:>15} [{}{}]", "CMDLINE", cmdline, extra);

    if dump_header {
        let mut f = File::create("header")?;
        if header.has_name() {
            let name = std::str::from_utf8(myboot::utils::trim_end(header.get_name())).unwrap_or("");
            writeln!(f, "name={}", name)?;
        }
        writeln!(f, "cmdline={}{}", cmdline, extra)?;
        if let Some((os_ver, patch)) = header.get_os_version() {
            writeln!(f, "os_version={}", os_ver)?;
            writeln!(f, "os_patch_level={}", patch)?;
        }
    }

    if let Some(ref kernel) = blocks.kernel {
        dump_block(kernel.data, "kernel", !no_decompress)?;
    }
    if let Some(dtb) = blocks.kernel_dtb {
        dump_block(dtb, "kernel_dtb", false)?;
    }
    if let Some(ref ramdisk) = blocks.ramdisk {
        if let Some(ref entries) = ramdisk.vendor_entries {
            fs::create_dir_all("vendor_ramdisks")?;
            for entry in entries {
                let name = std::str::from_utf8(myboot::utils::trim_end(entry.name)).unwrap_or("ramdisk");
                let filename = format!("vendor_ramdisks/{}.cpio", name);
                dump_block(entry.data, &filename, !no_decompress)?;
            }
        } else {
            dump_block(ramdisk.data, "ramdisk.cpio", !no_decompress)?;
        }
    }
    if let Some(data) = blocks.second {
        dump_block(data, "second", false)?;
    }
    if let Some(data) = blocks.extra {
        dump_block(data, "extra", false)?;
    }
    if let Some(data) = blocks.recovery_dtbo {
        dump_block(data, "recovery_dtbo", false)?;
    }
    if let Some(data) = blocks.dtb {
        dump_block(data, "dtb", false)?;
    }
    if let Some(data) = blocks.bootconfig {
        dump_block(data, "bootconfig", false)?;
    }

    Ok(())
}

fn cmd_repack(src: &str, out: &str, no_compress: bool) -> Result<()> {
    let (mmap, _f) = map_file(src)?;
    let boot = BootImage::parse(&mmap)?;
    let blocks = &boot.blocks;

    let mut patcher = BootImagePatchOption::new(&boot);
    patcher.no_compress(no_compress);

    if let Some(ref kernel) = blocks.kernel {
        if let Ok(data) = fs::read("kernel") {
            patcher.replace_kernel(data);
        }
    }
    if let Some(_kdtb) = blocks.kernel_dtb {
        if let Ok(data) = fs::read("kernel_dtb") {
            patcher.replace_kernel_dtb(data);
        }
    }
    if let Some(ref ramdisk) = blocks.ramdisk {
        if let Some(ref entries) = ramdisk.vendor_entries {
            for (i, entry) in entries.iter().enumerate() {
                let name = std::str::from_utf8(myboot::utils::trim_end(entry.name)).unwrap_or("ramdisk");
                let filename = format!("vendor_ramdisks/{}.cpio", name);
                if let Ok(data) = fs::read(&filename) {
                    patcher.replace_vendor_ramdisk(i, data);
                }
            }
        } else {
            if let Ok(data) = fs::read("ramdisk.cpio") {
                patcher.replace_ramdisk(data);
            }
        }
    }
    if let Ok(data) = fs::read("second") {
        patcher.replace_second(data);
    }
    if let Ok(data) = fs::read("extra") {
        patcher.replace_extra(data);
    }
    if let Ok(data) = fs::read("recovery_dtbo") {
        patcher.replace_recovery_dtbo(data);
    }
    if let Ok(data) = fs::read("dtb") {
        patcher.replace_dtb(data);
    }
    if let Ok(data) = fs::read("bootconfig") {
        patcher.replace_bootconfig(data);
    }

    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out)?;

    eprintln!("Repack to boot image: [{}]", out);
    patcher.patch(&mut output)?;

    Ok(())
}

fn cmd_verify(file: &str) -> Result<()> {
    let (mmap, _f) = map_file(file)?;
    let boot = BootImage::parse(&mmap)?;
    let payload = &mmap[boot.payload_offset..];
    let signed = sign::verify_boot_image(payload);
    if signed {
        println!("Boot image is signed with AVB 1.0");
    } else {
        println!("Boot image is NOT signed");
    }
    Ok(())
}

fn cmd_sign(file: &str, key_path: Option<&str>) -> Result<()> {
    let (mmap, _f) = map_file(file)?;
    let boot = BootImage::parse(&mmap)?;
    let payload = &mmap[boot.payload_offset..boot.tail_offset];
    let tail_off = boot.tail_offset;

    let pk8 = if let Some(ref path) = key_path {
        fs::read(path)?
    } else {
        bail!("no key provided (required for signing)");
    };

    let sig = sign::sign_boot_image(payload, &pk8)?;

    let mut fd = OpenOptions::new().write(true).open(file)?;
    fd.seek(SeekFrom::Start(tail_off as u64))?;
    fd.write_all(&sig)?;
    let current = fd.seek(SeekFrom::Current(0))?;
    let eof = fd.seek(SeekFrom::End(0))?;
    if eof > current {
        fd.seek(SeekFrom::Start(current))?;
        use std::io::Write;
        fd.write_all(&vec![0u8; (eof - current) as usize])?;
    }

    Ok(())
}

fn cmd_info(file: &str) -> Result<()> {
    let (mmap, _f) = map_file(file)?;
    let boot = BootImage::parse(&mmap)?;
    let header = &boot.header;

    println!("version: {}", header.get_version());
    println!("layout: {:?}", header.get_layout());

    if header.has_kernel_size() { println!("kernel_size: {}", header.get_kernel_size()); }
    if header.has_ramdisk_size() { println!("ramdisk_size: {}", header.get_ramdisk_size()); }
    if header.has_second_size() { println!("second_size: {}", header.get_second_size()); }
    if header.has_page_size() { println!("page_size: {}", header.get_page_size()); }
    if header.has_header_version() { println!("header_version: {}", header.get_header_version()); }
    if header.has_recovery_dtbo_size() { println!("recovery_dtbo_size: {}", header.get_recovery_dtbo_size()); }
    if header.has_recovery_dtbo_offset() { println!("recovery_dtbo_offset: {}", header.get_recovery_dtbo_offset()); }
    if header.has_header_size() { println!("header_size: {}", header.get_header_size()); }
    if header.has_dtb_size() { println!("dtb_size: {}", header.get_dtb_size()); }
    if header.has_signature_size() { println!("signature_size: {}", header.get_signature_size()); }
    if header.has_vendor_ramdisk_table_size() { println!("vendor_ramdisk_table_size: {}", header.get_vendor_ramdisk_table_size()); }
    if header.has_vendor_ramdisk_table_entry_num() { println!("vendor_ramdisk_table_entry_num: {}", header.get_vendor_ramdisk_table_entry_num()); }
    if header.has_vendor_ramdisk_table_entry_size() { println!("vendor_ramdisk_table_entry_size: {}", header.get_vendor_ramdisk_table_entry_size()); }
    if header.has_bootconfig_size() { println!("bootconfig_size: {}", header.get_bootconfig_size()); }

    if let Some((os_ver, patch)) = header.get_os_version() {
        println!("os_version: {}", os_ver);
        println!("patch_level: {}", patch);
    }

    if let Some(ref kernel) = boot.blocks.kernel {
        println!("kernel format: {}", fmt2name(kernel.compress_format));
    }
    if let Some(ref ramdisk) = boot.blocks.ramdisk {
        if let Some(ref entries) = ramdisk.vendor_entries {
            println!("vendor ramdisk entries: {}", entries.len());
            for (i, entry) in entries.iter().enumerate() {
                let name = std::str::from_utf8(myboot::utils::trim_end(entry.name)).unwrap_or("???");
                println!("  [{}] name={} type={} size={} fmt={}",
                    i, name, entry.entry_type, entry.size, fmt2name(entry.compress_format));
            }
        } else {
            println!("ramdisk format: {}", fmt2name(ramdisk.compress_format));
        }
    }
    if let Some(ref dtb) = boot.blocks.kernel_dtb {
        println!("kernel_dtb size: {}", dtb.len());
    }

    if boot.avb_info.is_some() {
        println!("AVB: present");
    }
    if boot.is_chromeos {
        println!("chromeos: true");
    }

    Ok(())
}

fn cmd_cpio_ls(file: &str) -> Result<()> {
    let data = fs::read(file)?;
    let cpio = Cpio::load_from_data(&data)?;
    cpio.ls("/", true)?;
    Ok(())
}

fn cmd_hexpatch(file: &str, from: &str, to: &str) -> Result<()> {
    let mut data = fs::read(file)?;
    let offsets = hexpatch(&mut data, from, to)?;
    for off in &offsets {
        eprintln!("Patch @ {:#010X} [{}] -> [{}]", off, from, to);
    }
    if !offsets.is_empty() {
        fs::write(file, &data)?;
    } else {
        eprintln!("Pattern not found");
    }
    Ok(())
}

fn cmd_dtb_patch(file: &str, no_verity: bool, want_initramfs: bool) -> Result<()> {
    let mut data = fs::read(file)?;
    if no_verity {
        dtb::dtb_patch_verity(&mut data)?;
    }
    if want_initramfs {
        dtb::dtb_patch_initramfs(&mut data)?;
    }
    fs::write(file, &data)?;
    Ok(())
}

fn cmd_split(file: &str, no_decompress: bool) -> Result<()> {
    let (mmap, _f) = map_file(file)?;
    let boot = BootImage::parse(&mmap)?;
    if let Some(ref kernel) = boot.blocks.kernel {
        dump_block(kernel.data, "kernel", !no_decompress)?;
    }
    if let Some(dtb) = boot.blocks.kernel_dtb {
        dump_block(dtb, "kernel_dtb", false)?;
    }
    Ok(())
}

fn cmd_sha1(file: &str) -> Result<()> {
    let data = fs::read(file)?;
    let hash = sign::sha1_hash(&data);
    for b in &hash {
        print!("{:02x}", b);
    }
    println!();
    Ok(())
}

fn cmd_compress(format: &str, file: &str, out: &str) -> Result<()> {
    let fmt = match format {
        "gzip" | "gz" => CompressFormat::GZIP,
        "zopfli" => CompressFormat::ZOPFLI,
        "xz" => CompressFormat::XZ,
        "lzma" => CompressFormat::LZMA,
        "bzip2" | "bz2" => CompressFormat::BZIP2,
        "lz4" => CompressFormat::LZ4,
        "lz4_legacy" | "lz4legacy" => CompressFormat::LZ4_LEGACY,
        _ => bail!("unsupported format: {}", format),
    };

    let in_data = if file == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        fs::read(file)?
    };

    let mut out_buf = Vec::new();
    let mut enc = get_encoder(fmt, &mut out_buf)?;
    enc.write_all(&in_data)?;
    enc.finish()?;

    if out == "-" {
        std::io::stdout().write_all(&out_buf)?;
    } else {
        fs::write(out, &out_buf)?;
    }
    Ok(())
}

fn cmd_decompress(file: &str, out: &str) -> Result<()> {
    let in_data = if file == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        fs::read(file)?
    };

    let fmt = parse_compress_format(&in_data);
    if fmt == CompressFormat::UNKNOWN {
        bail!("unknown compression format");
    }

    let mut decoder = get_decoder(fmt, &in_data)?;
    let mut out_data = Vec::new();
    decoder.read_to_end(&mut out_data)?;

    if out == "-" {
        std::io::stdout().write_all(&out_data)?;
    } else {
        fs::write(out, &out_data)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Unpack { no_decompress, dump_header, file } => cmd_unpack(&file, no_decompress, dump_header),
        Command::Repack { no_compress, src, out } => cmd_repack(&src, &out, no_compress),
        Command::Verify { file } => cmd_verify(&file),
        Command::Sign { file, key } => cmd_sign(&file, key.as_deref()),
        Command::CpioLs { file } => cmd_cpio_ls(&file),
        Command::HexPatch { file, from, to } => cmd_hexpatch(&file, &from, &to),
        Command::DtbPatch { file, no_verity, want_initramfs } => cmd_dtb_patch(&file, no_verity, want_initramfs),
        Command::Split { no_decompress, file } => cmd_split(&file, no_decompress),
        Command::Sha1 { file } => cmd_sha1(&file),
        Command::Compress { format, file, out } => cmd_compress(&format, &file, &out),
        Command::Decompress { file, out } => cmd_decompress(&file, &out),
        Command::Info { file } => cmd_info(&file),
    }
}
