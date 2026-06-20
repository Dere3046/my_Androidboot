pub const BOOT_MAGIC: &[u8] = b"ANDROID!";
pub const VENDOR_BOOT_MAGIC: &[u8] = b"VNDRBOOT";
pub const CHROMEOS_MAGIC: &[u8] = b"CHROMEOS";

pub const BOOT_MAGIC_SIZE: usize = 8;
pub const BOOT_NAME_SIZE: usize = 16;
pub const BOOT_ARGS_SIZE: usize = 512;
pub const BOOT_EXTRA_ARGS_SIZE: usize = 1024;
pub const BOOT_ID_SIZE: usize = 32;
pub const VENDOR_BOOT_ARGS_SIZE: usize = 2048;
pub const VENDOR_RAMDISK_NAME_SIZE: usize = 32;
pub const VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE: usize = 16;

pub const VENDOR_RAMDISK_TYPE_NONE: u32 = 0;
pub const VENDOR_RAMDISK_TYPE_PLATFORM: u32 = 1;
pub const VENDOR_RAMDISK_TYPE_RECOVERY: u32 = 2;
pub const VENDOR_RAMDISK_TYPE_DLKM: u32 = 3;

pub const AVB_FOOTER_MAGIC: &[u8] = b"AVBf";
pub const AVB_MAGIC: &[u8] = b"AVB0";
pub const AVB_FOOTER_SIZE: usize = 64;
pub const AVB_RELEASE_STRING_SIZE: usize = 48;

pub const MTK_MAGIC: &[u8] = b"\x88\x16\x88\x58";
pub const DHTB_MAGIC: &[u8] = b"DHTB\0\0\0\0";
pub const BLOB_MAGIC: &[u8] = b"-SIGNED-BY-SIGNBLOB-";
pub const SEANDROID_MAGIC: &[u8] = b"SEANDROIDENFORCE";
pub const LG_BUMP_MAGIC: &[u8] = b"\x41\xa9\xe4\x67\x74\x4d\x1d\x1b\xa4\x29\xf2\xec\xea\x65\x52\x79";
pub const ZIMAGE_MAGIC: &[u8] = b"\x01\x6f\x28\x18";
pub const DTB_MAGIC: &[u8] = b"\xd0\x0d\xfe\xed";

pub const GZIP1_MAGIC: &[u8] = b"\x1f\x8b";
pub const GZIP2_MAGIC: &[u8] = b"\x1f\x9e";
pub const LZOP_MAGIC: &[u8] = b"\x89LZO";
pub const XZ_MAGIC: &[u8] = b"\xfd7zXZ";
pub const BZIP_MAGIC: &[u8] = b"BZh";
pub const LZ41_MAGIC: &[u8] = b"\x03\x21\x4c\x18";
pub const LZ42_MAGIC: &[u8] = b"\x04\x22\x4d\x18";
pub const LZ4_LEG_MAGIC: &[u8] = b"\x02\x21\x4c\x18";

pub const AMONET_MICROLOADER_MAGIC: &[u8] = b"\xd1\xdc\x4b\x84\x34\x10\xd7\x73";
pub const AMONET_MICROLOADER_SZ: usize = 1024;

pub const NOOKHD_RL_MAGIC: &[u8] = b"Red Loader";
pub const NOOKHD_GL_MAGIC: &[u8] = b"Green Loader";
pub const NOOKHD_GR_MAGIC: &[u8] = b"Green Recovery";
pub const NOOKHD_EB_MAGIC: &[u8] = b"eMMC Bootloader";
pub const NOOKHD_ER_MAGIC: &[u8] = b"eMMC Recovery";
pub const NOOKHD_PRE_HEADER_SZ: usize = 1048576;
pub const ACCLAIM_MAGIC: &[u8] = b"BauwksBoot";
pub const ACCLAIM_PRE_HEADER_SZ: usize = 262144;

pub const SHA256_DIGEST_SIZE: usize = 32;
pub const SHA1_DIGEST_SIZE: usize = 20;

pub const HEADER_FILE: &str = "header";
pub const KERNEL_FILE: &str = "kernel";
pub const RAMDISK_FILE: &str = "ramdisk.cpio";
pub const SECOND_FILE: &str = "second";
pub const EXTRA_FILE: &str = "extra";
pub const RECV_DTBO_FILE: &str = "recovery_dtbo";
pub const DTB_FILE: &str = "dtb";
pub const KER_DTB_FILE: &str = "kernel_dtb";
pub const BOOTCONFIG_FILE: &str = "bootconfig";
pub const VND_RAMDISK_DIR: &str = "vendor_ramdisks";
