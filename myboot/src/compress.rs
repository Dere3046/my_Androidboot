use crate::constants::*;
use crate::utils::guess_lzma;
use bzip2::Compression as BzCompression;
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use flate2::Compression as GzCompression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use lz4::block::CompressionMode;
use lz4::liblz4::BlockChecksum;
use lz4::{
    BlockMode, BlockSize, ContentChecksum, Decoder as Lz4FrameDecoder, Encoder as Lz4FrameEncoder,
    EncoderBuilder as Lz4FrameEncoderBuilder,
};
use lzma_rust2::{CheckType, LzmaOptions, LzmaReader, LzmaWriter, XzOptions, XzReader, XzWriter};
use std::cmp::min;
use std::io::{BufWriter, Read, Write};
use std::num::NonZeroU64;
use zopfli::{BlockType, GzipEncoder as ZopFliEncoder, Options as ZopfliOptions};

const LZ4_BLOCK_SIZE: usize = 0x800000;
const LZ4HC_CLEVEL_MAX: i32 = 12;
const LZ4_MAGIC_U32: u32 = 0x184c2102;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum CompressFormat {
    UNKNOWN,
    GZIP,
    ZOPFLI,
    XZ,
    LZMA,
    BZIP2,
    LZ4,
    LZ4_LEGACY,
    LZ4_LG,
    LZOP,
    MTK,
    DTB,
    ZIMAGE,
}

pub fn parse_compress_format(data: &[u8]) -> CompressFormat {
    if data.len() < 2 {
        return CompressFormat::UNKNOWN;
    }
    if data.starts_with(GZIP1_MAGIC) || data.starts_with(GZIP2_MAGIC) {
        return CompressFormat::GZIP;
    }
    if data.len() >= 4 {
        if data.starts_with(LZOP_MAGIC) {
            return CompressFormat::LZOP;
        }
        if data.starts_with(XZ_MAGIC) {
            return CompressFormat::XZ;
        }
        if data.starts_with(LZ41_MAGIC) || data.starts_with(LZ42_MAGIC) {
            return CompressFormat::LZ4;
        }
        if data.starts_with(LZ4_LEG_MAGIC) {
            return CompressFormat::LZ4_LEGACY;
        }
        if data.starts_with(MTK_MAGIC) {
            return CompressFormat::MTK;
        }
        if data.starts_with(DTB_MAGIC) {
            return CompressFormat::DTB;
        }
    }
    if data.len() >= 4 && data.starts_with(BZIP_MAGIC) {
        return CompressFormat::BZIP2;
    }
    if guess_lzma(data) {
        return CompressFormat::LZMA;
    }
    CompressFormat::UNKNOWN
}

pub fn is_compressed(fmt: CompressFormat) -> bool {
    matches!(
        fmt,
        CompressFormat::GZIP
            | CompressFormat::ZOPFLI
            | CompressFormat::XZ
            | CompressFormat::LZMA
            | CompressFormat::BZIP2
            | CompressFormat::LZ4
            | CompressFormat::LZ4_LEGACY
            | CompressFormat::LZ4_LG
    )
}

pub fn fmt2name(fmt: CompressFormat) -> &'static str {
    match fmt {
        CompressFormat::UNKNOWN => "raw",
        CompressFormat::GZIP => "gzip",
        CompressFormat::ZOPFLI => "zopfli",
        CompressFormat::XZ => "xz",
        CompressFormat::LZMA => "lzma",
        CompressFormat::BZIP2 => "bzip2",
        CompressFormat::LZ4 => "lz4",
        CompressFormat::LZ4_LEGACY => "lz4_legacy",
        CompressFormat::LZ4_LG => "lz4_lg",
        CompressFormat::LZOP => "lzop",
        CompressFormat::MTK => "mtk",
        CompressFormat::DTB => "dtb",
        CompressFormat::ZIMAGE => "zimage",
    }
}

pub trait WriteFinish<W: Write>: Write {
    fn finish(self: Box<Self>) -> std::io::Result<W>;
}

macro_rules! finish_impl {
    ($($t:ty),*) => {$(
        impl<W: Write> WriteFinish<W> for $t {
            fn finish(self: Box<Self>) -> std::io::Result<W> {
                Self::finish(*self)
            }
        }
    )*}
}

finish_impl!(GzEncoder<W>, BzEncoder<W>, XzWriter<W>, LzmaWriter<W>);

impl<W: Write> WriteFinish<W> for BufWriter<ZopFliEncoder<W>> {
    fn finish(self: Box<Self>) -> std::io::Result<W> {
        let inner = self.into_inner()?;
        ZopFliEncoder::finish(inner)
    }
}

impl<W: Write> WriteFinish<W> for Lz4FrameEncoder<W> {
    fn finish(self: Box<Self>) -> std::io::Result<W> {
        let (w, r) = Self::finish(*self);
        r?;
        Ok(w)
    }
}

struct Chunker {
    buf: Vec<u8>,
    chunk_size: usize,
}

impl Chunker {
    fn new(chunk_size: usize) -> Self {
        Chunker {
            buf: Vec::with_capacity(chunk_size * 2),
            chunk_size,
        }
    }

    fn out_chunks<F: FnMut(&[u8]) -> std::io::Result<()>>(
        &mut self,
        data: &[u8],
        mut flush: F,
    ) -> std::io::Result<()> {
        self.buf.extend_from_slice(data);
        while self.buf.len() >= self.chunk_size {
            let chunk = self.buf[..self.chunk_size].to_vec();
            self.buf.drain(..self.chunk_size);
            flush(&chunk)?;
        }
        Ok(())
    }

    fn final_chunk<F: FnMut(&[u8]) -> std::io::Result<()>>(&mut self, mut flush: F) -> std::io::Result<()> {
        if !self.buf.is_empty() {
            let chunk = std::mem::take(&mut self.buf);
            flush(&chunk)?;
        }
        Ok(())
    }
}

struct Lz4BlockEncoder<W: Write> {
    write: W,
    chunker: Chunker,
    out_buf: Box<[u8]>,
    total: u32,
}

impl<W: Write> Lz4BlockEncoder<W> {
    fn new(write: W) -> Self {
        let out_sz = lz4::block::compress_bound(LZ4_BLOCK_SIZE).unwrap_or(LZ4_BLOCK_SIZE);
        Lz4BlockEncoder {
            write,
            chunker: Chunker::new(LZ4_BLOCK_SIZE),
            out_buf: unsafe { Box::new_uninit_slice(out_sz).assume_init() },
            total: 0,
        }
    }

    fn encode_block(write: &mut W, out_buf: &mut [u8], chunk: &[u8]) -> std::io::Result<()> {
        let compressed_size = lz4::block::compress_to_buffer(
            chunk,
            Some(CompressionMode::HIGHCOMPRESSION(LZ4HC_CLEVEL_MAX)),
            false,
            out_buf,
        )?;
        let block_size = compressed_size as u32;
        write.write_all(&block_size.to_le_bytes())?;
        write.write_all(&out_buf[..compressed_size])?;
        Ok(())
    }
}

impl<W: Write> Write for Lz4BlockEncoder<W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.total += data.len() as u32;
        self.chunker.out_chunks(data, |chunk| {
            Self::encode_block(&mut self.write, &mut self.out_buf, chunk)
        })?;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<W: Write> WriteFinish<W> for Lz4BlockEncoder<W> {
    fn finish(self: Box<Self>) -> std::io::Result<W> {
        let mut this = *self;
        this.chunker.final_chunk(|chunk| {
            Self::encode_block(&mut this.write, &mut this.out_buf, chunk)
        })?;
        this.write.write_all(&LZ4_MAGIC_U32.to_le_bytes())?;
        this.write.write_all(&this.total.to_le_bytes())?;
        Ok(this.write)
    }
}

struct Lz4BlockDecoder {
    buf: Vec<u8>,
    pos: usize,
}

impl Lz4BlockDecoder {
    fn new(compressed: &[u8]) -> std::io::Result<Self> {
        let mut buf = Vec::new();
        let mut off = 4usize;
        while off + 4 <= compressed.len() {
            let block_sz = u32::from_le_bytes(
                compressed[off..off + 4].try_into().unwrap(),
            ) as usize;
            off += 4;
            if off + block_sz > compressed.len() {
                break;
            }
            if block_sz == 0 {
                continue;
            }
            let decompressed = lz4::block::decompress(&compressed[off..off + block_sz], Some(LZ4_BLOCK_SIZE as i32))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            buf.extend_from_slice(&decompressed);
            off += block_sz;
        }
        Ok(Self { buf, pos: 0 })
    }
}

impl Read for Lz4BlockDecoder {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let len = min(out.len(), self.buf.len() - self.pos);
        out[..len].copy_from_slice(&self.buf[self.pos..self.pos + len]);
        self.pos += len;
        Ok(len)
    }
}

pub fn get_decoder(format: CompressFormat, data: &[u8]) -> std::io::Result<Box<dyn Read + '_>> {
    Ok(match format {
        CompressFormat::GZIP | CompressFormat::ZOPFLI => {
            Box::new(MultiGzDecoder::new(data))
        }
        CompressFormat::XZ => {
            Box::new(XzReader::new(std::io::Cursor::new(data.to_vec()), true))
        }
        CompressFormat::LZMA => {
            Box::new(LzmaReader::new_mem_limit(std::io::Cursor::new(data.to_vec()), u32::MAX, None)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?)
        }
        CompressFormat::BZIP2 => Box::new(BzDecoder::new(data)),
        CompressFormat::LZ4 => Box::new(
            Lz4FrameDecoder::new(data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        ),
        CompressFormat::LZ4_LEGACY | CompressFormat::LZ4_LG => {
            Box::new(Lz4BlockDecoder::new(data)?)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("unsupported format: {:?}", format),
            ))
        }
    })
}

pub fn get_encoder<'a, W: Write + 'a>(format: CompressFormat, w: &'a mut W) -> std::io::Result<Box<dyn WriteFinish<&'a mut W> + 'a>> {
    Ok(match format {
        CompressFormat::XZ => {
            let mut opt = XzOptions::with_preset(9);
            opt.set_check_sum_type(CheckType::Crc32);
            Box::new(XzWriter::new(w, opt)?)
        }
        CompressFormat::LZMA => Box::new(LzmaWriter::new_use_header(
            w,
            &LzmaOptions::with_preset(9),
            None,
        )?),
        CompressFormat::BZIP2 => Box::new(BzEncoder::new(w, BzCompression::best())),
        CompressFormat::LZ4 => {
            let encoder = Lz4FrameEncoderBuilder::new()
                .block_size(BlockSize::Max4MB)
                .block_mode(BlockMode::Independent)
                .checksum(ContentChecksum::ChecksumEnabled)
                .block_checksum(BlockChecksum::BlockChecksumEnabled)
                .level(9)
                .auto_flush(true)
                .build(w)?;
            Box::new(encoder)
        }
        CompressFormat::LZ4_LEGACY | CompressFormat::LZ4_LG => {
            Box::new(Lz4BlockEncoder::new(w))
        }
        CompressFormat::ZOPFLI => {
            let opt = ZopfliOptions {
                iteration_count: unsafe { NonZeroU64::new_unchecked(1) },
                maximum_block_splits: 1,
                ..Default::default()
            };
            Box::new(ZopFliEncoder::new_buffered(opt, BlockType::Dynamic, w)?)
        }
        CompressFormat::GZIP => Box::new(GzEncoder::new(w, GzCompression::best())),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("unsupported format: {:?}", format),
            ))
        }
    })
}
