use std::io::{Read, Write};

pub fn align_to<T: num_traits::PrimInt + std::ops::Shr<Output = T>>(v: T, a: T) -> T {
    (v + a - T::one()) / a * a
}

pub fn align_padding<T: num_traits::PrimInt + std::ops::Shr<Output = T>>(v: T, a: T) -> T {
    align_to(v, a) - v
}

pub trait ReadExt: Read {
    fn read_pod<T: bytemuck::Pod>(&mut self) -> std::io::Result<T> {
        let mut buf = vec![0u8; std::mem::size_of::<T>()];
        self.read_exact(&mut buf)?;
        Ok(bytemuck::pod_read_unaligned(&buf))
    }

    fn skip(&mut self, n: usize) -> std::io::Result<()> {
        let mut buf = vec![0u8; n];
        self.read_exact(&mut buf)
    }
}

impl<R: Read> ReadExt for R {}

pub trait WriteExt: Write {
    fn write_pod<T: bytemuck::Pod>(&mut self, val: &T) -> std::io::Result<()> {
        self.write_all(bytemuck::bytes_of(val))
    }

    fn write_zeros(&mut self, n: usize) -> std::io::Result<()> {
        let buf = vec![0u8; n];
        self.write_all(&buf)
    }

    fn write_all_size(&mut self, n: usize) -> std::io::Result<()> {
        let buf = vec![0u8; n];
        self.write_all(&buf)
    }
}

impl<W: Write> WriteExt for W {}

pub trait SliceExt {
    fn u32_at(&self, offset: usize) -> Option<u32>;
    fn starts_with_at(&self, offset: usize, pattern: &[u8]) -> bool;
}

impl SliceExt for [u8] {
    fn u32_at(&self, offset: usize) -> Option<u32> {
        let d = self.get(offset..offset + 4)?;
        Some(u32::from_le_bytes(d.try_into().unwrap()))
    }

    fn starts_with_at(&self, offset: usize, pattern: &[u8]) -> bool {
        self.get(offset..)
            .map(|s| s.starts_with(pattern))
            .unwrap_or(false)
    }
}

pub fn trim_end(buf: &[u8]) -> &[u8] {
    let mut end = buf.len();
    while end > 0 && buf[end - 1] == 0 {
        end -= 1;
    }
    &buf[..end]
}

pub fn guess_lzma(buf: &[u8]) -> bool {
    if buf.len() <= 13 {
        return false;
    }
    if buf[0] != 0x5d {
        return false;
    }
    let dict_sz = u32::from_le_bytes(buf[1..5].try_into().unwrap());
    if dict_sz == 0 || (dict_sz & (dict_sz - 1)) != 0 {
        return false;
    }
    buf[5..13] == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
}


