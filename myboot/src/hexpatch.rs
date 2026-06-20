use anyhow::{Result, bail};

pub fn hex2byte(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        bail!("hex string must have even length");
    }
    let mut v = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk)?;
        let byte = u8::from_str_radix(s, 16)?;
        v.push(byte);
    }
    Ok(v)
}

pub fn hexpatch(data: &mut Vec<u8>, from_pattern: &str, to_pattern: &str) -> Result<Vec<usize>> {
    let from = hex2byte(from_pattern)?;
    let to = hex2byte(to_pattern)?;
    if from.is_empty() {
        bail!("empty search pattern");
    }
    let mut offsets = Vec::new();
    let mut pos = 0;
    while pos + from.len() <= data.len() {
        if data[pos..pos + from.len()] == from[..] {
            offsets.push(pos);
            let copy_len = std::cmp::min(to.len(), data.len() - pos);
            data[pos..pos + copy_len].copy_from_slice(&to[..copy_len]);
            pos += from.len();
        } else {
            pos += 1;
        }
    }
    Ok(offsets)
}
