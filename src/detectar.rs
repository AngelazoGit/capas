//! Identificación del tipo de archivo por "números mágicos" y heurísticas.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Tipo {
    Zip,
    Gzip,
    Bzip2,
    Xz,
    Lzma,
    Zlib,
    Tar,
    SieteZ,
    Rar,
    Cab,
    ArUnix,
    Elf,
    Pe,
    MachO,
    MachOFat,
    ClaseJava,
    Dex,
    Pyc,
    Wasm,
    Pdf,
    Imagen,
    Texto,
    Desconocido,
}

impl Tipo {
    pub fn nombre(self) -> &'static str {
        match self {
            Tipo::Zip => "ZIP (zip/jar/apk/docx...)",
            Tipo::Gzip => "GZIP",
            Tipo::Bzip2 => "BZIP2",
            Tipo::Xz => "XZ",
            Tipo::Lzma => "LZMA",
            Tipo::Zlib => "ZLIB",
            Tipo::Tar => "TAR",
            Tipo::SieteZ => "7-Zip",
            Tipo::Rar => "RAR",
            Tipo::Cab => "CAB",
            Tipo::ArUnix => "AR (.a/.deb)",
            Tipo::Elf => "ELF ejecutable",
            Tipo::Pe => "PE ejecutable (Windows)",
            Tipo::MachO => "Mach-O ejecutable",
            Tipo::MachOFat => "Mach-O universal (fat)",
            Tipo::ClaseJava => "Clase Java",
            Tipo::Dex => "Android DEX",
            Tipo::Pyc => "Bytecode Python",
            Tipo::Wasm => "WebAssembly",
            Tipo::Pdf => "PDF",
            Tipo::Imagen => "Imagen",
            Tipo::Texto => "Texto / script",
            Tipo::Desconocido => "Binario desconocido",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Tipo::Zip => "zip",
            Tipo::Gzip => "gz",
            Tipo::Bzip2 => "bz2",
            Tipo::Xz => "xz",
            Tipo::Lzma => "lzma",
            Tipo::Zlib => "zlib",
            Tipo::Tar => "tar",
            Tipo::SieteZ => "7z",
            Tipo::Rar => "rar",
            Tipo::Cab => "cab",
            Tipo::ArUnix => "a",
            Tipo::Elf => "elf",
            Tipo::Pe => "exe",
            Tipo::MachO | Tipo::MachOFat => "macho",
            Tipo::ClaseJava => "class",
            Tipo::Dex => "dex",
            Tipo::Pyc => "pyc",
            Tipo::Wasm => "wasm",
            Tipo::Pdf => "pdf",
            Tipo::Imagen => "img",
            Tipo::Texto => "txt",
            Tipo::Desconocido => "bin",
        }
    }

    /// Los contenedores no se "tallan" (carving) por dentro: ya se extraen.
    pub fn es_contenedor(self) -> bool {
        matches!(
            self,
            Tipo::Zip
                | Tipo::Gzip
                | Tipo::Bzip2
                | Tipo::Xz
                | Tipo::Lzma
                | Tipo::Zlib
                | Tipo::Tar
                | Tipo::SieteZ
                | Tipo::Rar
                | Tipo::Cab
                | Tipo::ArUnix
                | Tipo::MachOFat
                | Tipo::Pdf
        )
    }
}

fn u32le(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}
fn u32be(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_be_bytes(b.try_into().unwrap()))
}

pub fn es_pe(d: &[u8]) -> bool {
    if !d.starts_with(b"MZ") {
        return false;
    }
    match u32le(d, 0x3c) {
        Some(off) if (off as usize) < d.len().saturating_sub(4) => {
            &d[off as usize..off as usize + 4] == b"PE\0\0"
        }
        _ => false,
    }
}

pub fn detectar(d: &[u8]) -> Tipo {
    if d.starts_with(b"PK\x03\x04") || d.starts_with(b"PK\x05\x06") {
        return Tipo::Zip;
    }
    if d.starts_with(&[0x1f, 0x8b, 0x08]) {
        return Tipo::Gzip;
    }
    if d.len() > 10 && d.starts_with(b"BZh") && (b'1'..=b'9').contains(&d[3]) {
        return Tipo::Bzip2;
    }
    if d.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return Tipo::Xz;
    }
    if d.starts_with(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]) {
        return Tipo::SieteZ;
    }
    if d.starts_with(b"Rar!\x1a\x07") {
        return Tipo::Rar;
    }
    if d.starts_with(b"MSCF\0\0\0\0") {
        return Tipo::Cab;
    }
    if d.starts_with(b"!<arch>\n") {
        return Tipo::ArUnix;
    }
    if d.len() > 262 && &d[257..262] == b"ustar" {
        return Tipo::Tar;
    }
    if d.starts_with(b"\x7fELF") {
        return Tipo::Elf;
    }
    if es_pe(d) {
        return Tipo::Pe;
    }
    match u32be(d, 0) {
        Some(0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE) => return Tipo::MachO,
        Some(0xCAFEBABE) => {
            // Mismo mágico para clases Java y Mach-O fat: se distingue
            // por el siguiente entero (nº de arquitecturas vs versión Java).
            let n = u32be(d, 4).unwrap_or(0);
            return if n > 0 && n < 40 { Tipo::MachOFat } else { Tipo::ClaseJava };
        }
        _ => {}
    }
    if d.starts_with(b"dex\n") && d.len() > 0x70 {
        return Tipo::Dex;
    }
    if d.starts_with(b"\0asm") {
        return Tipo::Wasm;
    }
    if d.starts_with(b"%PDF") {
        return Tipo::Pdf;
    }
    if d.len() >= 16 && d[2] == b'\r' && d[3] == b'\n' {
        let ver = u16::from_le_bytes([d[0], d[1]]);
        if (2900..=4000).contains(&ver) || (20121..=62211).contains(&ver) {
            return Tipo::Pyc;
        }
    }
    if d.starts_with(b"\x89PNG")
        || d.starts_with(&[0xFF, 0xD8, 0xFF])
        || d.starts_with(b"GIF8")
        || d.starts_with(b"BM")
            && d.len() > 14
            && u32le(d, 2).map(|n| n as usize == d.len()).unwrap_or(false)
    {
        return Tipo::Imagen;
    }
    if d.len() > 13 && d[0] == 0x5D && d[1] == 0x00 && d[2] == 0x00 {
        return Tipo::Lzma;
    }
    if d.len() > 2 && d[0] == 0x78 && matches!(d[1], 0x01 | 0x5E | 0x9C | 0xDA) {
        return Tipo::Zlib;
    }
    if es_texto(d) {
        return Tipo::Texto;
    }
    Tipo::Desconocido
}

pub fn es_texto(d: &[u8]) -> bool {
    if d.is_empty() {
        return true;
    }
    let muestra = &d[..d.len().min(64 * 1024)];
    if std::str::from_utf8(muestra).is_err() {
        // Puede estar cortado a mitad de un carácter multibyte.
        let corte = muestra.len().saturating_sub(4);
        if std::str::from_utf8(&muestra[..corte]).is_err()
            && muestra.iter().filter(|&&b| b >= 0x80).count() > muestra.len() / 20
        {
            return false;
        }
    }
    let raros = muestra
        .iter()
        .filter(|&&b| b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t' | 0x0c))
        .count();
    raros * 100 < muestra.len()
}

pub fn entropia(d: &[u8]) -> f64 {
    if d.is_empty() {
        return 0.0;
    }
    let mut f = [0u64; 256];
    for &b in d {
        f[b as usize] += 1;
    }
    let n = d.len() as f64;
    f.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}
