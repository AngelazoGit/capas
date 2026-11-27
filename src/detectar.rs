//! Identificación del tipo de archivo por "números mágicos" y heurísticas.

use serde::Serialize;

use crate::idioma::tr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Tipo {
    Zip,
    Gzip,
    Bzip2,
    Xz,
    Lzma,
    Zlib,
    Zstd,
    Lz4,
    Iso,
    Chd,
    Disco,
    Tar,
    SieteZ,
    Rar,
    Cab,
    Ole,
    ArUnix,
    Elf,
    Pe,
    MachO,
    MachOFat,
    ClaseJava,
    Dex,
    Pyc,
    Wasm,
    Shader,
    DotNet,
    Pdf,
    Imagen,
    Audio,
    Video,
    Fuente,
    BaseDatos,
    RecursoJuego,
    Texto,
    Desconocido,
}

impl Tipo {
    pub fn nombre(self) -> &'static str {
        match self {
            Tipo::Zip => tr("ZIP (zip/jar/apk/docx...)","ZIP (zip/jar/apk/docx...)"),
            Tipo::Gzip => "GZIP",
            Tipo::Bzip2 => "BZIP2",
            Tipo::Xz => "XZ",
            Tipo::Lzma => "LZMA",
            Tipo::Zlib => "ZLIB",
            Tipo::Zstd => "Zstandard",
            Tipo::Lz4 => "LZ4",
            Tipo::Iso => tr("ISO 9660 disc image","imagen de disco ISO 9660"),
            Tipo::Chd => tr("CHD compressed disc image","imagen de disco comprimida CHD"),
            Tipo::Disco => tr("partitioned disk image (MBR/GPT)","imagen de disco con particiones (MBR/GPT)"),
            Tipo::Tar => "TAR",
            Tipo::SieteZ => "7-Zip",
            Tipo::Rar => "RAR",
            Tipo::Cab => "CAB",
            Tipo::Ole => tr("OLE compound file (MSI/DOC/XLS)","archivo compuesto OLE (MSI/DOC/XLS)"),
            Tipo::ArUnix => "AR (.a/.deb)",
            Tipo::Elf => tr("ELF executable","ELF ejecutable"),
            Tipo::Pe => tr("PE executable (Windows)","PE ejecutable (Windows)"),
            Tipo::MachO => tr("Mach-O executable","Mach-O ejecutable"),
            Tipo::MachOFat => tr("Mach-O universal (fat)","Mach-O universal (fat)"),
            Tipo::ClaseJava => tr("Java class","Clase Java"),
            Tipo::Dex => "Android DEX",
            Tipo::Pyc => tr("Python bytecode","Bytecode Python"),
            Tipo::Wasm => "WebAssembly",
            Tipo::Shader => tr("Shader (SPIR-V)", "Shader (SPIR-V)"),
            Tipo::DotNet => tr(".NET assembly (CLI)", "Ensamblado .NET (CLI)"),
            Tipo::Pdf => "PDF",
            Tipo::Imagen => tr("Image","Imagen"),
            Tipo::Audio => "Audio",
            Tipo::Video => tr("Video","Vídeo"),
            Tipo::Fuente => tr("Font","Fuente tipográfica"),
            Tipo::BaseDatos => tr("Database","Base de datos"),
            Tipo::RecursoJuego => tr("Game / 3D resource","Recurso de juego / 3D"),
            Tipo::Texto => tr("Text / script","Texto / script"),
            Tipo::Desconocido => tr("Unknown binary","Binario desconocido"),
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
            Tipo::Zstd => "zst",
            Tipo::Lz4 => "lz4",
            Tipo::Iso => "iso",
            Tipo::Chd => "chd",
            Tipo::Disco => "img",
            Tipo::Tar => "tar",
            Tipo::SieteZ => "7z",
            Tipo::Rar => "rar",
            Tipo::Cab => "cab",
            Tipo::Ole => "msi",
            Tipo::ArUnix => "a",
            Tipo::Elf => "elf",
            Tipo::Pe => "exe",
            Tipo::MachO | Tipo::MachOFat => "macho",
            Tipo::ClaseJava => "class",
            Tipo::Dex => "dex",
            Tipo::Pyc => "pyc",
            Tipo::Wasm => "wasm",
            Tipo::Shader => "shader",
            Tipo::DotNet => "dotnet",
            Tipo::Pdf => "pdf",
            Tipo::Imagen => "img",
            Tipo::Audio => "audio",
            Tipo::Video => "video",
            Tipo::Fuente => "font",
            Tipo::BaseDatos => "db",
            Tipo::RecursoJuego => "res",
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
                | Tipo::Zstd
                | Tipo::Lz4
                | Tipo::Iso
                | Tipo::Chd
                | Tipo::Disco
                | Tipo::Tar
                | Tipo::SieteZ
                | Tipo::Rar
                | Tipo::Cab
                | Tipo::Ole
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

/// ¿El PE tiene cabecera CLR (directorio de datos 14)? → es un ensamblado .NET.
/// Comprobación ligera (sin parsear todo el PE).
pub fn pe_tiene_clr(d: &[u8]) -> bool {
    let lf = match u32le(d, 0x3c) {
        Some(v) => v as usize,
        None => return false,
    };
    let opt = lf + 24; // PE sig(4) + COFF header(20)
    let magic = match d.get(opt..opt + 2) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => return false,
    };
    let dd = match magic {
        0x10b => opt + 96,  // PE32
        0x20b => opt + 112, // PE32+
        _ => return false,
    };
    let dir14 = dd + 14 * 8; // directorio de datos nº 14 (COM descriptor)
    match (u32le(d, dir14), u32le(d, dir14 + 4)) {
        (Some(rva), Some(sz)) => rva != 0 && sz != 0,
        _ => false,
    }
}

/// ¿El MBR (bytes 0x1BE..0x1FE) tiene al menos una partición con tipo no nulo y
/// un LBA de inicio plausible dentro de la imagen? Evita falsos positivos de 55AA.
fn mbr_valido(d: &[u8]) -> bool {
    for i in 0..4 {
        let e = 0x1be + i * 16;
        let tipo = d[e + 4];
        let lba = u32::from_le_bytes([d[e + 8], d[e + 9], d[e + 10], d[e + 11]]) as u64;
        let sectores = u32::from_le_bytes([d[e + 12], d[e + 13], d[e + 14], d[e + 15]]) as u64;
        if tipo != 0 && lba > 0 && sectores > 0 && lba.saturating_mul(512) < d.len() as u64 {
            return true;
        }
    }
    false
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
    if d.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Tipo::Zstd;
    }
    if d.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
        return Tipo::Lz4;
    }
    // ISO 9660: "CD001" en el descriptor de volumen (sector 16). Cocido (2048),
    // o crudo de 2352 B (Mode1 +16, Mode2 form1 +24) de pistas de datos .bin.
    if (d.len() >= 0x8006 && &d[0x8001..0x8006] == b"CD001")
        || (d.len() >= 16 * 2352 + 22 && &d[16 * 2352 + 17..16 * 2352 + 22] == b"CD001")
        || (d.len() >= 16 * 2352 + 30 && &d[16 * 2352 + 25..16 * 2352 + 30] == b"CD001")
    {
        return Tipo::Iso;
    }
    if d.starts_with(b"MComprHD") {
        return Tipo::Chd;
    }
    // Tabla de particiones: GPT ("EFI PART" en el sector 1) o MBR con entradas válidas.
    if d.len() >= 0x208 && &d[0x200..0x208] == b"EFI PART" {
        return Tipo::Disco;
    }
    if d.len() >= 0x200 && d[0x1fe] == 0x55 && d[0x1ff] == 0xAA && mbr_valido(d) {
        return Tipo::Disco;
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
    // Compound File Binary (OLE2): MSI/MSP/MST, Office 97-2003, thumbs.db…
    if d.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return Tipo::Ole;
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
        if pe_tiene_clr(d) {
            return Tipo::DotNet;
        }
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
    // SPIR-V: magia 0x07230203 (little o big endian).
    if d.len() >= 20 && (d[0..4] == [0x03, 0x02, 0x23, 0x07] || d[0..4] == [0x07, 0x23, 0x02, 0x03]) {
        return Tipo::Shader;
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
    // Contenedor RIFF: el subtipo (bytes 8..12) decide la familia.
    if d.len() >= 12 && &d[0..4] == b"RIFF" {
        match &d[8..12] {
            b"WAVE" => return Tipo::Audio,
            b"AVI " => return Tipo::Video,
            b"WEBP" => return Tipo::Imagen,
            _ => {}
        }
    }
    // Contenedor ISO-BMFF (mp4/mov/m4a/m4v/heic/avif): la "marca" en 8..12 decide.
    if d.len() >= 12 && &d[4..8] == b"ftyp" {
        let marca = &d[8..12];
        if matches!(marca, b"avif" | b"avis" | b"heic" | b"heix" | b"heif" | b"hevc" | b"mif1" | b"msf1") {
            return Tipo::Imagen;
        }
        if matches!(&d[8..11], b"M4A" | b"M4B") {
            return Tipo::Audio;
        }
        return Tipo::Video;
    }
    // Audio sin contenedor.
    if d.starts_with(b"OggS") || d.starts_with(b"fLaC") || d.starts_with(b"ID3")
        || d.starts_with(b"MThd")                       // MIDI
        || d.starts_with(b".snd")                       // Sun/NeXT AU
        || d.starts_with(b"MAC ")                       // Monkey's Audio (.ape)
        || d.starts_with(b"wvpk")                       // WavPack
        || d.starts_with(b"IMPM")                       // Impulse Tracker (.it)
        || d.starts_with(b"Extended Module:")           // FastTracker (.xm)
        || (d.len() >= 12 && &d[0..4] == b"FORM" && &d[8..12] == b"AIFF") // AIFF
        || (d.len() > 2 && d[0] == 0xFF && matches!(d[1], 0xFB | 0xF3 | 0xF2))
    {
        return Tipo::Audio;
    }
    // Vídeo Matroska / WebM (EBML).
    if d.starts_with(&[0x1A, 0x45, 0xDF, 0xA3])
        || d.starts_with(b"FLV")                                     // Flash Video
        || d.starts_with(&[0x30, 0x26, 0xB2, 0x75])                 // ASF / WMV / WMA
        || d.starts_with(&[0x00, 0x00, 0x01, 0xBA])                 // MPEG Program Stream
        || d.starts_with(&[0x00, 0x00, 0x01, 0xB3])                 // MPEG vídeo
    {
        return Tipo::Video;
    }
    // Recursos de juego / 3D / motores (firmas inconfundibles).
    if d.starts_with(b"UnityFS")                                     // Unity asset bundle
        || d.starts_with(b"glTF")                                    // glTF binario (.glb)
        || d.starts_with(b"BLENDER")                                 // Blender (.blend)
        || d.starts_with(b"GDPC")                                    // Godot pack (.pck)
        || d.starts_with(b"Kaydara FBX Binary")                      // FBX binario
        || d.starts_with(b"VTF\0")                                   // Valve texture
        || d.starts_with(&[0x34, 0x12, 0xAA, 0x55])                 // Valve VPK
        || d.starts_with(&[0xAB, b'K', b'T', b'X'])                 // KTX / KTX2 textura
        || d.starts_with(b"BKHD")                                    // Wwise soundbank
        || d.starts_with(b"FSB5")                                    // FMOD soundbank
    {
        return Tipo::RecursoJuego;
    }
    // Bases de datos / formatos de datos.
    if d.starts_with(b"SQLite format 3\0")
        || (d.len() >= 19 && &d[4..19] == b"Standard Jet DB")       // Access (.mdb)
        || (d.len() >= 19 && &d[4..19] == b"Standard ACE DB")       // Access (.accdb)
        || d.starts_with(b"\x89HDF\r\n")                            // HDF5
    {
        return Tipo::BaseDatos;
    }
    // Fuentes tipográficas.
    if d.starts_with(b"OTTO") || d.starts_with(b"wOFF") || d.starts_with(b"wOF2")
        || d.starts_with(b"ttcf") || d.starts_with(b"true") || d.starts_with(&[0x00, 0x01, 0x00, 0x00])
    {
        return Tipo::Fuente;
    }
    if d.starts_with(b"\x89PNG")
        || d.starts_with(&[0xFF, 0xD8, 0xFF])
        || d.starts_with(b"GIF8")
        || d.starts_with(b"DDS ")
        || d.starts_with(b"8BPS")                                     // Photoshop PSD
        || d.starts_with(b"qoif")                                     // QOI
        || d.starts_with(b"icns")                                     // Apple icon
        || d.starts_with(b"#?RADIANCE")                               // Radiance HDR
        || d.starts_with(&[0x76, 0x2F, 0x31, 0x01])                  // OpenEXR
        || d.starts_with(&[0xFF, 0x0A])                              // JPEG XL (raw)
        || d.starts_with(&[0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20]) // JPEG XL (ISO)
        || d.starts_with(&[0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20]) // JPEG 2000
        || d.starts_with(&[0x00, 0x00, 0x01, 0x00]) // ICO
        || d.starts_with(b"II*\x00") // TIFF LE
        || d.starts_with(b"MM\x00*") // TIFF BE
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

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn firmas_nuevas() {
        // HEIC/AVIF ya no se confunden con vídeo (regresión del contenedor ftyp).
        let mut heic = vec![0u8; 16];
        heic[4..8].copy_from_slice(b"ftyp");
        heic[8..12].copy_from_slice(b"heic");
        assert_eq!(detectar(&heic), Tipo::Imagen);
        let mut avif = heic.clone();
        avif[8..12].copy_from_slice(b"avif");
        assert_eq!(detectar(&avif), Tipo::Imagen);
        // Un .mp4 de verdad sigue siendo vídeo.
        let mut mp4 = heic.clone();
        mp4[8..12].copy_from_slice(b"isom");
        assert_eq!(detectar(&mp4), Tipo::Video);

        assert_eq!(detectar(b"UnityFS\0\0\0\0"), Tipo::RecursoJuego);
        assert_eq!(detectar(b"glTF\x02\x00\x00\x00"), Tipo::RecursoJuego);
        assert_eq!(detectar(b"MThd\0\0\0\x06"), Tipo::Audio);
        assert_eq!(detectar(b"8BPS\0\x01"), Tipo::Imagen);
    }
}

#[cfg(test)]
mod pruebas_chd {
    use super::{detectar, Tipo};
    #[test]
    fn detecta_chd() {
        let mut d = b"MComprHD".to_vec();
        d.extend_from_slice(&[0u8; 120]);
        assert_eq!(detectar(&d), Tipo::Chd);
    }
}
