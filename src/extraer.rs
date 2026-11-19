//! Capas de contenedores y compresión: cada función devuelve los "hijos"
//! (la siguiente capa) contenidos en un bloque de bytes.

use std::io::{Cursor, Read, Write};

use anyhow::{anyhow, bail, Result};

use crate::idioma::{tfmt, tr};
use crate::detectar::{self, Tipo};

pub struct Hijo {
    pub nombre: String,
    pub datos: Vec<u8>,
}

/// Lee como máximo `limite` bytes; si hay más, es un error (posible bomba).
fn leer_limitado<R: Read>(r: R, limite: u64) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    r.take(limite + 1).read_to_end(&mut v)?;
    if v.len() as u64 > limite {
        bail!("{}", tfmt(tr("exceeds the limit of {} bytes (decompression bomb?)","supera el límite de {} bytes (¿bomba de descompresión?)"), &[limite.to_string()]));
    }
    Ok(v)
}

struct EscritorLimitado {
    v: Vec<u8>,
    limite: usize,
}
impl Write for EscritorLimitado {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.v.len() + b.len() > self.limite {
            return Err(std::io::Error::other(tr("size limit exceeded","supera el límite de tamaño")));
        }
        self.v.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn quitar_extension(nombre: &str, exts: &[&str]) -> String {
    let base = nombre.rsplit('/').next().unwrap_or(nombre);
    // Las extensiones son ASCII: comparar el sufijo sobre el nombre original
    // evita cortar a mitad de carácter con nombres Unicode.
    for e in exts {
        if base.len() > e.len() && base[base.len() - e.len()..].eq_ignore_ascii_case(e) {
            let r = &base[..base.len() - e.len()];
            return if *e == ".tgz" || *e == ".tbz2" || *e == ".txz" {
                format!("{r}.tar")
            } else {
                r.to_string()
            };
        }
    }
    format!("{base}.descomprimido")
}

pub fn gzip(d: &[u8], nombre: &str, lim: u64) -> Result<Vec<Hijo>> {
    let dec = flate2::read::MultiGzDecoder::new(d);
    let interno = {
        // El nombre original puede venir en la cabecera gzip.
        let gz = flate2::read::GzDecoder::new(d);
        gz.header()
            .and_then(|h| h.filename())
            .map(|f| String::from_utf8_lossy(f).into_owned())
    };
    let datos = leer_limitado(dec, lim)?;
    let n = interno.unwrap_or_else(|| quitar_extension(nombre, &[".gz", ".tgz", ".gzip"]));
    Ok(vec![Hijo { nombre: n, datos }])
}

pub fn zlib(d: &[u8], nombre: &str, lim: u64) -> Result<Vec<Hijo>> {
    let datos = leer_limitado(flate2::read::ZlibDecoder::new(d), lim)?;
    if datos.is_empty() {
        bail!("flujo zlib vacío");
    }
    Ok(vec![Hijo { nombre: quitar_extension(nombre, &[".zlib", ".z"]), datos }])
}

pub fn bzip2(d: &[u8], nombre: &str, lim: u64) -> Result<Vec<Hijo>> {
    let datos = leer_limitado(bzip2::read::MultiBzDecoder::new(d), lim)?;
    Ok(vec![Hijo { nombre: quitar_extension(nombre, &[".bz2", ".tbz2", ".bzip2"]), datos }])
}

pub fn xz(d: &[u8], nombre: &str, lim: u64) -> Result<Vec<Hijo>> {
    let mut w = EscritorLimitado { v: Vec::new(), limite: lim as usize };
    lzma_rs::xz_decompress(&mut Cursor::new(d), &mut w).map_err(|e| anyhow!("xz: {e:?}"))?;
    Ok(vec![Hijo { nombre: quitar_extension(nombre, &[".xz", ".txz"]), datos: w.v }])
}

pub fn lzma(d: &[u8], nombre: &str, lim: u64) -> Result<Vec<Hijo>> {
    let mut w = EscritorLimitado { v: Vec::new(), limite: lim as usize };
    lzma_rs::lzma_decompress(&mut Cursor::new(d), &mut w).map_err(|e| anyhow!("lzma: {e:?}"))?;
    Ok(vec![Hijo { nombre: quitar_extension(nombre, &[".lzma"]), datos: w.v }])
}

pub fn zip(d: &[u8], lim: u64, notas: &mut Vec<String>) -> Result<Vec<Hijo>> {
    let mut z = zip::ZipArchive::new(Cursor::new(d))?;
    let mut hijos = Vec::new();
    let mut total = 0u64;
    for i in 0..z.len() {
        let mut f = match z.by_index(i) {
            Ok(f) => f,
            Err(e) => {
                notas.push(tfmt(tr("entry #{} not readable: {}","entrada #{} no legible: {}"), &[i.to_string(), e.to_string()]));
                continue;
            }
        };
        if !f.is_file() {
            continue;
        }
        let nombre = f.name().to_string();
        if f.encrypted() {
            notas.push(tfmt(tr("'{}' is encrypted, skipped","'{}' está cifrado, se omite"), &[nombre.clone()]));
            continue;
        }
        let restante = lim.saturating_sub(total);
        match leer_limitado(&mut f, restante) {
            Ok(datos) => {
                total += datos.len() as u64;
                hijos.push(Hijo { nombre, datos });
            }
            Err(e) => notas.push(format!("'{nombre}': {e}")),
        }
    }
    Ok(hijos)
}

pub fn tar(d: &[u8], lim: u64, notas: &mut Vec<String>) -> Result<Vec<Hijo>> {
    let mut a = tar::Archive::new(Cursor::new(d));
    let mut hijos = Vec::new();
    let mut total = 0u64;
    for e in a.entries()? {
        let mut e = e?;
        if !e.header().entry_type().is_file() {
            continue;
        }
        let nombre = e.path()?.to_string_lossy().into_owned();
        match leer_limitado(&mut e, lim.saturating_sub(total)) {
            Ok(datos) => {
                total += datos.len() as u64;
                hijos.push(Hijo { nombre, datos });
            }
            Err(err) => notas.push(format!("'{nombre}': {err}")),
        }
    }
    Ok(hijos)
}

pub fn ar(d: &[u8]) -> Result<Vec<Hijo>> {
    let a = goblin::archive::Archive::parse(d)?;
    let mut hijos = Vec::new();
    for m in a.members() {
        if let Ok(datos) = a.extract(m, d) {
            hijos.push(Hijo { nombre: m.trim_end_matches('/').to_string(), datos: datos.to_vec() });
        }
    }
    Ok(hijos)
}

pub fn macho_fat(d: &[u8]) -> Result<Vec<Hijo>> {
    let multi = goblin::mach::MultiArch::new(d)?;
    let mut hijos = Vec::new();
    for (i, arch) in multi.iter_arches().enumerate() {
        let arch = arch?;
        let (o, s) = (arch.offset as usize, arch.size as usize);
        if let Some(datos) = d.get(o..o + s) {
            let nombre = format!(
                "arch{i}_{}.macho",
                goblin::mach::cputype::get_arch_name_from_types(arch.cputype, arch.cpusubtype)
                    .unwrap_or("desconocida")
            );
            hijos.push(Hijo { nombre, datos: datos.to_vec() });
        }
    }
    Ok(hijos)
}

/// Extrae los flujos (streams) de un PDF, descomprimiendo los FlateDecode.
pub fn pdf(d: &[u8], lim: u64) -> Vec<Hijo> {
    let mut hijos = Vec::new();
    let mut pos = 0;
    let mut n = 0;
    while let Some(i) = buscar(&d[pos..], b"stream") {
        let ini = pos + i + 6;
        // "endstream" también contiene "stream": saltarlo.
        if pos + i >= 3 && &d[pos + i - 3..pos + i] == b"end" {
            pos = ini;
            continue;
        }
        let mut s = ini;
        if d.get(s) == Some(&b'\r') {
            s += 1;
        }
        if d.get(s) == Some(&b'\n') {
            s += 1;
        }
        let Some(f) = buscar(&d[s..], b"endstream") else { break };
        let cuerpo = &d[s..s + f];
        pos = s + f + 9;
        n += 1;
        let datos = leer_limitado(flate2::read::ZlibDecoder::new(cuerpo), lim)
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| cuerpo.to_vec());
        hijos.push(Hijo { nombre: format!("flujo_{n:04}.bin"), datos });
        if n >= 10_000 {
            break;
        }
    }
    hijos
}

pub fn buscar(h: &[u8], aguja: &[u8]) -> Option<usize> {
    if aguja.is_empty() || h.len() < aguja.len() {
        return None;
    }
    let primero = aguja[0];
    let mut i = 0;
    while i + aguja.len() <= h.len() {
        match h[i..h.len() - aguja.len() + 1].iter().position(|&b| b == primero) {
            Some(p) => {
                i += p;
                if &h[i..i + aguja.len()] == aguja {
                    return Some(i);
                }
                i += 1;
            }
            None => return None,
        }
    }
    None
}

/// Busca bloques base64 largos en texto que, decodificados, sean un
/// formato reconocible (scripts que llevan cargas embebidas).
pub fn base64_embebido(d: &[u8]) -> Vec<Hijo> {
    const MIN: usize = 64;
    let es_b64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=';
    let mut hijos = Vec::new();
    let mut i = 0;
    while i < d.len() && hijos.len() < 64 {
        if !es_b64(d[i]) {
            i += 1;
            continue;
        }
        let ini = i;
        let mut limpio = Vec::new();
        while i < d.len() && (es_b64(d[i]) || matches!(d[i], b'\n' | b'\r' | b'\\')) {
            if es_b64(d[i]) {
                limpio.push(d[i]);
            }
            i += 1;
        }
        if limpio.len() >= MIN {
            if let Some(dec) = decodificar_b64(&limpio) {
                let t = detectar::detectar(&dec);
                if !matches!(t, Tipo::Texto | Tipo::Desconocido) {
                    hijos.push(Hijo {
                        nombre: format!("base64_0x{ini:x}.{}", t.extension()),
                        datos: dec,
                    });
                }
            }
        }
    }
    hijos
}

fn decodificar_b64(s: &[u8]) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    }
    let s: Vec<u8> = s.iter().copied().filter(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for ch in s.chunks(4) {
        let mut acc = 0u32;
        for (k, &c) in ch.iter().enumerate() {
            acc |= val(c)? << (18 - 6 * k);
        }
        let bytes = acc.to_be_bytes();
        let n = match ch.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => 0,
        };
        out.extend_from_slice(&bytes[1..1 + n]);
    }
    Some(out)
}

/// "Carving": busca firmas de otros formatos incrustadas dentro de un binario
/// (instaladores autoextraíbles, payloads, recursos...) y las valida.
pub fn tallar(d: &[u8], lim: u64) -> Vec<Hijo> {
    const FIRMAS: &[(&[u8], Tipo)] = &[
        (b"PK\x03\x04", Tipo::Zip),
        (&[0x1f, 0x8b, 0x08], Tipo::Gzip),
        (&[0xFD, b'7', b'z', b'X', b'Z', 0x00], Tipo::Xz),
        (&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C], Tipo::SieteZ),
        (b"\x7fELF", Tipo::Elf),
        (b"MZ", Tipo::Pe),
        (b"BZh", Tipo::Bzip2),
        (b"\x89PNG\r\n\x1a\n", Tipo::Imagen),
        (b"%PDF-", Tipo::Pdf),
        (b"Rar!\x1a\x07", Tipo::Rar),
    ];
    let mut hijos = Vec::new();
    let mut ultimo_zip = None;
    for (firma, tipo) in FIRMAS {
        let mut pos = 1; // offset 0 es el propio archivo
        while pos < d.len() && hijos.len() < 64 {
            let Some(i) = buscar(&d[pos..], firma) else { break };
            let off = pos + i;
            pos = off + 1;
            let resto = &d[off..];
            let valido = match tipo {
                Tipo::Zip => {
                    // Un zip incrustado contiene muchas cabeceras locales:
                    // basta con tallar la primera de cada bloque válido.
                    if ultimo_zip.is_some() {
                        continue;
                    }
                    zip::ZipArchive::new(Cursor::new(resto)).is_ok()
                }
                Tipo::Gzip => resto.len() > 18 && resto[3] < 0x20 && {
                    let mut b = [0u8; 16];
                    flate2::read::GzDecoder::new(resto).read(&mut b).map(|n| n > 0).unwrap_or(false)
                },
                Tipo::Elf => goblin::elf::Elf::parse(resto).is_ok(),
                Tipo::Pe => detectar::es_pe(resto) && goblin::pe::PE::parse(resto).is_ok(),
                Tipo::Bzip2 => resto.len() > 10 && (b'1'..=b'9').contains(&resto[3]) && &resto[4..10] == b"\x31\x41\x59\x26\x53\x59",
                _ => true,
            };
            if !valido {
                continue;
            }
            if *tipo == Tipo::Zip {
                ultimo_zip = Some(off);
            }
            let fin = (off as u64 + lim).min(d.len() as u64) as usize;
            hijos.push(Hijo {
                nombre: format!("tallado_0x{off:08x}.{}", tipo.extension()),
                datos: d[off..fin].to_vec(),
            });
        }
    }
    hijos
}

/// Cadenas legibles (ASCII y UTF-16LE).
pub fn cadenas(d: &[u8], min: usize, max_total: usize) -> String {
    let mut s = String::new();
    let mut act = Vec::new();
    let volcar = |act: &mut Vec<u8>, off: usize, s: &mut String, pref: &str| {
        if act.len() >= min && s.len() < max_total {
            s.push_str(&format!("{pref}0x{:08x}  {}\n", off - act.len(), String::from_utf8_lossy(act)));
        }
        act.clear();
    };
    for (i, &b) in d.iter().enumerate() {
        if (0x20..0x7f).contains(&b) || b == b'\t' {
            act.push(b);
        } else {
            volcar(&mut act, i, &mut s, "");
        }
    }
    volcar(&mut act, d.len(), &mut s, "");
    // UTF-16LE
    let mut i = 0;
    let mut ini = 0;
    let mut u = Vec::new();
    while i + 1 < d.len() {
        if (0x20..0x7f).contains(&d[i]) && d[i + 1] == 0 {
            if u.is_empty() {
                ini = i;
            }
            u.push(d[i]);
        } else {
            if u.len() >= min && s.len() < max_total {
                s.push_str(&format!("[u16] 0x{ini:08x}  {}\n", String::from_utf8_lossy(&u)));
            }
            u.clear();
        }
        i += 2;
    }
    s
}

#[cfg(test)]
mod pruebas {
    use super::quitar_extension;

    #[test]
    fn quitar_extension_unicode_no_panica() {
        // Nombre con mayúscula Unicode cuya minúscula cambia de longitud en bytes.
        assert_eq!(quitar_extension("İ.GZ", &[".gz"]), "İ");
        assert_eq!(quitar_extension("datos.TGZ", &[".tgz"]), "datos.tar");
        assert_eq!(quitar_extension("sin_ext", &[".gz"]), "sin_ext.descomprimido");
    }
}
