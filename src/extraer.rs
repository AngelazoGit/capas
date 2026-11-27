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
        bail!("{}", tr("empty zlib stream", "flujo zlib vacío"));
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

pub fn zstd(d: &[u8], nombre: &str, lim: u64) -> Result<Vec<Hijo>> {
    let dec = ruzstd::StreamingDecoder::new(d).map_err(|e| anyhow!("zstd: {e}"))?;
    let datos = leer_limitado(dec, lim)?;
    Ok(vec![Hijo { nombre: quitar_extension(nombre, &[".zst", ".tzst", ".zstd"]), datos }])
}

pub fn lz4(d: &[u8], nombre: &str, lim: u64) -> Result<Vec<Hijo>> {
    let datos = leer_limitado(lz4_flex::frame::FrameDecoder::new(d), lim)?;
    Ok(vec![Hijo { nombre: quitar_extension(nombre, &[".lz4"]), datos }])
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

// ── Desempaquetado de bundles de motores de juego (opción --desempaquetar) ──
// Lectura defensiva: todo viene de datos no confiables, así que cada acceso se
// comprueba y un dato corrupto aborta con error en vez de entrar en pánico.

fn be_u16(d: &[u8], o: usize) -> Option<u16> { d.get(o..o + 2).map(|b| u16::from_be_bytes(b.try_into().unwrap())) }
fn be_u32(d: &[u8], o: usize) -> Option<u32> { d.get(o..o + 4).map(|b| u32::from_be_bytes(b.try_into().unwrap())) }
fn be_i64(d: &[u8], o: usize) -> Option<i64> { d.get(o..o + 8).map(|b| i64::from_be_bytes(b.try_into().unwrap())) }
fn le_u32(d: &[u8], o: usize) -> Option<u32> { d.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())) }
fn le_u64(d: &[u8], o: usize) -> Option<u64> { d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())) }

/// Cadena terminada en NUL a partir de `o`; devuelve (texto, offset siguiente).
fn cadena(d: &[u8], o: usize) -> Option<(String, usize)> {
    let fin = d[o..].iter().position(|&b| b == 0)?;
    let s = String::from_utf8_lossy(&d[o..o + fin]).into_owned();
    Some((s, o + fin + 1))
}

/// Si `d` es un bundle reconocido, lo desempaqueta; si no, None.
pub fn desempaquetar_bundle(d: &[u8], nombre: &str, lim: u64) -> Option<Result<Vec<Hijo>>> {
    if d.starts_with(b"UnityFS\0") {
        Some(unity_bundle(d, lim))
    } else if d.starts_with(b"GDPC") {
        Some(godot_pck(d, lim))
    } else {
        let _ = nombre;
        None
    }
}

fn descomprimir_bloque(tipo: u8, comp: &[u8], tam: usize) -> Result<Vec<u8>> {
    match tipo {
        0 => Ok(comp.to_vec()),
        2 | 3 => lz4_flex::block::decompress(comp, tam).map_err(|e| anyhow!("LZ4: {e}")),
        1 => bail!("{}", tr("LZMA-compressed block not supported yet", "bloque comprimido con LZMA aún no soportado")),
        n => bail!("{}", tfmt(tr("unknown block compression: {}", "compresión de bloque desconocida: {}"), &[n.to_string()])),
    }
}

/// Bundle de Unity (UnityFS): descomprime los bloques y separa los ficheros
/// internos (nodos). Soporta bloques sin comprimir y LZ4/LZ4HC.
pub fn unity_bundle(d: &[u8], lim: u64) -> Result<Vec<Hijo>> {
    let err = || anyhow!("{}", tr("corrupt or truncated UnityFS bundle", "bundle UnityFS corrupto o truncado"));
    let mut o = 8; // tras "UnityFS\0"
    let ver = be_u32(d, o).ok_or_else(err)?;
    o += 4;
    let (_uv, o1) = cadena(d, o).ok_or_else(err)?;
    let (_ur, o2) = cadena(d, o1).ok_or_else(err)?;
    o = o2;
    let _size = be_i64(d, o).ok_or_else(err)?;
    o += 8;
    let comp_info = be_u32(d, o).ok_or_else(err)? as usize;
    o += 4;
    let uncomp_info = be_u32(d, o).ok_or_else(err)? as usize;
    o += 4;
    let flags = be_u32(d, o).ok_or_else(err)?;
    o += 4;
    // Localiza blocksInfo (al final si el bit 0x80 está puesto).
    let (info_bruta, mut datos_ini) = if flags & 0x80 != 0 {
        let ini = d.len().checked_sub(comp_info).ok_or_else(err)?;
        (d.get(ini..ini + comp_info).ok_or_else(err)?, o)
    } else {
        (d.get(o..o + comp_info).ok_or_else(err)?, o + comp_info)
    };
    let info = descomprimir_bloque((flags & 0x3f) as u8, info_bruta, uncomp_info)?;
    // A partir de la versión 7, los datos se alinean a 16 bytes.
    if ver >= 7 && flags & 0x80 == 0 {
        datos_ini = (datos_ini + 15) & !15;
    }
    // Parseo de blocksInfo: hash(16) · nº bloques · bloques · nº nodos · nodos.
    let mut p = 16;
    let nb = be_u32(&info, p).ok_or_else(err)? as usize;
    p += 4;
    let mut bloques = Vec::with_capacity(nb.min(4096));
    for _ in 0..nb {
        let us = be_u32(&info, p).ok_or_else(err)?;
        let cs = be_u32(&info, p + 4).ok_or_else(err)?;
        let fl = be_u16(&info, p + 8).ok_or_else(err)?;
        p += 10;
        bloques.push((us, cs, fl));
    }
    let nn = be_u32(&info, p).ok_or_else(err)? as usize;
    p += 4;
    let mut nodos = Vec::with_capacity(nn.min(65536));
    for _ in 0..nn {
        let off = be_i64(&info, p).ok_or_else(err)?;
        let sz = be_i64(&info, p + 8).ok_or_else(err)?;
        let (nombre, np) = cadena(&info, p + 20).ok_or_else(err)?; // +4 flags
        p = np;
        nodos.push((off, sz, nombre));
    }
    // Descomprime los bloques en secuencia hasta formar el bloque de datos.
    let mut datos = Vec::new();
    let mut cur = datos_ini;
    for (us, cs, fl) in bloques {
        let comp = d.get(cur..cur + cs as usize).ok_or_else(err)?;
        cur += cs as usize;
        let dec = descomprimir_bloque((fl & 0x3f) as u8, comp, us as usize)?;
        if datos.len() as u64 + dec.len() as u64 > lim {
            bail!("{}", tfmt(tr("exceeds the limit of {} bytes (decompression bomb?)", "supera el límite de {} bytes (¿bomba de descompresión?)"), &[lim.to_string()]));
        }
        datos.extend_from_slice(&dec);
    }
    // Cada nodo es un trozo del bloque de datos.
    let mut hijos = Vec::new();
    for (off, sz, nombre) in nodos {
        let s = off.max(0) as usize;
        let e = s.saturating_add(sz.max(0) as usize);
        if let Some(trozo) = datos.get(s..e) {
            let limpio = nombre.rsplit(['/', '\\']).next().unwrap_or(&nombre).to_string();
            hijos.push(Hijo { nombre: if limpio.is_empty() { "nodo".into() } else { limpio }, datos: trozo.to_vec() });
        }
    }
    if hijos.is_empty() {
        bail!("{}", tr("no files could be unpacked from the bundle", "no se pudo desempaquetar ningún fichero del bundle"));
    }
    Ok(hijos)
}

/// Paquete de Godot (.pck, magia "GDPC"): índice de ficheros + datos.
pub fn godot_pck(d: &[u8], lim: u64) -> Result<Vec<Hijo>> {
    let err = || anyhow!("{}", tr("corrupt or truncated Godot .pck", ".pck de Godot corrupto o truncado"));
    let ver = le_u32(d, 4).ok_or_else(err)?;
    let mut o = 20; // magia(4) + pack_ver(4) + godot major/minor/patch(12)
    let mut base = 0u64;
    if ver >= 2 {
        let _flags = le_u32(d, o).ok_or_else(err)?;
        base = le_u64(d, o + 4).ok_or_else(err)?;
        o += 12;
    }
    o += 16 * 4; // 16 u32 reservados
    let n = le_u32(d, o).ok_or_else(err)? as usize;
    o += 4;
    let mut hijos = Vec::new();
    let mut total = 0u64;
    for _ in 0..n {
        let plen = le_u32(d, o).ok_or_else(err)? as usize;
        o += 4;
        let bytes = d.get(o..o + plen).ok_or_else(err)?;
        o += plen;
        let ruta = String::from_utf8_lossy(bytes).trim_end_matches('\0').trim_start_matches("res://").to_string();
        let off = le_u64(d, o).ok_or_else(err)?;
        let sz = le_u64(d, o + 8).ok_or_else(err)? as usize;
        o += 16 + 16; // offset(8)+size(8)+md5(16)
        if ver >= 2 {
            o += 4; // flags por fichero
        }
        let ini = (base + off) as usize;
        let fin = ini.saturating_add(sz);
        let Some(trozo) = d.get(ini..fin) else { continue };
        total += sz as u64;
        if total > lim {
            bail!("{}", tfmt(tr("exceeds the limit of {} bytes (decompression bomb?)", "supera el límite de {} bytes (¿bomba de descompresión?)"), &[lim.to_string()]));
        }
        let nombre = ruta.rsplit(['/', '\\']).next().unwrap_or(&ruta).to_string();
        hijos.push(Hijo { nombre: if nombre.is_empty() { "recurso".into() } else { nombre }, datos: trozo.to_vec() });
    }
    if hijos.is_empty() {
        bail!("{}", tr("no files could be unpacked from the .pck", "no se pudo desempaquetar ningún fichero del .pck"));
    }
    Ok(hijos)
}

#[cfg(test)]
mod pruebas_bundle {
    use super::*;

    #[test]
    fn godot_pck_v1() {
        let mut d = Vec::new();
        d.extend_from_slice(b"GDPC");
        d.extend_from_slice(&1u32.to_le_bytes()); // pack version 1
        d.extend_from_slice(&4u32.to_le_bytes()); // godot major
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&[0u8; 64]); // reservado
        d.extend_from_slice(&1u32.to_le_bytes()); // 1 fichero
        let ruta = b"a.txt";
        d.extend_from_slice(&(ruta.len() as u32).to_le_bytes());
        d.extend_from_slice(ruta);
        let off_pos = d.len();
        d.extend_from_slice(&0u64.to_le_bytes()); // offset (se rellena luego)
        d.extend_from_slice(&4u64.to_le_bytes()); // size
        d.extend_from_slice(&[0u8; 16]); // md5
        let data_off = d.len() as u64;
        d[off_pos..off_pos + 8].copy_from_slice(&data_off.to_le_bytes());
        d.extend_from_slice(b"HOLA");

        let hijos = godot_pck(&d, 1 << 20).unwrap();
        assert_eq!(hijos.len(), 1);
        assert_eq!(hijos[0].nombre, "a.txt");
        assert_eq!(hijos[0].datos, b"HOLA");
    }

    #[test]
    fn unity_fs_sin_comprimir() {
        let data = b"ASSETDATA";
        // blocksInfo sin comprimir.
        let mut info = Vec::new();
        info.extend_from_slice(&[0u8; 16]); // hash
        info.extend_from_slice(&1u32.to_be_bytes()); // 1 bloque
        info.extend_from_slice(&(data.len() as u32).to_be_bytes()); // us
        info.extend_from_slice(&(data.len() as u32).to_be_bytes()); // cs
        info.extend_from_slice(&0u16.to_be_bytes()); // flags bloque (sin comprimir)
        info.extend_from_slice(&1u32.to_be_bytes()); // 1 nodo
        info.extend_from_slice(&0i64.to_be_bytes()); // off
        info.extend_from_slice(&(data.len() as i64).to_be_bytes()); // size
        info.extend_from_slice(&0u32.to_be_bytes()); // flags nodo
        info.extend_from_slice(b"cab.dat\0");

        let mut d = Vec::new();
        d.extend_from_slice(b"UnityFS\0");
        d.extend_from_slice(&6u32.to_be_bytes()); // versión
        d.extend_from_slice(b"5\0");
        d.extend_from_slice(b"1\0");
        d.extend_from_slice(&0i64.to_be_bytes()); // size total (no se usa)
        d.extend_from_slice(&(info.len() as u32).to_be_bytes()); // comp info
        d.extend_from_slice(&(info.len() as u32).to_be_bytes()); // uncomp info
        d.extend_from_slice(&0u32.to_be_bytes()); // flags (sin comprimir, info al inicio)
        d.extend_from_slice(&info);
        d.extend_from_slice(data);

        let hijos = unity_bundle(&d, 1 << 20).unwrap();
        assert_eq!(hijos.len(), 1);
        assert_eq!(hijos[0].nombre, "cab.dat");
        assert_eq!(hijos[0].datos, data);
    }
}

// ── Imagen de disco ISO 9660 ──────────────────────────────────────────────
// Lee el descriptor de volumen primario y recorre el árbol de directorios,
// devolviendo cada fichero. Parser defensivo: datos no confiables, con guardas
// de límites, de bucles (extents visitados) y de presupuesto.

fn le32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// Formato de sector de la imagen: tamaño físico y offset de los datos de usuario.
/// 2048 = ISO "cocido"; 2352 = pista de datos cruda (.bin) Mode1 (+16) o Mode2 form1 (+24).
struct FmtIso {
    sector: usize,
    usuario: usize,
}

fn formato_iso(d: &[u8]) -> Option<FmtIso> {
    if d.len() >= 0x8006 && &d[0x8001..0x8006] == b"CD001" {
        return Some(FmtIso { sector: 2048, usuario: 0 });
    }
    let m1 = 16 * 2352 + 16;
    if d.len() >= m1 + 6 && &d[m1 + 1..m1 + 6] == b"CD001" {
        return Some(FmtIso { sector: 2352, usuario: 16 });
    }
    let m2 = 16 * 2352 + 24;
    if d.len() >= m2 + 6 && &d[m2 + 1..m2 + 6] == b"CD001" {
        return Some(FmtIso { sector: 2352, usuario: 24 });
    }
    None
}

/// Lee `len` bytes "lógicos" (áreas de usuario de 2048 B por sector) desde el LBA.
/// En imágenes cocidas es un trozo contiguo; en crudas ensambla sector a sector.
fn leer_logico(d: &[u8], f: &FmtIso, lba: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len.min(1 << 20));
    let mut restante = len;
    let mut s = lba as usize;
    while restante > 0 {
        let base = s.saturating_mul(f.sector) + f.usuario;
        let tomar = restante.min(2048);
        match d.get(base..base + tomar) {
            Some(b) => out.extend_from_slice(b),
            None => break,
        }
        restante -= tomar;
        s += 1;
    }
    out
}

/// Como `leer_logico`, pero escribe en streaming (sector a sector) a `out` en
/// vez de construir un Vec. Permite volcar a disco ficheros de varios GB sin
/// cargarlos en RAM. Devuelve cuántos bytes se escribieron.
fn escribir_logico(d: &[u8], f: &FmtIso, lba: u32, len: usize, out: &mut impl Write) -> std::io::Result<u64> {
    let mut restante = len;
    let mut s = lba as usize;
    let mut escritos = 0u64;
    while restante > 0 {
        let base = s.saturating_mul(f.sector) + f.usuario;
        let tomar = restante.min(2048);
        match d.get(base..base + tomar) {
            Some(b) => {
                out.write_all(b)?;
                escritos += b.len() as u64;
            }
            None => break,
        }
        restante -= tomar;
        s += 1;
    }
    Ok(escritos)
}

/// Convierte una ruta interna del ISO en una ruta relativa segura (sin "..",
/// sin raíz absoluta, componentes vacíos fuera). Vacía → "fichero".
fn ruta_iso_segura(nombre: &str) -> std::path::PathBuf {
    let norm = nombre.replace('\\', "/");
    let mut p = std::path::PathBuf::new();
    for c in norm.split('/') {
        let c = c.trim();
        if c.is_empty() || c == "." || c == ".." {
            continue;
        }
        p.push(c);
    }
    if p.as_os_str().is_empty() {
        std::path::PathBuf::from("fichero")
    } else {
        p
    }
}

/// Extrae una imagen ISO 9660. Los ficheros que caben en el presupuesto de
/// memoria (`lim`) se devuelven como hijos (para seguir el análisis por capas).
/// Los que NO caben: si `dir_grandes` es `Some`, se vuelcan a disco en streaming
/// (sin cargarlos en RAM) y su ruta se devuelve en el segundo vector; si es
/// `None`, se omiten. `truncado` se marca solo si algo quedó sin extraer.
pub fn iso9660(
    d: &[u8],
    lim: u64,
    dir_grandes: Option<&std::path::Path>,
    notas: &mut Vec<String>,
    truncado: &mut bool,
) -> Result<(Vec<Hijo>, Vec<std::path::PathBuf>)> {
    let fmt = formato_iso(d).ok_or_else(|| anyhow!("{}", tr("not a primary ISO 9660 volume", "no es un volumen ISO 9660 primario")))?;
    // PVD (sector 16): registro de directorio raíz en el offset 156.
    let pvd = leer_logico(d, &fmt, 16, 2048);
    if pvd.len() < 190 {
        bail!("{}", tr("corrupt or truncated ISO 9660 image", "imagen ISO 9660 corrupta o truncada"));
    }
    let raiz = &pvd[156..156 + 34];
    let raiz_lba = le32(raiz, 2).unwrap_or(0);
    let raiz_len = le32(raiz, 10).unwrap_or(0) as usize;

    let mut hijos = Vec::new();
    let mut total = 0u64;
    // Una ISO no está comprimida (ratio 1:1): no es una "bomba". El límite es de
    // MEMORIA (CAPAS mantiene lo extraído en RAM). Así que no se aborta la imagen
    // entera: se extrae lo que cabe y se omite el resto con una nota clara.
    let mut omitidos = 0usize;
    let mut bytes_omitidos = 0u64;
    let mut avisos = 0usize;
    // Ficheros grandes volcados a disco en streaming (no caben en RAM).
    let mut grandes: Vec<std::path::PathBuf> = Vec::new();
    let mut bytes_volcados = 0u64;
    let mut escritos: std::collections::HashSet<std::path::PathBuf> = std::collections::HashSet::new();
    let mut visitados = std::collections::HashSet::new();
    let mut pila = vec![(raiz_lba, raiz_len, String::new())];
    let mut registros = 0usize;

    while let Some((lba, len, prefijo)) = pila.pop() {
        if !visitados.insert(lba) {
            continue; // evita bucles de directorios
        }
        let dir = leer_logico(d, &fmt, lba, len);
        let mut pos = 0usize;
        while pos < dir.len() {
            registros += 1;
            if registros > 200_000 {
                bail!("{}", tr("too many ISO entries", "demasiadas entradas en el ISO"));
            }
            let rlen = dir[pos] as usize;
            if rlen == 0 {
                // Relleno hasta el siguiente sector lógico (2048) dentro del directorio.
                pos = (pos / 2048 + 1) * 2048;
                continue;
            }
            let Some(rec) = dir.get(pos..pos + rlen) else { break };
            if rec.len() < 34 {
                break;
            }
            let flags = rec[25];
            let nlen = rec[32] as usize;
            let Some(nombre_b) = rec.get(33..33 + nlen) else {
                pos += rlen;
                continue;
            };
            // Saltar "." (0x00) y ".." (0x01).
            if nlen == 1 && (nombre_b[0] == 0 || nombre_b[0] == 1) {
                pos += rlen;
                continue;
            }
            let ext_lba = le32(rec, 2).unwrap_or(0);
            let ext_len = le32(rec, 10).unwrap_or(0) as usize;
            let mut nombre = String::from_utf8_lossy(nombre_b).into_owned();
            if let Some(i) = nombre.find(';') {
                nombre.truncate(i);
            }
            let completo = if prefijo.is_empty() { nombre } else { format!("{prefijo}/{nombre}") };
            if flags & 0x02 != 0 {
                pila.push((ext_lba, ext_len, completo));
            } else {
                let tam = ext_len as u64;
                if tam > lim || total + tam > lim {
                    // No cabe en el presupuesto de memoria del bloque.
                    if let Some(base) = dir_grandes {
                        // Volcado a disco en streaming (sin cargarlo en RAM).
                        let mut rel = ruta_iso_segura(&completo);
                        let mut k = 1;
                        while !escritos.insert(base.join(&rel)) {
                            rel = ruta_iso_segura(&format!("{completo}~{k}"));
                            k += 1;
                        }
                        let destino = base.join(&rel);
                        let escrito = (|| -> std::io::Result<u64> {
                            if let Some(p) = destino.parent() {
                                std::fs::create_dir_all(p)?;
                            }
                            let f = std::fs::File::create(&destino)?;
                            let mut w = std::io::BufWriter::with_capacity(1 << 20, f);
                            let n = escribir_logico(d, &fmt, ext_lba, ext_len, &mut w)?;
                            w.flush()?;
                            Ok(n)
                        })();
                        match escrito {
                            Ok(n) => {
                                bytes_volcados += n;
                                if avisos < 8 {
                                    notas.push(tfmt(tr("streamed to disk (too big for RAM): {} ({})", "volcado a disco (demasiado grande para la RAM): {} ({})"), &[completo.clone(), crate::recursos::humano(n)]));
                                    avisos += 1;
                                }
                                grandes.push(destino);
                            }
                            Err(e) => {
                                omitidos += 1;
                                bytes_omitidos += tam;
                                if avisos < 8 {
                                    notas.push(tfmt(tr("could not stream '{}' to disk: {}", "no se pudo volcar '{}' a disco: {}"), &[completo.clone(), e.to_string()]));
                                    avisos += 1;
                                }
                            }
                        }
                    } else {
                        // Sin destino en disco: se omite, pero se sigue listando el resto.
                        omitidos += 1;
                        bytes_omitidos += tam;
                        if avisos < 8 {
                            notas.push(tfmt(tr("skipped (does not fit in the per-block memory budget): {} ({})", "omitido (no cabe en el presupuesto de memoria del bloque): {} ({})"), &[completo.clone(), crate::recursos::humano(tam)]));
                            avisos += 1;
                        }
                    }
                } else {
                    total += tam;
                    let datos = leer_logico(d, &fmt, ext_lba, ext_len);
                    if !datos.is_empty() {
                        hijos.push(Hijo { nombre: completo, datos });
                    }
                }
            }
            pos += rlen;
        }
    }
    if !grandes.is_empty() {
        notas.push(tfmt(
            tr("{} large file(s) ({}) streamed to disk (too big for RAM) — in the output folder, not re-analyzed.",
               "{} fichero(s) grande(s) ({}) volcado(s) a disco (demasiado grandes para la RAM) — en la carpeta de salida, sin volver a analizar."),
            &[grandes.len().to_string(), crate::recursos::humano(bytes_volcados)],
        ));
    }
    if omitidos > 0 {
        *truncado = true;
        notas.push(tfmt(
            tr("ISO larger than the per-block memory limit ({}): extracted {} files ({}), skipped {} ({}). Lower THREADS or free RAM to raise the limit — very large images do not fit in memory whole.",
               "ISO mayor que el límite de memoria por bloque ({}): extraídos {} ficheros ({}), omitidos {} ({}). Baja HILOS o libera RAM para subir el límite; las imágenes muy grandes no caben enteras en memoria."),
            &[crate::recursos::humano(lim), hijos.len().to_string(), crate::recursos::humano(total), omitidos.to_string(), crate::recursos::humano(bytes_omitidos)],
        ));
    }
    Ok((hijos, grandes))
}

#[cfg(test)]
mod pruebas_iso {
    use super::iso9660;

    // Construye un ISO 9660 mínimo con un fichero "FILE.TXT" en la raíz.
    fn mini_iso(contenido: &[u8]) -> Vec<u8> {
        const S: usize = 2048;
        let mut img = vec![0u8; 20 * S];
        let put = |img: &mut Vec<u8>, o: usize, v: u32| {
            img[o..o + 4].copy_from_slice(&v.to_le_bytes());
            img[o + 4..o + 8].copy_from_slice(&v.to_be_bytes());
        };
        // Registro de directorio de 34 bytes.
        let dir_rec = |img: &mut Vec<u8>, off: usize, lba: u32, len: u32, es_dir: bool, name: &[u8]| {
            let rlen = 33 + name.len();
            let rlen = rlen + (rlen & 1); // par
            img[off] = rlen as u8;
            img[off + 2..off + 6].copy_from_slice(&lba.to_le_bytes());
            img[off + 6..off + 10].copy_from_slice(&lba.to_be_bytes());
            img[off + 10..off + 14].copy_from_slice(&len.to_le_bytes());
            img[off + 14..off + 18].copy_from_slice(&len.to_be_bytes());
            img[off + 25] = if es_dir { 0x02 } else { 0 };
            img[off + 32] = name.len() as u8;
            img[off + 33..off + 33 + name.len()].copy_from_slice(name);
            rlen
        };
        // PVD en el sector 16.
        let pvd = 16 * S;
        img[pvd] = 1;
        img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        img[pvd + 6] = 1;
        dir_rec(&mut img, pvd + 156, 18, S as u32, true, &[0]); // raíz -> sector 18
        // Terminador en el sector 17.
        img[17 * S] = 255;
        img[17 * S + 1..17 * S + 6].copy_from_slice(b"CD001");
        // Directorio raíz en el sector 18: ".", "..", FILE.TXT;1
        let mut o = 18 * S;
        o += dir_rec(&mut img, o, 18, S as u32, true, &[0]);
        o += dir_rec(&mut img, o, 18, S as u32, true, &[1]);
        dir_rec(&mut img, o, 19, contenido.len() as u32, false, b"FILE.TXT;1");
        // Datos del fichero en el sector 19.
        img[19 * S..19 * S + contenido.len()].copy_from_slice(contenido);
        let _ = put;
        img
    }

    // Envuelve cada sector lógico de 2048 B en un sector crudo de 2352 B (Mode1,
    // datos de usuario a +16), como una pista de datos .bin.
    fn a_2352(img: &[u8]) -> Vec<u8> {
        const S: usize = 2048;
        let sectores = img.len() / S;
        let mut out = vec![0u8; sectores * 2352];
        for s in 0..sectores {
            out[s * 2352 + 16..s * 2352 + 16 + S].copy_from_slice(&img[s * S..s * S + S]);
        }
        out
    }

    #[test]
    fn lee_iso_minimo() {
        let img = mini_iso(b"HELLO ISO");
        let (mut n, mut t) = (Vec::new(), false);
        let (hijos, grandes) = iso9660(&img, 1 << 20, None, &mut n, &mut t).unwrap();
        assert_eq!(hijos.len(), 1);
        assert_eq!(hijos[0].nombre, "FILE.TXT"); // sin ";1"
        assert_eq!(hijos[0].datos, b"HELLO ISO");
        assert!(grandes.is_empty());
        assert!(!t, "no debe marcarse truncado si todo cabe");
    }

    #[test]
    fn lee_bin_crudo_2352() {
        let crudo = a_2352(&mini_iso(b"RAW CD TRACK"));
        let (mut n, mut t) = (Vec::new(), false);
        let (hijos, _g) = iso9660(&crudo, 1 << 20, None, &mut n, &mut t).unwrap();
        assert_eq!(hijos.len(), 1);
        assert_eq!(hijos[0].nombre, "FILE.TXT");
        assert_eq!(hijos[0].datos, b"RAW CD TRACK");
    }

    #[test]
    fn iso_que_no_cabe_sin_destino_se_omite() {
        // Sin dir_grandes y con límite por debajo del fichero: NO se aborta la
        // imagen, se omite el fichero, se marca truncado y se deja nota.
        let img = mini_iso(b"HELLO ISO");
        let (mut n, mut t) = (Vec::new(), false);
        let (hijos, grandes) = iso9660(&img, 4, None, &mut n, &mut t).unwrap();
        assert!(hijos.is_empty(), "el fichero no cabe, se omite");
        assert!(grandes.is_empty());
        assert!(t, "debe marcarse truncado");
        assert!(n.iter().any(|m| m.contains("omitid") || m.to_lowercase().contains("skip")));
    }

    #[test]
    fn iso_que_no_cabe_se_vuelca_a_disco() {
        // Con dir_grandes y límite por debajo del fichero: se VUELCA a disco en
        // streaming (no se pierde) y su ruta sale en `grandes`. No truncado.
        let img = mini_iso(b"HELLO ISO ON DISK");
        let dir = std::env::temp_dir().join(format!("capas_iso_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let (mut n, mut t) = (Vec::new(), false);
        let (hijos, grandes) = iso9660(&img, 4, Some(dir.as_path()), &mut n, &mut t).unwrap();
        assert!(hijos.is_empty(), "no cabe en RAM, va a disco");
        assert_eq!(grandes.len(), 1, "debe haber un fichero volcado");
        assert!(!t, "volcado a disco = completo, no truncado");
        let escrito = std::fs::read(&grandes[0]).unwrap();
        assert_eq!(escrito, b"HELLO ISO ON DISK");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Si entre los ficheros de un disco hay SYSTEM.CNF, deduce la plataforma
/// (PS1/PS2) y el ejecutable de arranque. Devuelve un texto de evidencia.
pub fn plataforma_disco(hijos: &[Hijo]) -> Option<String> {
    let cnf = hijos.iter().find(|h| {
        let n = h.nombre.rsplit(['/', '\\']).next().unwrap_or(&h.nombre).to_ascii_uppercase();
        n == "SYSTEM.CNF"
    })?;
    let texto = String::from_utf8_lossy(&cnf.datos);
    let mut boot = None;
    let mut plataforma = None;
    for linea in texto.lines() {
        let l = linea.trim();
        let up = l.to_ascii_uppercase();
        if up.starts_with("BOOT2") {
            plataforma = Some("PlayStation 2");
            boot = valor_arranque(l);
        } else if up.starts_with("BOOT") && up.contains('=') {
            plataforma = plataforma.or(Some("PlayStation 1"));
            if boot.is_none() {
                boot = valor_arranque(l);
            }
        }
    }
    let plataforma = plataforma?;
    Some(match boot {
        Some(b) => tfmt(tr("platform: {} · boot: {}", "plataforma: {} · arranque: {}"), &[plataforma.to_string(), b]),
        None => tfmt(tr("platform: {}", "plataforma: {}"), &[plataforma.to_string()]),
    })
}

/// Extrae el nombre del ejecutable de una línea `BOOT2 = cdrom0:\SLUS_123.45;1`.
fn valor_arranque(linea: &str) -> Option<String> {
    let v = linea.split('=').nth(1)?.trim();
    let v = v.rsplit([':', '\\', '/']).next().unwrap_or(v);
    let v = v.split(';').next().unwrap_or(v).trim();
    (!v.is_empty()).then(|| v.to_string())
}

#[cfg(test)]
mod pruebas_disco {
    use super::{plataforma_disco, Hijo};
    #[test]
    fn detecta_ps2_desde_system_cnf() {
        let hijos = vec![Hijo { nombre: "SYSTEM.CNF".into(), datos: b"BOOT2 = cdrom0:\\SLUS_200.02;1\nVER = 1.00\n".to_vec() }];
        let info = plataforma_disco(&hijos).unwrap();
        assert!(info.contains("PlayStation 2"));
        assert!(info.contains("SLUS_200.02"));
    }
    #[test]
    fn sin_system_cnf_no_hay_plataforma() {
        let hijos = vec![Hijo { nombre: "readme.txt".into(), datos: b"hola".to_vec() }];
        assert!(plataforma_disco(&hijos).is_none());
    }
}

// ── Tabla de particiones (MBR / GPT) ──────────────────────────────────────
// Lista las particiones de una imagen de disco y devuelve la región de cada
// una, para que el motor detecte su sistema de ficheros. Parser defensivo.

fn le64(d: &[u8], o: usize) -> u64 {
    d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)
}

fn tipo_mbr(t: u8) -> &'static str {
    match t {
        0x07 => "ntfs/exfat",
        0x0b | 0x0c => "fat32",
        0x04 | 0x06 | 0x0e => "fat",
        0x83 => "linux",
        0x82 => "linux-swap",
        0xef => "efi",
        0x05 | 0x0f => "extended",
        _ => "part",
    }
}

pub fn particiones(d: &[u8], lim: u64) -> Result<Vec<Hijo>> {
    const S: u64 = 512;
    let mut hijos = Vec::new();
    let mut total = 0u64;
    let empuja = |hijos: &mut Vec<Hijo>, total: &mut u64, nombre: String, ini: u64, bytes: u64| -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        let fin = ini.saturating_add(bytes).min(d.len() as u64);
        let ini = ini.min(d.len() as u64);
        let trozo = (fin - ini).min(lim.saturating_sub(*total));
        if trozo == 0 {
            return Ok(());
        }
        if let Some(b) = d.get(ini as usize..(ini + trozo) as usize) {
            *total += trozo;
            hijos.push(Hijo { nombre, datos: b.to_vec() });
        }
        Ok(())
    };

    // GPT: cabecera en el sector 1.
    if d.len() >= 0x208 && &d[0x200..0x208] == b"EFI PART" {
        let entradas_lba = le64(d, 0x200 + 0x48);
        let num = u32::from_le_bytes([d[0x200 + 0x50], d[0x200 + 0x51], d[0x200 + 0x52], d[0x200 + 0x53]]) as usize;
        let tam = u32::from_le_bytes([d[0x200 + 0x54], d[0x200 + 0x55], d[0x200 + 0x56], d[0x200 + 0x57]]) as usize;
        if tam >= 128 && num <= 1024 {
            let base = entradas_lba.saturating_mul(S) as usize;
            for i in 0..num {
                let e = base + i * tam;
                let Some(ent) = d.get(e..e + 128) else { break };
                if ent[0..16].iter().all(|&b| b == 0) {
                    continue; // tipo nulo = sin usar
                }
                let first = le64(ent, 32);
                let last = le64(ent, 40);
                if last < first {
                    continue;
                }
                let bytes = (last - first + 1).saturating_mul(S);
                empuja(&mut hijos, &mut total, format!("gpt_part{}", i + 1), first * S, bytes)?;
            }
        }
        if !hijos.is_empty() {
            return Ok(hijos);
        }
    }

    // MBR: 4 entradas primarias en 0x1BE.
    if d.len() >= 0x200 && d[0x1fe] == 0x55 && d[0x1ff] == 0xAA {
        for i in 0..4 {
            let e = 0x1be + i * 16;
            let tipo = d[e + 4];
            if tipo == 0 {
                continue;
            }
            let lba = u32::from_le_bytes([d[e + 8], d[e + 9], d[e + 10], d[e + 11]]) as u64;
            let sect = u32::from_le_bytes([d[e + 12], d[e + 13], d[e + 14], d[e + 15]]) as u64;
            empuja(&mut hijos, &mut total, format!("mbr_part{}_{}", i + 1, tipo_mbr(tipo)), lba * S, sect * S)?;
        }
    }
    Ok(hijos)
}

#[cfg(test)]
mod pruebas_particiones {
    use super::particiones;

    #[test]
    fn lee_gpt_sintetico() {
        const S: usize = 512;
        let mut img = vec![0u8; 40 * S];
        // MBR protector mínimo (no imprescindible, pero realista).
        img[0x1fe] = 0x55; img[0x1ff] = 0xAA;
        // Cabecera GPT en el sector 1.
        img[S..S + 8].copy_from_slice(b"EFI PART");
        img[S + 0x48..S + 0x50].copy_from_slice(&2u64.to_le_bytes()); // entradas en LBA 2
        img[S + 0x50..S + 0x54].copy_from_slice(&4u32.to_le_bytes()); // 4 entradas
        img[S + 0x54..S + 0x58].copy_from_slice(&128u32.to_le_bytes()); // 128 B/entrada
        // Entrada 0 (LBA 2): partición en los sectores 10..12 (2 sectores).
        let e = 2 * S;
        img[e..e + 16].copy_from_slice(&[0xA2; 16]); // type GUID no nulo
        img[e + 32..e + 40].copy_from_slice(&10u64.to_le_bytes()); // first_lba
        img[e + 40..e + 48].copy_from_slice(&11u64.to_le_bytes()); // last_lba
        // Datos de la partición (sector 10): un marcador reconocible.
        img[10 * S..10 * S + 11].copy_from_slice(b"PART-DATA-1");

        let hijos = particiones(&img, 1 << 20).unwrap();
        assert_eq!(hijos.len(), 1);
        assert_eq!(hijos[0].nombre, "gpt_part1");
        assert_eq!(hijos[0].datos.len(), 2 * S); // 2 sectores
        assert_eq!(&hijos[0].datos[..11], b"PART-DATA-1");
    }

    #[test]
    fn lee_mbr_sintetico() {
        const S: usize = 512;
        let mut img = vec![0u8; 20 * S];
        img[0x1fe] = 0x55; img[0x1ff] = 0xAA;
        let e = 0x1be;
        img[e + 4] = 0x0c; // FAT32
        img[e + 8..e + 12].copy_from_slice(&5u32.to_le_bytes());  // lba_start 5
        img[e + 12..e + 16].copy_from_slice(&3u32.to_le_bytes()); // 3 sectores
        img[5 * S..5 * S + 6].copy_from_slice(b"FATFS!");

        let hijos = particiones(&img, 1 << 20).unwrap();
        assert_eq!(hijos.len(), 1);
        assert_eq!(hijos[0].nombre, "mbr_part1_fat32");
        assert_eq!(hijos[0].datos.len(), 3 * S);
    }
}
