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

pub fn iso9660(d: &[u8], lim: u64) -> Result<Vec<Hijo>> {
    const S: usize = 2048; // tamaño de sector lógico
    let err = || anyhow!("{}", tr("corrupt or truncated ISO 9660 image", "imagen ISO 9660 corrupta o truncada"));
    // Descriptor de volumen primario en el sector 16: tipo 1 + "CD001".
    let pvd = d.get(16 * S..17 * S).ok_or_else(err)?;
    if pvd[0] != 1 || &pvd[1..6] != b"CD001" {
        bail!("{}", tr("not a primary ISO 9660 volume", "no es un volumen ISO 9660 primario"));
    }
    // Registro de directorio raíz en el offset 156 del PVD.
    let raiz = &pvd[156..156 + 34];
    let raiz_lba = le32(raiz, 2).ok_or_else(err)?;
    let raiz_len = le32(raiz, 10).ok_or_else(err)?;

    let mut hijos = Vec::new();
    let mut total = 0u64;
    let mut visitados = std::collections::HashSet::new();
    // Pila de directorios por explorar: (lba, longitud, prefijo).
    let mut pila = vec![(raiz_lba, raiz_len, String::new())];
    let mut registros = 0usize;

    while let Some((lba, len, prefijo)) = pila.pop() {
        if !visitados.insert(lba) {
            continue; // evita bucles de directorios
        }
        let ini = lba as usize * S;
        let Some(dir) = d.get(ini..ini + len as usize) else { continue };
        let mut pos = 0usize;
        while pos < dir.len() {
            registros += 1;
            if registros > 200_000 {
                bail!("{}", tr("too many ISO entries", "demasiadas entradas en el ISO"));
            }
            let rlen = dir[pos] as usize;
            if rlen == 0 {
                // Relleno hasta el siguiente sector dentro del directorio.
                pos = (pos / S + 1) * S;
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
            let es_dir = flags & 0x02 != 0;
            // Saltar "." (0x00) y ".." (0x01).
            if nlen == 1 && (nombre_b[0] == 0 || nombre_b[0] == 1) {
                pos += rlen;
                continue;
            }
            let ext_lba = le32(rec, 2).unwrap_or(0);
            let ext_len = le32(rec, 10).unwrap_or(0);
            // Nombre: quitar el sufijo de versión ";1".
            let mut nombre = String::from_utf8_lossy(nombre_b).into_owned();
            if let Some(i) = nombre.find(';') {
                nombre.truncate(i);
            }
            let completo = if prefijo.is_empty() { nombre.clone() } else { format!("{prefijo}/{nombre}") };
            if es_dir {
                pila.push((ext_lba, ext_len, completo));
            } else {
                let fi = ext_lba as usize * S;
                if let Some(datos) = d.get(fi..fi + ext_len as usize) {
                    total += ext_len as u64;
                    if total > lim {
                        bail!("{}", tfmt(tr("exceeds the limit of {} bytes (decompression bomb?)", "supera el límite de {} bytes (¿bomba de descompresión?)"), &[lim.to_string()]));
                    }
                    hijos.push(Hijo { nombre: completo, datos: datos.to_vec() });
                }
            }
            pos += rlen;
        }
    }
    Ok(hijos)
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

    #[test]
    fn lee_iso_minimo() {
        let img = mini_iso(b"HELLO ISO");
        let hijos = iso9660(&img, 1 << 20).unwrap();
        assert_eq!(hijos.len(), 1);
        assert_eq!(hijos[0].nombre, "FILE.TXT"); // sin ";1"
        assert_eq!(hijos[0].datos, b"HELLO ISO");
    }
}
