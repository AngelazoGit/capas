//! Extractores y lectores NATIVOS (sin herramientas externas): 7z, RAR, CAB,
//! OLE/MSI y CHD como contenedores; WASM, clases Java, DEX y .pyc como código.
//! Todo va dentro del binario, así CAPAS funciona sin instalar nada. Las
//! herramientas externas quedan solo como respaldo opcional.

use std::io::{Cursor, Read};
use std::path::Path;

use anyhow::{anyhow, bail, Result};

use crate::extraer::Hijo;

/// Resultado de abrir un contenedor que puede ir cifrado.
pub struct Abierto {
    pub hijos: Vec<Hijo>,
    /// Contraseña con la que se abrió (None = no hacía falta).
    pub clave: Option<String>,
}

/// Lee como máximo `lim` bytes de `r`. Si hay más, error (posible bomba).
fn leer_max(r: &mut dyn Read, lim: u64) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    let n = r.take(lim.saturating_add(1)).read_to_end(&mut v)?;
    if n as u64 > lim {
        bail!("contenido mayor que el límite ({lim} bytes): posible bomba de descompresión");
    }
    Ok(v)
}

// ───────────────────────────── 7-Zip ─────────────────────────────

fn siete_z_con(d: &[u8], lim: u64, clave: &str) -> Result<Vec<Hijo>> {
    use sevenz_rust2::{ArchiveReader, Password};
    let pw = if clave.is_empty() { Password::empty() } else { Password::from(clave) };
    let mut ar = ArchiveReader::new(Cursor::new(d), pw).map_err(|e| anyhow!("7z: {e}"))?;
    let mut hijos = Vec::new();
    let mut total = 0u64;
    let mut err: Option<anyhow::Error> = None;
    ar.for_each_entries(|e, r| {
        if e.is_directory || !e.has_stream {
            return Ok(true);
        }
        match leer_max(r, lim.saturating_sub(total)) {
            Ok(datos) => {
                total += datos.len() as u64;
                hijos.push(Hijo { nombre: e.name.clone(), datos });
                Ok(true)
            }
            Err(x) => {
                err = Some(x);
                Ok(false)
            }
        }
    })
    .map_err(|e| anyhow!("7z: {e}"))?;
    if let Some(e) = err {
        return Err(e);
    }
    Ok(hijos)
}

/// Abre un .7z en memoria. Prueba sin contraseña y luego con `candidatas`.
pub fn siete_z(d: &[u8], lim: u64, candidatas: &[String]) -> Result<Abierto> {
    match siete_z_con(d, lim, "") {
        Ok(h) => return Ok(Abierto { hijos: h, clave: None }),
        Err(e) => {
            let t = e.to_string().to_lowercase();
            if !(t.contains("password") || t.contains("contrase")) {
                // Puede ser un fallo de clave mal detectado: seguimos probando
                // solo si hay candidatas; si no, devolvemos el error real.
                if candidatas.is_empty() {
                    return Err(e);
                }
            }
        }
    }
    for c in candidatas {
        if let Ok(h) = siete_z_con(d, lim, c) {
            if !h.is_empty() {
                return Ok(Abierto { hijos: h, clave: Some(c.clone()) });
            }
        }
    }
    bail!("7z cifrado: ninguna contraseña conocida lo abre (añádela en el módulo de Claves)")
}

// ───────────────────────────── RAR ─────────────────────────────

fn rar_con(ruta: &Path, lim: u64, clave: Option<&str>) -> Result<Vec<Hijo>> {
    let archivo = match clave {
        Some(c) => unrar::Archive::with_password(ruta, c),
        None => unrar::Archive::new(ruta),
    };
    let mut abierto = archivo.open_for_processing().map_err(|e| anyhow!("RAR: {e}"))?;
    let mut hijos = Vec::new();
    let mut total = 0u64;
    loop {
        let Some(cab) = abierto.read_header().map_err(|e| anyhow!("RAR: {e}"))? else { break };
        let ent = cab.entry();
        if ent.is_file() {
            if total.saturating_add(ent.unpacked_size) > lim {
                bail!("RAR: contenido mayor que el límite ({lim} bytes)");
            }
            let nombre = ent.filename.to_string_lossy().replace('\\', "/");
            let (datos, resto) = cab.read().map_err(|e| anyhow!("RAR: {e}"))?;
            total += datos.len() as u64;
            hijos.push(Hijo { nombre, datos });
            abierto = resto;
        } else {
            abierto = cab.skip().map_err(|e| anyhow!("RAR: {e}"))?;
        }
    }
    Ok(hijos)
}

/// Abre un RAR (v2–v5) desde disco. Prueba sin contraseña y luego `candidatas`.
pub fn rar(ruta: &Path, lim: u64, candidatas: &[String]) -> Result<Abierto> {
    let primero = rar_con(ruta, lim, None);
    if let Ok(h) = &primero {
        if !h.is_empty() {
            return Ok(Abierto { hijos: primero.unwrap(), clave: None });
        }
    }
    for c in candidatas {
        if let Ok(h) = rar_con(ruta, lim, Some(c)) {
            if !h.is_empty() {
                return Ok(Abierto { hijos: h, clave: Some(c.clone()) });
            }
        }
    }
    match primero {
        Ok(h) if h.is_empty() => bail!("RAR vacío o cifrado: ninguna contraseña conocida lo abre (añádela en el módulo de Claves)"),
        Ok(h) => Ok(Abierto { hijos: h, clave: None }),
        Err(e) => Err(anyhow!("{e} — si está cifrado, añade su contraseña en el módulo de Claves")),
    }
}

// ───────────────────────────── CAB ─────────────────────────────

/// Abre un Microsoft Cabinet (.cab, también los que van dentro de un .msi).
pub fn cab(d: &[u8], lim: u64) -> Result<Vec<Hijo>> {
    let mut c = cab::Cabinet::new(Cursor::new(d))?;
    let nombres: Vec<String> = c
        .folder_entries()
        .flat_map(|f| f.file_entries().map(|e| e.name().to_string()).collect::<Vec<_>>())
        .collect();
    let mut hijos = Vec::new();
    let mut total = 0u64;
    for n in nombres {
        let mut r = c.read_file(&n)?;
        let datos = leer_max(&mut r, lim.saturating_sub(total))?;
        total += datos.len() as u64;
        hijos.push(Hijo { nombre: n.replace('\\', "/"), datos });
    }
    Ok(hijos)
}

// ─────────────────────── OLE / Compound File (MSI) ───────────────────────

/// Los nombres de flujo de un MSI van codificados (base-64 en el rango
/// U+3800–U+4840). Esto los devuelve legibles, como hace msitools.
fn nombre_msi(n: &str) -> String {
    const T: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
    let mut s = String::new();
    for ch in n.chars() {
        let c = ch as u32;
        if (0x3800..0x4800).contains(&c) {
            let v = c - 0x3800;
            s.push(T[(v & 0x3f) as usize] as char);
            s.push(T[((v >> 6) & 0x3f) as usize] as char);
        } else if (0x4800..0x4840).contains(&c) {
            s.push(T[(c - 0x4800) as usize] as char);
        } else if c == 0x4840 {
            s.push('!'); // prefijo de tabla interna del MSI
        } else if c < 0x20 {
            s.push_str(&format!("[{c}]")); // p. ej. \x05SummaryInformation
        } else {
            s.push(ch);
        }
    }
    s
}

/// Abre un Compound File Binary (MSI, MSP, MST, .doc/.xls/.ppt antiguos,
/// thumbs.db…) y devuelve sus flujos. Los CAB incrustados en un MSI salen
/// como hijos y el motor los abre en la siguiente capa.
pub fn ole(d: &[u8], lim: u64) -> Result<Vec<Hijo>> {
    let mut cf = cfb::CompoundFile::open(Cursor::new(d))?;
    let rutas: Vec<std::path::PathBuf> = cf.walk().filter(|e| e.is_stream()).map(|e| e.path().to_path_buf()).collect();
    let mut hijos = Vec::new();
    let mut total = 0u64;
    for p in rutas {
        let mut st = cf.open_stream(&p)?;
        let datos = leer_max(&mut st, lim.saturating_sub(total))?;
        total += datos.len() as u64;
        let nombre = p
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(x) => Some(nombre_msi(&x.to_string_lossy())),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("/");
        let nombre = if nombre.is_empty() { "flujo".to_string() } else { nombre };
        hijos.push(Hijo { nombre, datos });
    }
    Ok(hijos)
}

// ───────────────────────────── CHD (MAME) ─────────────────────────────

/// Abre una imagen CHD. Si es un CD (tramas de 2448 bytes), produce
/// `disc.bin` (sectores de 2352) y, si la pista de datos es legible, `disc.iso`
/// (2048 bytes de usuario por sector) para que el motor siga con el ISO.
/// Si es disco duro / DVD, produce la imagen cruda `disc.img`.
pub fn chd(ruta: &Path, lim: u64) -> Result<Vec<Hijo>> {
    let f = std::io::BufReader::new(std::fs::File::open(ruta)?);
    let mut c = chd::Chd::open(f, None).map_err(|e| anyhow!("CHD: {e:?}"))?;
    let (hunks, unidad, logico) = {
        let h = c.header();
        (h.hunk_count(), h.unit_bytes() as usize, h.logical_bytes())
    };
    if logico > lim {
        bail!("CHD: imagen de {logico} bytes mayor que el límite ({lim})");
    }
    let mut crudo = Vec::with_capacity(logico as usize);
    let mut buf = c.get_hunksized_buffer();
    let mut tmp = Vec::new();
    for i in 0..hunks {
        let mut h = c.hunk(i).map_err(|e| anyhow!("CHD hunk {i}: {e:?}"))?;
        h.read_hunk_in(&mut tmp, &mut buf).map_err(|e| anyhow!("CHD hunk {i}: {e:?}"))?;
        crudo.extend_from_slice(&buf);
    }
    crudo.truncate(logico as usize);

    if unidad != 2448 {
        return Ok(vec![Hijo { nombre: "disc.img".into(), datos: crudo }]);
    }
    // CD: tramas de 2352 (sector) + 96 (subcódigo).
    let mut bin = Vec::with_capacity(crudo.len() / 2448 * 2352);
    let mut iso = Vec::with_capacity(crudo.len() / 2448 * 2048);
    const SYNC: [u8; 12] = [0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0];
    for t in crudo.chunks_exact(2448) {
        let s = &t[..2352];
        bin.extend_from_slice(s);
        if s[..12] == SYNC {
            match s[15] {
                1 => iso.extend_from_slice(&s[16..16 + 2048]),
                2 => iso.extend_from_slice(&s[24..24 + 2048]), // Modo 2 forma 1 (PS1/PS2/CD-i)
                _ => {}
            }
        }
    }
    // Con pista de datos legible basta el ISO (evita duplicar cientos de MB);
    // si no (CD de audio, modo raro), se entrega el BIN completo.
    if iso.len() >= 17 * 2048 {
        Ok(vec![Hijo { nombre: "disc.iso".into(), datos: iso }])
    } else {
        Ok(vec![Hijo { nombre: "disc.bin".into(), datos: bin }])
    }
}
