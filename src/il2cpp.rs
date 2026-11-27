//! Lector de `global-metadata.dat` de Unity IL2CPP: extrae los nombres
//! (identificadores de tipos/métodos/campos/espacios) y los literales de cadena
//! del juego. No correlaciona con el binario nativo (eso reconstruye las firmas
//! C# completas y es version-sensitive; queda para más adelante), pero sacar
//! nombres y literales ya es lo más valioso para reversing de juegos Unity.

use anyhow::{anyhow, bail, Result};
use std::fmt::Write as _;

const MAGIA: u32 = 0xFAB1_1BAF;

/// ¿Es un `global-metadata.dat` de IL2CPP?
pub fn es_il2cpp(d: &[u8]) -> bool {
    d.len() >= 8 && u32::from_le_bytes([d[0], d[1], d[2], d[3]]) == MAGIA
}

fn u32le(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn i32le(d: &[u8], o: usize) -> Option<i32> {
    u32le(d, o).map(|v| v as i32)
}

/// Lista nombres y literales de un `global-metadata.dat`.
pub fn listar(d: &[u8]) -> Result<String> {
    if !es_il2cpp(d) {
        bail!("no es global-metadata.dat de IL2CPP");
    }
    let version = i32le(d, 4).ok_or_else(|| anyhow!("cabecera corta"))?;
    // Disposición estable en la mayoría de versiones (campos en bytes):
    //  8: stringLiteralOffset   12: stringLiteralSize (bytes; nº entradas = /8)
    // 16: stringLiteralDataOffset 20: stringLiteralDataSize
    // 24: stringOffset          28: stringSize   (blob de identificadores NUL-terminados)
    let sl_off = u32le(d, 8).unwrap_or(0) as usize;
    let sl_size = u32le(d, 12).unwrap_or(0) as usize;
    let sld_off = u32le(d, 16).unwrap_or(0) as usize;
    let sld_size = u32le(d, 20).unwrap_or(0) as usize;
    let str_off = u32le(d, 24).unwrap_or(0) as usize;
    let str_size = u32le(d, 28).unwrap_or(0) as usize;

    let dentro = |o: usize, s: usize| o.checked_add(s).map(|f| f <= d.len()).unwrap_or(false);
    if !dentro(str_off, str_size) || !dentro(sl_off, sl_size) || !dentro(sld_off, sld_size) {
        bail!("tablas fuera de rango (¿versión de metadatos no soportada?)");
    }

    // Identificadores: blob de cadenas terminadas en NUL.
    let mut nombres = Vec::new();
    let blob = &d[str_off..str_off + str_size];
    let mut i = 0;
    while i < blob.len() {
        let fin = blob[i..].iter().position(|&b| b == 0).map(|p| i + p).unwrap_or(blob.len());
        if fin > i {
            nombres.push(String::from_utf8_lossy(&blob[i..fin]).into_owned());
        }
        i = fin + 1;
    }

    // Literales de cadena: tabla de {length u32, dataIndex u32} → datos.
    let mut literales = Vec::new();
    let datos = &d[sld_off..sld_off + sld_size];
    let n_lit = sl_size / 8;
    for k in 0..n_lit {
        let base = sl_off + k * 8;
        let len = u32le(d, base).unwrap_or(0) as usize;
        let idx = u32le(d, base + 4).unwrap_or(0) as usize;
        if let Some(s) = datos.get(idx..idx + len) {
            literales.push(String::from_utf8_lossy(s).into_owned());
        }
    }

    let mut out = String::new();
    let _ = writeln!(out, "// Unity IL2CPP global-metadata.dat (versión {version})\n");
    let _ = writeln!(out, "// {} identificadores, {} literales de cadena\n", nombres.len(), literales.len());
    let _ = writeln!(out, "== Identificadores (tipos/métodos/campos/espacios) ==");
    for n in &nombres {
        let _ = writeln!(out, "  {n}");
    }
    let _ = writeln!(out, "\n== Literales de cadena ==");
    for s in &literales {
        let _ = writeln!(out, "  {s:?}");
    }
    Ok(out)
}

#[cfg(test)]
mod pruebas_il2cpp {
    use super::*;

    /// Construye un global-metadata.dat mínimo pero válido para probar la
    /// extracción (el formato es externo, así que el test no es circular).
    fn metadata_minimo() -> Vec<u8> {
        let ids = b"GameManager\0Player\0Attack\0";
        let lit_data = b"HELLOYOU WIN!"; // "HELLO"(5) + "YOU WIN!"(8)
        // Cabecera de 0x40 bytes (solo importan los primeros 32).
        let header_len = 0x40usize;
        let sl_off = header_len;
        let sl = {
            // 2 entradas {len u32, dataIndex u32}
            let mut v = Vec::new();
            v.extend_from_slice(&5u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&8u32.to_le_bytes());
            v.extend_from_slice(&5u32.to_le_bytes());
            v
        };
        let sld_off = sl_off + sl.len();
        let str_off = sld_off + lit_data.len();
        let mut d = vec![0u8; header_len];
        d[0..4].copy_from_slice(&MAGIA.to_le_bytes());
        d[4..8].copy_from_slice(&24i32.to_le_bytes()); // versión
        d[8..12].copy_from_slice(&(sl_off as u32).to_le_bytes());
        d[12..16].copy_from_slice(&(sl.len() as u32).to_le_bytes());
        d[16..20].copy_from_slice(&(sld_off as u32).to_le_bytes());
        d[20..24].copy_from_slice(&(lit_data.len() as u32).to_le_bytes());
        d[24..28].copy_from_slice(&(str_off as u32).to_le_bytes());
        d[28..32].copy_from_slice(&(ids.len() as u32).to_le_bytes());
        d.extend_from_slice(&sl);
        d.extend_from_slice(lit_data);
        d.extend_from_slice(ids);
        d
    }

    #[test]
    fn extrae_nombres_y_literales() {
        let d = metadata_minimo();
        assert!(es_il2cpp(&d));
        let s = listar(&d).expect("debe listar");
        assert!(s.contains("GameManager"), "falta identificador:\n{s}");
        assert!(s.contains("Player"));
        assert!(s.contains("\"HELLO\""), "falta literal HELLO:\n{s}");
        assert!(s.contains("\"YOU WIN!\""), "falta literal:\n{s}");
    }

    #[test]
    fn no_entra_en_panico_con_basura() {
        let d = metadata_minimo();
        for n in 0..d.len() {
            let _ = listar(&d[..n]); // truncado: nunca debe panic
        }
        // Magia válida + offsets/tamaños disparatados.
        let mut malo = vec![0xafu8, 0x1b, 0xb1, 0xfa];
        malo.extend_from_slice(&[0xffu8; 60]);
        let _ = listar(&malo);
    }
}
