//! Búsqueda global: recorre la carpeta de salida (todas las capas extraídas y
//! los archivos generados) buscando texto o bytes, y devuelve las coincidencias
//! con su ruta y un fragmento de contexto. Así el reverser busca una cadena y
//! salta a la capa donde aparece.

use std::path::{Path, PathBuf};

/// Una coincidencia: en qué archivo, en qué línea/offset y el contexto.
pub struct Coincidencia {
    pub ruta: PathBuf,
    pub linea: usize,
    pub contexto: String,
}

/// Qué se busca: texto (con/ sin distinción de mayúsculas) o bytes crudos.
pub enum Consulta {
    Texto { aguja: String, ignora_caso: bool },
    Bytes(Vec<u8>),
}

impl Consulta {
    /// Interpreta la cadena del usuario. `hex:DEADBEEF` o `0x...` → bytes; si no,
    /// texto (sin distinguir mayúsculas por defecto).
    pub fn desde(entrada: &str) -> Option<Consulta> {
        let e = entrada.trim();
        if e.is_empty() {
            return None;
        }
        let hx = e.strip_prefix("hex:").or_else(|| e.strip_prefix("0x"));
        if let Some(h) = hx {
            let limpio: String = h.chars().filter(|c| !c.is_whitespace()).collect();
            if limpio.len() >= 2 && limpio.len() % 2 == 0 && limpio.bytes().all(|b| b.is_ascii_hexdigit()) {
                let bytes: Vec<u8> = (0..limpio.len()).step_by(2).map(|i| u8::from_str_radix(&limpio[i..i + 2], 16).unwrap()).collect();
                return Some(Consulta::Bytes(bytes));
            }
        }
        Some(Consulta::Texto { aguja: e.to_string(), ignora_caso: true })
    }
}

fn contiene(heno: &[u8], aguja: &[u8]) -> Option<usize> {
    if aguja.is_empty() || aguja.len() > heno.len() {
        return None;
    }
    heno.windows(aguja.len()).position(|w| w == aguja)
}

/// Recorre `raiz` en busca de `q`. Acota nº de coincidencias y tamaño por fichero.
pub fn en_carpeta(raiz: &Path, q: &Consulta, max_hits: usize, max_file: u64) -> Vec<Coincidencia> {
    let mut hits = Vec::new();
    let mut pila = vec![raiz.to_path_buf()];
    while let Some(dir) = pila.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for ent in rd.flatten() {
            if hits.len() >= max_hits {
                return hits;
            }
            let p = ent.path();
            let Ok(md) = ent.metadata() else { continue };
            if md.is_dir() {
                pila.push(p);
                continue;
            }
            if md.len() > max_file {
                continue;
            }
            let Ok(datos) = std::fs::read(&p) else { continue };
            buscar_en_fichero(&p, &datos, q, &mut hits, max_hits);
        }
    }
    hits
}

fn buscar_en_fichero(ruta: &Path, datos: &[u8], q: &Consulta, hits: &mut Vec<Coincidencia>, max_hits: usize) {
    match q {
        Consulta::Texto { aguja, ignora_caso } => {
            let texto = String::from_utf8_lossy(datos);
            let aguja_cmp = if *ignora_caso { aguja.to_lowercase() } else { aguja.clone() };
            for (n, linea) in texto.lines().enumerate() {
                let comp = if *ignora_caso { linea.to_lowercase() } else { linea.to_string() };
                if comp.contains(&aguja_cmp) {
                    let ctx: String = linea.trim().chars().take(160).collect();
                    hits.push(Coincidencia { ruta: ruta.to_path_buf(), linea: n + 1, contexto: ctx });
                    if hits.len() >= max_hits {
                        return;
                    }
                }
            }
        }
        Consulta::Bytes(aguja) => {
            // Varias apariciones por fichero (hasta agotar el tope).
            let mut desde = 0;
            while let Some(rel) = contiene(&datos[desde..], aguja) {
                let off = desde + rel;
                let ini = off.saturating_sub(8);
                let fin = (off + aguja.len() + 8).min(datos.len());
                let ctx: String = datos[ini..fin].iter().map(|b| format!("{b:02x} ")).collect();
                hits.push(Coincidencia { ruta: ruta.to_path_buf(), linea: off, contexto: ctx.trim_end().to_string() });
                if hits.len() >= max_hits {
                    return;
                }
                desde = off + aguja.len();
            }
        }
    }
}

#[cfg(test)]
mod pruebas_buscar {
    use super::*;

    #[test]
    fn busca_texto_y_bytes() {
        let dir = std::env::temp_dir().join(format!("capas_buscar_{}", std::process::id()));
        let sub = dir.join("capas/a");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("f1.txt"), "hola\nSECRETO aqui\nadios").unwrap();
        std::fs::write(dir.join("f2.bin"), [0u8, 0xDE, 0xAD, 0xBE, 0xEF, 1]).unwrap();

        let t = Consulta::desde("secreto").unwrap();
        let h = en_carpeta(&dir, &t, 100, 1 << 20);
        assert!(h.iter().any(|c| c.contexto.contains("SECRETO") && c.linea == 2), "texto no hallado: {:?}", h.iter().map(|c| &c.contexto).collect::<Vec<_>>());

        let b = Consulta::desde("hex:DEADBEEF").unwrap();
        let hb = en_carpeta(&dir, &b, 100, 1 << 20);
        assert!(hb.iter().any(|c| c.linea == 1), "bytes no hallados en offset 1: {:?}", hb.iter().map(|c| c.linea).collect::<Vec<_>>());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
