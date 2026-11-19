//! Comparación entre versiones (Fase 3). Diff de dos índices SQLite por SHA-256:
//! qué archivos se añadieron, se quitaron o cambiaron entre una versión base y
//! la nueva. Útil para revisar qué cambió entre dos releases de un modpack/pack.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

use rusqlite::Connection;

use crate::idioma::{tfmt, tr};

pub struct Diff {
    pub anadidos: Vec<String>,
    pub quitados: Vec<String>,
    pub cambiados: Vec<String>,
}

fn cargar(db: &Path) -> rusqlite::Result<(HashMap<String, String>, HashMap<String, String>)> {
    // (sha -> nombre, nombre -> sha)
    let con = Connection::open(db)?;
    let mut sha_nombre = HashMap::new();
    let mut nombre_sha = HashMap::new();
    let mut st = con.prepare("SELECT sha256, nombre FROM files")?;
    let filas = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    for f in filas {
        let (sha, nombre) = f?;
        sha_nombre.insert(sha.clone(), nombre.clone());
        nombre_sha.insert(nombre, sha);
    }
    Ok((sha_nombre, nombre_sha))
}

pub fn comparar(nueva: &Path, base: &Path, raiz: &Path) -> rusqlite::Result<Diff> {
    let (n_sha, n_nombre) = cargar(nueva)?;
    let (b_sha, b_nombre) = cargar(base)?;

    let mut anadidos: Vec<String> = n_sha.iter().filter(|(s, _)| !b_sha.contains_key(*s)).map(|(_, n)| n.clone()).collect();
    let mut quitados: Vec<String> = b_sha.iter().filter(|(s, _)| !n_sha.contains_key(*s)).map(|(_, n)| n.clone()).collect();
    // Cambiados: mismo nombre, distinto SHA (no cuenta como añadido+quitado puro).
    let mut cambiados: Vec<String> = n_nombre
        .iter()
        .filter_map(|(nombre, sha_n)| match b_nombre.get(nombre) {
            Some(sha_b) if sha_b != sha_n => Some(nombre.clone()),
            _ => None,
        })
        .collect();
    // Quitar de añadidos/quitados los que en realidad son "cambiados" por nombre.
    let cambiados_set: std::collections::HashSet<&String> = cambiados.iter().collect();
    anadidos.retain(|n| !cambiados_set.contains(n));
    quitados.retain(|n| !cambiados_set.contains(n));
    anadidos.sort();
    quitados.sort();
    cambiados.sort();

    let mut s = String::new();
    let _ = writeln!(s, "# {}\n", tr("Version comparison", "Comparación entre versiones"));
    let _ = writeln!(s, "{}", tfmt(tr("- base: `{}`\n- new:  `{}`\n", "- base:  `{}`\n- nueva: `{}`\n"), &[base.display().to_string(), nueva.display().to_string()]));
    let _ = writeln!(s, "{}", tfmt(tr("**{} added · {} removed · {} changed**\n", "**{} añadidos · {} quitados · {} cambiados**\n"), &[anadidos.len().to_string(), quitados.len().to_string(), cambiados.len().to_string()]));
    seccion(&mut s, tr("Added", "Añadidos"), "➕", &anadidos);
    seccion(&mut s, tr("Removed", "Quitados"), "➖", &quitados);
    seccion(&mut s, tr("Changed", "Cambiados"), "✳", &cambiados);
    let _ = std::fs::write(raiz.join("comparacion.md"), s);

    Ok(Diff { anadidos, quitados, cambiados })
}

fn seccion(s: &mut String, titulo: &str, marca: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    let _ = writeln!(s, "\n## {titulo} ({})\n", items.len());
    for i in items {
        let _ = writeln!(s, "- {marca} {i}");
    }
}
