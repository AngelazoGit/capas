//! Localizador de caché: dada una aplicación, descubre dónde escribe sus
//! archivos para poder vigilar esa carpeta. Dos señales:
//!
//! - por NOMBRE: busca en las carpetas de caché estándar del sistema carpetas
//!   cuyo nombre coincida con la app.
//! - OBSERVANDO: mientras la app corre, mira qué carpetas se están escribiendo
//!   (archivos nuevos o modificados en una ventana de tiempo). Es la señal más
//!   fiable y no engancha nada: solo compara fechas de modificación.
//!
//! No intercepta la red ni el proceso: solo mira el sistema de archivos.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::idioma::{tfmt, tr};

const MAX_ENTRADAS: usize = 200_000; // tope del recorrido, por si una raíz es enorme
const PROFUNDIDAD: usize = 3;

#[derive(Clone)]
pub struct Candidato {
    pub ruta: PathBuf,
    pub razon: String,
    pub archivos_recientes: usize,
    pub mtime: u64,
}

/// Carpetas raíz donde las aplicaciones suelen guardar caché/datos.
pub fn raices() -> Vec<PathBuf> {
    let mut v = Vec::new();
    let mut add = |p: Option<PathBuf>| {
        if let Some(p) = p {
            if p.is_dir() && !v.contains(&p) {
                v.push(p);
            }
        }
    };
    let env_dir = |k: &str| env::var_os(k).map(PathBuf::from);
    let home = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE")).map(PathBuf::from);

    if cfg!(windows) {
        add(env_dir("LOCALAPPDATA"));
        add(env_dir("APPDATA"));
        add(home.as_ref().map(|h| h.join("AppData").join("LocalLow")));
        add(env_dir("ProgramData"));
        add(env_dir("TEMP"));
    } else if cfg!(target_os = "macos") {
        if let Some(h) = &home {
            add(Some(h.join("Library/Caches")));
            add(Some(h.join("Library/Application Support")));
            add(Some(h.join("Library/Logs")));
        }
        add(env_dir("TMPDIR"));
    } else {
        add(env_dir("XDG_CACHE_HOME").or_else(|| home.as_ref().map(|h| h.join(".cache"))));
        add(env_dir("XDG_DATA_HOME").or_else(|| home.as_ref().map(|h| h.join(".local/share"))));
        add(env_dir("XDG_CONFIG_HOME").or_else(|| home.as_ref().map(|h| h.join(".config"))));
        if let Some(h) = &home {
            add(Some(h.join(".local/share/Steam"))); // juegos / Proton
            add(Some(h.join(".steam")));
        }
        add(Some(PathBuf::from("/tmp")));
    }
    v
}

/// Recorre un directorio con tope de profundidad y de entradas, llamando a `f`
/// con cada (ruta, es_dir, mtime).
fn recorrer(raiz: &Path, prof: usize, contador: &mut usize, f: &mut impl FnMut(&Path, bool, u64)) {
    if prof == 0 || *contador >= MAX_ENTRADAS {
        return;
    }
    let Ok(rd) = fs::read_dir(raiz) else { return };
    for ent in rd.flatten() {
        if *contador >= MAX_ENTRADAS {
            return;
        }
        *contador += 1;
        let p = ent.path();
        let md = match ent.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        f(&p, md.is_dir(), mtime);
        if md.is_dir() {
            recorrer(&p, prof - 1, contador, f);
        }
    }
}

fn tokens(nombre: &str) -> Vec<String> {
    nombre
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3)
        .map(|t| t.to_lowercase())
        .collect()
}

/// Carpetas cuyo nombre coincide con la aplicación.
pub fn por_nombre(app: &str, raices: &[PathBuf]) -> Vec<Candidato> {
    let toks = tokens(app);
    if toks.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for r in raices {
        let mut cont = 0;
        recorrer(r, PROFUNDIDAD, &mut cont, &mut |p, es_dir, mtime| {
            if !es_dir {
                return;
            }
            let n = p.file_name().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
            if toks.iter().any(|t| n.contains(t.as_str())) {
                out.push(Candidato { ruta: p.to_path_buf(), razon: tr("name matches","coincide el nombre").into(), archivos_recientes: 0, mtime });
            }
        });
    }
    out
}

/// Observa qué carpetas se escriben durante `dur` (arranca la app antes).
pub fn observando(raices: &[PathBuf], dur: Duration) -> Vec<Candidato> {
    let t0 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!("{}", tfmt(tr("Watching for {}s… (keep the application running)","Observando durante {}s… (deja la aplicación funcionando)"), &[dur.as_secs().to_string()]));
    std::thread::sleep(dur);

    // Cuenta, por carpeta, cuántos archivos tienen mtime posterior al inicio.
    let mut por_dir: HashMap<PathBuf, (usize, u64)> = HashMap::new();
    for r in raices {
        let mut cont = 0;
        recorrer(r, PROFUNDIDAD, &mut cont, &mut |p, es_dir, mtime| {
            if es_dir || mtime < t0 {
                return;
            }
            if let Some(dir) = p.parent() {
                let e = por_dir.entry(dir.to_path_buf()).or_insert((0, 0));
                e.0 += 1;
                e.1 = e.1.max(mtime);
            }
        });
    }
    let mut out: Vec<Candidato> = por_dir
        .into_iter()
        .map(|(ruta, (n, mtime))| Candidato {
            ruta,
            razon: tr("written while the app was running","escrita mientras la app corría").into(),
            archivos_recientes: n,
            mtime,
        })
        .collect();
    out.sort_by(|a, b| b.archivos_recientes.cmp(&a.archivos_recientes));
    out
}

/// Pistas de rutas dentro del ejecutable de la app (cadenas tipo ruta).
pub fn pistas_exe(exe: &Path) -> Vec<String> {
    let Ok(datos) = fs::read(exe) else { return Vec::new() };
    let claves = ["cache", "appdata", "localappdata", "application support", "/.cache", "caches"];
    let mut out = Vec::new();
    let mut act: Vec<u8> = Vec::new();
    let volcar = |act: &mut Vec<u8>, out: &mut Vec<String>| {
        if act.len() >= 6 {
            let s = String::from_utf8_lossy(act).to_lowercase();
            if (s.contains('/') || s.contains('\\') || s.contains('%')) && claves.iter().any(|k| s.contains(k)) {
                let t = String::from_utf8_lossy(act).into_owned();
                if !out.contains(&t) {
                    out.push(t);
                }
            }
        }
        act.clear();
    };
    for &b in &datos {
        if (0x20..0x7f).contains(&b) {
            act.push(b);
        } else {
            volcar(&mut act, &mut out);
        }
    }
    volcar(&mut act, &mut out);
    out.truncate(20);
    out
}

/// Orquesta la localización y lo imprime; devuelve el mejor candidato.
pub fn localizar(app: &str, exe: Option<&Path>, observar: Option<Duration>) -> Option<PathBuf> {
    let raices = raices();
    eprintln!("{}", tfmt(tr("System cache roots: {}","Raíces de caché del sistema: {}"), &[raices.len().to_string()]));
    for r in &raices {
        eprintln!("  · {}", r.display());
    }
    eprintln!();

    let mut candidatos = Vec::new();
    if !app.is_empty() {
        candidatos.extend(por_nombre(app, &raices));
    }
    if let Some(dur) = observar {
        candidatos.extend(observando(&raices, dur));
    }

    // Dedupe por ruta, quedándonos con la razón más fuerte (observada > nombre).
    candidatos.sort_by(|a, b| a.ruta.cmp(&b.ruta));
    candidatos.dedup_by(|a, b| a.ruta == b.ruta);
    // Orden: primero las observadas (más archivos recientes), luego por fecha.
    candidatos.sort_by(|a, b| {
        b.archivos_recientes
            .cmp(&a.archivos_recientes)
            .then(b.mtime.cmp(&a.mtime))
    });

    if let Some(exe) = exe {
        let pistas = pistas_exe(exe);
        if !pistas.is_empty() {
            eprintln!("{}", tfmt(tr("Path hints in {}:","Pistas de ruta en {}:"), &[exe.display().to_string()]));
            for p in &pistas {
                eprintln!("  → {p}");
            }
            eprintln!();
        }
    }

    if candidatos.is_empty() {
        eprintln!("{}", tr("No candidate cache folders found.","No se encontraron carpetas de caché candidatas."));
        if observar.is_none() {
            eprintln!("{}", tr("Try launching the app and using --observar <seconds> to detect\n\
                       which folder it writes to, even if the name does not match.","Prueba a arrancar la aplicación y usar --observar <segundos> para detectar\n\
                       qué carpeta escribe, aunque su nombre no coincida."));
        }
        return None;
    }

    eprintln!("{}", tr("Candidates (best first):","Candidatos (mejor primero):"));
    for (i, c) in candidatos.iter().take(10).enumerate() {
        let act = if c.archivos_recientes > 0 {
            tfmt(tr("  · {} file(s) just written","  · {} archivo(s) recién escritos"), &[c.archivos_recientes.to_string()])
        } else {
            String::new()
        };
        eprintln!("  {}. {}  [{}]{act}", i + 1, c.ruta.display(), c.razon);
    }
    let mejor = &candidatos[0].ruta;
    eprintln!("\n{}", tr("To watch the cache (without touching it):","Para vigilar la caché (sin tocarla):"));
    eprintln!("  capas --vigilar \"{}\" --solo-informe", mejor.display());
    Some(mejor.clone())
}
