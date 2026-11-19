//! Modo vigilancia. Dos usos:
//!
//! - PUERTA (servidor): observa `incoming/`, audita cada pack y lo MUEVE —
//!   APROBADO → `approved/` (carpeta de Mods), el resto → `quarantine/`. El
//!   servidor solo carga de `approved/`, así la auditoría es obligatoria.
//!
//! - SOLO-INFORME (cliente): observa una carpeta de CACHÉ donde un servidor te
//!   escribe archivos. No mueve ni borra nada (el juego los necesita): audita y
//!   clasifica una COPIA y te avisa del veredicto. Es detección, no bloqueo
//!   previo; no toca la red ni el cliente.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::analisis::{self, Opciones};
use crate::auditar::Veredicto;
use crate::clasificar::Categoria;
use crate::idioma::{tfmt, tr};
use crate::recursos::{humano, Herramientas, Sistema};

pub struct Carpetas {
    pub incoming: PathBuf,
    pub approved: PathBuf,
    pub quarantine: PathBuf,
    pub reports: PathBuf,
}

impl Carpetas {
    pub fn desde(incoming: PathBuf, approved: Option<PathBuf>, quarantine: Option<PathBuf>, reports: Option<PathBuf>) -> Self {
        let base = incoming.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
        Carpetas {
            approved: approved.unwrap_or_else(|| base.join("approved")),
            quarantine: quarantine.unwrap_or_else(|| base.join("quarantine")),
            reports: reports.unwrap_or_else(|| base.join("reports")),
            incoming,
        }
    }
}

/// Bucle de vigilancia. Sondea cada `intervalo` hasta que `cancelar` se active.
/// Si `solo_informe`, no mueve nada (vigilancia de caché del cliente).
pub fn vigilar(
    c: &Carpetas,
    op: &Opciones,
    herr: &Herramientas,
    sis: &Sistema,
    intervalo: Duration,
    solo_informe: bool,
    cancelar: Arc<AtomicBool>,
) -> Result<()> {
    fs::create_dir_all(&c.incoming).with_context(|| format!("creando {}", c.incoming.display()))?;
    fs::create_dir_all(&c.reports)?;
    if solo_informe {
        eprintln!("{}", tfmt(tr("Watching (report only, no moving): {}","Vigilando (solo informe, sin mover): {}"), &[c.incoming.display().to_string()]));
        eprintln!("{}", tfmt(tr("  reports → {}\n(Ctrl-C to stop)\n","  informes → {}\n(Ctrl-C para parar)\n"), &[c.reports.display().to_string()]));
    } else {
        fs::create_dir_all(&c.approved)?;
        fs::create_dir_all(&c.quarantine)?;
        eprintln!("{}", tfmt(tr("Audit gate: {}","Puerta de auditoría: {}"), &[c.incoming.display().to_string()]));
        eprintln!("{}", tfmt(tr("  APPROVED → {}\n  rest     → {}\n  reports  → {}\n(Ctrl-C to stop)\n","  APROBADO → {}\n  resto    → {}\n  informes → {}\n(Ctrl-C para parar)\n"),
            &[c.approved.display().to_string(), c.quarantine.display().to_string(), c.reports.display().to_string()]));
    }

    // Espera a que un archivo deje de crecer (no procesar a medio escribir).
    let mut tam_previo: HashMap<PathBuf, u64> = HashMap::new();
    // En solo-informe los archivos se quedan: recordamos los ya vistos.
    let mut procesados: HashSet<(PathBuf, u64, u64)> = HashSet::new();

    while !cancelar.load(Ordering::Relaxed) {
        let mut archivos = Vec::new();
        if solo_informe {
            listar_recursivo(&c.incoming, &c.reports, &mut archivos);
        } else {
            for ent in fs::read_dir(&c.incoming).into_iter().flatten().flatten() {
                let p = ent.path();
                if p.is_file() {
                    archivos.push(p);
                }
            }
        }

        let presentes: HashSet<PathBuf> = archivos.iter().cloned().collect();
        for p in &archivos {
            let (tam, mtime) = metadatos(p);
            if tam == 0 {
                continue;
            }
            if solo_informe && procesados.contains(&(p.clone(), tam, mtime)) {
                continue; // ya informado y sin cambios
            }
            // Estabilidad: el tamaño no cambió desde el sondeo anterior.
            if tam_previo.get(p) != Some(&tam) {
                tam_previo.insert(p.clone(), tam);
                continue;
            }
            tam_previo.remove(p);
            let r = if solo_informe {
                informar(p, c, op, herr, sis).map(|_| procesados.insert((p.clone(), tam, mtime)))
            } else {
                procesar(p, c, op, herr, sis).map(|_| false)
            };
            if let Err(e) = r {
                eprintln!("  ! {}: {e:#}", p.display());
            }
        }
        tam_previo.retain(|p, _| presentes.contains(p));
        if solo_informe {
            procesados.retain(|(p, _, _)| presentes.contains(p));
        }
        std::thread::sleep(intervalo);
    }
    eprintln!("{}", tr("Watch stopped.","Vigilancia detenida."));
    Ok(())
}

/// Lista archivos recursivamente, sin entrar en la carpeta de informes.
fn listar_recursivo(dir: &Path, reports: &Path, out: &mut Vec<PathBuf>) {
    if same_path(dir, reports) {
        return;
    }
    for ent in fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = ent.path();
        if p.is_dir() {
            listar_recursivo(&p, reports, out);
        } else if p.is_file() {
            out.push(p);
        }
    }
}

fn same_path(a: &Path, b: &Path) -> bool {
    fs::canonicalize(a).ok() == fs::canonicalize(b).ok() && fs::canonicalize(a).is_ok()
}

fn metadatos(p: &Path) -> (u64, u64) {
    match fs::metadata(p) {
        Ok(m) => {
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            (m.len(), mtime)
        }
        Err(_) => (0, 0),
    }
}

/// PUERTA: audita y mueve según el veredicto.
fn procesar(archivo: &Path, c: &Carpetas, op: &Opciones, herr: &Herramientas, sis: &Sistema) -> Result<()> {
    let nombre = archivo.file_name().unwrap_or_default().to_string_lossy().into_owned();
    eprintln!("▸ {nombre} ({})", humano(fs::metadata(archivo).map(|m| m.len()).unwrap_or(0)));
    let dir_informe = c.reports.join(sello(&nombre));
    let veredicto = auditar_en(archivo, &dir_informe, op, herr, sis, false)?.0;
    let destino_dir = if veredicto == Veredicto::Aprobado { &c.approved } else { &c.quarantine };
    let destino = destino_unico(destino_dir, &nombre);
    mover(archivo, &destino)?;
    eprintln!("{}", tfmt(tr("  [{}] → {}   (report: {})","  [{}] → {}   (informe: {})"), &[veredicto.etiqueta().to_string(), destino.display().to_string(), dir_informe.join("auditoria.md").display().to_string()]));
    Ok(())
}

/// SOLO-INFORME: audita + clasifica una copia, sin tocar el original.
fn informar(archivo: &Path, c: &Carpetas, op: &Opciones, herr: &Herramientas, sis: &Sistema) -> Result<()> {
    let nombre = archivo.file_name().unwrap_or_default().to_string_lossy().into_owned();
    let dir_informe = c.reports.join(sello(&nombre));
    let (veredicto, cats) = auditar_en(archivo, &dir_informe, op, herr, sis, true)?;
    let resumen: String = cats
        .iter()
        .take(4)
        .map(|(cat, n)| format!("{} {n}", cat.etiqueta()))
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!(
        "▸ [{}] {} ({})  ·  {}",
        veredicto.etiqueta(),
        nombre,
        humano(fs::metadata(archivo).map(|m| m.len()).unwrap_or(0)),
        if resumen.is_empty() { "—".into() } else { resumen }
    );
    if veredicto != Veredicto::Aprobado {
        eprintln!("{}", tfmt(tr("    report: {}","    informe: {}"), &[dir_informe.join("auditoria.md").display().to_string()]));
    }
    Ok(())
}

/// Ejecuta el análisis con auditoría (y clasificación si se pide) sobre un
/// archivo, en su carpeta de informe. Devuelve veredicto y categorías.
fn auditar_en(
    archivo: &Path,
    dir_informe: &Path,
    op: &Opciones,
    herr: &Herramientas,
    sis: &Sistema,
    clasificar: bool,
) -> Result<(Veredicto, Vec<(Categoria, usize)>)> {
    let mut o = op.clone();
    o.auditar = true;
    o.clasificar = clasificar;
    let r = analisis::ejecutar(
        &[archivo.to_path_buf()],
        dir_informe,
        &o,
        herr.clone(),
        sis,
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let veredicto = r
        .auditoria
        .as_ref()
        .and_then(|a| a.paquetes.first())
        .map(|p| p.veredicto)
        .unwrap_or(Veredicto::Rechazado);
    let cats = r
        .clasificacion
        .as_ref()
        .map(|c| {
            Categoria::TODAS
                .iter()
                .filter_map(|cat| {
                    let n = c.por_categoria.get(cat.nombre()).copied().unwrap_or(0);
                    (n > 0).then_some((*cat, n))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok((veredicto, cats))
}

fn mover(origen: &Path, destino: &Path) -> Result<()> {
    if fs::rename(origen, destino).is_ok() {
        return Ok(());
    }
    fs::copy(origen, destino).with_context(|| format!("copiando a {}", destino.display()))?;
    fs::remove_file(origen).ok();
    Ok(())
}

fn destino_unico(dir: &Path, nombre: &str) -> PathBuf {
    let p = dir.join(nombre);
    if !p.exists() {
        return p;
    }
    let (t, e) = match nombre.rsplit_once('.') {
        Some((t, e)) if !t.is_empty() => (t.to_string(), format!(".{e}")),
        _ => (nombre.to_string(), String::new()),
    };
    for k in 1.. {
        let cand = dir.join(format!("{t}~{k}{e}"));
        if !cand.exists() {
            return cand;
        }
    }
    unreachable!()
}

fn sello(nombre: &str) -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let limpio: String = nombre.chars().map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect();
    format!("{t}_{limpio}")
}
