//! Modo vigilancia: la puerta de entrada al servidor. Observa una carpeta
//! `incoming/`, audita cada paquete que aparece (cuando termina de escribirse)
//! y lo encamina solo: APROBADO → `approved/` (la carpeta de Mods del
//! servidor), lo demás → `quarantine/`. El servidor solo carga de `approved/`,
//! y el único que escribe ahí es capas: así ningún pack llega sin auditar.
//!
//! No toca la red ni el TLS: la interceptación se hace controlando la carpeta
//! de la que el servidor carga los mods.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::analisis::{self, Opciones};
use crate::auditar::Veredicto;
use crate::recursos::{humano, Herramientas, Sistema};

pub struct Carpetas {
    pub incoming: PathBuf,
    pub approved: PathBuf,
    pub quarantine: PathBuf,
    pub reports: PathBuf,
}

impl Carpetas {
    /// Deriva approved/quarantine/reports junto a incoming si no se indican.
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

/// Bucle de vigilancia. Sondea cada `intervalo` hasta que `cancelar` se activa.
pub fn vigilar(
    c: &Carpetas,
    op: &Opciones,
    herr: &Herramientas,
    sis: &Sistema,
    intervalo: Duration,
    cancelar: Arc<AtomicBool>,
) -> Result<()> {
    for d in [&c.incoming, &c.approved, &c.quarantine, &c.reports] {
        fs::create_dir_all(d).with_context(|| format!("creando {}", d.display()))?;
    }
    eprintln!("Vigilando: {}", c.incoming.display());
    eprintln!("  APROBADO  → {}", c.approved.display());
    eprintln!("  resto     → {}", c.quarantine.display());
    eprintln!("  informes  → {}\n(Ctrl-C para parar)\n", c.reports.display());

    // Para no procesar un archivo a medio escribir: esperamos a que su tamaño
    // no cambie entre dos sondeos.
    let mut tam_previo: HashMap<PathBuf, u64> = HashMap::new();

    while !cancelar.load(std::sync::atomic::Ordering::Relaxed) {
        let entradas = match fs::read_dir(&c.incoming) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("  ! no se puede leer {}: {e}", c.incoming.display());
                std::thread::sleep(intervalo);
                continue;
            }
        };
        let mut vistos_ahora = std::collections::HashSet::new();
        for ent in entradas.flatten() {
            let p = ent.path();
            if !p.is_file() {
                continue;
            }
            vistos_ahora.insert(p.clone());
            let tam = ent.metadata().map(|m| m.len()).unwrap_or(0);
            let estable = tam_previo.get(&p) == Some(&tam) && tam > 0;
            if !estable {
                tam_previo.insert(p.clone(), tam);
                continue; // esperar otro ciclo a que deje de crecer
            }
            tam_previo.remove(&p);
            if let Err(e) = procesar(&p, c, op, herr, sis) {
                eprintln!("  ! {}: {e:#}", p.display());
            }
        }
        // Olvidar archivos que ya no están.
        tam_previo.retain(|p, _| vistos_ahora.contains(p));
        std::thread::sleep(intervalo);
    }
    eprintln!("Vigilancia detenida.");
    Ok(())
}

fn procesar(archivo: &Path, c: &Carpetas, op: &Opciones, herr: &Herramientas, sis: &Sistema) -> Result<()> {
    let nombre = archivo.file_name().unwrap_or_default().to_string_lossy().into_owned();
    let tam = fs::metadata(archivo).map(|m| m.len()).unwrap_or(0);
    eprintln!("▸ {nombre} ({})", humano(tam));

    let dir_informe = c.reports.join(sello(&nombre));
    let mut o = op.clone();
    o.auditar = true;
    o.clasificar = false; // para la puerta basta el veredicto; no duplicamos archivos
    let r = analisis::ejecutar(
        &[archivo.to_path_buf()],
        &dir_informe,
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
        .unwrap_or(Veredicto::Rechazado); // sin veredicto = no pasa

    let destino_dir = match veredicto {
        Veredicto::Aprobado => &c.approved,
        _ => &c.quarantine,
    };
    let destino = destino_unico(destino_dir, &nombre);
    mover(archivo, &destino)?;

    eprintln!(
        "  [{}] → {}   (informe: {})",
        veredicto.etiqueta(),
        destino.display(),
        dir_informe.join("auditoria.md").display()
    );
    Ok(())
}

/// Mueve el archivo; si es otro sistema de ficheros, copia y borra.
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

/// Marca de tiempo + nombre, para una subcarpeta de informe única.
fn sello(nombre: &str) -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let limpio: String = nombre.chars().map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect();
    format!("{t}_{limpio}")
}
