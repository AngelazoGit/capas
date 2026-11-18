//! Orquestación de un análisis completo (compartido por la consola y la interfaz).

use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::motor::{self, Config, Evento, Motor, Nodo};
use crate::recursos::{humano, Herramientas, Sistema};
use crate::{AUTOR, VERSION};

#[derive(Clone)]
pub struct Opciones {
    pub hilos: usize,
    pub profundidad: usize,
    pub max_archivo: u64,
    pub max_total: u64,
    pub timeout: Duration,
    pub max_instrucciones: usize,
    pub tallar: bool,
    pub clasificar: bool,
    pub auditar: bool,
    pub claves: crate::claves::Claves,
}

impl Opciones {
    /// Valores por defecto calculados a partir de los recursos del ordenador.
    pub fn para(sis: &Sistema) -> Self {
        let hilos = sis.nucleos.max(1);
        Opciones {
            hilos,
            profundidad: 12,
            max_archivo: limite_por_bloque(sis, hilos),
            max_total: 16 << 30,
            timeout: Duration::from_secs(300),
            max_instrucciones: 500_000,
            tallar: true,
            clasificar: true,
            auditar: false,
            claves: crate::claves::Claves::default(),
        }
    }
}

/// Cada hilo puede tener en memoria un bloque y sus hijos: se reparte la
/// RAM libre de forma conservadora.
pub fn limite_por_bloque(sis: &Sistema, hilos: usize) -> u64 {
    (sis.memoria_libre / (hilos.max(1) as u64 * 4)).clamp(64 << 20, 4 << 30)
}

pub struct Resumen {
    pub arbol: Vec<Nodo>,
    pub bloques: usize,
    pub bytes: u64,
    pub duracion: Duration,
    pub raiz: PathBuf,
    pub clasificacion: Option<crate::clasificar::Clasificacion>,
    pub auditoria: Option<crate::auditar::Auditoria>,
}

pub fn ejecutar(
    rutas: &[PathBuf],
    salida: &Path,
    op: &Opciones,
    herr: Herramientas,
    sis: &Sistema,
    eventos: Option<Sender<Evento>>,
    cancelar: Arc<AtomicBool>,
) -> Result<Resumen> {
    let entradas = recoger(rutas)?;
    if entradas.is_empty() {
        anyhow::bail!("no hay archivos que analizar");
    }
    fs::create_dir_all(salida).with_context(|| format!("creando {}", salida.display()))?;
    let raiz = fs::canonicalize(salida)?;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(op.hilos.max(1)).build()?;
    let m = Motor::new(
        Config {
            profundidad_max: op.profundidad,
            max_archivo: op.max_archivo,
            max_total: op.max_total,
            timeout: op.timeout,
            max_instrucciones: op.max_instrucciones,
            tallar: op.tallar,
            claves: op.claves.clone(),
        },
        herr,
        raiz.clone(),
        eventos,
        cancelar,
    );

    let t0 = Instant::now();
    let mut nombres = HashSet::new();
    let trabajos: Vec<_> = entradas
        .into_iter()
        .map(|p| {
            let base = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or("entrada".into());
            let mut n = base.clone();
            let mut k = 1;
            while !nombres.insert(n.clone()) {
                n = format!("{base}~{k}");
                k += 1;
            }
            (p, n)
        })
        .collect();

    let mut arbol: Vec<Nodo> = pool.install(|| {
        trabajos
            .into_par_iter()
            .filter_map(|(p, n)| {
                if m.cancelar.load(Ordering::Relaxed) {
                    return None;
                }
                let tam = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                if tam > op.max_archivo {
                    m.emitir(Evento::Aviso(format!(
                        "{} ({}) supera el límite por bloque",
                        p.display(),
                        humano(tam)
                    )));
                    return None;
                }
                match fs::read(&p) {
                    Ok(datos) => {
                        let dir = raiz.join(motor::ruta_segura(&n));
                        let _ = fs::create_dir_all(&dir);
                        Some(m.procesar(datos, n, p, dir, 0))
                    }
                    Err(e) => {
                        m.emitir(Evento::Aviso(format!("{}: {e}", p.display())));
                        None
                    }
                }
            })
            .collect()
    });
    arbol.sort_by(|a, b| a.nombre.cmp(&b.nombre));

    let duracion = t0.elapsed();
    let bloques = m.procesados.load(Ordering::Relaxed);
    fs::write(raiz.join("informe.json"), serde_json::to_string_pretty(&arbol)?)?;
    fs::write(raiz.join("informe.md"), informe_md(&arbol, sis, op.hilos, duracion, bloques, &m.herr))?;

    let clasificacion = if op.clasificar && !arbol.is_empty() {
        match crate::clasificar::clasificar(&arbol, &raiz, true) {
            Ok(c) => {
                m.emitir(Evento::Aviso(format!(
                    "clasificados {} archivo(s) en {} categorías → extraidos/",
                    c.total,
                    c.por_categoria.values().filter(|&&n| n > 0).count()
                )));
                Some(c)
            }
            Err(e) => {
                m.emitir(Evento::Aviso(format!("clasificación: {e}")));
                None
            }
        }
    } else {
        None
    };

    let auditoria = if op.auditar && !arbol.is_empty() {
        match crate::auditar::auditar(&arbol, &raiz) {
            Ok(a) => {
                for p in &a.paquetes {
                    m.emitir(Evento::Aviso(format!("auditoría «{}»: {}", p.nombre, p.veredicto.etiqueta())));
                }
                Some(a)
            }
            Err(e) => {
                m.emitir(Evento::Aviso(format!("auditoría: {e}")));
                None
            }
        }
    } else {
        None
    };

    Ok(Resumen { arbol, bloques, bytes: m.bytes_extraidos(), duracion, raiz, clasificacion, auditoria })
}

pub fn recoger(rutas: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut v = Vec::new();
    for r in rutas {
        recoger_en(r, &mut v).with_context(|| format!("leyendo {}", r.display()))?;
    }
    Ok(v)
}

fn recoger_en(p: &Path, v: &mut Vec<PathBuf>) -> Result<()> {
    let md = fs::symlink_metadata(p)?;
    if md.is_dir() {
        let mut hijos: Vec<_> = fs::read_dir(p)?.flatten().map(|e| e.path()).collect();
        hijos.sort();
        for h in hijos {
            recoger_en(&h, v)?;
        }
    } else if md.is_file() {
        v.push(p.to_path_buf());
    }
    Ok(())
}

fn informe_md(arbol: &[Nodo], sis: &Sistema, hilos: usize, t: Duration, bloques: usize, herr: &Herramientas) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Informe de capas\n");
    let _ = writeln!(
        s,
        "- Recursos: {} núcleos ({} hilos usados), {} de RAM libre",
        sis.nucleos,
        hilos,
        humano(sis.memoria_libre)
    );
    let _ = writeln!(
        s,
        "- Herramientas externas usadas: {}",
        if herr.rutas.is_empty() { "ninguna".to_string() } else { herr.rutas.keys().cloned().collect::<Vec<_>>().join(", ") }
    );
    let _ = writeln!(s, "- Duración: {:.1}s, bloques: {bloques}\n", t.as_secs_f64());
    let _ = writeln!(s, "## Árbol de capas\n");
    for n in arbol {
        nodo_md(n, 0, &mut s);
    }
    let _ = writeln!(s, "\n---\n*Generado por capas v{VERSION} — firmado por {AUTOR}*");
    s
}

fn nodo_md(n: &Nodo, nivel: usize, s: &mut String) {
    let sang = "  ".repeat(nivel);
    let _ = writeln!(
        s,
        "{sang}- **{}** — capa {} · {} · {} · entropía {:.2} · `{}`",
        n.nombre,
        n.capa,
        n.descripcion,
        humano(n.tamano),
        n.entropia,
        &n.sha256[..16]
    );
    for r in &n.resultados {
        let _ = writeln!(s, "{sang}  - 📄 `{r}`");
    }
    for nota in &n.notas {
        let _ = writeln!(s, "{sang}  - ⚠ {nota}");
    }
    for h in &n.hijos {
        nodo_md(h, nivel + 1, s);
    }
}
