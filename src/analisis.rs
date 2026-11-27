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
use crate::idioma::{tfmt, tr};
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
    pub desempaquetar: bool,
    pub clasificar: bool,
    pub agrupar: bool,
    pub reconstruir: bool,
    pub indice: bool,
    pub indice_db: Option<PathBuf>,
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
            desempaquetar: false,
            clasificar: true,
            agrupar: false,
            reconstruir: false,
            indice: true,
            indice_db: None,
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
            desempaquetar: op.desempaquetar,
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
                // Los archivos que elige el usuario (nivel 0) no se descartan por el
                // límite por bloque — ese límite protege de bombas en las capas hijas.
                // Solo se omite si supera el presupuesto total (evita agotar la RAM).
                let tam = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                if tam > op.max_total {
                    m.emitir(Evento::Aviso(tfmt(tr("{} ({}) exceeds the total budget","{} ({}) supera el presupuesto total"), &[p.display().to_string(), humano(tam)])));
                    return None;
                }
                // Para no cargar en RAM archivos enormes (ISOs/juegos de varios GB),
                // se mapea el fichero en memoria (mmap): el SO trae las páginas bajo
                // demanda y las libera si falta RAM, así que el input apenas consume
                // memoria. Si el mmap falla (p. ej. sistema de archivos raro), se lee
                // normal. El mmap es de solo lectura; para el análisis nos vale.
                let dir = raiz.join(motor::ruta_segura(&n));
                let _ = fs::create_dir_all(&dir);
                let mapa = fs::File::open(&p).ok().and_then(|f| unsafe { memmap2::Mmap::map(&f).ok() });
                if let Some(mapa) = mapa {
                    Some(m.procesar(&mapa, n, p, dir, 0))
                } else {
                    match fs::read(&p) {
                        Ok(datos) => Some(m.procesar(&datos, n, p, dir, 0)),
                        Err(e) => {
                            m.emitir(Evento::Aviso(format!("{}: {e}", p.display())));
                            None
                        }
                    }
                }
            })
            .collect()
    });
    arbol.sort_by(|a, b| a.nombre.cmp(&b.nombre));

    // Relaciones de familia: ajusta la confianza (COMPATIBLE/CONFIRMADO) antes
    // de escribir los informes, para que se propague a todo.
    let relaciones = if !arbol.is_empty() {
        match crate::relaciones::relacionar(&mut arbol, &raiz) {
            Ok(v) => {
                if !v.is_empty() {
                    m.emitir(Evento::Aviso(tfmt(
                        tr("{} file relation(s) → relaciones.md", "{} relación(es) de archivos → relaciones.md"),
                        &[v.len().to_string()],
                    )));
                }
                v
            }
            Err(e) => {
                m.emitir(Evento::Aviso(tfmt(tr("relations: {}", "relaciones: {}"), &[e.to_string()])));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let duracion = t0.elapsed();
    let bloques = m.procesados.load(Ordering::Relaxed);
    fs::write(raiz.join("informe.json"), serde_json::to_string_pretty(&arbol)?)?;
    fs::write(raiz.join("informe.md"), informe_md(&arbol, sis, op.hilos, duracion, bloques, &m.herr))?;
    if let Some(n) = diagnostico_desconocidos(&arbol, &raiz) {
        if n > 0 {
            m.emitir(Evento::Aviso(tfmt(tr("{} unknown file(s) → desconocidos.txt (send it to me to add detection)","{} archivo(s) desconocidos → desconocidos.txt (mándamelo para añadir su detección)"), &[n.to_string()])));
        }
    }
    if let Some(n) = crate::plugins::analizar(&arbol, &raiz) {
        if n > 0 {
            m.emitir(Evento::Aviso(tfmt(tr("{} plugin(s)/active code → plugins.md (functions and imported APIs)","{} plugin(s)/código activo → plugins.md (funciones y APIs que importan)"), &[n.to_string()])));
        }
    }

    let clasificacion = if op.clasificar && !arbol.is_empty() {
        match crate::clasificar::clasificar(&arbol, &raiz, true) {
            Ok(c) => {
                m.emitir(Evento::Aviso(tfmt(tr("classified {} file(s) in {} categories → extraidos/","clasificados {} archivo(s) en {} categorías → extraidos/"), &[c.total.to_string(), c.por_categoria.values().filter(|&&n| n > 0).count().to_string()])));
                Some(c)
            }
            Err(e) => {
                m.emitir(Evento::Aviso(tfmt(tr("classification: {}","clasificación: {}"), &[e.to_string()])));
                None
            }
        }
    } else {
        None
    };

    if op.agrupar && !arbol.is_empty() {
        match crate::clasificar::agrupar(&arbol, &raiz, true) {
            Ok(c) => m.emitir(Evento::Aviso(tfmt(tr("{} resource set(s) grouped ({} files) → extraidos/conjuntos/","{} conjunto(s) de recursos agrupados ({} archivos) → extraidos/conjuntos/"), &[c.grupos.to_string(), c.archivos.to_string()]))),
            Err(e) => m.emitir(Evento::Aviso(tfmt(tr("grouping: {}","agrupación: {}"), &[e.to_string()]))),
        }
    }

    if op.reconstruir && !arbol.is_empty() {
        match crate::clasificar::reconstruir(&arbol, &raiz, true) {
            Ok((p, a)) => m.emitir(Evento::Aviso(tfmt(tr("{} package(s) rebuilt ({} files) → extraidos/reconstruido/","{} paquete(s) reconstruidos ({} archivos) → extraidos/reconstruido/"), &[p.to_string(), a.to_string()]))),
            Err(e) => m.emitir(Evento::Aviso(tfmt(tr("rebuild: {}","reconstrucción: {}"), &[e.to_string()]))),
        }
    }

    let auditoria = if op.auditar && !arbol.is_empty() {
        match crate::auditar::auditar(&arbol, &raiz) {
            Ok(a) => {
                for p in &a.paquetes {
                    m.emitir(Evento::Aviso(tfmt(tr("audit «{}»: {}","auditoría «{}»: {}"), &[p.nombre.clone(), p.veredicto.etiqueta().to_string()])));
                }
                Some(a)
            }
            Err(e) => {
                m.emitir(Evento::Aviso(tfmt(tr("audit: {}","auditoría: {}"), &[e.to_string()])));
                None
            }
        }
    } else {
        None
    };

    if op.indice && !arbol.is_empty() {
        let db = op.indice_db.clone().unwrap_or_else(|| raiz.join("capas.db"));
        match crate::indice::escribir(&db, &arbol, &relaciones, auditoria.as_ref()) {
            Ok(r) => m.emitir(Evento::Aviso(tfmt(
                tr("SQLite index: {} file(s) this run, {} unique total → {}", "índice SQLite: {} archivo(s) esta vez, {} únicos en total → {}"),
                &[r.archivos.to_string(), r.total_db.to_string(), db.display().to_string()],
            ))),
            Err(e) => m.emitir(Evento::Aviso(tfmt(tr("SQLite index: {}", "índice SQLite: {}"), &[e.to_string()]))),
        }
    }

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
    let _ = writeln!(s, "# {}\n", tr("Layer report","Informe de capas"));
    let _ = writeln!(s, "{}", tfmt(tr("- Resources: {} cores ({} threads used), {} free RAM","- Recursos: {} núcleos ({} hilos usados), {} de RAM libre"), &[sis.nucleos.to_string(), hilos.to_string(), humano(sis.memoria_libre)]));
    let _ = writeln!(s, "{}", tfmt(tr("- External tools used: {}","- Herramientas externas usadas: {}"), &[if herr.rutas.is_empty() { tr("none","ninguna").to_string() } else { herr.rutas.keys().cloned().collect::<Vec<_>>().join(", ") }]));
    let _ = writeln!(s, "{}", tfmt(tr("- Duration: {}s, blocks: {}\n","- Duración: {}s, bloques: {}\n"), &[format!("{:.1}", t.as_secs_f64()), bloques.to_string()]));
    // Resumen de confianza.
    let mut conf: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    cuenta_confianza(arbol, &mut conf);
    let _ = writeln!(s, "## {}\n", tr("Confidence","Confianza"));
    for c in crate::clasificar::Confianza::TODAS {
        let n = conf.get(c.clave()).copied().unwrap_or(0);
        if n > 0 {
            let _ = writeln!(s, "- **{}**: {}", c.etiqueta(), n);
        }
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "## {}\n", tr("Layer tree","Árbol de capas"));
    for n in arbol {
        nodo_md(n, 0, &mut s);
    }
    let _ = writeln!(s, "{}", tfmt(tr("\n---\n*Generated by capas v{} — signed by {}*","\n---\n*Generado por capas v{} — firmado por {}*"), &[VERSION.to_string(), AUTOR.to_string()]));
    s
}

fn cuenta_confianza(nodos: &[Nodo], conf: &mut std::collections::BTreeMap<&'static str, usize>) {
    for n in nodos {
        *conf.entry(n.confianza.clave()).or_insert(0) += 1;
        cuenta_confianza(&n.hijos, conf);
    }
}

fn nodo_md(n: &Nodo, nivel: usize, s: &mut String) {
    let sang = "  ".repeat(nivel);
    let _ = writeln!(s, "{}", tfmt(tr("{}- **{}** — [{}] {} · {} · entropy {} · `{}`","{}- **{}** — [{}] {} · {} · entropía {} · `{}`"), &[sang.clone(), n.nombre.clone(), n.confianza.etiqueta().to_string(), n.descripcion.clone(), humano(n.tamano), format!("{:.2}", n.entropia), n.sha256[..16].to_string()]));
    let _ = writeln!(s, "{}", tfmt(tr("{}  - {} · evidence: {}","{}  - {} · evidencia: {}"), &[sang.clone(), tfmt(tr("layer {}","capa {}"), &[n.capa.to_string()]), n.evidencia.clone()]));
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

/// Vuelca los archivos detectados como "desconocidos" con sus bytes mágicos,
/// agrupados por firma + extensión, para poder ampliar la detección.
fn diagnostico_desconocidos(arbol: &[Nodo], raiz: &Path) -> Option<usize> {
    use std::collections::BTreeMap;

    let mut muestras: Vec<(String, String, u64, String)> = Vec::new(); // (nombre, ext, tam, hex16)
    recoge_desconocidos(arbol, &mut muestras);
    if muestras.is_empty() {
        return Some(0);
    }
    // Agrupa por (primeros 8 bytes, extensión) para ver patrones.
    let mut grupos: BTreeMap<(String, String), (usize, Vec<String>)> = BTreeMap::new();
    for (nombre, ext, _tam, hex) in &muestras {
        let firma = hex.split_whitespace().take(4).collect::<Vec<_>>().join(" ");
        let e = grupos.entry((firma, ext.clone())).or_default();
        e.0 += 1;
        if e.1.len() < 3 {
            e.1.push(nombre.clone());
        }
    }
    let mut s = String::new();
    let _ = writeln!(s, "# {}\n", tr("Unknown files — diagnostics","Archivos desconocidos — diagnóstico"));
    let _ = writeln!(s, "{}", tfmt(tr("{} file(s) with no content-based detection.\n","{} archivo(s) sin detección por contenido.\n"), &[muestras.len().to_string()]));
    let _ = writeln!(s, "## {}\n", tr("Grouped by signature (first bytes) + extension","Agrupados por firma (primeros bytes) + extensión"));
    let _ = writeln!(s, "| {} | {} | {} | {} |", tr("#","nº"), tr("extension","extensión"), tr("signature (hex)","firma (hex)"), tr("examples","ejemplos"));
    let _ = writeln!(s, "|--:|---|---|---|");
    let mut orden: Vec<_> = grupos.into_iter().collect();
    orden.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    for ((firma, ext), (n, ejemplos)) in &orden {
        let ext = if ext.is_empty() { tr("(none)","(sin)") } else { ext.as_str() };
        let _ = writeln!(s, "| {n} | {ext} | `{firma}` | {} |", ejemplos.join(", "));
    }
    let _ = writeln!(s, "\n## {}\n", tr("Detail (first 16 bytes)","Detalle (primeros 16 bytes)"));
    for (nombre, _ext, tam, hex) in muestras.iter().take(500) {
        let ascii: String = hex
            .split_whitespace()
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .map(|b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        let _ = writeln!(s, "- {nombre} ({}) `{hex}`  |{ascii}|", humano(*tam));
    }
    let _ = writeln!(s, "\n---\n{}", tr("Send me this file (or paste the table above) and I will add detection for your formats.","Mándame este archivo (o pega la tabla de arriba) y añado la detección de tus formatos."));
    let _ = fs::write(raiz.join("desconocidos.txt"), s);
    Some(muestras.len())
}

fn recoge_desconocidos(nodos: &[Nodo], out: &mut Vec<(String, String, u64, String)>) {
    use crate::detectar::Tipo;
    for n in nodos {
        if n.tipo == Tipo::Desconocido {
            let ext = n
                .nombre
                .rsplit('.')
                .next()
                .filter(|e| !e.is_empty() && e.len() <= 8 && *e != n.nombre)
                .map(|e| e.to_lowercase())
                .unwrap_or_default();
            let mut buf = [0u8; 16];
            let leidos = std::fs::File::open(&n.ruta_fisica)
                .and_then(|mut f| std::io::Read::read(&mut f, &mut buf))
                .unwrap_or(0);
            let hex = buf[..leidos].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
            let base = n.nombre.rsplit(['/', '\\']).next().unwrap_or(&n.nombre).to_string();
            out.push((base, ext, n.tamano, hex));
        }
        recoge_desconocidos(&n.hijos, out);
    }
}
