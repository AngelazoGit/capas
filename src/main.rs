//! capas — desmonta y decompila archivos capa a capa usando los recursos
//! del ordenador (todos los núcleos, la RAM disponible y las herramientas
//! de ingeniería inversa instaladas).
//!
//! Autor: @angelazo
//!
//! Sin argumentos abre la interfaz gráfica; con archivos funciona en consola.

mod analisis;
mod auditar;
mod clasificar;
mod claves;
mod detectar;
mod ejecutables;
mod extraer;
mod gui;
mod idioma;
mod indice;
mod localizar;
mod motor;
mod plugins;
mod recursos;
mod relaciones;
mod vigilar;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;

use recursos::{humano, Herramientas, Sistema, HERRAMIENTAS_CONOCIDAS};

pub const AUTOR: &str = "@angelazo";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "capas",
    version,
    author = AUTOR,
    about = "Take files apart layer by layer and decompile them using your computer's resources — by @angelazo",
    long_about = "Feed in files (or folders) and the program peels them layer by layer:\n\
                  archives -> containers -> executables/bytecode -> disassembly/code.\n\
                  Uses all cores, tunes memory to the free RAM, and leverages\n\
                  objdump, readelf, javap, jadx, CFR, pycdc, wabt, radare2, RetDec, Ghidra and 7z\n\
                  if installed.\n\n\
                  Classifies the final files by category in extraidos/ and can open\n\
                  protected ZIPs with the key module (--clave, --comunes, --diccionario).\n\
                  With --auditar it reviews packages (asset packs/mods) and gives an\n\
                  APPROVED/QUARANTINE/REJECTED verdict without running anything.\n\n\
                  With no arguments it opens the GUI.\n\n\
                  Signed by @angelazo."
)]
struct Args {
    /// Files or folders to analyze (with none, the GUI opens)
    archivos: Vec<PathBuf>,

    /// Output folder
    #[arg(short, long, default_value = "salida_capas")]
    salida: PathBuf,

    /// Worker threads (default: all cores)
    #[arg(short = 'j', long)]
    hilos: Option<usize>,

    /// Maximum layer depth
    #[arg(short, long, default_value_t = 12)]
    profundidad: usize,

    /// Max size of an extracted block in MiB (default: based on free RAM)
    #[arg(long)]
    max_archivo_mb: Option<u64>,

    /// Max total to extract in MiB (zip-bomb protection)
    #[arg(long, default_value_t = 16384)]
    max_total_mb: u64,

    /// Max time per external tool, in seconds
    #[arg(short, long, default_value_t = 300)]
    timeout: u64,

    /// Max instructions of the built-in disassembler per binary
    #[arg(long, default_value_t = 500_000)]
    max_instrucciones: usize,

    /// Do not carve embedded files by signature
    #[arg(long)]
    sin_tallado: bool,

    /// Do not use external tools, built-in analysis only
    #[arg(long)]
    sin_externas: bool,

    /// Do not classify or gather files into extraidos/<category>/
    #[arg(long)]
    sin_clasificar: bool,

    /// Audit packages (asset packs/mods): APPROVED/QUARANTINE/REJECTED verdict
    #[arg(long)]
    auditar: bool,

    /// Group resources sharing a base name (world.blocky + world.png) into one .zip per set
    #[arg(long)]
    agrupar: bool,

    /// Rebuild each package with its original structure (folder + loadable .zip)
    #[arg(long)]
    reconstruir: bool,

    // ── Modo vigilancia: puerta de auditoría antes de la carga del servidor ──
    /// Watch this folder: audit each incoming pack and route it automatically
    #[arg(long, value_name = "INCOMING")]
    vigilar: Option<PathBuf>,

    /// Client cache watch: audit/classify without moving or deleting anything
    #[arg(long)]
    solo_informe: bool,

    // ── Localizador: averiguar dónde guarda su caché una aplicación ──
    /// Find the cache folder of this application (by name)
    #[arg(long, value_name = "APP")]
    localizar_cache: Option<String>,

    /// The app executable, to look for path hints in its binary
    #[arg(long, value_name = "RUTA")]
    exe: Option<PathBuf>,

    /// Watch for N seconds which folders the app writes while running
    #[arg(long, value_name = "SEGUNDOS")]
    observar: Option<u64>,

    /// Approved folder (the server's Mods folder). Default: ../approved
    #[arg(long, value_name = "DIR")]
    aprobados: Option<PathBuf>,

    /// Quarantine folder. Default: ../quarantine
    #[arg(long, value_name = "DIR")]
    cuarentena: Option<PathBuf>,

    /// Reports folder. Default: ../reports
    #[arg(long, value_name = "DIR")]
    reportes: Option<PathBuf>,

    /// Seconds between polls of the watched folder
    #[arg(long, default_value_t = 5)]
    intervalo: u64,

    // ── Módulo de claves (abrir ZIP protegidos que tengas derecho a abrir) ──
    /// Password to try (repeatable: --clave a --clave b)
    #[arg(long = "clave", value_name = "CLAVE")]
    claves: Vec<String>,

    /// Try a built-in list of common passwords
    #[arg(long)]
    comunes: bool,

    /// Password dictionary: a text file, one per line
    #[arg(long, value_name = "ARCHIVO")]
    diccionario: Option<PathBuf>,

    /// Brute force: alphabet (d=digits, l=lowercase, a=alphanumeric, A=full, or literal)
    #[arg(long, value_name = "ALFABETO")]
    fuerza_bruta: Option<String>,

    /// Maximum length for brute force
    #[arg(long, default_value_t = 4)]
    fuerza_long: usize,

    /// Cap on passwords tried per file (0 = no cap)
    #[arg(long, default_value_t = 2_000_000)]
    max_intentos: u64,

    /// Show detected resources and exit
    #[arg(long)]
    recursos: bool,

    /// Open the GUI; if files are given, start analyzing them
    #[arg(long)]
    gui: bool,

    /// Interface and message language: en | es (default: auto-detected)
    #[arg(long, value_name = "LANG")]
    idioma: Option<String>,

    /// Base de datos SQLite del índice (por defecto: <salida>/capas.db). Persistente si apuntas a una fija.
    #[arg(long, value_name = "RUTA")]
    indice: Option<PathBuf>,

    /// No escribir el índice SQLite
    #[arg(long)]
    sin_indice: bool,
}

fn opciones(a: &Args, sis: &Sistema) -> analisis::Opciones {
    let mut op = analisis::Opciones::para(sis);
    op.hilos = a.hilos.unwrap_or(sis.nucleos).max(1);
    op.profundidad = a.profundidad;
    op.max_archivo = a
        .max_archivo_mb
        .map(|m| m << 20)
        .unwrap_or_else(|| analisis::limite_por_bloque(sis, op.hilos));
    op.max_total = a.max_total_mb << 20;
    op.timeout = Duration::from_secs(a.timeout);
    op.max_instrucciones = a.max_instrucciones;
    op.tallar = !a.sin_tallado;
    op.clasificar = !a.sin_clasificar;
    op.auditar = a.auditar;
    op.agrupar = a.agrupar;
    op.reconstruir = a.reconstruir;
    op.indice = !a.sin_indice;
    op.indice_db = a.indice.clone();
    op.claves = claves::Claves {
        explicitas: a.claves.clone(),
        comunes: a.comunes,
        diccionario: a.diccionario.clone(),
        fuerza: a.fuerza_bruta.as_ref().map(|al| {
            claves::FuerzaBruta::nuevo(&claves::FuerzaBruta::alfabeto_por_nombre(al), a.fuerza_long)
        }),
        max_intentos: a.max_intentos,
    };
    op
}

fn main() -> Result<()> {
    let a = Args::parse();
    match a.idioma.as_deref() {
        Some(l) => idioma::set_es(l.eq_ignore_ascii_case("es")),
        None => idioma::autodetectar(),
    }
    let sis = Sistema::detectar();

    // Localizador de caché: descubre dónde escribe una app y sugiere vigilarla.
    if a.localizar_cache.is_some() || a.observar.is_some() {
        eprintln!("capas v{VERSION} — {} {AUTOR} · {}\n", idioma::tr("by","por"), idioma::tr("cache locator","localizador de caché"));
        localizar::localizar(
            a.localizar_cache.as_deref().unwrap_or(""),
            a.exe.as_deref(),
            a.observar.map(Duration::from_secs),
        );
        return Ok(());
    }

    // Modo vigilancia: puerta de auditoría antes de la carga del servidor.
    if let Some(incoming) = a.vigilar.clone() {
        let herr = Herramientas::detectar(a.sin_externas);
        let mut op = opciones(&a, &sis);
        op.auditar = true;
        let c = vigilar::Carpetas::desde(incoming, a.aprobados.clone(), a.cuarentena.clone(), a.reportes.clone());
        eprintln!("capas v{VERSION} — {} {AUTOR} · {}\n", idioma::tr("by","por"), idioma::tr("watch mode","modo vigilancia"));
        return vigilar::vigilar(&c, &op, &herr, &sis, Duration::from_secs(a.intervalo.max(1)), a.solo_informe, Arc::new(AtomicBool::new(false)));
    }

    if (a.archivos.is_empty() && !a.recursos) || a.gui {
        let auto = a.gui && !a.archivos.is_empty();
        return gui::lanzar(sis, a.archivos, a.salida, auto);
    }

    let herr = Herramientas::detectar(a.sin_externas);
    let op = opciones(&a, &sis);

    eprintln!("capas v{VERSION} — {} {AUTOR}\n", idioma::tr("by","por"));
    eprintln!("== {} ==", idioma::tr("Computer resources","Recursos del ordenador"));
    eprintln!("  {} : {} ({} {} )", idioma::tr("Logical cores","Núcleos lógicos"), sis.nucleos, idioma::tr("using","usando"), format!("{} {}", op.hilos, idioma::tr("threads","hilos")));
    eprintln!("  {} : {} / {}", idioma::tr("Memory       ","Memoria      "), humano(sis.memoria_libre), humano(sis.memoria_total));
    eprintln!("  {}: {}", idioma::tr("Per-block limit","Límite por bloque"), humano(op.max_archivo));
    eprintln!("  {}:", idioma::tr("External tools","Herramientas externas"));
    for (n, desc) in HERRAMIENTAS_CONOCIDAS {
        let marca = if herr.get(n).is_some() { "[x]" } else { "[ ]" };
        eprintln!("    {marca} {n:<18} {desc}");
    }
    if a.recursos {
        return Ok(());
    }

    eprintln!("\n== {} ==", idioma::tr("Analyzing","Analizando"));
    let r = analisis::ejecutar(&a.archivos, &a.salida, &op, herr, &sis, None, Arc::new(AtomicBool::new(false)))?;
    eprintln!(
        "\n== {} {:.1}s: {} {}, {} {} ==",
        idioma::tr("Done in","Terminado en"),
        r.duracion.as_secs_f64(),
        r.bloques,
        idioma::tr("blocks processed","bloques procesados"),
        humano(r.bytes),
        idioma::tr("extracted","extraídos")
    );
    if let Some(c) = &r.clasificacion {
        eprintln!("\n== {} ==", idioma::tr("Classification","Clasificación"));
        for cat in clasificar::Categoria::TODAS {
            let n = c.por_categoria.get(cat.nombre()).copied().unwrap_or(0);
            if n > 0 {
                eprintln!("  {:<22} {n}", cat.etiqueta());
            }
        }
        eprintln!("  {}: {}", idioma::tr("Files gathered in","Archivos reunidos en"), r.raiz.join("extraidos").display());
    }
    if let Some(au) = &r.auditoria {
        eprintln!("\n== {} ==", idioma::tr("Package audit","Auditoría de paquetes"));
        for p in &au.paquetes {
            eprintln!("  [{}] {}", p.veredicto.etiqueta(), p.nombre);
            for h in p.hallazgos.iter().filter(|h| h.nivel != auditar::Nivel::Info) {
                eprintln!("      - {}: {}", h.regla, h.detalle);
            }
        }
        eprintln!("  {}: {}", idioma::tr("Report","Informe"), r.raiz.join("auditoria.md").display());
    }
    eprintln!("{}: {}", idioma::tr("Report","Informe"), r.raiz.join("informe.md").display());
    Ok(())
}
