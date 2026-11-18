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
mod motor;
mod recursos;
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
    about = "Desmonta y decompila archivos por capas usando los recursos del ordenador — por @angelazo",
    long_about = "Mete archivos (o carpetas) y el programa los pela capa a capa:\n\
                  comprimidos -> contenedores -> ejecutables/bytecode -> desensamblado/código.\n\
                  Usa todos los núcleos, ajusta la memoria a la RAM libre y aprovecha\n\
                  objdump, readelf, javap, jadx, CFR, pycdc, wabt, radare2, RetDec, Ghidra y 7z\n\
                  si están instalados.\n\n\
                  Clasifica los archivos finales por categoría en extraidos/ y puede abrir\n\
                  ZIP protegidos con el módulo de claves (--clave, --comunes, --diccionario).\n\
                  Con --auditar revisa paquetes (asset packs/mods) y da un veredicto\n\
                  APROBADO/CUARENTENA/RECHAZADO sin ejecutar nada.\n\n\
                  Sin argumentos abre la interfaz gráfica.\n\n\
                  Firmado por @angelazo."
)]
struct Args {
    /// Archivos o carpetas a analizar (si no hay ninguno se abre la interfaz)
    archivos: Vec<PathBuf>,

    /// Carpeta de salida
    #[arg(short, long, default_value = "salida_capas")]
    salida: PathBuf,

    /// Hilos de trabajo (por defecto: todos los núcleos)
    #[arg(short = 'j', long)]
    hilos: Option<usize>,

    /// Profundidad máxima de capas
    #[arg(short, long, default_value_t = 12)]
    profundidad: usize,

    /// Tamaño máximo de un bloque extraído en MiB (por defecto: según RAM libre)
    #[arg(long)]
    max_archivo_mb: Option<u64>,

    /// Total máximo a extraer en MiB (protección contra bombas zip)
    #[arg(long, default_value_t = 16384)]
    max_total_mb: u64,

    /// Tiempo máximo por herramienta externa, en segundos
    #[arg(short, long, default_value_t = 300)]
    timeout: u64,

    /// Máximo de instrucciones del desensamblador interno por binario
    #[arg(long, default_value_t = 500_000)]
    max_instrucciones: usize,

    /// No buscar archivos incrustados por firma (carving)
    #[arg(long)]
    sin_tallado: bool,

    /// No usar herramientas externas, solo el análisis interno
    #[arg(long)]
    sin_externas: bool,

    /// No clasificar ni reunir los archivos en extraidos/<categoria>/
    #[arg(long)]
    sin_clasificar: bool,

    /// Auditar paquetes (asset packs/mods): veredicto APROBADO/CUARENTENA/RECHAZADO
    #[arg(long)]
    auditar: bool,

    // ── Modo vigilancia: puerta de auditoría antes de la carga del servidor ──
    /// Vigilar esta carpeta: audita cada pack que llega y lo encamina solo
    #[arg(long, value_name = "INCOMING")]
    vigilar: Option<PathBuf>,

    /// Carpeta de aprobados (la de Mods del servidor). Por defecto: ../approved
    #[arg(long, value_name = "DIR")]
    aprobados: Option<PathBuf>,

    /// Carpeta de cuarentena. Por defecto: ../quarantine
    #[arg(long, value_name = "DIR")]
    cuarentena: Option<PathBuf>,

    /// Carpeta de informes. Por defecto: ../reports
    #[arg(long, value_name = "DIR")]
    reportes: Option<PathBuf>,

    /// Segundos entre sondeos de la carpeta vigilada
    #[arg(long, default_value_t = 5)]
    intervalo: u64,

    // ── Módulo de claves (abrir ZIP protegidos que tengas derecho a abrir) ──
    /// Contraseña a probar (se puede repetir: --clave a --clave b)
    #[arg(long = "clave", value_name = "CLAVE")]
    claves: Vec<String>,

    /// Probar una lista incorporada de contraseñas habituales
    #[arg(long)]
    comunes: bool,

    /// Diccionario de contraseñas: un archivo de texto, una por línea
    #[arg(long, value_name = "ARCHIVO")]
    diccionario: Option<PathBuf>,

    /// Fuerza bruta: alfabeto (d=dígitos, l=minúsculas, a=alfanumérico, A=completo, o literal)
    #[arg(long, value_name = "ALFABETO")]
    fuerza_bruta: Option<String>,

    /// Longitud máxima para la fuerza bruta
    #[arg(long, default_value_t = 4)]
    fuerza_long: usize,

    /// Tope de contraseñas a probar por archivo (0 = sin tope)
    #[arg(long, default_value_t = 2_000_000)]
    max_intentos: u64,

    /// Mostrar los recursos detectados y salir
    #[arg(long)]
    recursos: bool,

    /// Abrir la interfaz gráfica; si se indican archivos, empieza a analizarlos
    #[arg(long)]
    gui: bool,
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
    let sis = Sistema::detectar();

    // Modo vigilancia: puerta de auditoría antes de la carga del servidor.
    if let Some(incoming) = a.vigilar.clone() {
        let herr = Herramientas::detectar(a.sin_externas);
        let mut op = opciones(&a, &sis);
        op.auditar = true;
        let c = vigilar::Carpetas::desde(incoming, a.aprobados.clone(), a.cuarentena.clone(), a.reportes.clone());
        eprintln!("capas v{VERSION} — por {AUTOR} · modo vigilancia\n");
        return vigilar::vigilar(&c, &op, &herr, &sis, Duration::from_secs(a.intervalo.max(1)), Arc::new(AtomicBool::new(false)));
    }

    if (a.archivos.is_empty() && !a.recursos) || a.gui {
        let auto = a.gui && !a.archivos.is_empty();
        return gui::lanzar(sis, a.archivos, a.salida, auto);
    }

    let herr = Herramientas::detectar(a.sin_externas);
    let op = opciones(&a, &sis);

    eprintln!("capas v{VERSION} — por {AUTOR}\n");
    eprintln!("== Recursos del ordenador ==");
    eprintln!("  Núcleos lógicos : {} (usando {} hilos)", sis.nucleos, op.hilos);
    eprintln!("  Memoria         : {} libre de {}", humano(sis.memoria_libre), humano(sis.memoria_total));
    eprintln!("  Límite por bloque: {}", humano(op.max_archivo));
    eprintln!("  Herramientas externas:");
    for (n, desc) in HERRAMIENTAS_CONOCIDAS {
        let marca = if herr.get(n).is_some() { "[x]" } else { "[ ]" };
        eprintln!("    {marca} {n:<18} {desc}");
    }
    if a.recursos {
        return Ok(());
    }

    eprintln!("\n== Analizando ==");
    let r = analisis::ejecutar(&a.archivos, &a.salida, &op, herr, &sis, None, Arc::new(AtomicBool::new(false)))?;
    eprintln!(
        "\n== Terminado en {:.1}s: {} bloques procesados, {} extraídos ==",
        r.duracion.as_secs_f64(),
        r.bloques,
        humano(r.bytes)
    );
    if let Some(c) = &r.clasificacion {
        eprintln!("\n== Clasificación ==");
        for cat in clasificar::Categoria::TODAS {
            let n = c.por_categoria.get(cat.nombre()).copied().unwrap_or(0);
            if n > 0 {
                eprintln!("  {:<22} {n}", cat.etiqueta());
            }
        }
        eprintln!("  Archivos reunidos en: {}", r.raiz.join("extraidos").display());
    }
    if let Some(au) = &r.auditoria {
        eprintln!("\n== Auditoría de paquetes ==");
        for p in &au.paquetes {
            eprintln!("  [{}] {}", p.veredicto.etiqueta(), p.nombre);
            for h in p.hallazgos.iter().filter(|h| h.nivel != auditar::Nivel::Info) {
                eprintln!("      - {}: {}", h.regla, h.detalle);
            }
        }
        eprintln!("  Informe: {}", r.raiz.join("auditoria.md").display());
    }
    eprintln!("Informe: {}", r.raiz.join("informe.md").display());
    Ok(())
}
