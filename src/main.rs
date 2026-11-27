//! capas — desmonta y decompila archivos capa a capa usando los recursos
//! del ordenador (todos los núcleos, la RAM disponible y las herramientas
//! de ingeniería inversa instaladas).
//!
//! Autor: @angelazo
//!
//! Sin argumentos abre la interfaz gráfica; con archivos funciona en consola.

// En Windows se compila como app de GUI (sin ventana de consola negra al abrir
// la interfaz). Para el modo CLI se reutiliza la consola del proceso padre.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod analisis;
mod api;
mod auditar;
mod comparar;
mod decompilar;
mod clasificar;
mod codigo;
mod claves;
mod detectar;
mod dotnet;
mod lua;
mod edicion;
mod ejecutables;
mod extraer;
#[cfg(feature = "gpu")]
mod gpu;
mod gui;
mod idioma;
mod indice;
mod licencia;
mod localizar;
mod mcp;
mod motor;
mod zipcrypto;
mod nativo;
mod pyc_tablas;
mod plugins;
mod politica;
mod recursos;
mod relaciones;
mod vigilar;
#[cfg(test)]
mod pruebas_nativo;

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

    /// Output folder (default: output_capas in English, salida_capas in Spanish)
    #[arg(short, long)]
    salida: Option<PathBuf>,

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

    /// [Pro] Unpack engine bundles (Unity UnityFS, Godot .pck) into their inner files
    #[arg(long)]
    desempaquetar: bool,

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

    /// Known-plaintext file to break a ZipCrypto archive WITHOUT its password
    #[arg(long, value_name = "ARCHIVO")]
    texto_plano: Option<PathBuf>,

    /// Auto-detect known headers (XML/SVG/HTML…) to break ZipCrypto without a password (slower)
    #[arg(long)]
    auto_texto_plano: bool,

    /// Use the GPU to accelerate ZipCrypto brute force (falls back to CPU if unavailable)
    #[arg(long)]
    gpu: bool,

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

    // ── Edición / monetización ──
    /// Edition: core (free) | pro | studio (also CAPAS_EDICION)
    #[arg(long, value_name = "ED")]
    edicion: Option<String>,

    /// [Pro] Evaluate policy (allow/warn/review/block) and write politica.md
    #[arg(long)]
    politica: bool,

    /// [Pro] Compare this run index against an earlier baseline (.db)
    #[arg(long, value_name = "BASE_DB")]
    comparar: Option<PathBuf>,

    /// [Studio] CI/CD mode: machine output and exit code from the policy
    #[arg(long)]
    ci: bool,

    /// [Studio] Serve the index as a local API on this port and exit
    #[arg(long, value_name = "PUERTO")]
    api: Option<u16>,

    /// Run as an MCP server over stdio (connect an AI client: Claude Desktop, Ollama, …)
    #[arg(long)]
    mcp: bool,

    /// License file (also CAPAS_LICENCIA, or capas.lic next to the binary)
    #[arg(long, value_name = "FILE")]
    licencia: Option<PathBuf>,

    /// Activate with a pasted key (CAPAS-...); also CAPAS_CLAVE
    #[arg(long, value_name = "KEY")]
    licencia_clave: Option<String>,

    /// Print the native listing of a code file (.class, .dex, .pyc, .wasm, ELF/PE/Mach-O) and exit
    #[arg(long, value_name = "FILE")]
    listar_codigo: Option<PathBuf>,

    /// Decompile a .class or .pyc to readable pseudo-source with the native engine and exit
    #[arg(long, value_name = "FILE")]
    decompilar: Option<PathBuf>,

    /// [Vendor] Sign a BATCH of compact keys (--clave-privada, --edicion, --cantidad, --dias)
    #[arg(long)]
    firmar_lote: bool,

    /// [Vendor] How many keys to sign with --firmar-lote
    #[arg(long, default_value_t = 1)]
    cantidad: u64,

    /// [Vendor] Generate an Ed25519 key pair in this folder and exit
    #[arg(long, value_name = "DIR")]
    generar_clave: Option<PathBuf>,

    /// [Vendor] Sign a license (with --clave-privada, --edicion, --titular, --dias) and exit
    #[arg(long)]
    firmar_licencia: bool,

    /// [Vendor] Private key file (.key) used to sign
    #[arg(long, value_name = "FILE")]
    clave_privada: Option<PathBuf>,

    /// [Vendor] License holder (name or email)
    #[arg(long, value_name = "HOLDER")]
    titular: Option<String>,

    /// [Vendor] License validity in days (0 = no expiry)
    #[arg(long, default_value_t = 0)]
    dias: u64,
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
    op.desempaquetar = a.desempaquetar;
    op.indice = !a.sin_indice;
    op.indice_db = a.indice.clone();
    op.claves = claves::Claves {
        explicitas: a.claves.clone(),
        comunes: a.comunes,
        diccionario: a.diccionario.clone(),
        fuerza: a.fuerza_bruta.as_ref().and_then(|al| {
            claves::FuerzaBruta::nuevo(&claves::FuerzaBruta::alfabeto_por_nombre(al), a.fuerza_long)
        }),
        max_intentos: a.max_intentos,
        texto_plano: a.texto_plano.clone(),
        auto_texto_plano: a.auto_texto_plano,
        usar_gpu: a.gpu,
    };
    op
}

/// En Windows (subsistema GUI) reutiliza la consola del proceso padre si se
/// lanzó desde una, para que el modo CLI siga mostrando su salida.
#[cfg(windows)]
fn adjuntar_consola() {
    unsafe extern "system" {
        fn AttachConsole(dw_process_id: u32) -> i32;
    }
    const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}
#[cfg(not(windows))]
fn adjuntar_consola() {}

fn main() -> Result<()> {
    adjuntar_consola();
    let a = Args::parse();
    match a.idioma.as_deref() {
        Some(l) => idioma::set_es(l.eq_ignore_ascii_case("es")),
        None => idioma::autodetectar(),
    }
    // La fuerza bruta NO puede activarse sin un abecedario: si se pide con un
    // alfabeto vacío (o longitud 0), se avisa y no se ejecuta ningún intento.
    if let Some(al) = &a.fuerza_bruta {
        if claves::FuerzaBruta::nuevo(&claves::FuerzaBruta::alfabeto_por_nombre(al), a.fuerza_long).is_none() {
            eprintln!("{}", idioma::tr(
                "--fuerza-bruta needs a non-empty alphabet and --fuerza-long >= 1 (d=digits, l=lowercase, a=alphanumeric, A=full, or your own characters). No attempts were made.",
                "--fuerza-bruta necesita un abecedario no vacío y --fuerza-long >= 1 (d=dígitos, l=minúsculas, a=alfanumérico, A=completo, o tus propios caracteres). No se hizo ningún intento.",
            ));
            std::process::exit(2);
        }
    }
    // Listado nativo de código (sin herramientas externas) y salir.
    if let Some(p) = &a.listar_codigo {
        let d = std::fs::read(p)?;
        let r = match detectar::detectar(&d) {
            detectar::Tipo::ClaseJava => codigo::clase_java(&d),
            detectar::Tipo::Dex => codigo::dex(&d),
            detectar::Tipo::Pyc => codigo::pyc(&d),
            detectar::Tipo::Wasm => codigo::wasm_a_wat(&d),
            detectar::Tipo::Shader => codigo::spirv_a_fuente(&d),
            detectar::Tipo::DotNet => dotnet::listar(&d),
            detectar::Tipo::Lua => lua::listar(&d),
            detectar::Tipo::Elf | detectar::Tipo::Pe | detectar::Tipo::MachO => {
                ejecutables::analizar(&d, 200_000).map(|i| format!("{}\n{}", i.cabeceras, i.desensamblado.unwrap_or_default()))
            }
            otro => Err(anyhow::anyhow!("{}: {}", idioma::tr("not a code file", "no es un archivo de código"), otro.nombre())),
        };
        match r {
            Ok(t) => println!("{t}"),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        }
        return Ok(());
    }
    if let Some(p) = &a.decompilar {
        let d = std::fs::read(p)?;
        let r = match detectar::detectar(&d) {
            detectar::Tipo::ClaseJava => decompilar::java(&d),
            detectar::Tipo::Pyc => decompilar::python(&d),
            detectar::Tipo::Shader => codigo::spirv_a_fuente(&d),
            detectar::Tipo::DotNet => dotnet::listar(&d),
            detectar::Tipo::Lua => lua::listar(&d),
            otro => Err(anyhow::anyhow!("{}: {}", idioma::tr("cannot decompile", "no se puede decompilar"), otro.nombre())),
        };
        match r {
            Ok(t) => println!("{t}"),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        }
        return Ok(());
    }
    // El nombre por defecto de la carpeta de salida sigue el idioma activo.
    let salida = a
        .salida
        .clone()
        .unwrap_or_else(|| PathBuf::from(idioma::tr("output_capas", "salida_capas")));
    // [Vendedor] Generar par de claves.
    if let Some(dir) = &a.generar_clave {
        match licencia::generar_clave() {
            Ok((priv_hex, pub_hex)) => {
                let _ = std::fs::create_dir_all(dir);
                let pk = dir.join("capas_public.txt");
                let sk = dir.join("capas_private.key");
                let _ = std::fs::write(&sk, &priv_hex);
                let _ = std::fs::write(&pk, &pub_hex);
                eprintln!("{}", idioma::tfmt(idioma::tr("Private key (SECRET, keep it safe): {}", "Clave privada (SECRETA, guárdala): {}"), &[sk.display().to_string()]));
                eprintln!("{}", idioma::tfmt(idioma::tr("Public key  (embed it in PUBLICA_HEX): {}", "Clave pública  (incrústala en PUBLICA_HEX): {}"), &[pk.display().to_string()]));
                eprintln!("\nPUBLICA_HEX = \"{pub_hex}\"");
            }
            Err(e) => eprintln!("generar-clave: {e}"),
        }
        return Ok(());
    }
    // [Vendedor] Firmar una licencia.
    if a.firmar_licencia {
        let priv_file = a.clave_privada.as_ref().ok_or_else(|| anyhow::anyhow!("falta --clave-privada"))?;
        let priv_hex = std::fs::read_to_string(priv_file)?;
        let titular = a.titular.clone().ok_or_else(|| anyhow::anyhow!("falta --titular"))?;
        let ed = a.edicion.as_deref().unwrap_or("pro");
        match licencia::firmar(priv_hex.trim(), ed, &titular, a.dias) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("firmar-licencia: {e}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }
    // [Vendedor] Firmar un LOTE de claves compactas (una por línea a stdout).
    if a.firmar_lote {
        let priv_file = a.clave_privada.as_ref().ok_or_else(|| anyhow::anyhow!("falta --clave-privada"))?;
        let priv_hex = std::fs::read_to_string(priv_file)?;
        let ed = a.edicion.as_deref().unwrap_or("pro");
        match licencia::firmar_lote(priv_hex.trim(), ed, a.cantidad, a.dias) {
            Ok(claves) => {
                for c in &claves {
                    println!("{c}");
                }
                eprintln!("{}", idioma::tfmt(idioma::tr("{} key(s) signed (edition {}).", "{} clave(s) firmadas (edición {})."), &[claves.len().to_string(), ed.to_string()]));
            }
            Err(e) => {
                eprintln!("firmar-lote: {e}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    edicion::resolver(a.edicion.as_deref());
    licencia::aplicar(a.licencia.clone());
    licencia::aplicar_clave(a.licencia_clave.clone());
    let sis = Sistema::detectar();

    // [Studio] Puente MCP por stdio: expone el análisis local como tools para una IA.
    if a.mcp {
        if !edicion::permite(edicion::MCP) {
            eprintln!("{}", edicion::bloqueado("--mcp", edicion::MCP));
            std::process::exit(7);
        }
        return mcp::servir(sis, Herramientas::detectar(a.sin_externas));
    }

    // [Studio] API local de solo lectura sobre el índice.
    if let Some(puerto) = a.api {
        if !edicion::permite(edicion::API) {
            eprintln!("{}", edicion::bloqueado("--api", edicion::API));
            std::process::exit(7);
        }
        let db = a.indice.clone().unwrap_or_else(|| salida.join("capas.db"));
        return api::servir(db, puerto).map_err(Into::into);
    }

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
        return gui::lanzar(sis, a.archivos, salida, auto);
    }

    let herr = Herramientas::detectar(a.sin_externas);
    let mut op = opciones(&a, &sis);
    // La política y el modo CI necesitan la auditoría.
    if (a.politica && edicion::permite(edicion::POLITICA)) || (a.ci && edicion::permite(edicion::CI)) {
        op.auditar = true;
    }
    // El desempaquetado de bundles es de pago: si no hay edición, se avisa y se omite.
    if op.desempaquetar && !edicion::permite(edicion::DESEMPAQUETAR) {
        eprintln!("{}", edicion::bloqueado("--desempaquetar", edicion::DESEMPAQUETAR));
        op.desempaquetar = false;
    }

    eprintln!("capas v{VERSION} — {} {AUTOR}  ·  {} {}\n", idioma::tr("by","por"), idioma::tr("edition","edición"), edicion::actual().nombre());
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
    let r = analisis::ejecutar(&a.archivos, &salida, &op, herr, &sis, None, Arc::new(AtomicBool::new(false)))?;
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

    // [Pro] Comparación entre versiones.
    if let Some(base) = &a.comparar {
        if edicion::permite(edicion::COMPARAR) {
            let db = a.indice.clone().unwrap_or_else(|| r.raiz.join("capas.db"));
            match comparar::comparar(&db, base, &r.raiz) {
                Ok(d) => eprintln!(
                    "\n== {} ==\n  {} +{} · -{} · ✳{}  →  {}",
                    idioma::tr("Version comparison","Comparación entre versiones"),
                    idioma::tr("vs base:","vs base:"),
                    d.anadidos.len(), d.quitados.len(), d.cambiados.len(),
                    r.raiz.join("comparacion.md").display(),
                ),
                Err(e) => eprintln!("  comparar: {e}"),
            }
        } else {
            eprintln!("{}", edicion::bloqueado("--comparar", edicion::COMPARAR));
        }
    }

    // [Pro] Política / [Studio] CI.
    let quiere_pol = a.politica || a.ci;
    if quiere_pol {
        let min = if a.ci { edicion::CI } else { edicion::POLITICA };
        if edicion::permite(min) {
            let pol = politica::evaluar(r.auditoria.as_ref(), &r.arbol);
            let _ = politica::escribir(&r.raiz, &pol);
            eprintln!(
                "\n== {} ==\n  {}: {}  →  {}",
                idioma::tr("Operational policy","Política operativa"),
                idioma::tr("overall action","acción global"),
                pol.global.etiqueta(),
                r.raiz.join("politica.md").display(),
            );
            if a.ci {
                // Línea máquina a stdout + código de salida.
                println!("capas action={} code={} packages={}", pol.global.etiqueta(), pol.global.codigo(), pol.paquetes.len());
                std::process::exit(pol.global.codigo());
            }
        } else {
            eprintln!("{}", edicion::bloqueado(if a.ci { "--ci" } else { "--politica" }, min));
        }
    }
    Ok(())
}
