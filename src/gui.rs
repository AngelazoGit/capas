//! Interfaz gráfica de capas — estética de tr("command center", "centro de mando") de anime de los 90:
//! morados profundos, verde neón y naranja de alerta. Diseño original de @angelazo.

use std::collections::{HashMap, VecDeque};
use std::f32::consts::TAU;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Layout, Margin, Pos2,
    Rect, RichText, Sense, Shape, Stroke, StrokeKind, Ui, Vec2,
};

use crate::analisis::{self, Opciones, Resumen};
use crate::auditar::{Nivel, Veredicto};
use crate::clasificar::{Categoria, Confianza};
use crate::idioma::{tfmt, tr};
use crate::claves::{Claves, FuerzaBruta};
use crate::detectar::Tipo;
use crate::motor::{Evento, Nodo};
use crate::recursos::{humano, Herramientas, Sistema, HERRAMIENTAS_CONOCIDAS};
use crate::{AUTOR, VERSION};

// ── Temas (máscaras) ─────────────────────────────────────────────────────
// Máscaras: "Limpio" (clara, business — por defecto), "Sereno" (oscuro suave),
// "Neutro" (grises) y "Mando" (intenso, el original morado/verde/naranja).
#[derive(Clone, Copy)]
struct Paleta {
    fondo: Color32,
    morado_oscuro: Color32,
    morado: Color32,
    morado_medio: Color32,
    morado_claro: Color32,
    verde: Color32,
    verde_oscuro: Color32,
    acento: Color32,
    naranja: Color32,
    naranja_oscuro: Color32,
    rojo: Color32,
    texto: Color32,
    hondo: Color32,
    rejilla_bg: Color32,
}

const SERENO: Paleta = Paleta {
    fondo: Color32::from_rgb(0x19, 0x14, 0x29),
    morado_oscuro: Color32::from_rgb(0x23, 0x1c, 0x3a),
    morado: Color32::from_rgb(0x30, 0x26, 0x50),
    morado_medio: Color32::from_rgb(0x5b, 0x4c, 0x85),
    morado_claro: Color32::from_rgb(0xb6, 0xa4, 0xe2),
    verde: Color32::from_rgb(0x86, 0xc9, 0x6e),
    acento: Color32::from_rgb(0x86, 0xc9, 0x6e),
    verde_oscuro: Color32::from_rgb(0x3c, 0x5b, 0x34),
    naranja: Color32::from_rgb(0xe6, 0xa1, 0x5a),
    naranja_oscuro: Color32::from_rgb(0x7e, 0x56, 0x2e),
    rojo: Color32::from_rgb(0xdf, 0x6e, 0x7c),
    texto: Color32::from_rgb(0xec, 0xe8, 0xf6),
    hondo: Color32::from_rgb(0x13, 0x0f, 0x20),
    rejilla_bg: Color32::from_rgb(0x1e, 0x18, 0x30),
};

const MANDO: Paleta = Paleta {
    fondo: Color32::from_rgb(0x0f, 0x07, 0x1c),
    morado_oscuro: Color32::from_rgb(0x1a, 0x0b, 0x2e),
    morado: Color32::from_rgb(0x2e, 0x14, 0x52),
    morado_medio: Color32::from_rgb(0x55, 0x2a, 0x93),
    morado_claro: Color32::from_rgb(0x9b, 0x6b, 0xe3),
    verde: Color32::from_rgb(0x8c, 0xff, 0x3c),
    acento: Color32::from_rgb(0x8c, 0xff, 0x3c),
    verde_oscuro: Color32::from_rgb(0x2b, 0x6e, 0x1e),
    naranja: Color32::from_rgb(0xff, 0x8a, 0x1c),
    naranja_oscuro: Color32::from_rgb(0x8a, 0x3a, 0x05),
    rojo: Color32::from_rgb(0xff, 0x2e, 0x4a),
    texto: Color32::from_rgb(0xe9, 0xdd, 0xff),
    hondo: Color32::from_rgb(0x08, 0x04, 0x10),
    rejilla_bg: Color32::from_rgb(0x12, 0x08, 0x22),
};

const NEUTRO: Paleta = Paleta {
    fondo: Color32::from_rgb(0x1e, 0x1e, 0x22),
    morado_oscuro: Color32::from_rgb(0x28, 0x28, 0x2e),
    morado: Color32::from_rgb(0x33, 0x33, 0x3b),
    morado_medio: Color32::from_rgb(0x5a, 0x5a, 0x66),
    morado_claro: Color32::from_rgb(0xb8, 0xb8, 0xc4),
    verde: Color32::from_rgb(0x8f, 0xb9, 0x8a),
    acento: Color32::from_rgb(0x8f, 0xb9, 0x8a),
    verde_oscuro: Color32::from_rgb(0x44, 0x53, 0x3f),
    naranja: Color32::from_rgb(0xcf, 0xa8, 0x78),
    naranja_oscuro: Color32::from_rgb(0x6b, 0x5a, 0x42),
    rojo: Color32::from_rgb(0xc9, 0x8a, 0x8a),
    texto: Color32::from_rgb(0xe8, 0xe8, 0xec),
    hondo: Color32::from_rgb(0x16, 0x16, 0x19),
    rejilla_bg: Color32::from_rgb(0x24, 0x24, 0x28),
};

// "Limpio" (Clean): máscara clara, estilo business — blancos y negros con
// acentos sobrios, para quien se satura con las interfaces oscuras.
const LIMPIO: Paleta = Paleta {
    fondo: Color32::from_rgb(0xf5, 0xf5, 0xf7),
    morado_oscuro: Color32::from_rgb(0xff, 0xff, 0xff),
    morado: Color32::from_rgb(0xe7, 0xe7, 0xea),
    morado_medio: Color32::from_rgb(0xbf, 0xbf, 0xc8),
    morado_claro: Color32::from_rgb(0x44, 0x47, 0x4f),
    verde: Color32::from_rgb(0x2f, 0x8f, 0x52),
    acento: Color32::from_rgb(0x2f, 0x8f, 0x52),
    verde_oscuro: Color32::from_rgb(0xd6, 0xea, 0xd9),
    naranja: Color32::from_rgb(0xb0, 0x71, 0x16),
    naranja_oscuro: Color32::from_rgb(0xf0, 0xe1, 0xc6),
    rojo: Color32::from_rgb(0xc2, 0x3b, 0x2e),
    texto: Color32::from_rgb(0x1a, 0x1b, 0x1f),
    hondo: Color32::from_rgb(0xff, 0xff, 0xff),
    rejilla_bg: Color32::from_rgb(0xee, 0xee, 0xf1),
};

// Serio: oscuro de producto, acento índigo; verde = éxito, ámbar = aviso.
const SERIO: Paleta = Paleta {
    fondo: Color32::from_rgb(0x0f, 0x11, 0x17),
    morado_oscuro: Color32::from_rgb(0x19, 0x1c, 0x26),
    morado: Color32::from_rgb(0x26, 0x2a, 0x37),
    morado_medio: Color32::from_rgb(0x35, 0x3b, 0x4d),
    morado_claro: Color32::from_rgb(0x9a, 0xa3, 0xb7),
    verde: Color32::from_rgb(0x35, 0xd4, 0x9a),
    acento: Color32::from_rgb(0x6d, 0x5c, 0xf5),
    verde_oscuro: Color32::from_rgb(0x16, 0x35, 0x2a),
    naranja: Color32::from_rgb(0xf0, 0xb8, 0x4e),
    naranja_oscuro: Color32::from_rgb(0x3a, 0x2f, 0x17),
    rojo: Color32::from_rgb(0xef, 0x5f, 0x6b),
    texto: Color32::from_rgb(0xe9, 0xeb, 0xf2),
    hondo: Color32::from_rgb(0x0b, 0x0d, 0x12),
    rejilla_bg: Color32::from_rgb(0x15, 0x17, 0x1f),
};

// 0 = Sereno, 1 = Mando, 2 = Neutro, 3 = Limpio, 4 = Serio (por defecto).
static TEMA: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(4);

fn pal() -> Paleta {
    match TEMA.load(Ordering::Relaxed) {
        0 => SERENO,
        1 => MANDO,
        2 => NEUTRO,
        3 => LIMPIO,
        _ => SERIO,
    }
}

/// Índice de máscara a partir de su nombre (CAPAS_TEMA): serio/limpio/sereno/neutro/mando.
fn tema_por_nombre(s: &str) -> Option<u8> {
    match s.trim().to_lowercase().as_str() {
        "serio" | "serious" | "pro" | "oscuro" | "dark" => Some(4),
        "limpio" | "clean" | "claro" | "light" => Some(3),
        "sereno" | "serene" => Some(0),
        "neutro" | "neutral" | "gris" | "gray" | "grey" => Some(2),
        "mando" | "command" | "intenso" | "intense" => Some(1),
        _ => None,
    }
}
fn fondo() -> Color32 { pal().fondo }
fn morado_oscuro() -> Color32 { pal().morado_oscuro }
fn morado() -> Color32 { pal().morado }
fn morado_medio() -> Color32 { pal().morado_medio }
fn morado_claro() -> Color32 { pal().morado_claro }
fn verde() -> Color32 { pal().verde }
fn acento() -> Color32 { pal().acento }
fn verde_oscuro() -> Color32 { pal().verde_oscuro }
fn naranja() -> Color32 { pal().naranja }
fn naranja_oscuro() -> Color32 { pal().naranja_oscuro }
fn rojo() -> Color32 { pal().rojo }
fn texto() -> Color32 { pal().texto }
fn hondo() -> Color32 { pal().hondo }
fn rejilla_bg() -> Color32 { pal().rejilla_bg }

fn titulo(t: f32) -> FontId {
    FontId::new(t, FontFamily::Name("titulo".into()))
}
fn mono(t: f32) -> FontId {
    FontId::new(t, FontFamily::Monospace)
}

fn color_tipo(t: Tipo) -> Color32 {
    match t {
        Tipo::Elf | Tipo::Pe | Tipo::MachO => naranja(),
        Tipo::ClaseJava | Tipo::Dex | Tipo::Pyc | Tipo::Wasm => morado_claro(),
        Tipo::RecursoJuego => morado_claro(),
        Tipo::Texto | Tipo::Imagen => texto(),
        Tipo::Desconocido => rojo(),
        _ => verde(),
    }
}

fn color_veredicto(v: Veredicto) -> Color32 {
    match v {
        Veredicto::Aprobado => verde(),
        Veredicto::Cuarentena => naranja(),
        Veredicto::Rechazado => rojo(),
    }
}

fn color_confianza(c: Confianza) -> Color32 {
    match c {
        Confianza::Confirmado => verde(),
        Confianza::Compatible => morado_claro(),
        Confianza::Probable => naranja(),
        Confianza::Desconocido => rojo(),
    }
}

fn color_categoria(c: Categoria) -> Color32 {
    match c {
        Categoria::Ejecutable | Categoria::Bytecode => naranja(),
        Categoria::Imagen | Categoria::Audio | Categoria::Video | Categoria::RecursoJuego => morado_claro(),
        Categoria::Desconocido => rojo(),
        _ => verde(),
    }
}

fn codigo_tipo(tp: Tipo) -> &'static str {
    match tp {
        Tipo::Zip => "ZIP",
        Tipo::Gzip => "GZIP",
        Tipo::Bzip2 => "BZIP2",
        Tipo::Xz => "XZ",
        Tipo::Lzma => "LZMA",
        Tipo::Zlib => "ZLIB",
        Tipo::Zstd => "ZSTD",
        Tipo::Lz4 => "LZ4",
        Tipo::Iso => "ISO",
        Tipo::Chd => "CHD",
        Tipo::Disco => "DISK",
        Tipo::Tar => "TAR",
        Tipo::SieteZ => "7Z",
        Tipo::Rar => "RAR",
        Tipo::Cab => "CAB",
        Tipo::ArUnix => "AR",
        Tipo::Elf => "ELF",
        Tipo::Pe => "PE",
        Tipo::MachO | Tipo::MachOFat => "MACH-O",
        Tipo::ClaseJava => "JAVA",
        Tipo::Dex => "DEX",
        Tipo::Pyc => "PYC",
        Tipo::Wasm => "WASM",
        Tipo::Pdf => "PDF",
        Tipo::Imagen => tr("IMAGE", "IMAGEN"),
        Tipo::Audio => "AUDIO",
        Tipo::Video => tr("VIDEO", "VÍDEO"),
        Tipo::Fuente => tr("FONT", "FUENTE"),
        Tipo::BaseDatos => tr("DATABASE", "BASE DATOS"),
        Tipo::RecursoJuego => tr("GAME/3D", "JUEGO/3D"),
        Tipo::Texto => tr("TEXT", "TEXTO"),
        Tipo::Desconocido => tr("UNKNOWN", "DESCONOCIDO"),
    }
}

// ── Estado ──────────────────────────────────────────────────────────────
enum Fase {
    Espera,
    Analizando { rx: Receiver<Evento>, hilo: JoinHandle<anyhow::Result<Resumen>>, cancelar: Arc<AtomicBool> },
    Terminado,
}

struct Linea {
    t: f64,
    texto: String,
    color: Color32,
}

struct Visor {
    titulo: String,
    lineas: Vec<String>,
    truncado: bool,
}

pub struct App {
    sis: Sistema,
    herr: Herramientas,
    op: Opciones,
    externas: bool,
    archivos: Vec<PathBuf>,
    salida: PathBuf,
    fase: Fase,
    t_inicio: f64,
    t_fin: f64,
    registro: VecDeque<Linea>,
    bloques: usize,
    bytes_vistos: u64,
    por_capa: Vec<usize>,
    por_tipo: HashMap<Tipo, usize>,
    ultimo: Option<(Tipo, String, f64)>,
    senal: VecDeque<f32>,
    ult_muestra: (f64, usize),
    arbol: Vec<Nodo>,
    raiz: Option<PathBuf>,
    seleccion: Option<Vec<usize>>,
    visor: Option<Visor>,
    auto_iniciar: bool,
    tema: u8,
    // Rediseño "Serio": vista activa de la barra lateral y filtro de bloques.
    vista: Vista,
    solo_pendientes: bool,
    // Comparar (Pro): dos carpetas de salida y su diff.
    cmp_a: Option<PathBuf>,
    cmp_b: Option<PathBuf>,
    cmp_resultado: Option<(Vec<String>, Vec<String>, usize)>,
    // Barra de búsqueda del análisis.
    buscar: String,
    // Comprobación de actualización (hilo de fondo → estado compartido).
    actualizacion: std::sync::Arc<std::sync::Mutex<Option<Act>>>,
    // Módulo de claves (interfaz).
    clave_entrada: String,
    clave_lic: String,
    lic_estado: Option<String>,
    usar_comunes: bool,
    diccionario: Option<PathBuf>,
    fuerza_bruta: bool,
    fuerza_alfabeto: usize, // índice en ALFABETOS
    fuerza_long: usize,
    claves_halladas: Vec<(String, String)>, // (archivo, contraseña)
    // Resultado de la clasificación.
    clasif: Vec<(Categoria, usize)>,
    // Resultado de la auditoría: (nombre, veredicto, hallazgos que no son info).
    audit: Vec<(String, Veredicto, Vec<(Nivel, String)>)>,
}

/// Vistas de la barra lateral del rediseño "Serio".
#[derive(Clone, Copy, PartialEq, Eq)]
enum Vista {
    Inicio,
    Analisis,
    Explorador,
    Comparar,
    Herramientas,
    Ajustes,
}

impl Vista {
    fn etiqueta(self) -> &'static str {
        match self {
            Vista::Inicio => tr("Home", "Inicio"),
            Vista::Analisis => tr("Analysis", "Análisis"),
            Vista::Explorador => tr("Explorer", "Explorador"),
            Vista::Comparar => tr("Compare", "Comparar"),
            Vista::Herramientas => tr("Tools", "Herramientas"),
            Vista::Ajustes => tr("Settings", "Ajustes"),
        }
    }
    fn icono(self) -> &'static str {
        match self {
            Vista::Inicio => "home",
            Vista::Analisis => "lupa",
            Vista::Explorador => "carpeta",
            Vista::Comparar => "comparar",
            Vista::Herramientas => "llave",
            Vista::Ajustes => "engranaje",
        }
    }
}

const ALFABETOS: &[(&str, &str)] = &[
    ("Digits 0-9", "d"),
    ("Lowercase a-z", "l"),
    ("Alphanumeric", "a"),
    ("Full + Upper", "A"),
];

pub fn lanzar(sis: Sistema, archivos: Vec<PathBuf>, salida: PathBuf, auto_iniciar: bool) -> anyhow::Result<()> {
    let opciones = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(tfmt(tr("CAPAS · layered decomposition system · {}","CAPAS · sistema de descomposición estratificada · {}"), &[AUTOR.to_string()]))
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([1100.0, 700.0])
            .with_icon(icono())
            .with_drag_and_drop(true),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "capas",
        opciones,
        Box::new(move |cc| {
            configurar_estilo(&cc.egui_ctx);
            // Máscara inicial elegible con la variable CAPAS_TEMA.
            if let Some(t) = std::env::var("CAPAS_TEMA").ok().and_then(|s| tema_por_nombre(&s)) {
                TEMA.store(t, Ordering::Relaxed);
            }
            let mut app = App::new(sis, archivos, salida);
            app.tema = TEMA.load(Ordering::Relaxed);
            // Vista inicial elegible (pruebas/capturas): CAPAS_VISTA=<nombre>.
            if let Ok(v) = std::env::var("CAPAS_VISTA") {
                app.vista = match v.trim().to_lowercase().as_str() {
                    "inicio" | "home" => Vista::Inicio,
                    "explorador" | "explorer" => Vista::Explorador,
                    "comparar" | "compare" => Vista::Comparar,
                    "herramientas" | "tools" | "config" => Vista::Herramientas,
                    "ajustes" | "settings" => Vista::Ajustes,
                    _ => Vista::Analisis,
                };
            }
            app.auto_iniciar = auto_iniciar && !app.archivos.is_empty();
            Ok(Box::new(app))
        }),
    )
    .map_err(|e| anyhow::anyhow!("could not open the interface: {e}"))
}

impl App {
    fn new(sis: Sistema, archivos: Vec<PathBuf>, salida: PathBuf) -> Self {
        let op = Opciones::para(&sis);
        let mut app = App {
            herr: Herramientas::detectar(false),
            op,
            externas: true,
            archivos,
            salida,
            fase: Fase::Espera,
            t_inicio: 0.0,
            t_fin: 0.0,
            registro: VecDeque::new(),
            bloques: 0,
            bytes_vistos: 0,
            por_capa: Vec::new(),
            por_tipo: HashMap::new(),
            ultimo: None,
            senal: VecDeque::from(vec![0.0; 120]),
            ult_muestra: (0.0, 0),
            arbol: Vec::new(),
            raiz: None,
            seleccion: None,
            visor: None,
            auto_iniciar: false,
            tema: 4,
            vista: Vista::Analisis,
            solo_pendientes: false,
            cmp_a: None,
            cmp_b: None,
            cmp_resultado: None,
            buscar: String::new(),
            actualizacion: std::sync::Arc::new(std::sync::Mutex::new(None)),
            clave_entrada: String::new(),
            clave_lic: String::new(),
            lic_estado: None,
            usar_comunes: false,
            diccionario: None,
            fuerza_bruta: false,
            fuerza_alfabeto: 0,
            fuerza_long: 4,
            claves_halladas: Vec::new(),
            clasif: Vec::new(),
            audit: Vec::new(),
            sis,
        };
        app.log(0.0, tfmt(tr("CAPAS v{} STARTED · OPERATOR {}","CAPAS v{} INICIADO · OPERADOR {}"), &[VERSION.to_string(), AUTOR.to_string()]), naranja());
        app.log(
            0.0,
            format!(
                "{} CORES · {} FREE · {} EXTERNAL SUBSYSTEMS",
                app.sis.nucleos,
                humano(app.sis.memoria_libre),
                app.herr.rutas.len()
            ),
            acento(),
        );
        app.log(0.0, tr("WAITING FOR SAMPLES. DRAG FILES ONTO THE WINDOW.", "EN ESPERA DE MUESTRAS. ARRASTRA ARCHIVOS A LA VENTANA.").into(), morado_claro());
        app
    }

    fn log(&mut self, t: f64, texto: String, color: Color32) {
        self.registro.push_back(Linea { t, texto, color });
        while self.registro.len() > 2000 {
            self.registro.pop_front();
        }
    }

    fn analizando(&self) -> bool {
        matches!(self.fase, Fase::Analizando { .. })
    }

    fn construir_claves(&self) -> Claves {
        let explicitas: Vec<String> = self
            .clave_entrada
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        Claves {
            explicitas,
            comunes: self.usar_comunes,
            diccionario: self.diccionario.clone(),
            fuerza: self.fuerza_bruta.then(|| {
                let alf = ALFABETOS[self.fuerza_alfabeto].1;
                FuerzaBruta::nuevo(&FuerzaBruta::alfabeto_por_nombre(alf), self.fuerza_long)
            }),
            max_intentos: 2_000_000,
        }
    }

    fn claves_activas(&self) -> bool {
        !self.clave_entrada.trim().is_empty() || self.usar_comunes || self.diccionario.is_some() || self.fuerza_bruta
    }

    fn iniciar(&mut self, ctx: &egui::Context, ahora: f64) {
        if self.archivos.is_empty() || self.analizando() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let cancelar = Arc::new(AtomicBool::new(false));
        let rutas = self.archivos.clone();
        let salida = self.salida.clone();
        self.op.claves = self.construir_claves();
        let op = self.op.clone();
        let herr = if self.externas { self.herr.clone() } else { Herramientas::default() };
        let sis = self.sis.clone();
        let c2 = cancelar.clone();
        let ctx2 = ctx.clone();
        let hilo = std::thread::spawn(move || {
            let r = analisis::ejecutar(&rutas, &salida, &op, herr, &sis, Some(tx), c2);
            ctx2.request_repaint();
            r
        });
        self.bloques = 0;
        self.bytes_vistos = 0;
        self.por_capa.clear();
        self.por_tipo.clear();
        self.ultimo = None;
        self.arbol.clear();
        self.seleccion = None;
        self.visor = None;
        self.claves_halladas.clear();
        self.clasif.clear();
        self.audit.clear();
        self.t_inicio = ahora;
        self.ult_muestra = (ahora, 0);
        self.log(ahora, tfmt(tr("DECOMPOSITION START · {} SAMPLE(S) · {} THREADS","INICIO DE DESCOMPOSICIÓN · {} MUESTRA(S) · {} HILOS"), &[self.archivos.len().to_string(), self.op.hilos.to_string()]), naranja());
        self.fase = Fase::Analizando { rx, hilo, cancelar };
    }

    fn sondear(&mut self, ahora: f64) {
        let mut eventos = Vec::new();
        let mut terminado = false;
        if let Fase::Analizando { rx, hilo, .. } = &self.fase {
            while let Ok(e) = rx.try_recv() {
                eventos.push(e);
            }
            terminado = hilo.is_finished();
        }
        for e in eventos {
            match e {
                Evento::Bloque { n, capa, tipo, tamano, ruta } => {
                    self.bloques = n.max(self.bloques);
                    self.bytes_vistos += tamano;
                    if self.por_capa.len() <= capa {
                        self.por_capa.resize(capa + 1, 0);
                    }
                    self.por_capa[capa] += 1;
                    *self.por_tipo.entry(tipo).or_default() += 1;
                    self.ultimo = Some((tipo, ruta.clone(), ahora));
                    self.log(
                        ahora,
                        tfmt(tr("LAYER {} │ {} │ {} │ {}","CAPA {} │ {} │ {} │ {}"), &[format!("{capa:02}"), format!("{:<11}", codigo_tipo(tipo)), format!("{:>10}", humano(tamano)), ruta.clone()]),
                        color_tipo(tipo),
                    );
                }
                Evento::Aviso(a) => {
                    // Captura "contraseña hallada para 'archivo': clave".
                    if let Some(resto) = a.strip_prefix("contraseña hallada para '") {
                        if let Some((arch, clave)) = resto.split_once("': ") {
                            self.claves_halladas.push((arch.to_string(), clave.to_string()));
                            self.log(ahora, tfmt(tr("🔓 KEY «{}» → {}","🔓 CLAVE «{}» → {}"), &[clave.to_string(), arch.to_string()]), verde());
                            continue;
                        }
                    }
                    let col = if a.contains('✔') || a.contains("clasificados") { verde() } else { naranja() };
                    self.log(ahora, tfmt(tr("NOTICE: {}","AVISO: {}"), &[a.to_string()]), col);
                }
            }
        }
        // Señal de rendimiento: bloques/segundo muestreados cada 0,1 s.
        if ahora - self.ult_muestra.0 >= 0.1 {
            let dt = (ahora - self.ult_muestra.0) as f32;
            let v = (self.bloques - self.ult_muestra.1) as f32 / dt;
            self.senal.push_back(v);
            if self.senal.len() > 120 {
                self.senal.pop_front();
            }
            self.ult_muestra = (ahora, self.bloques);
        }
        if terminado {
            if let Fase::Analizando { hilo, .. } = std::mem::replace(&mut self.fase, Fase::Terminado) {
                self.t_fin = ahora;
                match hilo.join() {
                    Ok(Ok(r)) => {
                        self.log(
                            ahora,
                            tfmt(
                                tr(
                                    "DECOMPOSITION COMPLETE · {} BLOCKS · {} EXTRACTED · {}s",
                                    "DESCOMPOSICIÓN COMPLETADA · {} BLOQUES · {} EXTRAÍDOS · {}s",
                                ),
                                &[r.bloques.to_string(), humano(r.bytes), format!("{:.2}", r.duracion.as_secs_f64())],
                            ),
                            verde(),
                        );
                        self.log(ahora, tfmt(tr("REPORT: {}","INFORME: {}"), &[r.raiz.join("informe.md").display().to_string()]), verde());
                        if let Some(c) = &r.clasificacion {
                            self.clasif = Categoria::TODAS
                                .iter()
                                .filter_map(|cat| {
                                    let n = c.por_categoria.get(cat.nombre()).copied().unwrap_or(0);
                                    (n > 0).then_some((*cat, n))
                                })
                                .collect();
                            self.log(ahora, tfmt(tr("CLASSIFIED {} FILE(S) → extraidos/","CLASIFICADOS {} ARCHIVO(S) → extraidos/"), &[c.total.to_string()]), verde());
                        }
                        if let Some(au) = &r.auditoria {
                            self.audit = au
                                .paquetes
                                .iter()
                                .map(|p| {
                                    let hs = p
                                        .hallazgos
                                        .iter()
                                        .filter(|h| h.nivel != Nivel::Info)
                                        .map(|h| (h.nivel, format!("{}: {}", h.regla, h.detalle)))
                                        .collect();
                                    (p.nombre.clone(), p.veredicto, hs)
                                })
                                .collect();
                            for p in &au.paquetes {
                                let col = color_veredicto(p.veredicto);
                                self.log(ahora, tfmt(tr("AUDIT [{}] {}","AUDITORÍA [{}] {}"), &[p.veredicto.etiqueta().to_string(), p.nombre.clone()]), col);
                            }
                        }
                        self.arbol = r.arbol;
                        self.raiz = Some(r.raiz);
                        if !self.arbol.is_empty() {
                            self.seleccion = Some(vec![0]);
                        }
                    }
                    Ok(Err(e)) => self.log(ahora, tfmt(tr("FAILURE: {}","FALLO: {}"), &[format!("{e:#}")]), rojo()),
                    Err(_) => self.log(ahora, tr("FAILURE: the analysis thread stopped", "FALLO: el hilo de análisis se ha detenido").into(), rojo()),
                }
            }
        }
    }

    fn abrir_resultado(&mut self, rel: &str) {
        let Some(raiz) = &self.raiz else { return };
        let p = raiz.join(rel);
        if p.is_dir() {
            abrir_en_sistema(&p);
            return;
        }
        const MAX: usize = 4 << 20;
        match fs::read(&p) {
            Ok(mut b) => {
                let truncado = b.len() > MAX;
                b.truncate(MAX);
                let texto = String::from_utf8_lossy(&b);
                self.visor = Some(Visor {
                    titulo: rel.to_string(),
                    lineas: texto.lines().map(|l| l.replace('\t', "    ")).collect(),
                    truncado,
                });
            }
            Err(e) => {
                self.visor = Some(Visor { titulo: rel.into(), lineas: vec![tfmt(tr("could not read: {}","no se pudo leer: {}"), &[e.to_string()])], truncado: false })
            }
        }
    }
}

impl eframe::App for App {
    fn clear_color(&self, _v: &egui::Visuals) -> [f32; 4] {
        fondo().to_normalized_gamma_f32()
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let ahora = ctx.input(|i| i.time);

        // Archivos soltados sobre la ventana.
        let soltados: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).filter(|p| !p.as_os_str().is_empty()).collect());
        if !soltados.is_empty() && !self.analizando() {
            for p in soltados {
                if !self.archivos.contains(&p) {
                    self.log(ahora, tfmt(tr("SAMPLE RECEIVED: {}","MUESTRA RECIBIDA: {}"), &[p.display().to_string()]), morado_claro());
                    self.archivos.push(p);
                }
            }
        }

        if std::mem::take(&mut self.auto_iniciar) {
            self.iniciar(&ctx, ahora);
        }
        self.sondear(ahora);
        // Animaciones continuas (suaves cuando está en espera).
        ctx.request_repaint_after(if self.analizando() { Duration::from_millis(16) } else { Duration::from_millis(50) });

        // ── Rediseño "Serio": barra lateral · cabecera · cuerpo · barra de estado ──
        let marco_nav = egui::Frame::new().fill(hondo()).inner_margin(Margin { left: 14, right: 14, top: 16, bottom: 12 });
        let marco_cab = egui::Frame::new().fill(morado_oscuro()).inner_margin(Margin { left: 22, right: 22, top: 0, bottom: 0 });
        let marco_cuerpo = egui::Frame::new().fill(fondo()).inner_margin(Margin::same(18));

        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(216.0)
            .frame(marco_nav)
            .show(ui, |ui| self.nav_ui(ui));
        egui::Panel::top("encabezado")
            .exact_size(72.0)
            .frame(marco_cab)
            .show(ui, |ui| self.encabezado_ui(ui, &ctx, ahora));
        egui::Panel::bottom("estado")
            .exact_size(36.0)
            .frame(egui::Frame::new().fill(morado_oscuro()).inner_margin(Margin::symmetric(16, 6)))
            .show(ui, |ui| self.barra_estado_ui(ui));
        egui::CentralPanel::default().frame(marco_cuerpo).show(ui, |ui| match self.vista {
            Vista::Inicio => self.vista_inicio(ui),
            Vista::Analisis => self.vista_analisis(ui),
            Vista::Explorador => self.vista_explorador(ui),
            Vista::Comparar => self.vista_comparar(ui),
            Vista::Herramientas => self.recursos_ui(ui, ahora),
            Vista::Ajustes => self.vista_ajustes(ui),
        });

        // Resaltado al arrastrar archivos encima.
        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            let r = ctx.content_rect();
            let p = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::unique("soltar")));
            p.rect_filled(r, 0.0, Color32::from_black_alpha(170));
            p.rect_stroke(r.shrink(12.0), 0.0, Stroke::new(4.0, acento()), StrokeKind::Inside);
            p.text(r.center(), Align2::CENTER_CENTER, tr("DROP THE SAMPLE", "SUELTA LA MUESTRA"), titulo(64.0), acento());
        }
    }
}

// ── Secciones ───────────────────────────────────────────────────────────
impl App {
    fn cabecera(&mut self, ui: &mut Ui, ahora: f64) {
        let r = ui.max_rect();
        let p = ui.painter().clone();
        // Título: se mide para colocar el subtítulo justo al lado.
        let g = p.layout_no_wrap("CAPAS".into(), titulo(64.0), naranja());
        let ancho_titulo = g.size().x;
        p.galley(r.left_top() + Vec2::new(0.0, -4.0), g, naranja());
        let x = r.left() + ancho_titulo + 18.0;
        p.line_segment([Pos2::new(x - 9.0, r.top() + 6.0), Pos2::new(x - 9.0, r.top() + 72.0)], Stroke::new(2.0, acento()));
        p.text(Pos2::new(x, r.top() + 4.0), Align2::LEFT_TOP, tr("LAYERED DECOMPOSITION", "SISTEMA DE DESCOMPOSICIÓN"), titulo(20.0), texto());
        p.text(Pos2::new(x, r.top() + 27.0), Align2::LEFT_TOP, tr("SYSTEM FOR FILES", "ESTRATIFICADA DE ARCHIVOS"), titulo(20.0), texto());
        p.text(
            Pos2::new(x, r.top() + 56.0),
            Align2::LEFT_TOP,
            tfmt(tr("v{}  ·  OPERATOR {}","v{}  ·  OPERADOR {}"), &[VERSION.to_string(), AUTOR.to_string()]),
            mono(12.0),
            acento(),
        );

        // Reloj T+ y estado.
        let (estado, color) = match self.fase {
            Fase::Espera => (tr("IDLE", "EN ESPERA"), morado_claro()),
            Fase::Analizando { .. } => (tr("DECOMPOSING", "DESCOMPONIENDO"), naranja()),
            Fase::Terminado => (tr("COMPLETED", "COMPLETADO"), verde()),
        };
        let t = match self.fase {
            Fase::Espera => 0.0,
            Fase::Analizando { .. } => ahora - self.t_inicio,
            Fase::Terminado => self.t_fin - self.t_inicio,
        };
        let reloj = format!("T+{:02}:{:02}.{:02}", (t / 60.0) as u64, (t % 60.0) as u64, ((t * 100.0) % 100.0) as u64);
        p.text(r.right_top() + Vec2::new(0.0, -2.0), Align2::RIGHT_TOP, reloj, mono(40.0), naranja());

        let caja = Rect::from_min_size(Pos2::new(r.right() - 340.0, r.top() + 50.0), Vec2::new(180.0, 26.0));
        let parpadeo = self.analizando() && (ahora * 3.0).fract() < 0.5;
        p.rect_filled(caja, 0.0, if parpadeo { color } else { morado_oscuro() });
        p.rect_stroke(caja, 0.0, Stroke::new(2.0, color), StrokeKind::Inside);
        p.text(caja.center(), Align2::CENTER_CENTER, estado, titulo(15.0), if parpadeo { fondo() } else { color });
        p.text(
            Pos2::new(r.right(), r.top() + 63.0),
            Align2::RIGHT_CENTER,
            tfmt(tr("{} BLOCKS","{} BLOQUES"), &[self.bloques.to_string()]),
            mono(14.0),
            acento(),
        );

        // Franja inferior: rayas de alerta animadas mientras trabaja.
        let franja = Rect::from_min_max(Pos2::new(r.left(), r.bottom() - 8.0), r.right_bottom());
        if self.analizando() {
            rayas(&p, franja, naranja(), fondo(), (ahora * 40.0) as f32);
        } else {
            p.rect_filled(franja, 0.0, morado());
            p.line_segment([franja.left_top(), franja.right_top()], Stroke::new(1.0, morado_claro()));
        }
    }

    fn recursos_ui(&mut self, ui: &mut Ui, ahora: f64) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            seccion(ui, "01", tr("PROCESSING CORES", "NÚCLEOS DE PROCESO"), acento(), |ui| {
                let n = self.sis.nucleos.min(64);
                let activos = if self.analizando() { self.op.hilos.min(n) } else { 0 };
                let radio = 20.0;
                let paso_x = radio * 1.5 + 3.0;
                let por_fila = (((ui.available_width() - 2.0 * radio) / paso_x) as usize + 1).clamp(1, n.max(1));
                let filas = n.div_ceil(por_fila).max(1);
                let alto = filas as f32 * radio * 1.75 + radio * 1.3;
                let (resp, p) = ui.allocate_painter(Vec2::new(ui.available_width(), alto), Sense::hover());
                let o = resp.rect.left_top() + Vec2::new(radio + 2.0, radio + 2.0);
                for i in 0..n {
                    let (f, c) = (i / por_fila, i % por_fila);
                    let centro = o + Vec2::new(c as f32 * paso_x, f as f32 * radio * 1.75 + if c % 2 == 1 { radio * 0.87 } else { 0.0 });
                    let fase = ((ahora * 4.0 + i as f64 * 0.7).sin() * 0.5 + 0.5) as f32;
                    let (relleno, borde) = if i < activos {
                        (mezclar(verde_oscuro(), acento(), fase * 0.7), acento())
                    } else {
                        (morado_oscuro(), morado_medio())
                    };
                    hexagono(&p, centro, radio, relleno, Stroke::new(1.5, borde));
                    p.text(centro, Align2::CENTER_CENTER, format!("{:02}", i + 1), mono(10.0), if i < activos { fondo() } else { morado_claro() });
                }
                ui.label(RichText::new(tfmt(tr("{} LOGICAL · {} ASSIGNED","{} LÓGICOS · {} ASIGNADOS"), &[self.sis.nucleos.to_string(), self.op.hilos.to_string()])).font(mono(11.0)).color(acento()));
            });

            seccion(ui, "02", tr("MEMORY", "MEMORIA"), acento(), |ui| {
                let total = self.sis.memoria_total.max(1);
                let usada = total.saturating_sub(self.sis.memoria_libre);
                barra_segmentada(ui, usada as f32 / total as f32, morado_claro());
                ui.label(
                    RichText::new(tfmt(tr("{} FREE / {}","{} LIBRE / {}"), &[humano(self.sis.memoria_libre), humano(self.sis.memoria_total)]))
                        .font(mono(11.0))
                        .color(texto()),
                );
                ui.label(RichText::new(tfmt(tr("PER-BLOCK LIMIT: {}","LÍMITE POR BLOQUE: {}"), &[humano(self.op.max_archivo)])).font(mono(11.0)).color(naranja()));
            });

            seccion(ui, "03", tr("EXTERNAL SUBSYSTEMS", "SUBSISTEMAS EXTERNOS"), naranja(), |ui| {
                for (n, desc) in HERRAMIENTAS_CONOCIDAS {
                    let ok = self.herr.get(n).is_some() && self.externas;
                    ui.horizontal(|ui| {
                        let (r, p) = ui.allocate_painter(Vec2::splat(12.0), Sense::hover());
                        let c = r.rect.center();
                        if ok {
                            p.rect_filled(Rect::from_center_size(c, Vec2::splat(9.0)), 0.0, acento());
                        } else {
                            p.rect_stroke(Rect::from_center_size(c, Vec2::splat(9.0)), 0.0, Stroke::new(1.0, morado_medio()), StrokeKind::Inside);
                        }
                        ui.label(RichText::new(*n).font(mono(12.0)).color(if ok { verde() } else { morado_medio() }))
                            .on_hover_text(*desc);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new(if ok { tr("ACTIVE","ACTIVO") } else { tr("ABSENT","AUSENTE") }).font(mono(10.0)).color(if ok { verde() } else { morado_medio() }));
                        });
                    });
                }
            });

            let bloqueado = self.analizando();
            seccion(ui, "04", tr("PARAMETERS", "PARÁMETROS"), morado_claro(), |ui| {
                ui.add_enabled_ui(!bloqueado, |ui| {
                    let max_hilos = (self.sis.nucleos * 2).max(1);
                    let mut h = self.op.hilos;
                    if ui.add(egui::Slider::new(&mut h, 1..=max_hilos).text("HILOS")).changed() {
                        self.op.hilos = h;
                        self.op.max_archivo = analisis::limite_por_bloque(&self.sis, h);
                    }
                    ui.add(egui::Slider::new(&mut self.op.profundidad, 1..=32).text(tr("DEPTH", "PROFUNDIDAD")));
                    let mut t = self.op.timeout.as_secs();
                    if ui.add(egui::Slider::new(&mut t, 5..=1800).text("TIMEOUT s")).changed() {
                        self.op.timeout = Duration::from_secs(t);
                    }
                    ui.checkbox(&mut self.op.tallar, tr("FIND EMBEDDED FILES", "BUSCAR ARCHIVOS INCRUSTADOS"));
                    ui.checkbox(&mut self.externas, tr("USE EXTERNAL SUBSYSTEMS", "USAR SUBSISTEMAS EXTERNOS"));
                    ui.checkbox(&mut self.op.clasificar, tr("CLASSIFY AND GATHER FILES", "CLASIFICAR Y REUNIR ARCHIVOS"));
                    ui.checkbox(&mut self.op.agrupar, tr("GROUP RESOURCES (same name → .zip)", "AGRUPAR RECURSOS (mismo nombre → .zip)"));
                    ui.checkbox(&mut self.op.reconstruir, tr("REBUILD PACKAGES (structure + .zip)", "RECONSTRUIR PAQUETES (estructura + .zip)"));
                    ui.checkbox(&mut self.op.auditar, tr("AUDIT PACKAGES (ASSET PACKS/MODS)", "AUDITAR PAQUETES (ASSET PACKS/MODS)"));
                    // Desempaquetar bundles de motor: función de pago (Pro).
                    let pro = crate::edicion::permite(crate::edicion::DESEMPAQUETAR);
                    if pro {
                        ui.checkbox(&mut self.op.desempaquetar, tr("UNPACK ENGINE BUNDLES (Unity/Godot)", "DESEMPAQUETAR BUNDLES DE MOTOR (Unity/Godot)"));
                    } else {
                        self.op.desempaquetar = false;
                        ui.add_enabled(false, egui::Checkbox::new(&mut false, tr("UNPACK ENGINE BUNDLES (Unity/Godot) · PRO", "DESEMPAQUETAR BUNDLES DE MOTOR (Unity/Godot) · PRO")))
                            .on_disabled_hover_text(tr("Available in CAPAS Pro.", "Disponible en CAPAS Pro."));
                    }
                    ui.add_space(2.0);
                    ui.label(RichText::new(tr("Appearance, language and license are in Settings.", "La apariencia, el idioma y la licencia están en Ajustes.")).font(FontId::proportional(10.5)).color(morado_medio()));
                });
            });

            seccion(ui, "05", tr("KEYS (PROTECTED ZIP)", "CLAVES (ZIP PROTEGIDO)"), naranja(), |ui| {
                ui.add_enabled_ui(!bloqueado, |ui| {
                    ui.label(RichText::new(tr("PASSWORDS TO TRY (one per line):", "CONTRASEÑAS A PROBAR (una por línea):")).font(mono(10.0)).color(morado_claro()));
                    ui.add(
                        egui::TextEdit::multiline(&mut self.clave_entrada)
                            .font(mono(12.0))
                            .desired_rows(2)
                            .desired_width(f32::INFINITY)
                            .hint_text(tr("key1\nkey2", "clave1\nclave2")),
                    );
                    ui.checkbox(&mut self.usar_comunes, tr("COMMON PASSWORD LIST", "LISTA DE CONTRASEÑAS HABITUALES"));
                    ui.horizontal(|ui| {
                        if ui.add(boton(tr("DICTIONARY…", "DICCIONARIO…"), morado_claro())).clicked() {
                            if let Some(f) = rfd::FileDialog::new().pick_file() {
                                self.diccionario = Some(f);
                            }
                        }
                        if self.diccionario.is_some() && ui.add(boton("QUITAR", naranja())).clicked() {
                            self.diccionario = None;
                        }
                    });
                    if let Some(d) = &self.diccionario {
                        ui.label(RichText::new(acortar(&d.display().to_string(), 36)).font(mono(10.0)).color(verde()));
                    }
                    ui.checkbox(&mut self.fuerza_bruta, tr("BRUTE FORCE (bounded)", "FUERZA BRUTA (acotada)"));
                    if self.fuerza_bruta {
                        egui::ComboBox::from_id_salt("alf")
                            .selected_text(ALFABETOS[self.fuerza_alfabeto].0)
                            .show_ui(ui, |ui| {
                                for (i, (n, _)) in ALFABETOS.iter().enumerate() {
                                    ui.selectable_value(&mut self.fuerza_alfabeto, i, *n);
                                }
                            });
                        ui.add(egui::Slider::new(&mut self.fuerza_long, 1..=8).text(tr("MAX LEN", "LONG. MÁX")));
                        ui.label(RichText::new(tr("⚠ long brute force can take a while", "⚠ la fuerza bruta larga puede tardar mucho")).font(mono(9.0)).color(naranja()));
                    }
                    let estado = if self.claves_activas() { (tr("MODULE ACTIVE", "MÓDULO ACTIVO"), verde()) } else { (tr("INACTIVE (encrypted ZIPs skipped)", "INACTIVO (ZIP cifrados se omiten)"), morado_medio()) };
                    ui.label(RichText::new(estado.0).font(mono(10.0)).color(estado.1));
                });
                for (arch, clave) in &self.claves_halladas {
                    ui.label(RichText::new(format!("🔓 {} → «{}»", acortar(arch, 20), clave)).font(mono(10.0)).color(verde()));
                }
            });
        });
    }

    fn central_ui(&mut self, ui: &mut Ui, ctx: &egui::Context, ahora: f64) {
        // Fila de instrumentos.
        ui.columns(3, |c| {
            seccion(&mut c[0], "A", tr("CLASSIFICATION", "CLASIFICACIÓN"), naranja(), |ui| self.clasificacion(ui, ahora));
            seccion(&mut c[1], "B", tr("DEPTH", "PROFUNDIDAD"), acento(), |ui| self.profundidad(ui));
            seccion(&mut c[2], "C", tr("PERFORMANCE", "RENDIMIENTO"), acento(), |ui| self.senal_ui(ui, ahora));
        });
        ui.add_space(6.0);

        if self.visor.is_some() {
            self.visor_ui(ui);
        } else {
            self.cola_ui(ui, ctx, ahora);
        }
    }

    fn clasificacion(&mut self, ui: &mut Ui, ahora: f64) {
        let (resp, p) = ui.allocate_painter(Vec2::new(ui.available_width(), 128.0), Sense::hover());
        let r = resp.rect;
        rejilla(&p, r, 16.0);
        match &self.ultimo {
            Some((tipo, ruta, t)) => {
                let c = color_tipo(*tipo);
                let destello = (1.0 - ((ahora - t) as f32 * 3.0)).clamp(0.0, 1.0);
                if destello > 0.0 {
                    p.rect_filled(r, 0.0, c.gamma_multiply(0.18 * destello));
                }
                p.text(r.center_top() + Vec2::new(0.0, 8.0), Align2::CENTER_TOP, tr("PATTERN DETECTED", "PATRÓN DETECTADO"), mono(11.0), texto());
                texto_ajustado(&p, r.center() + Vec2::new(0.0, 4.0), codigo_tipo(*tipo), 46.0, r.width() - 20.0, c);
                let corto = acortar(ruta, (r.width() / 6.2) as usize);
                p.text(r.center_bottom() - Vec2::new(0.0, 6.0), Align2::CENTER_BOTTOM, corto, mono(10.0), morado_claro());
            }
            None => {
                texto_ajustado(&p, r.center(), tr("NO PATTERN", "SIN PATRÓN"), 34.0, r.width() - 20.0, morado_medio());
            }
        }
        // Recuento por tipo.
        let mut v: Vec<_> = self.por_tipo.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1));
        ui.horizontal_wrapped(|ui| {
            for (t, n) in v.into_iter().take(6) {
                ui.label(RichText::new(format!("{} ×{n}", codigo_tipo(*t))).font(mono(10.0)).color(color_tipo(*t)));
            }
        });
    }

    fn profundidad(&mut self, ui: &mut Ui) {
        let (resp, p) = ui.allocate_painter(Vec2::new(ui.available_width(), 128.0), Sense::hover());
        let r = resp.rect;
        rejilla(&p, r, 16.0);
        let n = self.por_capa.len().max(6);
        let max = self.por_capa.iter().copied().max().unwrap_or(1).max(1) as f32;
        let ancho = r.width() / n as f32;
        for i in 0..n {
            let v = self.por_capa.get(i).copied().unwrap_or(0);
            let h = (v as f32 / max) * (r.height() - 36.0);
            let x0 = r.left() + i as f32 * ancho + 3.0;
            let b = Rect::from_min_max(Pos2::new(x0, r.bottom() - 16.0 - h), Pos2::new(x0 + ancho - 6.0, r.bottom() - 16.0));
            let c = mezclar(acento(), naranja(), i as f32 / (n - 1).max(1) as f32);
            if v > 0 {
                p.rect_filled(b, 0.0, c.gamma_multiply(0.85));
                p.text(b.center_top() - Vec2::new(0.0, 2.0), Align2::CENTER_BOTTOM, v.to_string(), mono(10.0), c);
            }
            p.text(Pos2::new(b.center().x, r.bottom() - 2.0), Align2::CENTER_BOTTOM, format!("{i}"), mono(10.0), morado_claro());
        }
        ui.label(
            RichText::new(tfmt(tr("LAYERS: {} · VOLUME: {}","ESTRATOS: {} · VOLUMEN: {}"), &[self.por_capa.len().to_string(), humano(self.bytes_vistos)]))
                .font(mono(10.0))
                .color(acento()),
        );
    }

    fn senal_ui(&mut self, ui: &mut Ui, ahora: f64) {
        let (resp, p) = ui.allocate_painter(Vec2::new(ui.available_width(), 128.0), Sense::hover());
        let r = resp.rect;
        rejilla(&p, r, 16.0);
        let max = self.senal.iter().copied().fold(1.0f32, f32::max);
        let n = self.senal.len().max(2);
        // Onda decorativa de sincronía (naranja) modulada por la actividad.
        let act = self.senal.back().copied().unwrap_or(0.0) / max;
        let amp = if self.analizando() { 0.15 + 0.3 * act } else { 0.05 };
        let onda: Vec<Pos2> = (0..=100)
            .map(|i| {
                let f = i as f32 / 100.0;
                let y = r.center().y + (f * TAU * 3.0 + ahora as f32 * 4.0).sin() * r.height() * amp;
                Pos2::new(r.left() + f * r.width(), y)
            })
            .collect();
        p.add(Shape::line(onda, Stroke::new(1.0, naranja().gamma_multiply(0.6))));
        // Datos reales (verde).
        let pts: Vec<Pos2> = self
            .senal
            .iter()
            .enumerate()
            .map(|(i, v)| Pos2::new(r.left() + i as f32 / (n - 1) as f32 * r.width(), r.bottom() - 4.0 - v / max * (r.height() - 12.0)))
            .collect();
        p.add(Shape::line(pts, Stroke::new(2.0, acento())));
        let actual = self.senal.back().copied().unwrap_or(0.0);
        ui.label(RichText::new(format!("{actual:.0} {} · {} {max:.0}", tr("BLOCKS/s","BLOQUES/s"), tr("PEAK","PICO"))).font(mono(10.0)).color(acento()));
    }

    fn cola_ui(&mut self, ui: &mut Ui, ctx: &egui::Context, ahora: f64) {
        seccion(ui, "D", tr("SAMPLES", "MUESTRAS"), morado_claro(), |ui| {
            let alto = (ui.available_height() - 110.0).max(160.0);
            let (resp, p) = ui.allocate_painter(Vec2::new(ui.available_width(), alto), Sense::click());
            let r = resp.rect;
            rejilla(&p, r, 28.0);
            if self.archivos.is_empty() {
                // Hexágono pulsante de tr("drop zone", "zona de carga").
                let pulso = ((ahora * 2.0).sin() * 0.5 + 0.5) as f32;
                let rad = (r.height() * 0.46).min(r.width() * 0.3).max(40.0);
                hexagono(&p, r.center(), rad + 10.0 * pulso, Color32::TRANSPARENT, Stroke::new(1.0, morado_medio()));
                hexagono(&p, r.center(), rad, morado_oscuro(), Stroke::new(3.0, mezclar(morado_claro(), acento(), pulso)));
                p.text(r.center() - Vec2::new(0.0, 16.0), Align2::CENTER_CENTER, tr("DROP HERE", "ARRASTRA AQUÍ"), titulo(24.0), acento());
                p.text(r.center() + Vec2::new(0.0, 18.0), Align2::CENTER_CENTER, tr("FILES OR FOLDERS", "ARCHIVOS O CARPETAS"), titulo(15.0), texto());
                p.text(r.center() + Vec2::new(0.0, 42.0), Align2::CENTER_CENTER, tr("or click to choose", "o haz clic para elegir"), mono(11.0), morado_claro());
                if resp.clicked() {
                    self.elegir_archivos();
                }
            } else {
                let mut quitar = None;
                let mut sub = ui.new_child(egui::UiBuilder::new().max_rect(r.shrink(8.0)));
                egui::ScrollArea::vertical().id_salt("cola").show(&mut sub, |ui| {
                    for (i, a) in self.archivos.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("{:02}", i + 1)).font(mono(13.0)).color(naranja()));
                            let tam = fs::metadata(a).map(|m| if m.is_dir() { "CARPETA".into() } else { humano(m.len()) }).unwrap_or_default();
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if !self.analizando() && ui.small_button("×").clicked() {
                                    quitar = Some(i);
                                }
                                ui.label(RichText::new(tam).font(mono(11.0)).color(verde()));
                                ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                                    let nombre = a.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                                    ui.label(RichText::new(nombre).font(mono(13.0)).color(texto()));
                                    let dir = a.parent().map(|d| d.display().to_string()).unwrap_or_default();
                                    ui.add(egui::Label::new(RichText::new(dir).font(mono(11.0)).color(morado_medio())).truncate());
                                });
                            });
                        });
                    }
                });
                if let Some(i) = quitar {
                    self.archivos.remove(i);
                }
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let libre = !self.analizando();
                if ui.add_enabled(libre, boton(tr("+ FILES", "+ ARCHIVOS"), morado_claro())).clicked() {
                    self.elegir_archivos();
                }
                if ui.add_enabled(libre, boton(tr("+ FOLDER", "+ CARPETA"), morado_claro())).clicked() {
                    if let Some(d) = rfd::FileDialog::new().pick_folder() {
                        self.archivos.push(d);
                    }
                }
                if ui.add_enabled(libre && !self.archivos.is_empty(), boton(tr("CLEAR", "VACIAR"), morado_claro())).clicked() {
                    self.archivos.clear();
                }
                if ui
                    .add_enabled(libre, boton(&tfmt(tr("OUTPUT: {}","SALIDA: {}"), &[acortar(&self.salida.display().to_string(), 26)]), acento()))
                    .on_hover_text(tfmt(tr("Folder where extracted layers are saved:\n{}","Carpeta donde se guardan las capas extraídas:\n{}"), &[self.salida.display().to_string()]))
                    .clicked()
                {
                    if let Some(d) = rfd::FileDialog::new().pick_folder() {
                        self.salida = d;
                    }
                }
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| match &self.fase {
                    Fase::Analizando { cancelar, .. } => {
                        if ui.add(boton(tr("■ ABORT", "■ ABORTAR"), rojo()).min_size(Vec2::new(170.0, 40.0))).clicked() {
                            cancelar.store(true, Ordering::Relaxed);
                        }
                    }
                    _ => {
                        let listo = !self.archivos.is_empty();
                        if ui
                            .add_enabled(listo, boton(tr("▶ START DECOMPOSITION", "▶ INICIAR DESCOMPOSICIÓN"), naranja()).min_size(Vec2::new(250.0, 40.0)))
                            .clicked()
                        {
                            self.iniciar(ctx, ahora);
                        }
                        if let Some(r) = &self.raiz {
                            if ui.add(boton(tr("OPEN OUTPUT", "ABRIR SALIDA"), acento()).min_size(Vec2::new(120.0, 40.0))).clicked() {
                                abrir_en_sistema(r);
                            }
                        }
                    }
                });
            });
        });
    }

    fn elegir_archivos(&mut self) {
        if let Some(v) = rfd::FileDialog::new().pick_files() {
            for p in v {
                if !self.archivos.contains(&p) {
                    self.archivos.push(p);
                }
            }
        }
    }

    // ═══════════════════════ Rediseño "Serio" ═══════════════════════
    // Barra lateral de navegación.
    fn nav_ui(&mut self, ui: &mut Ui) {
        // Marca: logo índigo + wordmark claro + descriptor.
        let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 46.0), Sense::hover());
        let p = ui.painter().clone();
        marca_capas(&p, Pos2::new(rect.left() + 16.0, rect.center().y + 1.0), 13.0, acento());
        p.text(Pos2::new(rect.left() + 42.0, rect.center().y), Align2::LEFT_CENTER, "CAPAS", titulo(25.0), texto());
        ui.add_space(2.0);
        ui.label(RichText::new(tr("Universal file exploration\nand reverse engineering", "Exploración y retroingeniería\nde archivos universales")).font(FontId::proportional(10.5)).color(morado_claro()));
        ui.add_space(14.0);
        let yd = ui.cursor().top();
        ui.painter().line_segment([Pos2::new(ui.max_rect().left(), yd), Pos2::new(ui.max_rect().right(), yd)], Stroke::new(1.0, morado()));
        ui.add_space(12.0);

        for v in [Vista::Inicio, Vista::Analisis, Vista::Explorador, Vista::Comparar, Vista::Herramientas, Vista::Ajustes] {
            if nav_item(ui, v.icono(), v.etiqueta(), self.vista == v) {
                self.vista = v;
            }
        }

        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            ui.add_space(2.0);
            let ed = crate::edicion::actual();
            let (et, ec) = match ed {
                crate::edicion::Edicion::Core => (tr("CORE edition", "edición CORE"), morado_claro()),
                crate::edicion::Edicion::Pro => (tr("PRO edition", "edición PRO"), acento()),
                crate::edicion::Edicion::Studio => (tr("STUDIO edition", "edición STUDIO"), acento()),
            };
            if ed == crate::edicion::Edicion::Core
                && ui.add(egui::Label::new(RichText::new(tr("› activate with a key", "› activar con una clave")).font(FontId::proportional(10.5)).color(morado_medio())).sense(Sense::click())).clicked()
            {
                self.vista = Vista::Ajustes;
            }
            ui.horizontal(|ui| {
                let (rid, _) = ui.allocate_exact_size(Vec2::splat(9.0), Sense::hover());
                ui.painter().circle_filled(rid.center(), 3.5, ec);
                ui.label(RichText::new(et).font(FontId::proportional(11.5)).color(ec));
            });
        });
    }

    // Cabecera: estado, título, pastilla de IA y acción principal.
    fn encabezado_ui(&mut self, ui: &mut Ui, ctx: &egui::Context, ahora: f64) {
        ui.horizontal_centered(|ui| {
            // Insignia de estado (check verde al terminar, punto al trabajar).
            let (badge, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
            let p = ui.painter().clone();
            match self.fase {
                Fase::Terminado => {
                    p.circle_filled(badge.center(), 13.0, verde());
                    let c = badge.center();
                    p.add(egui::Shape::line(vec![c + Vec2::new(-5.0, 0.0), c + Vec2::new(-1.5, 3.6), c + Vec2::new(5.0, -4.2)], Stroke::new(2.4, Color32::from_rgb(0x0b, 0x2a, 0x1e))));
                }
                Fase::Analizando { .. } => {
                    let pulso = ((ahora * 3.0).sin() * 0.5 + 0.5) as f32;
                    p.circle_filled(badge.center(), 7.0 + 3.0 * pulso, acento().gamma_multiply(0.5));
                    p.circle_filled(badge.center(), 5.0, acento());
                }
                Fase::Espera => {
                    p.circle_stroke(badge.center(), 11.0, Stroke::new(2.0, morado_medio()));
                }
            }
            ui.add_space(4.0);
            ui.vertical(|ui| {
                ui.add_space(13.0);
                let via = self.vista.etiqueta();
                ui.label(RichText::new(format!("CAPAS   ›   {via}")).font(FontId::proportional(11.0)).color(morado_claro()));
                let t = match self.fase {
                    Fase::Analizando { .. } => tr("Decomposing…", "Descomponiendo…"),
                    Fase::Terminado => tr("Analysis complete", "Análisis completado"),
                    Fase::Espera => tr("Ready to analyze", "Listo para analizar"),
                };
                ui.label(RichText::new(t).font(titulo(22.0)).color(texto()));
            });
            ui.add_space(14.0);
            pastilla(ui, "ia", tr("AI disconnected", "IA desconectada"), morado_claro(), morado());
            // Aviso de actualización disponible (clicable → abre releases).
            if let Some(Act::Disponible(v)) = self.actualizacion.lock().unwrap().clone() {
                ui.add_space(8.0);
                let txt = tfmt(tr("Update v{}", "Actualización v{}"), &[v]);
                let g = ui.painter().layout_no_wrap(txt, FontId::proportional(11.5), Color32::from_rgb(0xf6, 0xf7, 0xfb));
                let (resp, p) = ui.allocate_painter(Vec2::new(g.size().x + 36.0, 25.0), Sense::click());
                p.rect_filled(resp.rect, CornerRadius::same(12), acento());
                dibujar_icono(&p, resp.rect.left_center() + Vec2::new(14.0, 0.0), 6.0, "extraer", Color32::from_rgb(0xf6, 0xf7, 0xfb));
                p.galley(Pos2::new(resp.rect.left() + 25.0, resp.rect.center().y - g.size().y / 2.0), g, Color32::from_rgb(0xf6, 0xf7, 0xfb));
                if resp.on_hover_text(tr("Open the latest release", "Abrir la última versión")).clicked() {
                    abrir_en_sistema(Path::new(URL_RELEASES));
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let es = crate::idioma::es();
                if ui.add(boton_sec(if es { "ES" } else { "EN" })).on_hover_text(tr("Switch language", "Cambiar idioma")).clicked() {
                    crate::idioma::set_es(!es);
                }
                ui.add_space(6.0);
                if self.analizando() {
                    let cancelar = if let Fase::Analizando { cancelar, .. } = &self.fase { Some(cancelar.clone()) } else { None };
                    if ui.add(boton_pri(tr("■ Abort", "■ Abortar"), rojo())).clicked() {
                        if let Some(c) = cancelar {
                            c.store(true, Ordering::Relaxed);
                        }
                    }
                } else {
                    let listo = !self.archivos.is_empty();
                    if ui.add_enabled(listo, boton_pri(tr("▶ Analyze", "▶ Analizar"), acento())).clicked() {
                        self.iniciar(ctx, ahora);
                    }
                    if let Some(r) = self.raiz.clone() {
                        if ui.add(boton_sec(tr("Open output", "Abrir salida"))).clicked() {
                            abrir_en_sistema(&r);
                        }
                    }
                }
            });
        });
        let r = ui.max_rect();
        ui.painter().line_segment([Pos2::new(r.left() - 22.0, r.bottom()), Pos2::new(r.right() + 22.0, r.bottom())], Stroke::new(1.0, morado()));
    }

    // Vista de análisis: identidad · tarjetas · búsqueda · tres paneles.
    fn vista_analisis(&mut self, ui: &mut Ui) {
        if self.archivos.is_empty() && self.arbol.is_empty() && !self.analizando() {
            self.zona_carga(ui);
            return;
        }
        if self.arbol.is_empty() {
            self.barra_entrada(ui);
        } else {
            self.identidad_ui(ui);
        }
        self.tarjetas_ui(ui);
        ui.add_space(10.0);
        self.barra_busqueda_ui(ui);
        ui.add_space(10.0);

        egui::Panel::left("p_arbol")
            .resizable(true)
            .default_size(330.0)
            .min_size(220.0)
            .frame(card_frame())
            .show_inside(ui, |ui| self.panel_arbol(ui));
        egui::Panel::right("p_detalle")
            .resizable(true)
            .default_size(360.0)
            .min_size(260.0)
            .frame(card_frame())
            .show_inside(ui, |ui| self.panel_detalle(ui));
        egui::CentralPanel::default()
            .frame(card_frame())
            .show_inside(ui, |ui| self.panel_lista(ui));
    }

    // Bloque de identidad del archivo analizado (icono + nombre + breadcrumb tipado).
    fn identidad_ui(&mut self, ui: &mut Ui) {
        let (nombre, desc, tipo) = match self.arbol.first() {
            Some(n) => (n.nombre.clone(), n.descripcion.clone(), n.tipo),
            None => return,
        };
        ui.horizontal(|ui| {
            let (badge, _) = ui.allocate_exact_size(Vec2::splat(46.0), Sense::hover());
            let p = ui.painter().clone();
            p.rect_filled(badge, CornerRadius::same(10), morado());
            dibujar_icono(&p, badge.center(), 13.0, icono_tipo(tipo), acento());
            ui.add_space(6.0);
            ui.vertical(|ui| {
                ui.add_space(2.0);
                ui.label(RichText::new(&nombre).font(titulo(21.0)).color(texto()));
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    ui.label(RichText::new(if desc.is_empty() { tr("File", "Archivo").to_string() } else { desc }).font(FontId::proportional(11.5)).color(morado_claro()));
                    ui.label(RichText::new("›").font(FontId::proportional(11.5)).color(morado_medio()));
                    ui.label(RichText::new(tr("Analysis", "Análisis")).font(FontId::proportional(11.5)).color(morado_claro()));
                    ui.label(RichText::new("›").font(FontId::proportional(11.5)).color(morado_medio()));
                    ui.label(RichText::new(acortar(&nombre, 28)).font(FontId::proportional(11.5)).color(morado_claro()));
                });
            });
            // Acciones de cola a la derecha.
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let libre = !self.analizando();
                if ui.add_enabled(libre, boton_sec(tr("Output", "Salida"))).on_hover_text(self.salida.display().to_string()).clicked() {
                    if let Some(d) = rfd::FileDialog::new().pick_folder() {
                        self.salida = d;
                    }
                }
                if ui.add_enabled(libre, boton_sec(tr("+ Files", "+ Archivos"))).clicked() {
                    self.elegir_archivos();
                }
            });
        });
        ui.add_space(12.0);
    }

    // Barra de búsqueda + filtros + vista.
    fn barra_busqueda_ui(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            // Campo de búsqueda con icono.
            let alto = 34.0;
            let ancho = (ui.available_width() - 230.0).max(220.0);
            let (rect, _) = ui.allocate_exact_size(Vec2::new(ancho, alto), Sense::hover());
            let p = ui.painter().clone();
            p.rect_filled(rect, CornerRadius::same(8), hondo());
            p.rect_stroke(rect, CornerRadius::same(8), Stroke::new(1.0, morado()), StrokeKind::Inside);
            dibujar_icono(&p, rect.left_center() + Vec2::new(16.0, 0.0), 7.0, "lupa", morado_claro());
            let mut child = ui.new_child(egui::UiBuilder::new().max_rect(Rect::from_min_max(rect.left_top() + Vec2::new(30.0, 0.0), rect.right_bottom())).layout(Layout::left_to_right(Align::Center)));
            child.visuals_mut().extreme_bg_color = Color32::TRANSPARENT;
            child.visuals_mut().widgets.inactive.bg_stroke = Stroke::NONE;
            child.visuals_mut().widgets.hovered.bg_stroke = Stroke::NONE;
            child.visuals_mut().widgets.active.bg_stroke = Stroke::NONE;
            child.add(egui::TextEdit::singleline(&mut self.buscar).font(FontId::proportional(13.0)).desired_width(ancho - 44.0).hint_text(tr("Search files, formats or paths…", "Buscar archivos, formatos o rutas…")));

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                // Conmutador lista/cuadrícula (decorativo por ahora, lista activa).
                let (tg, _) = ui.allocate_exact_size(Vec2::new(64.0, alto), Sense::hover());
                let p = ui.painter().clone();
                p.rect_filled(tg, CornerRadius::same(8), morado());
                p.rect_filled(Rect::from_min_size(tg.left_top(), Vec2::new(32.0, alto)), CornerRadius::same(8), acento().gamma_multiply(0.30));
                for i in 0..3 {
                    p.line_segment([Pos2::new(tg.left() + 10.0, tg.top() + 11.0 + i as f32 * 6.0), Pos2::new(tg.left() + 22.0, tg.top() + 11.0 + i as f32 * 6.0)], Stroke::new(1.6, acento()));
                }
                dibujar_icono(&p, Pos2::new(tg.left() + 48.0, tg.center().y), 6.0, "capas", morado_claro());
                // Filtros.
                ui.menu_button(tr("  Filters  ", "  Filtros  "), |ui| {
                    if ui.checkbox(&mut self.solo_pendientes, tr("Only pending", "Solo pendientes")).changed() {}
                    if ui.button(tr("Clear search", "Limpiar búsqueda")).clicked() {
                        self.buscar.clear();
                    }
                });
            });
        });
    }

    fn zona_carga(&mut self, ui: &mut Ui) {
        ui.add_space(24.0);
        egui::Frame::new()
            .fill(morado_oscuro())
            .stroke(Stroke::new(1.5, morado_medio()))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::same(30))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.vertical_centered(|ui| {
                    ui.add_space(26.0);
                    ui.label(RichText::new(tr("Drop files or folders here", "Arrastra archivos o carpetas aquí")).font(titulo(24.0)).color(texto()));
                    ui.add_space(6.0);
                    ui.label(RichText::new(tr("Everything is analyzed locally. Nothing leaves your machine.", "Todo se analiza en local. Nada sale de tu equipo.")).font(FontId::proportional(12.5)).color(morado_claro()));
                    ui.add_space(22.0);
                });
                ui.horizontal(|ui| {
                    let w = ui.available_width();
                    ui.add_space(((w - 330.0) / 2.0).max(0.0));
                    if ui.add(boton_pri(tr("Choose files", "Elegir archivos"), acento())).clicked() {
                        self.elegir_archivos();
                    }
                    if ui.add(boton_sec(tr("Choose folder", "Elegir carpeta"))).clicked() {
                        if let Some(d) = rfd::FileDialog::new().pick_folder() {
                            self.archivos.push(d);
                        }
                    }
                });
                ui.add_space(26.0);
            });
    }

    fn barra_entrada(&mut self, ui: &mut Ui) {
        let libre = !self.analizando();
        ui.horizontal(|ui| {
            ui.label(RichText::new(tfmt(tr("{} input(s)", "{} entrada(s)"), &[self.archivos.len().to_string()])).font(mono(11.0)).color(morado_claro()));
            ui.add_space(6.0);
            if ui.add_enabled(libre, boton_sec(tr("+ Files", "+ Archivos"))).clicked() {
                self.elegir_archivos();
            }
            if ui.add_enabled(libre, boton_sec(tr("+ Folder", "+ Carpeta"))).clicked() {
                if let Some(d) = rfd::FileDialog::new().pick_folder() {
                    self.archivos.push(d);
                }
            }
            if ui.add_enabled(libre && !self.archivos.is_empty(), boton_sec(tr("Clear", "Vaciar"))).clicked() {
                self.archivos.clear();
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(libre, boton_sec(&tfmt(tr("Output: {}", "Salida: {}"), &[acortar(&self.salida.display().to_string(), 22)])))
                    .on_hover_text(self.salida.display().to_string())
                    .clicked()
                {
                    if let Some(d) = rfd::FileDialog::new().pick_folder() {
                        self.salida = d;
                    }
                }
            });
        });
        ui.add_space(12.0);
    }

    fn tarjetas_ui(&mut self, ui: &mut Ui) {
        let (bloques, pendientes) = resumen_arbol(&self.arbol);
        let capas = self.por_capa.len();
        let avisos: usize = self.audit.iter().map(|(_, _, h)| h.len()).sum();
        let datos = [
            (tr("Blocks", "Bloques"), bloques, acento(), false, false),
            (tr("Layers", "Capas"), capas, acento(), false, false),
            (tr("Warnings", "Avisos"), avisos, naranja(), avisos > 0, false),
            (tr("Pending", "Pendientes"), pendientes, if pendientes > 0 { rojo() } else { verde() }, pendientes > 0, self.solo_pendientes),
        ];
        let mut pulsado = None;
        ui.columns(4, |c| {
            for (i, (et, val, col, alerta, activo)) in datos.iter().enumerate() {
                if stat_card(&mut c[i], et, *val, *col, *alerta, *activo) {
                    pulsado = Some(i);
                }
            }
        });
        match pulsado {
            Some(3) => self.solo_pendientes = !self.solo_pendientes,
            Some(_) => self.solo_pendientes = false,
            None => {}
        }
    }

    fn panel_arbol(&mut self, ui: &mut Ui) {
        encabezado_panel(ui, if self.solo_pendientes { tr("LAYER TREE · PENDING", "ÁRBOL · PENDIENTES") } else { tr("LAYER TREE", "ÁRBOL DE CAPAS") });
        if self.arbol.is_empty() {
            vacio(ui, if self.analizando() { tr("Decomposing…", "Descomponiendo…") } else { tr("No data yet", "Sin datos todavía") });
            return;
        }
        let mut nueva = None;
        let solo = self.solo_pendientes;
        egui::ScrollArea::vertical().id_salt("arbol2").auto_shrink([false, false]).show(ui, |ui| {
            if solo {
                let mut flat = Vec::new();
                recoge_pendientes(&self.arbol, &mut Vec::new(), &mut flat);
                if flat.is_empty() {
                    vacio(ui, tr("No pending blocks", "Sin bloques pendientes"));
                }
                for (ruta, n) in flat {
                    let elegido = self.seleccion.as_ref() == Some(&ruta);
                    let txt = RichText::new(format!("⚠ [{}] {} · {}", codigo_tipo(n.tipo), n.nombre, humano(n.tamano)))
                        .font(mono(12.0))
                        .color(if elegido { fondo() } else { rojo() })
                        .background_color(if elegido { rojo() } else { Color32::TRANSPARENT });
                    if ui.add(egui::Label::new(txt).sense(Sense::click())).clicked() {
                        nueva = Some(ruta.clone());
                    }
                }
            } else {
                for (i, n) in self.arbol.iter().enumerate() {
                    arbol_nodo(ui, n, vec![i], &self.seleccion, &mut nueva);
                }
            }
        });
        if let Some(s) = nueva {
            self.seleccion = Some(s);
        }
    }

    fn panel_lista(&mut self, ui: &mut Ui) {
        // Breadcrumb del contenedor seleccionado.
        let sel = self.seleccion.clone();
        let ruta_txt = sel
            .as_ref()
            .and_then(|s| buscar_nodo(&self.arbol, s).map(|n| n.nombre.clone()))
            .unwrap_or_else(|| self.arbol.first().map(|n| n.nombre.clone()).unwrap_or_default());
        ui.horizontal(|ui| {
            dibujar_icono(&ui.painter().clone(), ui.cursor().left_center() + Vec2::new(7.0, 9.0), 7.0, "carpeta", acento());
            ui.add_space(18.0);
            ui.label(RichText::new(tr("CONTENTS", "CONTENIDO")).font(titulo(12.5)).color(morado_claro()));
            ui.label(RichText::new(format!("· {}", acortar(&ruta_txt, 22))).font(FontId::proportional(11.5)).color(morado_medio()));
        });
        ui.add_space(4.0);
        let y = ui.cursor().top();
        ui.painter().line_segment([Pos2::new(ui.max_rect().left(), y), Pos2::new(ui.max_rect().right(), y)], Stroke::new(1.0, morado()));
        ui.add_space(6.0);

        // Nodo cuyos hijos se muestran (la selección, o la raíz).
        let base = sel.clone().filter(|s| buscar_nodo(&self.arbol, s).map(|n| !n.hijos.is_empty()).unwrap_or(false));
        let (origen, nodo) = match &base {
            Some(s) => (s.clone(), buscar_nodo(&self.arbol, s).cloned()),
            None => (vec![], None),
        };
        let hijos: Vec<(Vec<usize>, Nodo)> = match &nodo {
            Some(n) => n.hijos.iter().enumerate().map(|(i, h)| { let mut r = origen.clone(); r.push(i); (r, h.clone()) }).collect(),
            None => self.arbol.iter().enumerate().map(|(i, h)| (vec![i], h.clone())).collect(),
        };
        let q = self.buscar.trim().to_lowercase();
        let filtradas: Vec<_> = hijos.into_iter().filter(|(_, h)| {
            (!self.solo_pendientes || h.incompleto) && (q.is_empty() || h.nombre.to_lowercase().contains(&q) || codigo_tipo(h.tipo).to_lowercase().contains(&q))
        }).collect();

        // Cabecera de columnas.
        let w = ui.available_width();
        let (cx_tipo, cx_tam, cx_est) = (w * 0.50, w * 0.66, w * 0.80);
        ui.horizontal(|ui| {
            let (hr, _) = ui.allocate_exact_size(Vec2::new(w, 18.0), Sense::hover());
            let p = ui.painter().clone();
            let fid = FontId::proportional(10.5);
            p.text(Pos2::new(hr.left() + 8.0, hr.center().y), Align2::LEFT_CENTER, tr("Name", "Nombre"), fid.clone(), morado_medio());
            p.text(Pos2::new(hr.left() + cx_tipo, hr.center().y), Align2::LEFT_CENTER, tr("Type", "Tipo"), fid.clone(), morado_medio());
            p.text(Pos2::new(hr.left() + cx_tam, hr.center().y), Align2::LEFT_CENTER, tr("Size", "Tamaño"), fid.clone(), morado_medio());
            p.text(Pos2::new(hr.left() + cx_est, hr.center().y), Align2::LEFT_CENTER, tr("Status", "Estado"), fid, morado_medio());
        });
        ui.add_space(2.0);

        if filtradas.is_empty() {
            vacio(ui, if self.buscar.is_empty() { tr("No items here", "Sin elementos aquí") } else { tr("No matches", "Sin coincidencias") });
            return;
        }
        let mut nueva = None;
        egui::ScrollArea::vertical().id_salt("tabla").auto_shrink([false, false]).show(ui, |ui| {
            for (ruta, h) in &filtradas {
                let elegido = self.seleccion.as_ref() == Some(ruta);
                let (row, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 30.0), Sense::click());
                let p = ui.painter().clone();
                if elegido {
                    p.rect_filled(row, CornerRadius::same(6), acento().gamma_multiply(0.22));
                    p.rect_filled(Rect::from_min_size(row.left_top(), Vec2::new(2.5, row.height())), CornerRadius::same(2), acento());
                } else if resp.hovered() {
                    p.rect_filled(row, CornerRadius::same(6), morado().gamma_multiply(0.55));
                }
                dibujar_icono(&p, Pos2::new(row.left() + 16.0, row.center().y), 7.0, icono_tipo(h.tipo), if elegido { acento() } else { color_tipo(h.tipo) });
                let fid = FontId::proportional(12.5);
                p.text(Pos2::new(row.left() + 30.0, row.center().y), Align2::LEFT_CENTER, acortar(&h.nombre, 28), fid.clone(), texto());
                p.text(Pos2::new(row.left() + cx_tipo, row.center().y), Align2::LEFT_CENTER, codigo_tipo(h.tipo), FontId::monospace(11.0), morado_claro());
                p.text(Pos2::new(row.left() + cx_tam, row.center().y), Align2::LEFT_CENTER, humano(h.tamano), FontId::monospace(11.0), morado_claro());
                // Chip de estado.
                let (et, ec) = estado_etiqueta(h.confianza, h.incompleto);
                let g = p.layout_no_wrap(et.to_string(), FontId::proportional(10.5), ec);
                let chip_rect = Rect::from_min_size(Pos2::new(row.left() + cx_est, row.center().y - 9.0), Vec2::new(g.size().x + 20.0, 18.0));
                p.rect_filled(chip_rect, CornerRadius::same(9), ec.gamma_multiply(0.18));
                p.circle_filled(Pos2::new(chip_rect.left() + 9.0, chip_rect.center().y), 2.6, ec);
                p.galley(Pos2::new(chip_rect.left() + 15.0, chip_rect.center().y - g.size().y / 2.0), g, ec);
                if resp.clicked() {
                    nueva = Some(ruta.clone());
                }
            }
        });
        if let Some(s) = nueva {
            self.seleccion = Some(s);
        }
    }

    fn panel_detalle(&mut self, ui: &mut Ui) {
        encabezado_panel(ui, tr("BLOCK DETAILS", "FICHA DEL BLOQUE"));
        let Some(sel) = self.seleccion.clone() else {
            vacio(ui, tr("No block selected", "Ningún bloque seleccionado"));
            return;
        };
        let Some(n) = buscar_nodo(&self.arbol, &sel) else { return };
        let n = n.clone();
        let mut abrir = None;
        let alto = (ui.available_height() - 132.0).max(140.0);
        egui::ScrollArea::vertical().id_salt("detalle").max_height(alto).auto_shrink([false, false]).show(ui, |ui| {
            ui.label(RichText::new(&n.nombre).font(titulo(18.0)).color(color_tipo(n.tipo)));
            ui.horizontal(|ui| {
                chip(ui, n.confianza.etiqueta(), color_confianza(n.confianza));
                if n.incompleto {
                    chip(ui, tr("PENDING", "PENDIENTE"), rojo());
                }
            });
            ui.add_space(8.0);
            egui::Grid::new("detalle_grid").num_columns(2).spacing([10.0, 3.0]).show(ui, |ui| {
                for (k, v) in [
                    (tr("Layer", "Capa"), n.capa.to_string()),
                    (tr("Type", "Tipo"), n.descripcion.clone()),
                    (tr("Size", "Tamaño"), humano(n.tamano)),
                    (tr("Entropy", "Entropía"), format!("{:.3} bits/byte", n.entropia)),
                    ("SHA-256", n.sha256.chars().take(32).collect()),
                    ("", n.sha256.chars().skip(32).collect()),
                ] {
                    ui.label(RichText::new(k).font(mono(11.0)).color(morado_claro()));
                    ui.label(RichText::new(v).font(mono(11.0)).color(texto()));
                    ui.end_row();
                }
            });
            barra_segmentada(ui, (n.entropia / 8.0) as f32, if n.entropia > 7.5 { rojo() } else { verde() });

            ui.add_space(10.0);
            ui.label(RichText::new(tr("PREVIEW", "VISTA PREVIA")).font(mono(10.0)).color(morado_claro()));
            egui::Frame::new().fill(hondo()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(10)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                let mut algo = false;
                if !n.descripcion.is_empty() {
                    ui.label(RichText::new(&n.descripcion).font(mono(11.0)).color(texto()));
                    algo = true;
                }
                if !n.evidencia.is_empty() {
                    ui.label(RichText::new(&n.evidencia).font(mono(10.5)).color(morado_claro()));
                    algo = true;
                }
                if !algo {
                    ui.label(RichText::new(tr("no preview available", "sin vista previa")).font(mono(10.0)).color(morado_medio()));
                }
            });

            if !n.resultados.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new(tr("RESULTS", "RESULTADOS")).font(mono(10.0)).color(naranja()));
                for r in &n.resultados {
                    let corto = r.rsplit('/').next().unwrap_or(r);
                    if ui.add(egui::Label::new(RichText::new(format!("▸ {corto}")).font(mono(11.0)).color(acento())).sense(Sense::click())).on_hover_text(r).clicked() {
                        abrir = Some(r.clone());
                    }
                }
            }
        });
        if let Some(r) = abrir {
            self.abrir_resultado(&r);
        }

        ui.add_space(6.0);
        let sep = ui.cursor().top();
        ui.painter().line_segment([Pos2::new(ui.max_rect().left(), sep), Pos2::new(ui.max_rect().right(), sep)], Stroke::new(1.0, morado()));
        ui.add_space(8.0);
        let ancho = ui.available_width();
        ui.horizontal(|ui| {
            if ui.add(boton_pri(tr("▶ Extract", "▶ Extraer"), acento()).min_size(Vec2::new(ancho * 0.56, 36.0))).clicked() {
                if let Some(raiz) = self.raiz.clone() {
                    abrir_en_sistema(&raiz.join("extraidos"));
                } else if let Some(r) = n.resultados.first() {
                    self.abrir_resultado(r);
                }
            }
            if n.tipo == Tipo::Texto || !n.resultados.is_empty() {
                if ui.add(boton_sec(tr("Preview", "Vista previa"))).clicked() {
                    if let Some(r) = n.resultados.first() {
                        self.abrir_resultado(r);
                    }
                }
            }
        });
        ui.add_space(6.0);
        if ui
            .add(boton_sec(tr("Ask an AI", "Preguntar a una IA")).min_size(Vec2::new(ui.available_width(), 34.0)))
            .on_hover_text(tr("Copies a local prompt to the clipboard — no connection.", "Copia un prompt local al portapapeles — sin conexión."))
            .clicked()
        {
            let ahora = ui.input(|i| i.time);
            ui.ctx().copy_text(prompt_ia(&n));
            self.log(ahora, tr("AI prompt copied to clipboard (offline).", "Prompt para IA copiado al portapapeles (sin conexión).").into(), acento());
        }
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(tr("Optional · disabled", "Opcional · desactivada")).font(FontId::proportional(10.5)).color(morado_medio()));
        });
    }

    // ── Inicio ───────────────────────────────────────────────────────────
    fn vista_inicio(&mut self, ui: &mut Ui) {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::new(340.0, 72.0), Sense::hover());
                let p = ui.painter().clone();
                marca_capas(&p, Pos2::new(r.left() + 26.0, r.center().y), 22.0, acento());
                p.text(Pos2::new(r.left() + 64.0, r.center().y), Align2::LEFT_CENTER, "CAPAS", titulo(44.0), texto());
            });
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(tr("Explore and reverse-engineer any file, layer by layer — fully local.", "Explora y haz ingeniería inversa de cualquier archivo, capa a capa — 100% local.")).font(FontId::proportional(14.5)).color(morado_claro()));
            });
            ui.add_space(22.0);
            self.zona_carga(ui);
            ui.add_space(16.0);
            ui.columns(3, |c| {
                tarjeta_info(&mut c[0], "capas", tr("Layered decomposition", "Descomposición por capas"), tr("Unpacks archives, disk images, binaries and engine bundles recursively.", "Desempaqueta archivos, imágenes de disco, binarios y bundles de motor de forma recursiva."));
                tarjeta_info(&mut c[1], "lupa", tr("Identifies everything", "Lo identifica todo"), tr("200+ formats from every platform, each with a confidence level.", "200+ formatos de todas las plataformas, cada uno con su nivel de confianza."));
                tarjeta_info(&mut c[2], "monitor", tr("Fully local", "100% local"), tr("Nothing leaves your machine. No account, no connection required.", "Nada sale de tu equipo. Sin cuenta ni conexión."));
            });
            if !self.arbol.is_empty() {
                ui.add_space(14.0);
                egui::Frame::new().fill(morado_oscuro()).stroke(Stroke::new(1.0, morado())).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(14)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let (bloques, pend) = resumen_arbol(&self.arbol);
                        ui.label(RichText::new(tr("Last analysis", "Último análisis")).font(titulo(14.0)).color(texto()));
                        ui.label(RichText::new(tfmt(tr("· {} blocks · {} layers · {} pending", "· {} bloques · {} capas · {} pendientes"), &[bloques.to_string(), self.por_capa.len().to_string(), pend.to_string()])).font(FontId::proportional(12.5)).color(morado_claro()));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.add(boton_pri(tr("View analysis", "Ver análisis"), acento())).clicked() {
                                self.vista = Vista::Analisis;
                            }
                        });
                    });
                });
            }
        });
    }

    // ── Explorador ───────────────────────────────────────────────────────
    fn vista_explorador(&mut self, ui: &mut Ui) {
        titulo_vista(ui, "carpeta", tr("Explorer", "Explorador"), tr("Browse the extracted output on disk.", "Navega por la salida extraída en disco."));
        let Some(raiz) = self.raiz.clone() else {
            panel_vacio(ui, "carpeta", tr("Nothing to explore yet", "Nada que explorar aún"), tr("Run an analysis and its extracted files will appear here.", "Analiza algo y los archivos extraídos aparecerán aquí."));
            return;
        };
        let destino = { let e = raiz.join("extraidos"); if e.is_dir() { e } else { raiz.clone() } };
        ui.horizontal(|ui| {
            ui.label(RichText::new(acortar(&destino.display().to_string(), 70)).font(mono(11.0)).color(morado_claro()));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(boton_sec(tr("Open in system", "Abrir en el sistema"))).clicked() {
                    abrir_en_sistema(&destino);
                }
            });
        });
        ui.add_space(8.0);
        egui::Frame::new().fill(morado_oscuro()).stroke(Stroke::new(1.0, morado())).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(12)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                arbol_disco(ui, &destino, 0);
            });
        });
    }

    // ── Comparar ─────────────────────────────────────────────────────────
    fn vista_comparar(&mut self, ui: &mut Ui) {
        titulo_vista(ui, "comparar", tr("Compare", "Comparar"), tr("Diff two analyses to see what changed between versions.", "Compara dos análisis para ver qué cambió entre versiones."));
        if !crate::edicion::permite(crate::edicion::COMPARAR) {
            tarjeta_pro(ui, tr("Compare is a CAPAS Pro feature.", "Comparar es una función de CAPAS Pro."), &mut self.vista);
            return;
        }
        ui.label(RichText::new(tr("Pick two output folders (each containing informe.json).", "Elige dos carpetas de salida (cada una con su informe.json).")).font(FontId::proportional(12.5)).color(morado_claro()));
        ui.add_space(8.0);
        let mut lanzar = false;
        ui.horizontal(|ui| {
            if ui.add(boton_sec(tr("Folder A…", "Carpeta A…"))).clicked() {
                if let Some(d) = rfd::FileDialog::new().pick_folder() { self.cmp_a = Some(d); }
            }
            ui.label(RichText::new(self.cmp_a.as_ref().map(|p| acortar(&p.display().to_string(), 30)).unwrap_or_else(|| "—".into())).font(mono(10.5)).color(morado_claro()));
        });
        ui.horizontal(|ui| {
            if ui.add(boton_sec(tr("Folder B…", "Carpeta B…"))).clicked() {
                if let Some(d) = rfd::FileDialog::new().pick_folder() { self.cmp_b = Some(d); }
            }
            ui.label(RichText::new(self.cmp_b.as_ref().map(|p| acortar(&p.display().to_string(), 30)).unwrap_or_else(|| "—".into())).font(mono(10.5)).color(morado_claro()));
        });
        ui.add_space(8.0);
        if ui.add_enabled(self.cmp_a.is_some() && self.cmp_b.is_some(), boton_pri(tr("▶ Compare", "▶ Comparar"), acento())).clicked() {
            lanzar = true;
        }
        if lanzar {
            if let (Some(a), Some(b)) = (self.cmp_a.clone(), self.cmp_b.clone()) {
                self.cmp_resultado = Some(comparar_salidas(&a, &b));
            }
        }
        if let Some((nuevos, quitados, comunes)) = &self.cmp_resultado {
            ui.add_space(12.0);
            egui::Frame::new().fill(morado_oscuro()).stroke(Stroke::new(1.0, morado())).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(14)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    chip(ui, &tfmt(tr("+{} added", "+{} nuevos"), &[nuevos.len().to_string()]), verde());
                    chip(ui, &tfmt(tr("-{} removed", "-{} quitados"), &[quitados.len().to_string()]), rojo());
                    chip(ui, &tfmt(tr("{} shared", "{} comunes"), &[comunes.to_string()]), morado_claro());
                });
                ui.add_space(8.0);
                egui::ScrollArea::vertical().max_height(360.0).auto_shrink([false, false]).show(ui, |ui| {
                    for n in nuevos {
                        ui.label(RichText::new(format!("+ {n}")).font(mono(11.0)).color(verde()));
                    }
                    for q in quitados {
                        ui.label(RichText::new(format!("- {q}")).font(mono(11.0)).color(rojo()));
                    }
                });
            });
        }
    }

    // ── Ajustes ──────────────────────────────────────────────────────────
    fn vista_ajustes(&mut self, ui: &mut Ui) {
        titulo_vista(ui, "engranaje", tr("Settings", "Ajustes"), tr("Appearance, language and license.", "Apariencia, idioma y licencia."));
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.set_max_width(680.0);
            // Apariencia (máscaras).
            tarjeta_ajuste(ui, tr("Appearance", "Apariencia"), |ui| {
                ui.label(RichText::new(tr("Mask", "Máscara")).font(FontId::proportional(12.0)).color(morado_claro()));
                ui.add_space(4.0);
                let temas = [(4u8, tr("Serious", "Serio")), (3, tr("Clean", "Limpio")), (0, tr("Serene", "Sereno")), (2, tr("Neutral", "Neutro")), (1, tr("Command", "Mando"))];
                ui.horizontal_wrapped(|ui| {
                    for (idx, nombre) in temas {
                        let activo = self.tema == idx;
                        let b = egui::Button::new(RichText::new(nombre).font(FontId::proportional(12.5)).color(if activo { Color32::from_rgb(0xf6, 0xf7, 0xfb) } else { morado_claro() }))
                            .fill(if activo { acento() } else { morado() })
                            .corner_radius(CornerRadius::same(7))
                            .min_size(Vec2::new(0.0, 32.0));
                        if ui.add(b).clicked() {
                            self.tema = idx;
                            TEMA.store(idx, Ordering::Relaxed);
                            aplicar_visuals(&ui.ctx().clone());
                        }
                    }
                });
                ui.add_space(10.0);
                ui.label(RichText::new(tr("Language", "Idioma")).font(FontId::proportional(12.0)).color(morado_claro()));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let es = crate::idioma::es();
                    for (lab, val) in [("English", false), ("Español", true)] {
                        let activo = es == val;
                        let b = egui::Button::new(RichText::new(lab).font(FontId::proportional(12.5)).color(if activo { Color32::from_rgb(0xf6, 0xf7, 0xfb) } else { morado_claro() }))
                            .fill(if activo { acento() } else { morado() })
                            .corner_radius(CornerRadius::same(7))
                            .min_size(Vec2::new(0.0, 32.0));
                        if ui.add(b).clicked() {
                            crate::idioma::set_es(val);
                        }
                    }
                });
            });
            ui.add_space(12.0);
            // Licencia / edición.
            tarjeta_ajuste(ui, tr("License", "Licencia"), |ui| {
                let ed = crate::edicion::actual();
                ui.horizontal(|ui| {
                    let (rid, _) = ui.allocate_exact_size(Vec2::splat(9.0), Sense::hover());
                    ui.painter().circle_filled(rid.center(), 3.5, if ed == crate::edicion::Edicion::Core { morado_claro() } else { acento() });
                    ui.label(RichText::new(tfmt(tr("Current edition: CAPAS {}", "Edición actual: CAPAS {}"), &[ed.nombre().to_string()])).font(FontId::proportional(13.0)).color(texto()));
                });
                if ed == crate::edicion::Edicion::Core {
                    ui.add_space(6.0);
                    ui.label(RichText::new(tr("Activate with your key (paste CAPAS-…):", "Activa con tu clave (pega CAPAS-…):")).font(FontId::proportional(12.0)).color(morado_claro()));
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.clave_lic).font(mono(11.5)).desired_width(280.0).hint_text("CAPAS-..."));
                        if ui.add(boton_pri(tr("Activate", "Activar"), acento())).clicked() {
                            match crate::licencia::verificar_clave(self.clave_lic.trim()) {
                                Ok(e) => {
                                    crate::edicion::set(e);
                                    self.lic_estado = Some(tfmt(tr("Activated: CAPAS {}", "Activado: CAPAS {}"), &[e.nombre().to_string()]));
                                }
                                Err(m) => self.lic_estado = Some(tfmt(tr("Rejected: {}", "Rechazada: {}"), &[m])),
                            }
                        }
                    });
                }
                if let Some(msg) = &self.lic_estado {
                    let col = if crate::edicion::actual() == crate::edicion::Edicion::Core { rojo() } else { verde() };
                    ui.label(RichText::new(msg).font(FontId::proportional(11.5)).color(col));
                }
            });
            ui.add_space(12.0);
            // Actualizaciones.
            tarjeta_ajuste(ui, tr("Updates", "Actualizaciones"), |ui| {
                ui.label(RichText::new(tfmt(tr("Installed version: v{}", "Versión instalada: v{}"), &[VERSION.to_string()])).font(FontId::proportional(13.0)).color(texto()));
                ui.add_space(8.0);
                let estado = self.actualizacion.lock().unwrap().clone();
                ui.horizontal(|ui| {
                    let comprobando = matches!(estado, Some(Act::Comprobando));
                    if ui.add_enabled(!comprobando, boton_pri(tr("Check for updates", "Buscar actualizaciones"), acento())).clicked() {
                        let arc = self.actualizacion.clone();
                        *arc.lock().unwrap() = Some(Act::Comprobando);
                        std::thread::spawn(move || {
                            let r = comprobar_actualizacion();
                            *arc.lock().unwrap() = Some(r);
                        });
                    }
                    match &estado {
                        Some(Act::Comprobando) => {
                            ui.label(RichText::new(tr("Checking…", "Comprobando…")).font(FontId::proportional(12.0)).color(morado_claro()));
                        }
                        Some(Act::Disponible(v)) => {
                            if ui.add(boton_pri(&tfmt(tr("↓ Download v{}", "↓ Descargar v{}"), &[v.clone()]), verde())).clicked() {
                                abrir_en_sistema(Path::new(URL_RELEASES));
                            }
                        }
                        Some(Act::AlDia) => {
                            ui.label(RichText::new(tr("You're up to date.", "Estás al día.")).font(FontId::proportional(12.5)).color(verde()));
                        }
                        Some(Act::Error) => {
                            ui.label(RichText::new(tr("Couldn't check (no releases or no connection).", "No se pudo comprobar (sin releases o sin conexión).")).font(FontId::proportional(12.0)).color(naranja()));
                        }
                        None => {}
                    }
                });
                if let Some(Act::Disponible(v)) = &estado {
                    ui.add_space(4.0);
                    ui.label(RichText::new(tfmt(tr("Update available: v{}", "Actualización disponible: v{}"), &[v.clone()])).font(titulo(13.0)).color(acento()));
                }
                ui.add_space(4.0);
                ui.label(RichText::new(tr("Checks GitHub once, only when you press the button.", "Consulta GitHub una vez, solo al pulsar el botón.")).font(FontId::proportional(10.5)).color(morado_medio()));
            });
        });
    }

    fn visor_ui(&mut self, ui: &mut Ui) {
        let mut cerrar = false;
        let Some(v) = &self.visor else { return };
        seccion(ui, "V", tr("ANALYSIS VIEWER", "VISOR DE ANÁLISIS"), naranja(), |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(acortar(&v.titulo, ((ui.available_width() - 260.0) / 7.3).max(10.0) as usize)).font(mono(12.0)).color(naranja()))
                    .on_hover_text(&v.titulo);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(boton(tr("CLOSE", "CERRAR"), naranja())).clicked() {
                        cerrar = true;
                    }
                    ui.label(
                        RichText::new(tfmt(tr("{} LINES{}","{} LÍNEAS{}"), &[v.lineas.len().to_string(), if v.truncado { tr(" · TRUNCATED AT 4 MiB", " · TRUNCADO A 4 MiB").to_string() } else { String::new() }]))
                            .font(mono(10.0))
                            .color(morado_claro()),
                    );
                });
            });
            let alto_fila = 16.0;
            egui::Frame::new().fill(hondo()).inner_margin(Margin::same(6)).show(ui, |ui| {
                egui::ScrollArea::both().id_salt("visor").auto_shrink([false, false]).show_rows(
                    ui,
                    alto_fila,
                    v.lineas.len(),
                    |ui, rango| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        for i in rango {
                            let mut job = egui::text::LayoutJob::default();
                            let fmt = |c| egui::TextFormat { font_id: mono(12.0), color: c, ..Default::default() };
                            job.append(&format!("{:>6}  ", i + 1), 0.0, fmt(morado_medio()));
                            job.append(&v.lineas[i], 0.0, fmt(color_linea(&v.lineas[i])));
                            fila(ui, alto_fila, egui::Label::new(job).extend());
                        }
                    },
                );
            });
        });
        if cerrar {
            self.visor = None;
        }
    }

    fn estratos_ui(&mut self, ui: &mut Ui) {
        if !self.arbol.is_empty() {
            let mut conf: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
            cuenta_conf(&self.arbol, &mut conf);
            let total: usize = conf.values().sum();
            seccion(ui, "I", tr("CONFIDENCE", "CONFIANZA"), acento(), |ui| {
                for c in Confianza::TODAS {
                    let n = conf.get(c.clave()).copied().unwrap_or(0);
                    if n == 0 {
                        continue;
                    }
                    let col = color_confianza(c);
                    ui.horizontal(|ui| {
                        let (r, p) = ui.allocate_painter(Vec2::new(ui.available_width(), 15.0), Sense::hover());
                        let rr = r.rect;
                        let w = (n as f32 / total.max(1) as f32) * (rr.width() * 0.45);
                        p.rect_filled(Rect::from_min_size(rr.left_top(), Vec2::new(w, rr.height())), 0.0, col.gamma_multiply(0.5));
                        p.text(rr.left_center() + Vec2::new(4.0, 0.0), Align2::LEFT_CENTER, c.etiqueta(), mono(11.0), col);
                        p.text(rr.right_center() - Vec2::new(4.0, 0.0), Align2::RIGHT_CENTER, n.to_string(), mono(11.0), texto());
                    });
                }
            });
        }
        if !self.audit.is_empty() {
            seccion(ui, "H", tr("PACKAGE AUDIT", "AUDITORÍA DE PAQUETES"), naranja(), |ui| {
                for (nombre, veredicto, hallazgos) in &self.audit {
                    let c = color_veredicto(*veredicto);
                    ui.horizontal(|ui| {
                        let (r, p) = ui.allocate_painter(Vec2::new(96.0, 18.0), Sense::hover());
                        let rr = r.rect;
                        p.rect_filled(rr, 0.0, c.gamma_multiply(0.22));
                        p.rect_stroke(rr, 0.0, Stroke::new(1.0, c), StrokeKind::Inside);
                        p.text(rr.center(), Align2::CENTER_CENTER, veredicto.etiqueta(), titulo(12.0), c);
                        ui.add(egui::Label::new(RichText::new(acortar(nombre, 28)).font(mono(12.0)).color(texto())).truncate());
                    });
                    for (nivel, texto) in hallazgos {
                        let marca = if *nivel == Nivel::Rechazo { "⛔" } else { "⚠" };
                        ui.label(RichText::new(format!("   {marca} {texto}")).font(mono(10.0)).color(if *nivel == Nivel::Rechazo { rojo() } else { naranja() }));
                    }
                }
                if ui.add(boton(tr("▸ OPEN auditoria.md", "▸ ABRIR auditoria.md"), acento())).clicked() {
                    self.abrir_resultado("auditoria.md");
                }
            });
        }
        if !self.clasif.is_empty() {
            seccion(ui, "G", tr("CLASSIFICATION", "CLASIFICACIÓN"), morado_claro(), |ui| {
                let total: usize = self.clasif.iter().map(|(_, n)| *n).sum();
                let max = self.clasif.iter().map(|(_, n)| *n).max().unwrap_or(1).max(1) as f32;
                for (cat, n) in &self.clasif {
                    let c = color_categoria(*cat);
                    ui.horizontal(|ui| {
                        let (r, p) = ui.allocate_painter(Vec2::new(ui.available_width(), 15.0), Sense::hover());
                        let rr = r.rect;
                        let w = (*n as f32 / max) * (rr.width() * 0.45);
                        p.rect_filled(Rect::from_min_size(rr.left_top(), Vec2::new(w, rr.height())), 0.0, c.gamma_multiply(0.5));
                        p.text(rr.left_center() + Vec2::new(4.0, 0.0), Align2::LEFT_CENTER, cat.etiqueta(), mono(11.0), c);
                        p.text(rr.right_center() - Vec2::new(4.0, 0.0), Align2::RIGHT_CENTER, n.to_string(), mono(11.0), texto());
                    });
                }
                ui.add_space(2.0);
                if ui.add(boton(&tfmt(tr("▸ OPEN extraidos/ ({} files)","▸ ABRIR extraidos/ ({} archivos)"), &[total.to_string()]), acento())).clicked() {
                    if let Some(raiz) = &self.raiz {
                        abrir_en_sistema(&raiz.join("extraidos"));
                    }
                }
            });
        }
        let alto_arbol = (ui.available_height() * 0.55).max(180.0);
        seccion(ui, "E", tr("LAYER TREE", "ÁRBOL DE ESTRATOS"), acento(), |ui| {
            if self.arbol.is_empty() {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new(if self.analizando() { tr("DECOMPOSING…", "DESCOMPONIENDO…") } else { tr("NO DATA", "SIN DATOS") })
                            .font(titulo(22.0))
                            .color(morado_medio()),
                    );
                });
                ui.add_space(20.0);
                return;
            }
            let mut nueva = None;
            egui::ScrollArea::vertical().id_salt("arbol").max_height(alto_arbol).auto_shrink([false, true]).show(ui, |ui| {
                for (i, n) in self.arbol.iter().enumerate() {
                    arbol_nodo(ui, n, vec![i], &self.seleccion, &mut nueva);
                }
            });
            if let Some(s) = nueva {
                self.seleccion = Some(s);
            }
        });

        let Some(sel) = self.seleccion.clone() else { return };
        let Some(n) = buscar_nodo(&self.arbol, &sel) else { return };
        let n = n.clone();
        let mut abrir = None;
        seccion(ui, "F", tr("BLOCK DETAILS", "FICHA DEL BLOQUE"), naranja(), |ui| {
            egui::ScrollArea::vertical().id_salt("ficha").show(ui, |ui| {
                ui.label(RichText::new(&n.nombre).font(titulo(18.0)).color(color_tipo(n.tipo)));
                ui.horizontal(|ui| {
                    let c = color_confianza(n.confianza);
                    let (r, p) = ui.allocate_painter(Vec2::new(108.0, 18.0), Sense::hover());
                    let rr = r.rect;
                    p.rect_filled(rr, 0.0, c.gamma_multiply(0.22));
                    p.rect_stroke(rr, 0.0, Stroke::new(1.0, c), StrokeKind::Inside);
                    p.text(rr.center(), Align2::CENTER_CENTER, n.confianza.etiqueta(), titulo(12.0), c);
                    ui.add(egui::Label::new(RichText::new(&n.evidencia).font(mono(10.0)).color(morado_claro())).truncate());
                });
                egui::Grid::new("ficha_grid").num_columns(2).spacing([10.0, 2.0]).show(ui, |ui| {
                    for (k, v) in [
                        (tr("CONFIDENCE", "CONFIANZA"), n.confianza.etiqueta().to_string()),
                        (tr("LAYER", "CAPA"), n.capa.to_string()),
                        (tr("TYPE", "TIPO"), n.descripcion.clone()),
                        (tr("SIZE", "TAMAÑO"), humano(n.tamano)),
                        (tr("ENTROPY", "ENTROPÍA"), format!("{:.3} bits/byte", n.entropia)),
                        ("SHA-256", n.sha256[..32].to_string()),
                        ("", n.sha256[32..].to_string()),
                    ] {
                        ui.label(RichText::new(k).font(mono(11.0)).color(morado_claro()));
                        ui.label(RichText::new(v).font(mono(11.0)).color(texto()));
                        ui.end_row();
                    }
                });
                barra_segmentada(ui, (n.entropia / 8.0) as f32, if n.entropia > 7.5 { rojo() } else { verde() });
                if !n.resultados.is_empty() {
                    ui.add_space(4.0);
                    ui.label(RichText::new(tr("RESULTS", "RESULTADOS")).font(mono(11.0)).color(naranja()));
                    for r in &n.resultados {
                        let corto = r.rsplit('/').next().unwrap_or(r);
                        if ui.add(boton(&format!("▸ {corto}"), acento())).on_hover_text(r).clicked() {
                            abrir = Some(r.clone());
                        }
                    }
                }
                if !n.notas.is_empty() {
                    ui.add_space(4.0);
                    ui.label(RichText::new(tr("ALERTS", "ALERTAS")).font(mono(11.0)).color(rojo()));
                    for nota in &n.notas {
                        ui.label(RichText::new(format!("⚠ {nota}")).font(mono(11.0)).color(naranja()));
                    }
                }
                if ui.add(boton(tr("OPEN BLOCK FOLDER", "ABRIR CARPETA DEL BLOQUE"), morado_claro())).clicked() {
                    if let Some(raiz) = &self.raiz {
                        abrir_en_sistema(&raiz.join(&n.directorio));
                    }
                }
            });
        });
        if let Some(r) = abrir {
            self.abrir_resultado(&r);
        }
    }

    fn barra_estado_ui(&mut self, ui: &mut Ui) {
        // Línea superior sutil que separa la barra del registro.
        let top = ui.max_rect();
        ui.painter().line_segment(
            [Pos2::new(top.left() - 12.0, top.top() - 4.0), Pos2::new(top.right() + 12.0, top.top() - 4.0)],
            Stroke::new(1.0, morado()),
        );
        ui.horizontal_centered(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            // Izquierda: garantía de privacidad (monitor + local/offline).
            dibujar_icono(&ui.painter().clone(), ui.cursor().left_center() + Vec2::new(8.0, 0.0), 7.0, "monitor", morado_claro());
            ui.add_space(18.0);
            let (rid, _) = ui.allocate_exact_size(Vec2::splat(9.0), egui::Sense::hover());
            ui.painter().circle_filled(rid.center(), 4.0, verde());
            ui.label(RichText::new(tr("Local analysis · Offline", "Análisis local · Sin conexión")).font(FontId::proportional(11.5)).color(morado_claro()));

            // Centro/resumen del análisis actual.
            if !self.arbol.is_empty() {
                let (bloques, pend) = resumen_arbol(&self.arbol);
                let avisos: usize = self.audit.iter().map(|(_, _, h)| h.len()).sum();
                let nombre = self.arbol.first().map(|n| n.nombre.clone()).unwrap_or_default();
                ui.label(RichText::new("·").font(FontId::proportional(11.5)).color(morado_medio()));
                ui.label(RichText::new(tfmt(tr("{} · {} files · {} layers · {} warnings · {} pending", "{} · {} archivos · {} capas · {} avisos · {} pendientes"), &[acortar(&nombre, 24), bloques.to_string(), self.por_capa.len().to_string(), avisos.to_string(), pend.to_string()])).font(FontId::proportional(11.5)).color(morado_medio()));
            }

            // Derecha: Ver informe.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.raiz.is_some() {
                    let b = egui::Button::new(RichText::new(tr("View report", "Ver informe")).font(FontId::proportional(11.5)).color(texto()))
                        .fill(morado())
                        .stroke(Stroke::new(1.0, morado_medio()))
                        .corner_radius(CornerRadius::same(6))
                        .min_size(Vec2::new(0.0, 22.0));
                    if ui.add(b).clicked() {
                        self.abrir_resultado("informe.md");
                    }
                }
            });
        });
    }

    fn registro_ui(&mut self, ui: &mut Ui) {
        seccion(ui, ">", tr("OPERATIONS LOG", "REGISTRO DE OPERACIONES"), acento(), |ui| {
            egui::Frame::new().fill(hondo()).inner_margin(Margin::same(6)).show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("log")
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show_rows(ui, 16.0, self.registro.len(), |ui, rango| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        for l in self.registro.range(rango) {
                            let t = RichText::new(format!("[{:>8.2}] {}", l.t, l.texto)).font(mono(11.5)).color(l.color);
                            fila(ui, 16.0, egui::Label::new(t).truncate());
                        }
                    });
            });
        });
    }
}

// ── Árbol ───────────────────────────────────────────────────────────────
fn cuenta_conf(nodos: &[Nodo], conf: &mut std::collections::BTreeMap<&'static str, usize>) {
    for n in nodos {
        *conf.entry(n.confianza.clave()).or_insert(0) += 1;
        cuenta_conf(&n.hijos, conf);
    }
}

fn buscar_nodo<'a>(arbol: &'a [Nodo], ruta: &[usize]) -> Option<&'a Nodo> {
    let mut n = arbol.get(*ruta.first()?)?;
    for &i in &ruta[1..] {
        n = n.hijos.get(i)?;
    }
    Some(n)
}

fn arbol_nodo(ui: &mut Ui, n: &Nodo, ruta: Vec<usize>, sel: &Option<Vec<usize>>, nueva: &mut Option<Vec<usize>>) {
    let elegido = sel.as_ref() == Some(&ruta);
    let c = color_tipo(n.tipo);
    let texto = RichText::new(format!("[{}] {}  · {}", codigo_tipo(n.tipo), n.nombre, humano(n.tamano)))
        .font(mono(12.0))
        .color(if elegido { fondo() } else { c })
        .background_color(if elegido { c } else { Color32::TRANSPARENT });
    if n.hijos.is_empty() {
        ui.horizontal(|ui| {
            ui.add_space(18.0);
            if ui.add(egui::Label::new(texto).sense(Sense::click())).clicked() {
                *nueva = Some(ruta.clone());
            }
        });
    } else {
        let id = ui.make_persistent_id(&n.directorio);
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, n.capa < 3)
            .show_header(ui, |ui| {
                if ui.add(egui::Label::new(texto).sense(Sense::click())).clicked() {
                    *nueva = Some(ruta.clone());
                }
            })
            .body(|ui| {
                for (i, h) in n.hijos.iter().enumerate() {
                    let mut r = ruta.clone();
                    r.push(i);
                    arbol_nodo(ui, h, r, sel, nueva);
                }
            });
    }
}

// ── Piezas del rediseño "Serio" ─────────────────────────────────────────
/// Elemento de la barra lateral; devuelve true al hacer clic.
fn nav_item(ui: &mut Ui, icono: &str, etiqueta: &str, activo: bool) -> bool {
    let alto = 42.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), alto), Sense::click());
    let p = ui.painter().clone();
    if activo {
        p.rect_filled(rect, CornerRadius::same(9), acento().gamma_multiply(0.20));
        p.rect_filled(Rect::from_min_size(rect.left_top(), Vec2::new(3.0, alto)), CornerRadius::same(2), acento());
    } else if resp.hovered() {
        p.rect_filled(rect, CornerRadius::same(9), morado().gamma_multiply(0.6));
    }
    let icol = if activo { acento() } else { morado_claro() };
    let tcol = if activo { texto() } else { morado_claro() };
    dibujar_icono(&p, Pos2::new(rect.left() + 22.0, rect.center().y), 8.0, icono, icol);
    let fuente = if activo { titulo(14.5) } else { FontId::proportional(14.5) };
    p.text(Pos2::new(rect.left() + 42.0, rect.center().y), Align2::LEFT_CENTER, etiqueta, fuente, tcol);
    ui.add_space(5.0);
    resp.clicked()
}

/// Logo de CAPAS: pila isométrica de 3 capas (la de arriba separada), en
/// tonos de `base`. Dibuja de atrás (arriba) hacia delante (abajo).
fn marca_capas(p: &egui::Painter, centro: Pos2, escala: f32, base: Color32) {
    let (w, h, t, gap) = (escala, escala * 0.52, escala * 0.44, escala * 0.60);
    let tope = [base, base.gamma_multiply(0.80), base.gamma_multiply(0.63)];
    let lado = [base.gamma_multiply(0.52), base.gamma_multiply(0.42), base.gamma_multiply(0.34)];
    let borde = Stroke::new((escala * 0.07).max(1.0), hondo());
    for k in 0..3 {
        let extra = if k == 0 { escala * 0.34 } else { 0.0 };
        let (cx, cy) = (centro.x, centro.y + (k as f32 - 1.0) * gap - extra);
        let (tp, rp, bp, lp) = (Pos2::new(cx, cy - h), Pos2::new(cx + w, cy), Pos2::new(cx, cy + h), Pos2::new(cx - w, cy));
        let (lp2, bp2, rp2) = (Pos2::new(cx - w, cy + t), Pos2::new(cx, cy + h + t), Pos2::new(cx + w, cy + t));
        p.add(egui::Shape::convex_polygon(vec![lp, bp, bp2, lp2], lado[k], Stroke::NONE));
        p.add(egui::Shape::convex_polygon(vec![bp, rp, rp2, bp2], lado[k].gamma_multiply(0.82), Stroke::NONE));
        p.add(egui::Shape::convex_polygon(vec![tp, rp, bp, lp], tope[k], borde));
    }
}

/// Iconos vectoriales de línea (navegación, tarjetas, filas…). `s` = semitamaño.
fn dibujar_icono(p: &egui::Painter, c: Pos2, s: f32, kind: &str, col: Color32) {
    let st = Stroke::new((s * 0.17).max(1.4), col);
    let poli = |pts: Vec<Pos2>| p.add(egui::Shape::line(pts, st));
    let ln = |a: Pos2, b: Pos2| p.line_segment([a, b], st);
    let caja = |min: Pos2, max: Pos2| p.rect_stroke(Rect::from_min_max(min, max), CornerRadius::same((s * 0.22).max(1.0) as u8), st, StrokeKind::Middle);
    let g = |x: f32, y: f32| Pos2::new(c.x + x * s, c.y + y * s);
    match kind {
        "home" => {
            poli(vec![g(-1.0, -0.1), g(0.0, -1.0), g(1.0, -0.1)]);
            poli(vec![g(-0.72, -0.12), g(-0.72, 0.82), g(0.72, 0.82), g(0.72, -0.12)]);
        }
        "lupa" => {
            p.circle_stroke(g(-0.18, -0.18), s * 0.6, st);
            ln(g(0.28, 0.28), g(0.85, 0.85));
        }
        "carpeta" | "folder" => {
            poli(vec![g(-0.85, 0.62), g(-0.85, -0.42), g(-0.18, -0.42), g(0.0, -0.2), g(0.85, -0.2), g(0.85, 0.62), g(-0.85, 0.62)]);
        }
        "comparar" => {
            caja(g(-0.9, -0.72), g(-0.18, 0.72));
            caja(g(0.18, -0.72), g(0.9, 0.72));
        }
        "llave" => {
            for (row, kx) in [(-0.55f32, -0.25f32), (0.0, 0.35), (0.55, -0.1)] {
                ln(g(-0.85, row), g(0.85, row));
                p.circle_filled(g(kx, row), s * 0.2, morado_oscuro());
                p.circle_stroke(g(kx, row), s * 0.2, st);
            }
        }
        "engranaje" => {
            p.circle_stroke(c, s * 0.42, st);
            for i in 0..8 {
                let d = Vec2::angled(i as f32 * std::f32::consts::TAU / 8.0);
                ln(c + d * (s * 0.55), c + d * (s * 0.92));
            }
        }
        "capas" => {
            for dy in [-0.5f32, 0.1, 0.7] {
                let y = c.y + dy * s;
                poli(vec![Pos2::new(c.x, y - s * 0.34), Pos2::new(c.x + s * 0.9, y), Pos2::new(c.x, y + s * 0.34), Pos2::new(c.x - s * 0.9, y), Pos2::new(c.x, y - s * 0.34)]);
            }
        }
        "aviso" => {
            poli(vec![g(0.0, -0.8), g(0.85, 0.65), g(-0.85, 0.65), g(0.0, -0.8)]);
            ln(g(0.0, -0.12), g(0.0, 0.28));
            p.circle_filled(g(0.0, 0.5), s * 0.1, col);
        }
        "pendiente" => {
            caja(g(-0.7, -0.72), g(0.7, 0.82));
            p.rect_filled(Rect::from_center_size(g(0.0, -0.72), Vec2::new(s * 0.6, s * 0.3)), CornerRadius::same(2), col);
            poli(vec![g(-0.32, 0.12), g(-0.05, 0.4), g(0.42, -0.2)]);
        }
        "archivo" => {
            poli(vec![g(-0.6, -0.82), g(0.25, -0.82), g(0.6, -0.46), g(0.6, 0.82), g(-0.6, 0.82), g(-0.6, -0.82)]);
            poli(vec![g(0.25, -0.82), g(0.25, -0.46), g(0.6, -0.46)]);
        }
        "imagen" => {
            caja(g(-0.82, -0.66), g(0.82, 0.66));
            p.circle_filled(g(-0.32, -0.26), s * 0.14, col);
            poli(vec![g(-0.82, 0.5), g(-0.1, -0.1), g(0.3, 0.26), g(0.82, -0.2)]);
        }
        "disco" => {
            p.circle_stroke(c, s * 0.88, st);
            p.circle_stroke(c, s * 0.22, st);
        }
        "informe" => {
            poli(vec![g(-0.6, -0.82), g(0.25, -0.82), g(0.6, -0.46), g(0.6, 0.82), g(-0.6, 0.82), g(-0.6, -0.82)]);
            for yy in [-0.3f32, 0.05, 0.4] {
                ln(g(-0.35, yy), g(0.38, yy));
            }
        }
        "monitor" => {
            caja(g(-0.9, -0.7), g(0.9, 0.45));
            ln(g(-0.35, 0.82), g(0.35, 0.82));
            ln(g(0.0, 0.45), g(0.0, 0.82));
        }
        "pin" => {
            p.circle_stroke(g(0.0, -0.3), s * 0.42, st);
            ln(g(0.0, 0.12), g(0.0, 0.85));
        }
        "ia" => {
            caja(g(-0.72, -0.52), g(0.72, 0.62));
            p.circle_filled(g(-0.3, 0.05), s * 0.12, col);
            p.circle_filled(g(0.3, 0.05), s * 0.12, col);
            ln(g(0.0, -0.52), g(0.0, -0.82));
            p.circle_filled(g(0.0, -0.86), s * 0.12, col);
        }
        "ojo" => {
            poli(vec![g(-0.85, 0.0), g(0.0, -0.55), g(0.85, 0.0), g(0.0, 0.55), g(-0.85, 0.0)]);
            p.circle_filled(c, s * 0.22, col);
        }
        "extraer" => {
            ln(g(0.0, -0.75), g(0.0, 0.3));
            poli(vec![g(-0.35, -0.05), g(0.0, 0.35), g(0.35, -0.05)]);
            ln(g(-0.7, 0.7), g(0.7, 0.7));
        }
        "check" => {
            p.circle_stroke(c, s * 0.9, st);
            poli(vec![g(-0.4, 0.0), g(-0.1, 0.32), g(0.42, -0.3)]);
        }
        _ => {
            p.circle_stroke(c, s * 0.7, st);
        }
    }
}

/// Botón principal (relleno, esquinas suaves). Texto claro para contraste.
fn boton_pri(texto: &str, color: Color32) -> egui::Button<'static> {
    // Sobre acento/colores oscuros el texto va claro; sobre ámbar/verde claros, oscuro.
    let claro = color == acento() || color == rojo();
    egui::Button::new(RichText::new(texto.to_string()).font(titulo(13.5)).color(if claro { Color32::from_rgb(0xf6, 0xf7, 0xfb) } else { Color32::from_rgb(0x12, 0x14, 0x1a) }))
        .fill(color)
        .corner_radius(CornerRadius::same(8))
        .min_size(Vec2::new(0.0, 36.0))
}

/// Botón secundario (contorno).
fn boton_sec(texto: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(texto.to_string()).font(mono(12.0)).color(morado_claro()))
        .fill(morado())
        .stroke(Stroke::new(1.0, morado_medio()))
        .corner_radius(CornerRadius::same(7))
        .min_size(Vec2::new(0.0, 34.0))
}

/// Marco de tarjeta/panel del rediseño.
fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(morado_oscuro())
        .stroke(Stroke::new(1.0, morado()))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(14))
        .outer_margin(Margin::same(5))
}

/// Tarjeta de estadística clicable; devuelve true al pulsarla.
fn stat_card(ui: &mut Ui, etiqueta: &str, valor: usize, color: Color32, alerta: bool, activo: bool) -> bool {
    let id = ui.make_persistent_id(("stat", etiqueta));
    let hov = ui.ctx().read_response(id).map(|r| r.hovered()).unwrap_or(false);
    let frame = egui::Frame::new()
        .fill(if hov { mezclar(morado_oscuro(), morado(), 0.5) } else { morado_oscuro() })
        .stroke(Stroke::new(if activo { 1.6 } else { 1.0 }, if activo { color } else { morado() }))
        .corner_radius(CornerRadius::same(9))
        .inner_margin(Margin { left: 18, right: 14, top: 9, bottom: 10 });
    let inner = frame.show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(RichText::new(etiqueta.to_uppercase()).font(mono(10.0)).color(if activo { color } else { morado_claro() }));
            if alerta {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let (rid, _) = ui.allocate_exact_size(Vec2::splat(9.0), Sense::hover());
                    ui.painter().circle_filled(rid.center(), 3.5, color);
                });
            }
        });
        ui.label(RichText::new(valor.to_string()).font(titulo(31.0)).color(if valor > 0 { texto() } else { morado_medio() }));
    });
    // Barra de acento vertical a la izquierda.
    let rr = inner.response.rect;
    let bar = if valor > 0 || activo { color } else { morado_medio() };
    ui.painter().rect_filled(Rect::from_min_size(rr.left_top() + Vec2::new(0.0, 8.0), Vec2::new(3.0, rr.height() - 16.0)), CornerRadius::same(2), bar);
    ui.interact(rr, id, Sense::click()).clicked()
}

/// Encabezado fino de un panel-tarjeta.
fn encabezado_panel(ui: &mut Ui, t: &str) {
    ui.horizontal(|ui| {
        let (rid, _) = ui.allocate_exact_size(Vec2::new(10.0, 10.0), Sense::hover());
        ui.painter().rect_filled(Rect::from_center_size(rid.center(), Vec2::splat(7.0)), CornerRadius::same(2), acento());
        ui.label(RichText::new(t).font(titulo(13.0)).color(texto()));
    });
    ui.add_space(6.0);
    let y = ui.cursor().top();
    ui.painter().line_segment([Pos2::new(ui.max_rect().left(), y), Pos2::new(ui.max_rect().right(), y)], Stroke::new(1.0, morado()));
    ui.add_space(8.0);
}

/// Mensaje centrado para estados vacíos.
fn vacio(ui: &mut Ui, msg: &str) {
    ui.add_space(26.0);
    ui.vertical_centered(|ui| {
        ui.label(RichText::new(msg).font(mono(12.0)).color(morado_medio()));
    });
}

/// Etiqueta tipo "chip" con contorno de color.
fn chip(ui: &mut Ui, t: &str, col: Color32) {
    let g = ui.painter().layout_no_wrap(t.to_string(), titulo(12.0), col);
    let (resp, p) = ui.allocate_painter(g.size() + Vec2::new(16.0, 6.0), Sense::hover());
    p.rect_filled(resp.rect, CornerRadius::same(4), col.gamma_multiply(0.20));
    p.rect_stroke(resp.rect, CornerRadius::same(4), Stroke::new(1.0, col), StrokeKind::Inside);
    p.galley(resp.rect.center() - g.size() / 2.0, g, col);
}

/// Cabecera de una vista secundaria (icono + título + subtítulo).
fn titulo_vista(ui: &mut Ui, icono: &str, titulo_txt: &str, sub: &str) {
    ui.horizontal(|ui| {
        let (rid, _) = ui.allocate_exact_size(Vec2::splat(24.0), Sense::hover());
        dibujar_icono(&ui.painter().clone(), rid.center(), 9.5, icono, acento());
        ui.add_space(2.0);
        ui.vertical(|ui| {
            ui.label(RichText::new(titulo_txt).font(titulo(19.0)).color(texto()));
            ui.label(RichText::new(sub).font(FontId::proportional(12.0)).color(morado_claro()));
        });
    });
    ui.add_space(12.0);
}

/// Estado vacío centrado con icono grande.
fn panel_vacio(ui: &mut Ui, icono: &str, titulo_txt: &str, sub: &str) {
    ui.add_space(54.0);
    ui.vertical_centered(|ui| {
        let (rid, _) = ui.allocate_exact_size(Vec2::splat(50.0), Sense::hover());
        dibujar_icono(&ui.painter().clone(), rid.center(), 19.0, icono, morado_medio());
        ui.add_space(10.0);
        ui.label(RichText::new(titulo_txt).font(titulo(17.0)).color(morado_claro()));
        ui.label(RichText::new(sub).font(FontId::proportional(12.5)).color(morado_medio()));
    });
}

/// Tarjeta informativa (Inicio): insignia de icono + título + descripción.
fn tarjeta_info(ui: &mut Ui, icono: &str, titulo_txt: &str, desc: &str) {
    egui::Frame::new().fill(morado_oscuro()).stroke(Stroke::new(1.0, morado())).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(14)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.set_min_height(120.0);
        let (badge, _) = ui.allocate_exact_size(Vec2::splat(32.0), Sense::hover());
        let p = ui.painter().clone();
        p.rect_filled(badge, CornerRadius::same(8), acento().gamma_multiply(0.18));
        dibujar_icono(&p, badge.center(), 9.0, icono, acento());
        ui.add_space(9.0);
        ui.label(RichText::new(titulo_txt).font(titulo(14.5)).color(texto()));
        ui.add_space(2.0);
        ui.label(RichText::new(desc).font(FontId::proportional(12.0)).color(morado_claro()));
    });
}

/// Tarjeta de función Pro bloqueada.
fn tarjeta_pro(ui: &mut Ui, msg: &str, vista: &mut Vista) {
    egui::Frame::new().fill(morado_oscuro()).stroke(Stroke::new(1.0, acento().gamma_multiply(0.6))).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(18)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            chip(ui, "PRO", acento());
            ui.label(RichText::new(msg).font(titulo(14.0)).color(texto()));
        });
        ui.add_space(8.0);
        ui.label(RichText::new(tr("Activate CAPAS Pro to unlock version comparison and more.", "Activa CAPAS Pro para desbloquear la comparación de versiones y más.")).font(FontId::proportional(12.5)).color(morado_claro()));
        ui.add_space(12.0);
        if ui.add(boton_pri(tr("Go to Settings", "Ir a Ajustes"), acento())).clicked() {
            *vista = Vista::Ajustes;
        }
    });
}

/// Tarjeta de ajuste con título.
fn tarjeta_ajuste<R>(ui: &mut Ui, titulo_txt: &str, contenido: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new().fill(morado_oscuro()).stroke(Stroke::new(1.0, morado())).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(16)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new(titulo_txt).font(titulo(15.0)).color(texto()));
        ui.add_space(10.0);
        contenido(ui)
    }).inner
}

/// Icono según la extensión del archivo.
fn icono_archivo(nombre: &str) -> &'static str {
    let ext = nombre.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "tga" | "dds" | "ktx" | "svg" => "imagen",
        "iso" | "bin" | "cue" | "img" | "chd" => "disco",
        "md" | "txt" | "json" | "log" => "informe",
        _ => "archivo",
    }
}

/// Árbol del sistema de ficheros (Explorador). Profundidad acotada.
fn arbol_disco(ui: &mut Ui, dir: &Path, prof: usize) {
    if prof > 7 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut entradas: Vec<_> = rd.filter_map(|e| e.ok()).collect();
    entradas.sort_by_key(|e| (!e.path().is_dir(), e.file_name().to_string_lossy().to_lowercase()));
    for e in entradas {
        let path = e.path();
        let nombre = e.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            let id = ui.make_persistent_id(&path);
            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, prof < 1)
                .show_header(ui, |ui| {
                    dibujar_icono(&ui.painter().clone(), ui.cursor().left_center() + Vec2::new(8.0, 9.0), 7.0, "carpeta", acento());
                    ui.add_space(20.0);
                    ui.label(RichText::new(&nombre).font(mono(12.0)).color(texto()));
                })
                .body(|ui| arbol_disco(ui, &path, prof + 1));
        } else {
            let tam = e.metadata().ok().map(|m| humano(m.len())).unwrap_or_default();
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                dibujar_icono(&ui.painter().clone(), ui.cursor().left_center() + Vec2::new(7.0, 0.0), 7.0, icono_archivo(&nombre), morado_claro());
                ui.add_space(18.0);
                if ui.add(egui::Label::new(RichText::new(&nombre).font(mono(12.0)).color(morado_claro())).sense(Sense::click())).clicked() {
                    abrir_en_sistema(&path);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(tam).font(mono(10.5)).color(morado_medio()));
                });
            });
        }
    }
}

/// Compara dos carpetas de salida por los nombres de sus informe.json.
fn comparar_salidas(a: &Path, b: &Path) -> (Vec<String>, Vec<String>, usize) {
    fn nombres(dir: &Path) -> std::collections::BTreeSet<String> {
        let mut set = std::collections::BTreeSet::new();
        if let Ok(txt) = fs::read_to_string(dir.join("informe.json")) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
                fn rec(v: &serde_json::Value, set: &mut std::collections::BTreeSet<String>) {
                    if let Some(arr) = v.as_array() {
                        for n in arr {
                            rec(n, set);
                        }
                    } else if let Some(o) = v.as_object() {
                        if let Some(n) = o.get("nombre").and_then(|x| x.as_str()) {
                            set.insert(n.to_string());
                        }
                        if let Some(h) = o.get("hijos") {
                            rec(h, set);
                        }
                    }
                }
                rec(&v, &mut set);
            }
        }
        set
    }
    let (sa, sb) = (nombres(a), nombres(b));
    let nuevos: Vec<String> = sb.difference(&sa).cloned().collect();
    let quitados: Vec<String> = sa.difference(&sb).cloned().collect();
    let comunes = sa.intersection(&sb).count();
    (nuevos, quitados, comunes)
}

/// Estado de la comprobación de actualización (manual: la única conexión opcional).
#[derive(Clone)]
enum Act {
    Comprobando,
    Disponible(String),
    AlDia,
    Error,
}

const REPO: &str = "AngelazoGit/capas";
const URL_RELEASES: &str = "https://github.com/AngelazoGit/capas/releases/latest";

fn triple(s: &str) -> (u32, u32, u32) {
    let mut it = s.trim().trim_start_matches('v').split('.').map(|n| n.trim().parse::<u32>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0), it.next().unwrap_or(0))
}
/// ¿`a` es una versión semántica mayor que `b`? (x.y.z, componentes faltantes = 0)
fn version_mayor(a: &str, b: &str) -> bool {
    triple(a) > triple(b)
}

/// Pregunta a GitHub por la última release y compara con la versión instalada.
fn comprobar_actualizacion() -> Act {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let agente = ureq::AgentBuilder::new().timeout(Duration::from_secs(10)).build();
    let Ok(resp) = agente.get(&url).set("User-Agent", "capas-updater").set("Accept", "application/vnd.github+json").call() else {
        return Act::Error;
    };
    let Ok(cuerpo) = resp.into_string() else { return Act::Error };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&cuerpo) else { return Act::Error };
    match v.get("tag_name").and_then(|t| t.as_str()) {
        Some(tag) if version_mayor(tag, VERSION) => Act::Disponible(tag.trim_start_matches('v').to_string()),
        Some(_) => Act::AlDia,
        None => Act::Error,
    }
}

/// Pastilla redondeada con icono + texto (p. ej. "IA desconectada").
fn pastilla(ui: &mut Ui, icono: &str, txt: &str, fg: Color32, bg: Color32) {
    let g = ui.painter().layout_no_wrap(txt.to_string(), FontId::proportional(11.5), fg);
    let w = g.size().x + 34.0;
    let (resp, p) = ui.allocate_painter(Vec2::new(w, 25.0), Sense::hover());
    p.rect_filled(resp.rect, CornerRadius::same(12), bg);
    dibujar_icono(&p, resp.rect.left_center() + Vec2::new(14.0, 0.0), 6.0, icono, fg);
    p.galley(Pos2::new(resp.rect.left() + 25.0, resp.rect.center().y - g.size().y / 2.0), g, fg);
}

/// Etiqueta y color del estado de un bloque para la columna "Estado".
fn estado_etiqueta(c: Confianza, incompleto: bool) -> (&'static str, Color32) {
    if incompleto {
        (tr("Warning", "Con avisos"), naranja())
    } else {
        match c {
            Confianza::Confirmado | Confianza::Compatible => (tr("Identified", "Identificado"), verde()),
            Confianza::Probable => (tr("Probable", "Probable"), morado_claro()),
            Confianza::Desconocido => (tr("Unknown", "Desconocido"), rojo()),
        }
    }
}

/// Icono representativo de un tipo de bloque.
fn icono_tipo(t: Tipo) -> &'static str {
    match t {
        Tipo::Iso | Tipo::Disco | Tipo::Chd => "disco",
        Tipo::Imagen => "imagen",
        Tipo::Zip | Tipo::Tar | Tipo::SieteZ | Tipo::Rar | Tipo::Cab | Tipo::RecursoJuego | Tipo::Gzip | Tipo::Zstd | Tipo::Lz4 => "carpeta",
        Tipo::Texto => "informe",
        _ => "archivo",
    }
}

/// Cuenta (bloques_totales, pendientes) recorriendo el árbol.
fn resumen_arbol(nodos: &[Nodo]) -> (usize, usize) {
    fn rec(ns: &[Nodo], b: &mut usize, p: &mut usize) {
        for n in ns {
            *b += 1;
            if n.incompleto {
                *p += 1;
            }
            rec(&n.hijos, b, p);
        }
    }
    let (mut b, mut p) = (0, 0);
    rec(nodos, &mut b, &mut p);
    (b, p)
}

/// Lista plana de nodos incompletos con su ruta.
fn recoge_pendientes<'a>(nodos: &'a [Nodo], ruta: &mut Vec<usize>, out: &mut Vec<(Vec<usize>, &'a Nodo)>) {
    for (i, n) in nodos.iter().enumerate() {
        ruta.push(i);
        if n.incompleto {
            out.push((ruta.clone(), n));
        }
        recoge_pendientes(&n.hijos, ruta, out);
        ruta.pop();
    }
}

/// Prompt local (sin red) que el usuario puede pegar en cualquier IA.
fn prompt_ia(n: &Nodo) -> String {
    format!(
        "{}\n\n- {}: {}\n- {}: {} ({})\n- {}: {}\n- SHA-256: {}\n- {}: {:.3} bits/byte\n\n{}",
        tr("I analyzed a file with CAPAS (local, layered decompiler). Help me understand this block:",
           "He analizado un archivo con CAPAS (decompilador local por capas). Ayúdame a entender este bloque:"),
        tr("Name", "Nombre"), n.nombre,
        tr("Type", "Tipo"), n.descripcion, n.confianza.etiqueta(),
        tr("Size", "Tamaño"), humano(n.tamano),
        n.sha256,
        tr("Entropy", "Entropía"), n.entropia,
        tr("What is it, what is it for, and is anything suspicious?", "¿Qué es, para qué sirve y hay algo sospechoso?"),
    )
}

// ── Piezas visuales ─────────────────────────────────────────────────────
/// Panel con pestaña de título al estilo de los monitores de mando.
fn seccion<R>(ui: &mut Ui, codigo: &str, nombre: &str, color: Color32, contenido: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(morado_oscuro())
        .stroke(Stroke::new(1.5, color.gamma_multiply(0.8)))
        .inner_margin(Margin { left: 8, right: 8, top: 4, bottom: 8 })
        .outer_margin(Margin { left: 0, right: 0, top: 0, bottom: 6 })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let galley_cod = ui.painter().layout_no_wrap(codigo.to_string(), titulo(13.0), fondo());
                let (r, p) = ui.allocate_painter(galley_cod.size() + Vec2::new(14.0, 4.0), Sense::hover());
                p.rect_filled(r.rect, 0.0, color);
                p.galley(r.rect.center() - galley_cod.size() / 2.0, galley_cod, fondo());
                ui.label(RichText::new(nombre).font(titulo(15.0)).color(color));
                let resto = ui.available_rect_before_wrap();
                let y = resto.center().y;
                ui.painter().line_segment(
                    [Pos2::new(resto.left() + 4.0, y), Pos2::new(resto.right(), y)],
                    Stroke::new(1.0, color.gamma_multiply(0.4)),
                );
            });
            ui.add_space(2.0);
            contenido(ui)
        })
        .inner
}

fn boton(texto: &str, color: Color32) -> egui::Button<'static> {
    egui::Button::new(RichText::new(texto.to_string()).font(titulo(14.0)).color(color))
        .fill(morado_oscuro())
        .stroke(Stroke::new(1.5, color))
        .corner_radius(CornerRadius::ZERO)
}

/// Texto con tipografía de título que se encoge para caber en `ancho`.
fn texto_ajustado(p: &egui::Painter, centro: Pos2, texto: &str, tam: f32, ancho: f32, color: Color32) {
    let g = p.layout_no_wrap(texto.into(), titulo(tam), color);
    let t = if g.size().x > ancho { (tam * ancho / g.size().x).max(8.0) } else { tam };
    p.text(centro, Align2::CENTER_CENTER, texto, titulo(t), color);
}

fn hexagono(p: &egui::Painter, c: Pos2, r: f32, relleno: Color32, borde: Stroke) {
    let pts: Vec<Pos2> = (0..6)
        .map(|i| {
            let a = TAU / 6.0 * i as f32;
            c + Vec2::new(a.cos(), a.sin()) * r
        })
        .collect();
    p.add(Shape::convex_polygon(pts, relleno, borde));
}

fn rayas(p: &egui::Painter, r: Rect, a: Color32, b: Color32, desplaz: f32) {
    p.rect_filled(r, 0.0, b);
    let pp = p.with_clip_rect(r);
    let paso = 24.0;
    let h = r.height();
    let mut x = r.left() - paso * 2.0 + desplaz % paso;
    while x < r.right() + paso {
        let pts = vec![
            Pos2::new(x, r.bottom()),
            Pos2::new(x + h, r.top()),
            Pos2::new(x + h + paso / 2.0, r.top()),
            Pos2::new(x + paso / 2.0, r.bottom()),
        ];
        pp.add(Shape::convex_polygon(pts, a, Stroke::NONE));
        x += paso;
    }
}

fn rejilla(p: &egui::Painter, r: Rect, paso: f32) {
    p.rect_filled(r, 0.0, rejilla_bg());
    let s = Stroke::new(0.5, morado().gamma_multiply(0.9));
    let mut x = r.left();
    while x <= r.right() {
        p.line_segment([Pos2::new(x, r.top()), Pos2::new(x, r.bottom())], s);
        x += paso;
    }
    let mut y = r.top();
    while y <= r.bottom() {
        p.line_segment([Pos2::new(r.left(), y), Pos2::new(r.right(), y)], s);
        y += paso;
    }
    p.rect_stroke(r, 0.0, Stroke::new(1.0, morado_medio()), StrokeKind::Inside);
}

fn barra_segmentada(ui: &mut Ui, frac: f32, color: Color32) {
    let (resp, p) = ui.allocate_painter(Vec2::new(ui.available_width(), 14.0), Sense::hover());
    let r = resp.rect;
    let n = 30;
    let w = r.width() / n as f32;
    let llenos = (frac.clamp(0.0, 1.0) * n as f32).round() as usize;
    for i in 0..n {
        let s = Rect::from_min_size(Pos2::new(r.left() + i as f32 * w, r.top()), Vec2::new(w - 2.0, r.height()));
        let c = if i < llenos { if i as f32 / n as f32 > 0.8 { naranja() } else { color } } else { morado() };
        p.rect_filled(s, 0.0, c);
    }
}

/// Una fila de altura fija alineada a la izquierda (para listas virtualizadas).
fn fila(ui: &mut Ui, alto: f32, w: impl egui::Widget) {
    ui.allocate_ui_with_layout(Vec2::new(ui.available_width(), alto), Layout::left_to_right(Align::Center), |ui| {
        ui.set_min_height(alto);
        ui.add(w);
    });
}

/// Recorta por la izquierda: "…/final/de/la/ruta".
fn acortar(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max || max < 2 {
        s.to_string()
    } else {
        format!("…{}", s.chars().skip(n - (max - 1)).collect::<String>())
    }
}

fn mezclar(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    Color32::from_rgb(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()))
}

/// Resaltado sencillo para desensamblado y cabeceras.
fn color_linea(l: &str) -> Color32 {
    let t = l.trim_start();
    if t.starts_with(';') || t.starts_with("//") || t.starts_with("--") || t.starts_with("==") {
        morado_claro()
    } else if t.ends_with(':') || t.contains("PUNTO DE ENTRADA") {
        naranja()
    } else if [" call ", " jmp ", " ret", " j"].iter().any(|k| l.contains(k)) {
        verde()
    } else {
        texto()
    }
}

fn abrir_en_sistema(p: &Path) {
    #[cfg(target_os = "windows")]
    let prog = "explorer";
    #[cfg(target_os = "macos")]
    let prog = "open";
    #[cfg(all(unix, not(target_os = "macos")))]
    let prog = "xdg-open";
    let _ = std::process::Command::new(prog).arg(p).spawn();
}

// ── Estilo ──────────────────────────────────────────────────────────────
fn configurar_estilo(ctx: &egui::Context) {
    // Fuentes de marca embebidas: Inter (UI) + JetBrains Mono (datos).
    // Van dentro del binario para verse idénticas en Windows, Linux y macOS.
    const INTER: &[u8] = include_bytes!("../assets/fonts/Inter-Regular.otf");
    const INTER_SB: &[u8] = include_bytes!("../assets/fonts/Inter-SemiBold.otf");
    const INTER_BOLD: &[u8] = include_bytes!("../assets/fonts/Inter-Bold.otf");
    const JBMONO: &[u8] = include_bytes!("../assets/fonts/JetBrainsMono-Regular.ttf");

    let mut fuentes = FontDefinitions::default();
    fuentes.font_data.insert("inter".into(), Arc::new(FontData::from_static(INTER)));
    fuentes.font_data.insert("inter_sb".into(), Arc::new(FontData::from_static(INTER_SB)));
    fuentes.font_data.insert("inter_bold".into(), Arc::new(FontData::from_static(INTER_BOLD)));
    fuentes.font_data.insert("jbmono".into(), Arc::new(FontData::from_static(JBMONO)));

    // Respaldo (emoji/CJK) que egui ya trae, para conservarlo tras nuestras fuentes.
    let resp_prop = fuentes.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    let resp_mono = fuentes.families.get(&FontFamily::Monospace).cloned().unwrap_or_default();

    // Cuerpo (Proportional) = Inter Regular.
    let mut prop = vec!["inter".to_string()];
    prop.extend(resp_prop.iter().filter(|f| *f != "inter").cloned());
    fuentes.families.insert(FontFamily::Proportional, prop);

    // Títulos ("titulo") = Inter Bold.
    let mut titulo = vec!["inter_bold".to_string(), "inter_sb".to_string()];
    titulo.extend(resp_prop.iter().cloned());
    fuentes.families.insert(FontFamily::Name("titulo".into()), titulo);

    // Monoespaciada = JetBrains Mono.
    let mut mono = vec!["jbmono".to_string()];
    mono.extend(resp_mono.iter().filter(|f| *f != "jbmono").cloned());
    fuentes.families.insert(FontFamily::Monospace, mono);

    ctx.set_fonts(fuentes);

    aplicar_visuals(ctx);
    ctx.global_style_mut(|s| {
        s.spacing.item_spacing = Vec2::new(6.0, 4.0);
        s.spacing.button_padding = Vec2::new(10.0, 5.0);
    });
}

fn aplicar_visuals(ctx: &egui::Context) {
    // Tema 3 (Limpio) es claro; el resto parten de la base oscura.
    let mut v = if TEMA.load(Ordering::Relaxed) == 3 { egui::Visuals::light() } else { egui::Visuals::dark() };
    v.override_text_color = Some(texto());
    v.panel_fill = fondo();
    v.window_fill = morado_oscuro();
    v.extreme_bg_color = hondo();
    v.faint_bg_color = morado_oscuro();
    v.selection.bg_fill = verde_oscuro();
    v.selection.stroke = Stroke::new(1.0, acento());
    v.hyperlink_color = acento();
    v.window_corner_radius = CornerRadius::ZERO;
    v.window_stroke = Stroke::new(1.5, naranja());
    for (w, fondo, borde) in [
        (&mut v.widgets.noninteractive, morado_oscuro(), morado()),
        (&mut v.widgets.inactive, morado(), morado_medio()),
        (&mut v.widgets.hovered, morado_medio(), acento()),
        (&mut v.widgets.active, naranja_oscuro(), naranja()),
        (&mut v.widgets.open, morado_medio(), naranja()),
    ] {
        w.bg_fill = fondo;
        w.weak_bg_fill = fondo;
        w.bg_stroke = Stroke::new(1.0, borde);
        w.corner_radius = CornerRadius::ZERO;
    }
    v.widgets.hovered.fg_stroke = Stroke::new(1.5, acento());
    v.widgets.active.fg_stroke = Stroke::new(1.5, naranja());
    v.slider_trailing_fill = true;
    ctx.set_visuals(v);
}

/// Icono generado por código: hexágono naranja con núcleo verde sobre morado.
fn icono() -> egui::IconData {
    // Logo: pila isométrica de 3 capas en naranja de marca (independiente del tema).
    let n = 128usize;
    let mut rgba = vec![0u8; n * n * 4];
    let base = Color32::from_rgb(0x6d, 0x5c, 0xf5);
    let (w, h, t, gap) = (34.0f32, 18.0f32, 15.0f32, 21.0f32);
    let cx = n as f32 / 2.0;
    let cy0 = n as f32 / 2.0 + 6.0;
    // Prueba punto-en-rombo (cara superior) y banda de grosor por capa.
    let en_rombo = |x: f32, y: f32, ccx: f32, ccy: f32| (x - ccx).abs() / w + (y - ccy).abs() / h <= 1.0;
    let tope = [base, base.gamma_multiply(0.80), base.gamma_multiply(0.63)];
    let lado = [base.gamma_multiply(0.5), base.gamma_multiply(0.4), base.gamma_multiply(0.32)];
    for y in 0..n {
        for x in 0..n {
            let (fx, fy) = (x as f32 + 0.5, y as f32 + 0.5);
            let mut px = Color32::TRANSPARENT;
            // De atrás (arriba, k=0) hacia delante (abajo, k=2): el último pintado manda.
            for k in 0..3 {
                let extra = if k == 0 { 11.0 } else { 0.0 };
                let ccy = cy0 + (k as f32 - 1.0) * gap - extra;
                if en_rombo(fx, fy, cx, ccy) {
                    px = tope[k];
                } else if fx >= cx - w && fx <= cx + w && en_rombo(fx, fy - t, cx, ccy) && fy > ccy {
                    px = lado[k];
                }
            }
            if px != Color32::TRANSPARENT {
                let i = (y * n + x) * 4;
                rgba[i..i + 4].copy_from_slice(&px.to_array());
            }
        }
    }
    egui::IconData { rgba, width: n as u32, height: n as u32 }
}

#[cfg(test)]
mod pruebas_version {
    use super::version_mayor;
    #[test]
    fn compara_semver() {
        assert!(version_mayor("0.2.0", "0.1.0"));
        assert!(version_mayor("1.0.1", "1.0.0"));
        assert!(version_mayor("1.1.0", "1.0.9"));
        assert!(version_mayor("v0.2.0", "0.1.0"));
        assert!(!version_mayor("0.1.0", "0.1.0"));
        assert!(!version_mayor("0.1.0", "0.1")); // 0.1 == 0.1.0
        assert!(!version_mayor("0.1.0", "0.2.0"));
    }
}
