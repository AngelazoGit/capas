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
use crate::clasificar::Categoria;
use crate::idioma::{tfmt, tr};
use crate::claves::{Claves, FuerzaBruta};
use crate::detectar::Tipo;
use crate::motor::{Evento, Nodo};
use crate::recursos::{humano, Herramientas, Sistema, HERRAMIENTAS_CONOCIDAS};
use crate::{AUTOR, VERSION};

// ── Temas (máscaras) ─────────────────────────────────────────────────────
// Dos paletas con el mismo estilo (morado/verde/naranja): "Sereno" (limpio,
// suave a la vista, por defecto) y "Mando" (intenso, el original).
#[derive(Clone, Copy)]
struct Paleta {
    fondo: Color32,
    morado_oscuro: Color32,
    morado: Color32,
    morado_medio: Color32,
    morado_claro: Color32,
    verde: Color32,
    verde_oscuro: Color32,
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
    verde_oscuro: Color32::from_rgb(0x44, 0x53, 0x3f),
    naranja: Color32::from_rgb(0xcf, 0xa8, 0x78),
    naranja_oscuro: Color32::from_rgb(0x6b, 0x5a, 0x42),
    rojo: Color32::from_rgb(0xc9, 0x8a, 0x8a),
    texto: Color32::from_rgb(0xe8, 0xe8, 0xec),
    hondo: Color32::from_rgb(0x16, 0x16, 0x19),
    rejilla_bg: Color32::from_rgb(0x24, 0x24, 0x28),
};

// 0 = Sereno (por defecto), 1 = Mando, 2 = Neutro.
static TEMA: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

fn pal() -> Paleta {
    match TEMA.load(Ordering::Relaxed) {
        1 => MANDO,
        2 => NEUTRO,
        _ => SERENO,
    }
}
fn fondo() -> Color32 { pal().fondo }
fn morado_oscuro() -> Color32 { pal().morado_oscuro }
fn morado() -> Color32 { pal().morado }
fn morado_medio() -> Color32 { pal().morado_medio }
fn morado_claro() -> Color32 { pal().morado_claro }
fn verde() -> Color32 { pal().verde }
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
    // Módulo de claves (interfaz).
    clave_entrada: String,
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
            let mut app = App::new(sis, archivos, salida);
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
            tema: 0,
            clave_entrada: String::new(),
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
            verde(),
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

        let marco_panel = egui::Frame::new().fill(fondo()).inner_margin(Margin::same(10));

        egui::Panel::top("cabecera").exact_size(104.0).frame(marco_panel).show(ui, |ui| self.cabecera(ui, ahora));
        egui::Panel::bottom("registro")
            .resizable(true)
            .default_size(190.0)
            .frame(marco_panel)
            .show(ui, |ui| self.registro_ui(ui));
        egui::Panel::left("recursos")
            .resizable(false)
            .exact_size(310.0)
            .frame(marco_panel)
            .show(ui, |ui| self.recursos_ui(ui, ahora));
        egui::Panel::right("estratos")
            .resizable(true)
            .default_size(430.0)
            .frame(marco_panel)
            .show(ui, |ui| self.estratos_ui(ui));
        egui::CentralPanel::default().frame(marco_panel).show(ui, |ui| self.central_ui(ui, &ctx, ahora));

        // Resaltado al arrastrar archivos encima.
        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            let r = ctx.content_rect();
            let p = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::unique("soltar")));
            p.rect_filled(r, 0.0, Color32::from_black_alpha(170));
            p.rect_stroke(r.shrink(12.0), 0.0, Stroke::new(4.0, verde()), StrokeKind::Inside);
            p.text(r.center(), Align2::CENTER_CENTER, tr("DROP THE SAMPLE", "SUELTA LA MUESTRA"), titulo(64.0), verde());
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
        p.line_segment([Pos2::new(x - 9.0, r.top() + 6.0), Pos2::new(x - 9.0, r.top() + 72.0)], Stroke::new(2.0, verde()));
        p.text(Pos2::new(x, r.top() + 4.0), Align2::LEFT_TOP, tr("LAYERED DECOMPOSITION", "SISTEMA DE DESCOMPOSICIÓN"), titulo(20.0), texto());
        p.text(Pos2::new(x, r.top() + 27.0), Align2::LEFT_TOP, tr("SYSTEM FOR FILES", "ESTRATIFICADA DE ARCHIVOS"), titulo(20.0), texto());
        p.text(
            Pos2::new(x, r.top() + 56.0),
            Align2::LEFT_TOP,
            tfmt(tr("v{}  ·  OPERATOR {}","v{}  ·  OPERADOR {}"), &[VERSION.to_string(), AUTOR.to_string()]),
            mono(12.0),
            verde(),
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
            verde(),
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
            seccion(ui, "01", tr("PROCESSING CORES", "NÚCLEOS DE PROCESO"), verde(), |ui| {
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
                        (mezclar(verde_oscuro(), verde(), fase * 0.7), verde())
                    } else {
                        (morado_oscuro(), morado_medio())
                    };
                    hexagono(&p, centro, radio, relleno, Stroke::new(1.5, borde));
                    p.text(centro, Align2::CENTER_CENTER, format!("{:02}", i + 1), mono(10.0), if i < activos { fondo() } else { morado_claro() });
                }
                ui.label(RichText::new(tfmt(tr("{} LOGICAL · {} ASSIGNED","{} LÓGICOS · {} ASIGNADOS"), &[self.sis.nucleos.to_string(), self.op.hilos.to_string()])).font(mono(11.0)).color(verde()));
            });

            seccion(ui, "02", tr("MEMORY", "MEMORIA"), verde(), |ui| {
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
                            p.rect_filled(Rect::from_center_size(c, Vec2::splat(9.0)), 0.0, verde());
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
                    ui.separator();
                    let mut tema = self.tema;
                    egui::ComboBox::from_id_salt("tema")
                        .selected_text(match tema { 1 => tr("THEME: COMMAND", "TEMA: MANDO"), 2 => tr("THEME: NEUTRAL", "TEMA: NEUTRO"), _ => tr("THEME: SERENE", "TEMA: SERENO") })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut tema, 0u8, tr("SERENE (clean)", "SERENO (limpio)"));
                            ui.selectable_value(&mut tema, 2u8, tr("NEUTRAL (grayscale)", "NEUTRO (grises)"));
                            ui.selectable_value(&mut tema, 1u8, tr("COMMAND (intense)", "MANDO (intenso)"));
                        });
                    if tema != self.tema {
                        self.tema = tema;
                        TEMA.store(tema, Ordering::Relaxed);
                        aplicar_visuals(&ui.ctx().clone());
                    }
                    let mut idi = if crate::idioma::es() { 1u8 } else { 0u8 };
                    egui::ComboBox::from_id_salt("idioma")
                        .selected_text(if idi == 0 { "LANGUAGE: ENGLISH" } else { "IDIOMA: ESPAÑOL" })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut idi, 0u8, "English");
                            ui.selectable_value(&mut idi, 1u8, "Español");
                        });
                    crate::idioma::set_es(idi == 1);
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
            seccion(&mut c[1], "B", tr("DEPTH", "PROFUNDIDAD"), verde(), |ui| self.profundidad(ui));
            seccion(&mut c[2], "C", tr("PERFORMANCE", "RENDIMIENTO"), verde(), |ui| self.senal_ui(ui, ahora));
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
            let c = mezclar(verde(), naranja(), i as f32 / (n - 1).max(1) as f32);
            if v > 0 {
                p.rect_filled(b, 0.0, c.gamma_multiply(0.85));
                p.text(b.center_top() - Vec2::new(0.0, 2.0), Align2::CENTER_BOTTOM, v.to_string(), mono(10.0), c);
            }
            p.text(Pos2::new(b.center().x, r.bottom() - 2.0), Align2::CENTER_BOTTOM, format!("{i}"), mono(10.0), morado_claro());
        }
        ui.label(
            RichText::new(tfmt(tr("LAYERS: {} · VOLUME: {}","ESTRATOS: {} · VOLUMEN: {}"), &[self.por_capa.len().to_string(), humano(self.bytes_vistos)]))
                .font(mono(10.0))
                .color(verde()),
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
        p.add(Shape::line(pts, Stroke::new(2.0, verde())));
        let actual = self.senal.back().copied().unwrap_or(0.0);
        ui.label(RichText::new(format!("{actual:.0} {} · {} {max:.0}", tr("BLOCKS/s","BLOQUES/s"), tr("PEAK","PICO"))).font(mono(10.0)).color(verde()));
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
                hexagono(&p, r.center(), rad, morado_oscuro(), Stroke::new(3.0, mezclar(morado_claro(), verde(), pulso)));
                p.text(r.center() - Vec2::new(0.0, 16.0), Align2::CENTER_CENTER, tr("DROP HERE", "ARRASTRA AQUÍ"), titulo(24.0), verde());
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
                    .add_enabled(libre, boton(&tfmt(tr("OUTPUT: {}","SALIDA: {}"), &[acortar(&self.salida.display().to_string(), 26)]), verde()))
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
                            if ui.add(boton(tr("OPEN OUTPUT", "ABRIR SALIDA"), verde()).min_size(Vec2::new(120.0, 40.0))).clicked() {
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
                if ui.add(boton(tr("▸ OPEN auditoria.md", "▸ ABRIR auditoria.md"), verde())).clicked() {
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
                if ui.add(boton(&tfmt(tr("▸ OPEN extraidos/ ({} files)","▸ ABRIR extraidos/ ({} archivos)"), &[total.to_string()]), verde())).clicked() {
                    if let Some(raiz) = &self.raiz {
                        abrir_en_sistema(&raiz.join("extraidos"));
                    }
                }
            });
        }
        let alto_arbol = (ui.available_height() * 0.55).max(180.0);
        seccion(ui, "E", tr("LAYER TREE", "ÁRBOL DE ESTRATOS"), verde(), |ui| {
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
                egui::Grid::new("ficha_grid").num_columns(2).spacing([10.0, 2.0]).show(ui, |ui| {
                    for (k, v) in [
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
                        if ui.add(boton(&format!("▸ {corto}"), verde())).on_hover_text(r).clicked() {
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

    fn registro_ui(&mut self, ui: &mut Ui) {
        seccion(ui, ">", tr("OPERATIONS LOG", "REGISTRO DE OPERACIONES"), verde(), |ui| {
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
    let mut fuentes = FontDefinitions::default();
    let mut familia_titulo = Vec::new();
    for (nombre, rutas) in [
        (
            "serif_pesada",
            &[
                "/usr/share/fonts/truetype/dejavu/DejaVuSerifCondensed-Bold.ttf",
                "/usr/share/fonts/dejavu/DejaVuSerifCondensed-Bold.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf",
                "/usr/share/fonts/truetype/liberation/LiberationSerif-Bold.ttf",
                "/usr/share/fonts/liberation-serif/LiberationSerif-Bold.ttf",
                "C:\\Windows\\Fonts\\timesbd.ttf",
                "/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf",
                "/Library/Fonts/Times New Roman Bold.ttf",
            ][..],
        ),
    ] {
        if let Some(datos) = rutas.iter().find_map(|r| fs::read(r).ok()) {
            fuentes.font_data.insert(nombre.into(), Arc::new(FontData::from_owned(datos)));
            familia_titulo.push(nombre.to_string());
        }
    }
    for r in [
        "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "C:\\Windows\\Fonts\\consola.ttf",
        "/System/Library/Fonts/Menlo.ttc",
    ] {
        if let Ok(d) = fs::read(r) {
            fuentes.font_data.insert("mono_sistema".into(), Arc::new(FontData::from_owned(d)));
            fuentes.families.entry(FontFamily::Monospace).or_default().insert(0, "mono_sistema".into());
            break;
        }
    }
    let respaldo = fuentes.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    familia_titulo.extend(respaldo);
    fuentes.families.insert(FontFamily::Name("titulo".into()), familia_titulo);
    ctx.set_fonts(fuentes);

    aplicar_visuals(ctx);
    ctx.global_style_mut(|s| {
        s.spacing.item_spacing = Vec2::new(6.0, 4.0);
        s.spacing.button_padding = Vec2::new(10.0, 5.0);
    });
}

fn aplicar_visuals(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.override_text_color = Some(texto());
    v.panel_fill = fondo();
    v.window_fill = morado_oscuro();
    v.extreme_bg_color = hondo();
    v.faint_bg_color = morado_oscuro();
    v.selection.bg_fill = verde_oscuro();
    v.selection.stroke = Stroke::new(1.0, verde());
    v.hyperlink_color = verde();
    v.window_corner_radius = CornerRadius::ZERO;
    v.window_stroke = Stroke::new(1.5, naranja());
    for (w, fondo, borde) in [
        (&mut v.widgets.noninteractive, morado_oscuro(), morado()),
        (&mut v.widgets.inactive, morado(), morado_medio()),
        (&mut v.widgets.hovered, morado_medio(), verde()),
        (&mut v.widgets.active, naranja_oscuro(), naranja()),
        (&mut v.widgets.open, morado_medio(), naranja()),
    ] {
        w.bg_fill = fondo;
        w.weak_bg_fill = fondo;
        w.bg_stroke = Stroke::new(1.0, borde);
        w.corner_radius = CornerRadius::ZERO;
    }
    v.widgets.hovered.fg_stroke = Stroke::new(1.5, verde());
    v.widgets.active.fg_stroke = Stroke::new(1.5, naranja());
    v.slider_trailing_fill = true;
    ctx.set_visuals(v);
}

/// Icono generado por código: hexágono naranja con núcleo verde sobre morado.
fn icono() -> egui::IconData {
    let n = 64usize;
    let mut rgba = vec![0u8; n * n * 4];
    let c = n as f32 / 2.0;
    let dentro = |x: f32, y: f32, r: f32| {
        let (dx, dy) = ((x - c).abs(), (y - c).abs());
        dy <= r * 0.866 && dx * 0.866 + dy * 0.5 <= r * 0.866
    };
    for y in 0..n {
        for x in 0..n {
            let (fx, fy) = (x as f32 + 0.5, y as f32 + 0.5);
            let px = if dentro(fx, fy, 12.0) {
                verde()
            } else if dentro(fx, fy, 21.0) {
                morado()
            } else if dentro(fx, fy, 30.0) {
                naranja()
            } else {
                Color32::TRANSPARENT
            };
            let i = (y * n + x) * 4;
            rgba[i..i + 4].copy_from_slice(&px.to_array());
        }
    }
    egui::IconData { rgba, width: n as u32, height: n as u32 }
}
