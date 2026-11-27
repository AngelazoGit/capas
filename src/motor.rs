//! Motor de capas: identifica cada bloque, lo analiza/decompila, extrae la
//! siguiente capa y la procesa en paralelo con todos los núcleos.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::idioma::{tfmt, tr};
use crate::detectar::{self, Tipo};
use crate::ejecutables;
use crate::{codigo, nativo};
use crate::extraer::{self, Hijo};
use crate::recursos::{self, Herramientas};

pub struct Config {
    pub profundidad_max: usize,
    pub max_archivo: u64,
    pub max_total: u64,
    pub timeout: Duration,
    pub max_instrucciones: usize,
    pub tallar: bool,
    pub desempaquetar: bool,
    pub claves: crate::claves::Claves,
}

/// Mensajes que el motor envía a la interfaz mientras trabaja.
pub enum Evento {
    Bloque { n: usize, capa: usize, tipo: Tipo, tamano: u64, ruta: String },
    Aviso(String),
}

#[derive(Serialize, Clone)]
pub struct Nodo {
    pub nombre: String,
    pub capa: usize,
    pub tipo: Tipo,
    pub descripcion: String,
    pub tamano: u64,
    pub sha256: String,
    pub entropia: f64,
    pub directorio: String,
    pub confianza: crate::clasificar::Confianza,
    pub evidencia: String,
    pub resultados: Vec<String>,
    pub notas: Vec<String>,
    /// El análisis de este bloque quedó incompleto (cifrado, truncado, límite de
    /// profundidad/presupuesto, error de extracción…). La auditoría lo manda a revisión.
    #[serde(default)]
    pub incompleto: bool,
    pub hijos: Vec<Nodo>,
    /// Ruta del archivo en disco (no se serializa: es propia de esta máquina).
    #[serde(skip)]
    pub ruta_fisica: PathBuf,
}

pub struct Motor {
    pub cfg: Config,
    pub herr: Herramientas,
    vistos: Mutex<HashMap<String, String>>,
    usado: AtomicU64,
    pub procesados: AtomicUsize,
    raiz: PathBuf,
    script_ghidra: Mutex<Option<PathBuf>>,
    eventos: Option<Sender<Evento>>,
    pub cancelar: Arc<AtomicBool>,
}

impl Motor {
    pub fn new(
        cfg: Config,
        herr: Herramientas,
        raiz: PathBuf,
        eventos: Option<Sender<Evento>>,
        cancelar: Arc<AtomicBool>,
    ) -> Self {
        Motor {
            cfg,
            herr,
            vistos: Mutex::new(HashMap::new()),
            usado: AtomicU64::new(0),
            procesados: AtomicUsize::new(0),
            raiz,
            script_ghidra: Mutex::new(None),
            eventos,
            cancelar,
        }
    }

    pub fn emitir(&self, ev: Evento) {
        match &self.eventos {
            Some(tx) => {
                let _ = tx.send(ev);
            }
            None => match ev {
                Evento::Bloque { n, capa, tipo, tamano, ruta } => eprintln!(
                    "[{n:>5}] capa {capa} {:<26} {:>10}  {ruta}",
                    tipo.nombre(),
                    recursos::humano(tamano)
                ),
                Evento::Aviso(a) => eprintln!("  ! {a}"),
            },
        }
    }

    pub fn bytes_extraidos(&self) -> u64 {
        self.usado.load(Ordering::Relaxed)
    }

    /// Procesa un bloque. `ruta_fisica` es dónde está guardado en disco.
    pub fn procesar(&self, datos: &[u8], nombre: String, ruta_fisica: PathBuf, dir: PathBuf, capa: usize) -> Nodo {
        let n = self.procesados.fetch_add(1, Ordering::Relaxed) + 1;
        let tipo = detectar::detectar(datos);
        let sha = hex(&Sha256::digest(datos));
        let rel = dir.strip_prefix(&self.raiz).unwrap_or(&dir).display().to_string();
        let (confianza, evidencia) = crate::clasificar::confianza(tipo, &nombre);
        self.emitir(Evento::Bloque { n, capa, tipo, tamano: datos.len() as u64, ruta: rel.clone() });

        let mut nodo = Nodo {
            nombre: nombre.clone(),
            capa,
            tipo,
            descripcion: tipo.nombre().into(),
            tamano: datos.len() as u64,
            sha256: sha.clone(),
            entropia: (detectar::entropia(datos) * 1000.0).round() / 1000.0,
            directorio: rel,
            confianza,
            evidencia,
            resultados: Vec::new(),
            notas: Vec::new(),
            incompleto: false,
            hijos: Vec::new(),
            ruta_fisica: ruta_fisica.clone(),
        };

        {
            let mut v = self.vistos.lock().unwrap();
            if let Some(prev) = v.get(&sha) {
                nodo.notas.push(tfmt(tr("identical content to {}: analysis not repeated","contenido idéntico a {}: no se repite el análisis"), &[prev.clone()]));
                return nodo;
            }
            v.insert(sha, nodo.directorio.clone());
        }

        if self.cancelar.load(Ordering::Relaxed) {
            nodo.notas.push(tr("analysis cancelled by the operator","análisis cancelado por el operador").into());
            return nodo;
        }

        let analisis = dir.join("analisis");
        let _ = fs::create_dir_all(&analisis);
        if nodo.entropia > 7.5 && !tipo.es_contenedor() && tipo != Tipo::Imagen {
            nodo.notas.push(tfmt(
                tr("very high entropy ({}): probably compressed or encrypted", "entropía muy alta ({}): probablemente comprimido o cifrado"),
                &[format!("{:.2}", nodo.entropia)],
            ));
        }

        let hijos = self.capa(datos, &nombre, &ruta_fisica, &analisis, tipo, &mut nodo);
        // Un contenedor del que no se extrajo nada suele estar cifrado, truncado o
        // corrupto: análisis incompleto (el PDF puede no llevar flujos y no cuenta).
        if tipo.es_contenedor() && tipo != Tipo::Pdf && hijos.is_empty() {
            nodo.incompleto = true;
        }
        self.recorrer_hijos(hijos, &dir.join("capas"), capa, &mut nodo);
        nodo
    }

    fn guardar(&self, analisis: &Path, archivo: &str, contenido: &[u8], nodo: &mut Nodo) {
        let p = analisis.join(archivo);
        if fs::write(&p, contenido).is_ok() {
            nodo.resultados.push(p.strip_prefix(&self.raiz).unwrap_or(&p).display().to_string());
        }
    }

    fn externa(&self, prog: &str, args: &[&OsStr], analisis: &Path, archivo: &str, nodo: &mut Nodo) -> bool {
        let Some(ruta) = self.herr.get(prog) else { return false };
        match recursos::ejecutar(ruta, args, self.cfg.timeout, 256 << 20) {
            Ok(s) => {
                if s.agotado {
                    nodo.notas.push(tfmt(tr("{}: timed out ({}s)","{}: tiempo agotado ({}s)"), &[prog.to_string(), self.cfg.timeout.as_secs().to_string()]));
                }
                if !s.stdout.is_empty() {
                    self.guardar(analisis, archivo, &s.stdout, nodo);
                    true
                } else {
                    if s.codigo != Some(0) && !s.stderr.is_empty() {
                        let e = String::from_utf8_lossy(&s.stderr);
                        nodo.notas.push(format!("{prog}: {}", e.lines().next().unwrap_or("").trim()));
                    }
                    s.codigo == Some(0)
                }
            }
            Err(e) => {
                nodo.notas.push(format!("{prog}: {e}"));
                false
            }
        }
    }

    /// Analiza una capa y devuelve la siguiente (los hijos).
    fn capa(&self, d: &[u8], nombre: &str, ruta: &Path, an: &Path, tipo: Tipo, nodo: &mut Nodo) -> Vec<Hijo> {
        let lim = self.cfg.max_archivo.min(self.cfg.max_total.saturating_sub(self.bytes_extraidos()));
        let r = ruta.as_os_str();
        let mut notas = Vec::new();
        let res: anyhow::Result<Vec<Hijo>> = match tipo {
            Tipo::Zip => match self.cfg.claves.abrir_zip(d, lim, &mut notas) {
                Ok((hijos, clave)) => {
                    if let Some(c) = clave {
                        self.emitir(Evento::Aviso(format!("contraseña hallada para '{nombre}': {c}")));
                    }
                    Ok(hijos)
                }
                Err(e) => Err(e),
            },
            Tipo::Gzip => extraer::gzip(d, nombre, lim),
            Tipo::Bzip2 => extraer::bzip2(d, nombre, lim),
            Tipo::Xz => extraer::xz(d, nombre, lim),
            Tipo::Lzma => extraer::lzma(d, nombre, lim),
            Tipo::Zlib => extraer::zlib(d, nombre, lim),
            Tipo::Zstd => extraer::zstd(d, nombre, lim),
            Tipo::Lz4 => extraer::lz4(d, nombre, lim),
            Tipo::Iso => {
                let mut truncado = false;
                // Carpeta de salida de esta capa: ahí se vuelcan en streaming los
                // ficheros demasiado grandes para la RAM (an = <dir>/analisis).
                let capas = an.parent().map(|d| d.join("capas"));
                if let Some(c) = &capas {
                    let _ = fs::create_dir_all(c);
                }
                match extraer::iso9660(d, lim, capas.as_deref(), &mut notas, &mut truncado) {
                    Ok((hijos, grandes)) => {
                        if truncado {
                            nodo.incompleto = true;
                        }
                        // Los ficheros volcados a disco se listan como resultados abribles.
                        for g in grandes {
                            nodo.resultados.push(g.strip_prefix(&self.raiz).unwrap_or(&g).display().to_string());
                        }
                        if let Some(info) = extraer::plataforma_disco(&hijos) {
                            nodo.resultados.push(info);
                        }
                        Ok(hijos)
                    }
                    Err(e) => Err(e),
                }
            }
            Tipo::Tar => extraer::tar(d, lim, &mut notas),
            Tipo::ArUnix => extraer::ar(d),
            Tipo::MachOFat => extraer::macho_fat(d),
            Tipo::Pdf => Ok(extraer::pdf(d, lim)),
            // Contenedores: motor NATIVO primero; 7-Zip/chdman solo si el nativo falla.
            Tipo::SieteZ => {
                let cand = self.cfg.claves.candidatas_externas();
                self.con_nativo(nativo::siete_z(d, lim, &cand), ruta, an, nodo)
            }
            Tipo::Rar => {
                let cand = self.cfg.claves.candidatas_externas();
                self.con_nativo(nativo::rar(ruta, lim, &cand), ruta, an, nodo)
            }
            Tipo::Cab => self.con_nativo(nativo::cab(d, lim).map(|h| nativo::Abierto { hijos: h, clave: None }), ruta, an, nodo),
            Tipo::Ole => nativo::ole(d, lim),
            Tipo::Chd => match nativo::chd(ruta, lim) {
                Ok(h) => Ok(h),
                Err(e) if self.herr.get("chdman").is_some() => {
                    nodo.notas.push(tfmt(tr("native CHD reader: {} — using chdman", "lector CHD nativo: {} — se usa chdman"), &[e.to_string()]));
                    self.con_chdman(ruta, an, nodo)
                }
                Err(e) => Err(e),
            },
            Tipo::Disco => extraer::particiones(d, lim),
            Tipo::Elf | Tipo::Pe | Tipo::MachO => {
                self.nativo(d, r, an, tipo, nodo);
                Ok(Vec::new())
            }
            Tipo::DotNet => {
                // Ensamblado .NET: estructura CLI (tipos/campos/métodos) nativa,
                // y además el análisis PE habitual (secciones, imports…).
                match crate::dotnet::listar(d) {
                    Ok(t) => self.guardar(an, "dotnet_estructura.txt", t.as_bytes(), nodo),
                    Err(e) => nodo.notas.push(tfmt(tr("native .NET reader: {}", "lector .NET nativo: {}"), &[e.to_string()])),
                }
                self.nativo(d, r, an, Tipo::Pe, nodo);
                Ok(Vec::new())
            }
            Tipo::ClaseJava => {
                // Listado nativo (equivale a javap -c -p): no necesita JDK.
                match codigo::clase_java(d) {
                    Ok(t) => self.guardar(an, "clase.javap.txt", t.as_bytes(), nodo),
                    Err(e) => nodo.notas.push(tfmt(tr("native class reader: {}", "lector nativo de clases: {}"), &[e.to_string()])),
                }
                if let Ok(t) = crate::decompilar::java(d) {
                    self.guardar(an, "decompilado.capas.java", t.as_bytes(), nodo);
                }
                // Decompilación a fuente de máxima fidelidad si hay motor instalado (opcional).
                let _ = self.externa("cfr", &[r], an, "decompilado.java", nodo)
                    || self.externa("procyon", &[r], an, "decompilado.java", nodo);
                Ok(Vec::new())
            }
            Tipo::Dex => {
                // Listado nativo: clases, campos, métodos y bytecode Dalvik.
                match codigo::dex(d) {
                    Ok(t) => self.guardar(an, "dex_smali.txt", t.as_bytes(), nodo),
                    Err(e) => nodo.notas.push(tfmt(tr("native DEX reader: {}", "lector DEX nativo: {}"), &[e.to_string()])),
                }
                if self.herr.get("jadx").is_some() {
                    let out = an.join("jadx");
                    self.externa("jadx", &[OsStr::new("-d"), out.as_os_str(), r], an, "jadx.log", nodo);
                    nodo.resultados.push(format!("{}/jadx/", nodo.directorio));
                }
                Ok(Vec::new())
            }
            Tipo::Pyc => {
                // Desensamblado nativo exacto (Python 3.6–3.14), sin Python instalado.
                match codigo::pyc(d) {
                    Ok(t) => self.guardar(an, "pyc_dis.txt", t.as_bytes(), nodo),
                    Err(e) => nodo.notas.push(tfmt(tr("native .pyc reader: {}", "lector .pyc nativo: {}"), &[e.to_string()])),
                }
                if let Ok(t) = crate::decompilar::python(d) {
                    self.guardar(an, "decompilado.capas.py", t.as_bytes(), nodo);
                }
                let _ = self.externa("pycdc", &[r], an, "decompilado.py", nodo)
                    || self.externa("decompyle3", &[r], an, "decompilado.py", nodo)
                    || self.externa("uncompyle6", &[r], an, "decompilado.py", nodo);
                Ok(Vec::new())
            }
            Tipo::Wasm => {
                // WAT nativo (equivale a wasm2wat).
                match codigo::wasm_a_wat(d) {
                    Ok(t) => self.guardar(an, "modulo.wat", t.as_bytes(), nodo),
                    Err(e) => {
                        nodo.notas.push(tfmt(tr("native WASM reader: {}", "lector WASM nativo: {}"), &[e.to_string()]));
                        self.externa("wasm2wat", &[r], an, "modulo.wat", nodo);
                    }
                }
                self.externa("wasm-decompile", &[r], an, "decompilado.dcmp", nodo);
                Ok(Vec::new())
            }
            Tipo::Shader => {
                // SPIR-V → WGSL legible (nativo, con naga).
                match codigo::spirv_a_fuente(d) {
                    Ok(t) => self.guardar(an, "shader.wgsl", t.as_bytes(), nodo),
                    Err(e) => nodo.notas.push(tfmt(tr("native SPIR-V reader: {}", "lector SPIR-V nativo: {}"), &[e.to_string()])),
                }
                Ok(Vec::new())
            }
            Tipo::Texto => Ok(extraer::base64_embebido(d)),
            Tipo::RecursoJuego if self.cfg.desempaquetar => {
                match extraer::desempaquetar_bundle(d, nombre, lim) {
                    Some(r) => r,
                    None => Ok(Vec::new()),
                }
            }
            Tipo::Imagen | Tipo::Audio | Tipo::Video | Tipo::Fuente | Tipo::BaseDatos | Tipo::RecursoJuego => Ok(Vec::new()),
            Tipo::Desconocido => {
                // Pista por extensión: mejor que "Binario desconocido" a secas.
                if let Some(ext) = nombre.rsplit('.').next().filter(|e| !e.is_empty() && e.len() <= 8 && *e != nombre) {
                    nodo.descripcion = format!("Binario (.{})", ext.to_lowercase());
                }
                if let Some(f) = self.herr.get("file") {
                    if let Ok(s) = recursos::ejecutar(f, &[OsStr::new("-b"), r], self.cfg.timeout, 4096) {
                        let t = String::from_utf8_lossy(&s.stdout).trim().to_string();
                        if !t.is_empty() {
                            nodo.descripcion = format!("{} ({t})", tipo.nombre());
                        }
                    }
                }
                Ok(Vec::new())
            }
        };
        nodo.notas.extend(notas);

        let mut hijos = match res {
            Ok(h) => h,
            Err(e) => {
                nodo.notas.push(tfmt(tr("could not extract the layer: {}","no se pudo extraer la capa: {}"), &[e.to_string()]));
                nodo.incompleto = true;
                Vec::new()
            }
        };

        // Cadenas legibles para todo lo binario.
        if !matches!(tipo, Tipo::Texto | Tipo::Imagen) && !tipo.es_contenedor() {
            let c = extraer::cadenas(d, 6, 32 << 20);
            if !c.is_empty() {
                self.guardar(an, "cadenas.txt", c.as_bytes(), nodo);
            }
        }
        // Firmas incrustadas (payloads, instaladores, recursos).
        if self.cfg.tallar && !tipo.es_contenedor() && tipo != Tipo::Texto {
            let t = extraer::tallar(d, lim);
            if !t.is_empty() {
                nodo.notas.push(tfmt(tr("{} embedded block(s) found by signature","{} bloque(s) incrustado(s) encontrados por firma"), &[t.len().to_string()]));
            }
            hijos.extend(t);
        }
        hijos
    }

    fn nativo(&self, d: &[u8], r: &OsStr, an: &Path, tipo: Tipo, nodo: &mut Nodo) {
        let mut interno_x86 = false;
        match ejecutables::analizar(d, self.cfg.max_instrucciones) {
            Ok(inf) => {
                nodo.descripcion = format!("{} [{}]", tipo.nombre(), inf.arquitectura);
                self.guardar(an, "cabeceras.txt", inf.cabeceras.as_bytes(), nodo);
                if let Some(asm) = inf.desensamblado {
                    interno_x86 = true;
                    self.guardar(an, "desensamblado.asm", asm.as_bytes(), nodo);
                }
                nodo.notas.extend(inf.notas);
            }
            Err(e) => nodo.notas.push(tfmt(tr("internal analysis: {}","análisis interno: {}"), &[e.to_string()])),
        }
        // readelf ya no hace falta: las cabeceras completas (segmentos, sección
        // dinámica, reubicaciones, build-id) salen del análisis interno.
        // objdump solo si la arquitectura no tiene desensamblador integrado.
        if !interno_x86 {
            self.externa(
                "objdump",
                &[OsStr::new("-d"), OsStr::new("-C"), OsStr::new("--no-show-raw-insn"), r],
                an,
                "objdump.asm",
                nodo,
            );
        }
        self.externa(
            "r2",
            &[OsStr::new("-q"), OsStr::new("-e"), OsStr::new("scr.color=0"), OsStr::new("-c"), OsStr::new("aaa; afl; pdf @@F"), r],
            an,
            "radare2_funciones.asm",
            nodo,
        );
        // Decompilación a C con lo que haya instalado.
        if self.herr.get("retdec-decompiler").is_some() {
            let out = an.join("retdec.c");
            self.externa("retdec-decompiler", &[r, OsStr::new("-o"), out.as_os_str()], an, "retdec.log", nodo);
            if out.exists() {
                nodo.resultados.push(out.strip_prefix(&self.raiz).unwrap_or(&out).display().to_string());
            }
        }
        if self.herr.get("analyzeHeadless").is_some() {
            self.ghidra(r, an, nodo);
        }
    }

    fn ghidra(&self, r: &OsStr, an: &Path, nodo: &mut Nodo) {
        let dir_script = {
            let mut g = self.script_ghidra.lock().unwrap();
            if g.is_none() {
                let p = self.raiz.join(".ghidra_scripts");
                let _ = fs::create_dir_all(&p);
                let _ = fs::write(p.join("DecompilarTodo.java"), SCRIPT_GHIDRA);
                *g = Some(p);
            }
            g.clone().unwrap()
        };
        let proy = an.join(".ghidra_proyecto");
        let _ = fs::create_dir_all(&proy);
        let salida = an.join("ghidra_decompilado.c");
        self.externa(
            "analyzeHeadless",
            &[
                proy.as_os_str(),
                OsStr::new("p"),
                OsStr::new("-import"),
                r,
                OsStr::new("-scriptPath"),
                dir_script.as_os_str(),
                OsStr::new("-postScript"),
                OsStr::new("DecompilarTodo.java"),
                salida.as_os_str(),
                OsStr::new("-deleteProject"),
            ],
            an,
            "ghidra.log",
            nodo,
        );
        let _ = fs::remove_dir_all(&proy);
        if salida.exists() {
            nodo.resultados.push(salida.strip_prefix(&self.raiz).unwrap_or(&salida).display().to_string());
        }
    }

    /// Usa el resultado del extractor nativo; si falló y hay 7-Zip, lo intenta con él.
    fn con_nativo(&self, r: anyhow::Result<nativo::Abierto>, ruta: &Path, an: &Path, nodo: &mut Nodo) -> anyhow::Result<Vec<Hijo>> {
        match r {
            Ok(a) => {
                if let Some(c) = &a.clave {
                    self.emitir(Evento::Aviso(format!("contraseña hallada para '{}': {}", nodo.nombre, c)));
                    nodo.notas.push(tfmt(
                        tr("Opened with the password «{}» from the Keys module (no brute force).", "Abierto con la contraseña «{}» del módulo de Claves (sin fuerza bruta)."),
                        &[c.clone()],
                    ));
                }
                Ok(a.hijos)
            }
            Err(e) if es_error_de_clave(&e) => {
                // Cifrado y ninguna contraseña conocida lo abre: no se reintenta con 7-Zip
                // (probaría lo mismo) y se explica exactamente qué se ha intentado.
                nodo.incompleto = true;
                nodo.notas.push(self.nota_cifrado());
                Ok(Vec::new())
            }
            Err(e) if self.herr.get("7z").is_some() => {
                nodo.notas.push(tfmt(tr("native extractor: {} — retrying with 7-Zip", "extractor nativo: {} — se reintenta con 7-Zip"), &[e.to_string()]));
                self.con_7z(ruta, an, nodo)
            }
            Err(e) => Err(e),
        }
    }

    /// Explicación clara para un contenedor cifrado que no se ha podido abrir:
    /// qué contraseñas se probaron exactamente y que no hay fuerza bruta.
    fn nota_cifrado(&self) -> String {
        let k = &self.cfg.claves;
        let total = k.candidatas_externas().len();
        if total == 0 {
            return tr(
                "Password-protected, and the Keys module has no passwords to try. CAPAS does not guess or brute-force passwords: add this archive's password in the Keys module and analyze again.",
                "Protegido con contraseña y el módulo de Claves no tiene ninguna que probar. CAPAS no adivina contraseñas ni usa fuerza bruta: añade la contraseña de este archivo en el módulo de Claves y vuelve a analizar.",
            )
            .to_string();
        }
        let mut fuentes = Vec::new();
        if !k.explicitas.is_empty() {
            fuentes.push(tfmt(tr("{} added by you", "{} añadidas por ti"), &[k.explicitas.len().to_string()]));
        }
        if k.comunes {
            fuentes.push(tr("the list of common passwords", "la lista de contraseñas habituales").to_string());
        }
        if k.diccionario.is_some() {
            fuentes.push(tr("your dictionary file", "tu archivo de diccionario").to_string());
        }
        tfmt(
            tr(
                "Password-protected: {} passwords were tried ({}) and none opened it. No brute force is used. Add the right password in the Keys module and analyze again.",
                "Protegido con contraseña: se probaron {} contraseñas ({}) y ninguna lo abrió. No se usa fuerza bruta. Añade la contraseña correcta en el módulo de Claves y vuelve a analizar.",
            ),
            &[total.to_string(), fuentes.join(", ")],
        )
    }

    fn con_7z(&self, ruta: &Path, an: &Path, nodo: &mut Nodo) -> anyhow::Result<Vec<Hijo>> {
        if self.herr.get("7z").is_none() {
            anyhow::bail!("formato que requiere 7z (p7zip) instalado");
        }
        let tmp = an.join(".7z_tmp");
        let mut o = std::ffi::OsString::from("-o");
        o.push(&tmp);
        // Intenta sin contraseña y, si no sale nada (archivo cifrado), con las
        // contraseñas del módulo de Claves. No hay fuerza bruta aquí.
        let mut intentos: Vec<String> = vec!["-".to_string()];
        intentos.extend(self.cfg.claves.candidatas_externas());
        let mut usada: Option<String> = None;
        let mut ok = false;
        for (i, pass) in intentos.iter().enumerate() {
            let _ = fs::remove_dir_all(&tmp);
            let arg_p = std::ffi::OsString::from(format!("-p{pass}"));
            self.externa("7z", &[OsStr::new("x"), OsStr::new("-y"), &arg_p, &o, ruta.as_os_str()], an, "7z.log", nodo);
            if dir_con_archivos(&tmp) {
                ok = true;
                if i > 0 {
                    usada = Some(pass.clone());
                }
                break;
            }
        }
        if let Some(p) = &usada {
            self.emitir(Evento::Aviso(format!("contraseña hallada para '{}': {}", nodo.nombre, p)));
        }
        if !ok {
            nodo.incompleto = true;
            nodo.notas.push(self.nota_cifrado());
        }
        let mut hijos = Vec::new();
        let mut pila = vec![tmp.clone()];
        while let Some(d) = pila.pop() {
            for e in fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    pila.push(p);
                } else if let Ok(datos) = fs::read(&p) {
                    let nombre = p.strip_prefix(&tmp).unwrap().to_string_lossy().into_owned();
                    hijos.push(Hijo { nombre, datos });
                }
            }
        }
        let _ = fs::remove_dir_all(&tmp);
        Ok(hijos)
    }

    /// Imágenes CHD (MAME): se extraen con `chdman` a BIN/CUE (o cruda), y la
    /// pista resultante vuelve a pasar por el motor (se detecta como ISO/BIN).
    /// NOTA: requiere `chdman` instalado; sin él, deja una nota y no falla el resto.
    fn con_chdman(&self, ruta: &Path, an: &Path, nodo: &mut Nodo) -> anyhow::Result<Vec<Hijo>> {
        if self.herr.get("chdman").is_none() {
            nodo.notas.push(tr("install chdman (mame-tools) to open CHD images", "instala chdman (mame-tools) para abrir imágenes CHD").into());
            anyhow::bail!("CHD requiere chdman");
        }
        let tmp = an.join(".chd_tmp");
        let _ = fs::create_dir_all(&tmp);
        let cue = tmp.join("disc.cue");
        let bin = tmp.join("disc.bin");
        // Imagen de CD/DVD -> BIN/CUE.
        self.externa("chdman", &[OsStr::new("extractcd"), OsStr::new("-f"), OsStr::new("-i"), ruta.as_os_str(), OsStr::new("-o"), cue.as_os_str(), OsStr::new("-ob"), bin.as_os_str()], an, "chdman.log", nodo);
        let mut hijos = Vec::new();
        if let Ok(datos) = fs::read(&bin) {
            hijos.push(Hijo { nombre: "disc.bin".into(), datos });
            if let Ok(c) = fs::read(&cue) {
                hijos.push(Hijo { nombre: "disc.cue".into(), datos: c });
            }
        } else {
            // No es un CD: intentar extracción cruda (disco duro / raw).
            let raw = tmp.join("disc.img");
            self.externa("chdman", &[OsStr::new("extractraw"), OsStr::new("-f"), OsStr::new("-i"), ruta.as_os_str(), OsStr::new("-o"), raw.as_os_str()], an, "chdman.log", nodo);
            if let Ok(datos) = fs::read(&raw) {
                hijos.push(Hijo { nombre: "disc.img".into(), datos });
            }
        }
        let _ = fs::remove_dir_all(&tmp);
        if hijos.is_empty() {
            anyhow::bail!("chdman no produjo salida");
        }
        Ok(hijos)
    }

    fn recorrer_hijos(&self, hijos: Vec<Hijo>, base: &Path, capa: usize, nodo: &mut Nodo) {
        if hijos.is_empty() {
            return;
        }
        if capa + 1 > self.cfg.profundidad_max {
            nodo.notas.push(tfmt(tr("{} unexplored children: maximum depth reached","{} hijos sin explorar: profundidad máxima alcanzada"), &[hijos.len().to_string()]));
            nodo.incompleto = true;
        }
        // Nombres de directorio únicos y seguros (sin "..", rutas absolutas...).
        let mut usados = HashSet::new();
        let mut tareas = Vec::new();
        for h in hijos {
            let total = self.usado.fetch_add(h.datos.len() as u64, Ordering::Relaxed) + h.datos.len() as u64;
            if total > self.cfg.max_total {
                nodo.notas.push(tfmt(tr("'{}' skipped: total extraction budget exhausted","'{}' omitido: presupuesto total de extracción agotado"), &[h.nombre.clone()]));
                nodo.incompleto = true;
                continue;
            }
            let mut rel = ruta_segura(&h.nombre);
            let mut k = 1;
            while !usados.insert(rel.clone()) {
                rel = PathBuf::from(format!("{}~{k}", ruta_segura(&h.nombre).display()));
                k += 1;
            }
            let dir = base.join(&rel);
            let archivo = rel.file_name().map(|s| s.to_os_string()).unwrap_or_else(|| "datos".into());
            let fisico = dir.join(&archivo);
            if fs::create_dir_all(&dir).is_err() || fs::write(&fisico, &h.datos).is_err() {
                nodo.notas.push(tfmt(tr("could not write '{}'","no se pudo escribir '{}'"), &[h.nombre.clone()]));
                nodo.incompleto = true;
                continue;
            }
            tareas.push((h, dir, fisico));
        }
        if capa + 1 > self.cfg.profundidad_max {
            return;
        }
        let mut hijos: Vec<Nodo> = tareas
            .into_par_iter()
            .map(|(h, dir, fisico)| {
                let Hijo { nombre, datos } = h;
                self.procesar(&datos, nombre, fisico, dir, capa + 1)
            })
            .collect();
        hijos.sort_by(|a, b| a.nombre.cmp(&b.nombre));
        nodo.hijos = hijos;
    }
}

/// ¿El nombre (ignorando la extensión) es un dispositivo reservado de Windows?
fn es_reservado_windows(nombre: &str) -> bool {
    let tronco = nombre.split('.').next().unwrap_or(nombre).to_ascii_uppercase();
    matches!(tronco.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((tronco.starts_with("COM") || tronco.starts_with("LPT"))
            && tronco.len() == 4
            && tronco.as_bytes()[3].is_ascii_digit()
            && tronco.as_bytes()[3] != b'0')
}

/// ¿El directorio (recursivo) contiene al menos un archivo? Sirve para saber si
/// una extracción con 7z produjo algo (contraseña correcta) o nada (cifrado).
fn dir_con_archivos(dir: &Path) -> bool {
    let mut pila = vec![dir.to_path_buf()];
    while let Some(d) = pila.pop() {
        for e in fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                pila.push(p);
            } else if p.is_file() {
                return true;
            }
        }
    }
    false
}

pub fn ruta_segura(nombre: &str) -> PathBuf {
    let mut p = PathBuf::new();
    for comp in nombre.split(['/', '\\']) {
        if comp.is_empty() || comp == "." || comp == ".." {
            continue;
        }
        let limpio: String = comp
            .chars()
            .map(|c| if c.is_control() || matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|') { '_' } else { c })
            .take(120)
            .collect();
        // "analisis" y "capas" están reservados dentro de cada nodo.
        let mut limpio = if limpio == "analisis" || limpio == "capas" { format!("{limpio}_") } else { limpio };
        // Nombres de dispositivo reservados en Windows (CON, NUL, COM1…): prefijar.
        if es_reservado_windows(&limpio) {
            limpio = format!("_{limpio}");
        }
        p.push(limpio);
    }
    if p.as_os_str().is_empty() {
        p.push("sin_nombre");
    }
    p
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const SCRIPT_GHIDRA: &str = r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class DecompilarTodo extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter w = new PrintWriter(new FileWriter(a[0]));
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) break;
            DecompileResults r = d.decompileFunction(f, 60, monitor);
            if (r.decompileCompleted()) {
                w.println("// " + f.getName() + " @ " + f.getEntryPoint());
                w.println(r.getDecompiledFunction().getC());
            }
        }
        w.close();
    }
}
"#;

#[cfg(test)]
mod pruebas_ruta {
    use super::ruta_segura;
    use std::path::Path;

    fn s(x: &str) -> String {
        ruta_segura(x).to_string_lossy().replace('\\', "/")
    }

    #[test]
    fn sin_escape_de_directorio() {
        assert_eq!(s("../../etc/passwd"), "etc/passwd");
        assert_eq!(s("/etc/passwd"), "etc/passwd");
        assert_eq!(s("a/../../b"), "a/b");
        assert_eq!(s("foo\\bar"), "foo/bar");
        assert_eq!(s("C:\\Windows\\System32\\x.dll"), "C_/Windows/System32/x.dll");
        assert_eq!(s("\\\\server\\share\\f"), "server/share/f");
        assert_eq!(s("a\u{0}b"), "a_b");
    }

    #[test]
    fn nombres_reservados_y_vacios() {
        assert_eq!(s("analisis"), "analisis_");
        assert_eq!(s("capas"), "capas_");
        assert_eq!(s("CON"), "_CON");
        assert_eq!(s("nul.txt"), "_nul.txt");
        assert_eq!(s("COM1"), "_COM1");
        assert_eq!(s("COM0"), "COM0"); // 0 no es dispositivo
        assert_eq!(s("COMA"), "COMA"); // 4º no es dígito
        assert_eq!(s(""), "sin_nombre");
        assert_eq!(s(".."), "sin_nombre");
        assert_eq!(s("/"), "sin_nombre");
    }

    #[test]
    fn propiedad_siempre_bajo_la_base() {
        let base = Path::new("/salida/run");
        for evil in ["../../../../etc/shadow", "/root/.ssh/id_rsa", "..\\..\\x", "C:\\x", "foo/../../bar", "", ".."] {
            let p = base.join(ruta_segura(evil));
            assert!(p.starts_with(base), "escape con {evil:?} -> {p:?}");
            assert!(!p.components().any(|c| c.as_os_str() == ".."), "quedó .. con {evil:?}");
        }
    }
}

/// ¿El fallo del extractor nativo se debe a una contraseña que falta o no encaja?
fn es_error_de_clave(e: &anyhow::Error) -> bool {
    let t = e.to_string().to_lowercase();
    t.contains("contraseña") || t.contains("password") || t.contains("cifrado") || t.contains("encrypt")
}
