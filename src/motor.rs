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

use crate::detectar::{self, Tipo};
use crate::ejecutables;
use crate::extraer::{self, Hijo};
use crate::recursos::{self, Herramientas};

pub struct Config {
    pub profundidad_max: usize,
    pub max_archivo: u64,
    pub max_total: u64,
    pub timeout: Duration,
    pub max_instrucciones: usize,
    pub tallar: bool,
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
    pub resultados: Vec<String>,
    pub notas: Vec<String>,
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
    pub fn procesar(&self, datos: Vec<u8>, nombre: String, ruta_fisica: PathBuf, dir: PathBuf, capa: usize) -> Nodo {
        let n = self.procesados.fetch_add(1, Ordering::Relaxed) + 1;
        let tipo = detectar::detectar(&datos);
        let sha = hex(&Sha256::digest(&datos));
        let rel = dir.strip_prefix(&self.raiz).unwrap_or(&dir).display().to_string();
        self.emitir(Evento::Bloque { n, capa, tipo, tamano: datos.len() as u64, ruta: rel.clone() });

        let mut nodo = Nodo {
            nombre: nombre.clone(),
            capa,
            tipo,
            descripcion: tipo.nombre().into(),
            tamano: datos.len() as u64,
            sha256: sha.clone(),
            entropia: (detectar::entropia(&datos) * 1000.0).round() / 1000.0,
            directorio: rel,
            resultados: Vec::new(),
            notas: Vec::new(),
            hijos: Vec::new(),
            ruta_fisica: ruta_fisica.clone(),
        };

        {
            let mut v = self.vistos.lock().unwrap();
            if let Some(prev) = v.get(&sha) {
                nodo.notas.push(format!("contenido idéntico a {prev}: no se repite el análisis"));
                return nodo;
            }
            v.insert(sha, nodo.directorio.clone());
        }

        if self.cancelar.load(Ordering::Relaxed) {
            nodo.notas.push("análisis cancelado por el operador".into());
            return nodo;
        }

        let analisis = dir.join("analisis");
        let _ = fs::create_dir_all(&analisis);
        if nodo.entropia > 7.5 && !tipo.es_contenedor() && tipo != Tipo::Imagen {
            nodo.notas.push(format!(
                "entropía muy alta ({:.2}): probablemente comprimido o cifrado",
                nodo.entropia
            ));
        }

        let hijos = self.capa(&datos, &nombre, &ruta_fisica, &analisis, tipo, &mut nodo);
        drop(datos);
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
                    nodo.notas.push(format!("{prog}: tiempo agotado ({}s)", self.cfg.timeout.as_secs()));
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
            Tipo::Tar => extraer::tar(d, lim, &mut notas),
            Tipo::ArUnix => extraer::ar(d),
            Tipo::MachOFat => extraer::macho_fat(d),
            Tipo::Pdf => Ok(extraer::pdf(d, lim)),
            Tipo::SieteZ | Tipo::Rar | Tipo::Cab => self.con_7z(ruta, an, nodo),
            Tipo::Elf | Tipo::Pe | Tipo::MachO => {
                self.nativo(d, r, an, tipo, nodo);
                Ok(Vec::new())
            }
            Tipo::ClaseJava => {
                let ok = self.externa("javap", &[OsStr::new("-c"), OsStr::new("-p"), OsStr::new("-v"), r], an, "javap.txt", nodo);
                let fuente = self.externa("cfr", &[r], an, "decompilado.java", nodo)
                    || self.externa("procyon", &[r], an, "decompilado.java", nodo);
                if !ok && !fuente {
                    nodo.notas.push("instala un JDK (javap) o CFR/Procyon para decompilar".into());
                }
                Ok(Vec::new())
            }
            Tipo::Dex => {
                if self.herr.get("jadx").is_some() {
                    let out = an.join("jadx");
                    self.externa("jadx", &[OsStr::new("-d"), out.as_os_str(), r], an, "jadx.log", nodo);
                    nodo.resultados.push(format!("{}/jadx/", nodo.directorio));
                } else {
                    nodo.notas.push("instala jadx para decompilar DEX a Java".into());
                }
                Ok(Vec::new())
            }
            Tipo::Pyc => {
                let ok = self.externa("pycdc", &[r], an, "decompilado.py", nodo)
                    || self.externa("decompyle3", &[r], an, "decompilado.py", nodo)
                    || self.externa("uncompyle6", &[r], an, "decompilado.py", nodo);
                if !ok {
                    nodo.notas.push("instala pycdc/uncompyle6 para decompilar .pyc".into());
                }
                Ok(Vec::new())
            }
            Tipo::Wasm => {
                let a = self.externa("wasm2wat", &[r], an, "modulo.wat", nodo);
                let b = self.externa("wasm-decompile", &[r], an, "decompilado.dcmp", nodo);
                if !a && !b {
                    nodo.notas.push("instala wabt (wasm2wat / wasm-decompile)".into());
                }
                Ok(Vec::new())
            }
            Tipo::Texto => Ok(extraer::base64_embebido(d)),
            Tipo::Imagen => Ok(Vec::new()),
            Tipo::Desconocido => {
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
                nodo.notas.push(format!("no se pudo extraer la capa: {e}"));
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
                nodo.notas.push(format!("{} bloque(s) incrustado(s) encontrados por firma", t.len()));
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
            Err(e) => nodo.notas.push(format!("análisis interno: {e}")),
        }
        if tipo == Tipo::Elf {
            self.externa("readelf", &[OsStr::new("-a"), OsStr::new("-W"), r], an, "readelf.txt", nodo);
        }
        if !interno_x86 || self.herr.get("r2").is_none() {
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

    fn con_7z(&self, ruta: &Path, an: &Path, nodo: &mut Nodo) -> anyhow::Result<Vec<Hijo>> {
        if self.herr.get("7z").is_none() {
            anyhow::bail!("formato que requiere 7z (p7zip) instalado");
        }
        let tmp = an.join(".7z_tmp");
        let mut o = std::ffi::OsString::from("-o");
        o.push(&tmp);
        self.externa("7z", &[OsStr::new("x"), OsStr::new("-y"), OsStr::new("-p-"), &o, ruta.as_os_str()], an, "7z.log", nodo);
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

    fn recorrer_hijos(&self, hijos: Vec<Hijo>, base: &Path, capa: usize, nodo: &mut Nodo) {
        if hijos.is_empty() {
            return;
        }
        if capa + 1 > self.cfg.profundidad_max {
            nodo.notas.push(format!("{} hijos sin explorar: profundidad máxima alcanzada", hijos.len()));
        }
        // Nombres de directorio únicos y seguros (sin "..", rutas absolutas...).
        let mut usados = HashSet::new();
        let mut tareas = Vec::new();
        for h in hijos {
            let total = self.usado.fetch_add(h.datos.len() as u64, Ordering::Relaxed) + h.datos.len() as u64;
            if total > self.cfg.max_total {
                nodo.notas.push(format!("'{}' omitido: presupuesto total de extracción agotado", h.nombre));
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
                nodo.notas.push(format!("no se pudo escribir '{}'", h.nombre));
                continue;
            }
            tareas.push((h, dir, fisico));
        }
        if capa + 1 > self.cfg.profundidad_max {
            return;
        }
        let mut hijos: Vec<Nodo> = tareas
            .into_par_iter()
            .map(|(h, dir, fisico)| self.procesar(h.datos, h.nombre, fisico, dir, capa + 1))
            .collect();
        hijos.sort_by(|a, b| a.nombre.cmp(&b.nombre));
        nodo.hijos = hijos;
    }
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
        let limpio = if limpio == "analisis" || limpio == "capas" { format!("{limpio}_") } else { limpio };
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
