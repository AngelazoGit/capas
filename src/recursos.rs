//! Detección de los recursos del ordenador: CPU, memoria, disco y
//! herramientas externas (desensambladores / decompiladores) instaladas.

use std::collections::BTreeMap;
use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sysinfo::System;

#[derive(Debug, Clone)]
pub struct Sistema {
    pub nucleos: usize,
    pub memoria_total: u64,
    pub memoria_libre: u64,
}

impl Sistema {
    pub fn detectar() -> Self {
        let (total, libre) = match System::new() {
            Ok(mut s) => {
                s.refresh_memory();
                (s.total_memory(), s.available_memory())
            }
            Err(_) => (0, 0),
        };
        // Si no se puede leer la memoria, suponemos 2 GiB libres.
        let libre = if libre == 0 { 2 << 30 } else { libre };
        let nucleos = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Sistema {
            nucleos,
            memoria_total: total,
            memoria_libre: libre,
        }
    }
}

/// Herramientas externas que el programa sabe aprovechar si están instaladas.
pub const HERRAMIENTAS_CONOCIDAS: &[(&str, &str)] = &[
    ("objdump", "desensamblado ELF/PE de cualquier arquitectura (binutils)"),
    ("readelf", "cabeceras completas ELF"),
    ("file", "identificación de formatos desconocidos"),
    ("javap", "desensamblado de bytecode Java (.class)"),
    ("cfr", "decompilador Java -> código fuente"),
    ("procyon", "decompilador Java -> código fuente"),
    ("jadx", "decompilador Android DEX/APK -> Java"),
    ("pycdc", "decompilador de bytecode Python (.pyc)"),
    ("uncompyle6", "decompilador de bytecode Python (.pyc)"),
    ("decompyle3", "decompilador de bytecode Python (.pyc)"),
    ("wasm2wat", "WebAssembly binario -> texto"),
    ("wasm-decompile", "WebAssembly -> pseudocódigo"),
    ("retdec-decompiler", "decompilador nativo -> C"),
    ("r2", "radare2: análisis y desensamblado por funciones"),
    ("7z", "extracción de 7z/RAR/CAB/ISO/MSI"),
    ("analyzeHeadless", "Ghidra headless: decompilación nativa -> C (o define GHIDRA_HOME)"),
];

#[derive(Debug, Clone, Default)]
pub struct Herramientas {
    pub rutas: BTreeMap<String, PathBuf>,
}

impl Herramientas {
    pub fn detectar(desactivar: bool) -> Self {
        let mut rutas = BTreeMap::new();
        if desactivar {
            return Herramientas { rutas };
        }
        for (nombre, _) in HERRAMIENTAS_CONOCIDAS {
            if let Some(p) = buscar_en_path(nombre) {
                rutas.insert(nombre.to_string(), p);
            }
        }
        if !rutas.contains_key("analyzeHeadless") {
            if let Ok(home) = env::var("GHIDRA_HOME") {
                let p = Path::new(&home).join("support").join("analyzeHeadless");
                if p.is_file() {
                    rutas.insert("analyzeHeadless".into(), p);
                }
            }
        }
        Herramientas { rutas }
    }

    pub fn get(&self, nombre: &str) -> Option<&PathBuf> {
        self.rutas.get(nombre)
    }
}

fn buscar_en_path(nombre: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let p = dir.join(nombre);
        if p.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(m) = p.metadata() {
                    if m.permissions().mode() & 0o111 == 0 {
                        continue;
                    }
                }
            }
            return Some(p);
        }
        #[cfg(windows)]
        {
            let pe = dir.join(format!("{nombre}.exe"));
            if pe.is_file() {
                return Some(pe);
            }
        }
    }
    None
}

pub struct Salida {
    pub codigo: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub agotado: bool,
}

/// Ejecuta un programa externo con límite de tiempo y de tamaño de salida.
pub fn ejecutar(
    prog: &Path,
    args: &[&std::ffi::OsStr],
    timeout: Duration,
    max_salida: u64,
) -> std::io::Result<Salida> {
    let mut hijo = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut out = hijo.stdout.take().unwrap();
    let mut err = hijo.stderr.take().unwrap();
    let h_out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = (&mut out).take(max_salida).read_to_end(&mut v);
        // Vaciar el resto para que el proceso no se bloquee.
        let _ = std::io::copy(&mut out, &mut std::io::sink());
        v
    });
    let h_err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = (&mut err).take(1 << 20).read_to_end(&mut v);
        let _ = std::io::copy(&mut err, &mut std::io::sink());
        v
    });

    let inicio = Instant::now();
    let mut agotado = false;
    let estado = loop {
        if let Some(st) = hijo.try_wait()? {
            break Some(st);
        }
        if inicio.elapsed() > timeout {
            let _ = hijo.kill();
            agotado = true;
            break hijo.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Ok(Salida {
        codigo: estado.and_then(|s| s.code()),
        stdout: h_out.join().unwrap_or_default(),
        stderr: h_err.join().unwrap_or_default(),
        agotado,
    })
}

pub fn humano(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}
