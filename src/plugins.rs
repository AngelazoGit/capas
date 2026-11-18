//! Informe de plugins / código activo: recorre el árbol, reúne todo lo que es
//! código (ELF/PE/Mach-O y bytecode) y, para los nativos, extrae sus funciones
//! y las APIs que importa, marcando capacidades sensibles (red, ficheros,
//! procesos, registro, cripto). No ejecuta nada: solo lee y analiza.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use goblin::Object;
use serde::Serialize;

use crate::detectar::Tipo;
use crate::motor::Nodo;
use crate::recursos::humano;

/// Capacidad sensible → subcadenas de nombres de API que la delatan.
const CAPACIDADES: &[(&str, &[&str])] = &[
    ("red", &["socket", "connect", "recv", "send", "bind", "listen", "wsa", "inet", "gethostby",
        "getaddrinfo", "internetopen", "urldownload", "httpsend", "winhttp", "curl", "dns", "ssl", "tls"]),
    ("ficheros", &["fopen", "createfile", "readfile", "writefile", "deletefile", "unlink", "remove",
        "rename", "mkdir", "movefile", "copyfile"]),
    ("procesos", &["system", "popen", "execv", "execl", "execve", "fork", "createprocess", "shellexecute",
        "winexec", "loadlibrary", "dlopen", "getprocaddress", "ptrace", "virtualalloc"]),
    ("registro/persistencia", &["regopenkey", "regsetvalue", "regcreatekey", "schtasks", "crontab"]),
    ("cripto", &["crypt", "aes", "rsa", "evp_", "bcrypt", "cryptacquire", "sha256"]),
];

#[derive(Serialize)]
pub struct Plugin {
    pub nombre: String,
    pub tipo: String,
    pub arquitectura: Option<String>,
    pub tamano: u64,
    pub sha256: String,
    pub funciones: Vec<String>,
    pub importaciones: Vec<String>,
    pub capacidades: Vec<String>,
    pub nota: Option<String>,
}

#[derive(Serialize)]
pub struct InformePlugins {
    pub plugins: Vec<Plugin>,
}

fn es_codigo(t: Tipo) -> bool {
    matches!(
        t,
        Tipo::Elf | Tipo::Pe | Tipo::MachO | Tipo::MachOFat
            | Tipo::ClaseJava | Tipo::Dex | Tipo::Pyc | Tipo::Wasm
    )
}

/// Genera `plugins.md` / `.json` si hay código activo. Devuelve cuántos.
pub fn analizar(arbol: &[Nodo], raiz: &Path) -> Option<usize> {
    let mut plugins = Vec::new();
    recoge(arbol, &mut plugins);
    if plugins.is_empty() {
        return Some(0);
    }
    let inf = InformePlugins { plugins };
    let _ = fs::write(raiz.join("plugins.md"), informe(&inf));
    if let Ok(j) = serde_json::to_string_pretty(&inf) {
        let _ = fs::write(raiz.join("plugins.json"), j);
    }
    Some(inf.plugins.len())
}

fn recoge(nodos: &[Nodo], out: &mut Vec<Plugin>) {
    for n in nodos {
        if es_codigo(n.tipo) {
            out.push(construir(n));
        }
        recoge(&n.hijos, out);
    }
}

fn construir(n: &Nodo) -> Plugin {
    let base = n.nombre.rsplit(['/', '\\']).next().unwrap_or(&n.nombre).to_string();
    let mut p = Plugin {
        nombre: base,
        tipo: n.descripcion.clone(),
        arquitectura: None,
        tamano: n.tamano,
        sha256: n.sha256.clone(),
        funciones: Vec::new(),
        importaciones: Vec::new(),
        capacidades: Vec::new(),
        nota: None,
    };
    // Bytecode: las funciones se ven en su analisis/ (javap/decompilador).
    if matches!(n.tipo, Tipo::ClaseJava | Tipo::Dex | Tipo::Pyc | Tipo::Wasm) {
        p.nota = Some("funciones y métodos en su carpeta analisis/ (javap / decompilador)".into());
        return p;
    }
    let Ok(datos) = fs::read(&n.ruta_fisica) else {
        p.nota = Some("no se pudo leer para extraer funciones".into());
        return p;
    };
    extraer_nativo(&datos, &mut p);
    p.funciones.sort();
    p.funciones.dedup();
    p.funciones.truncate(400);
    p.importaciones.sort();
    p.importaciones.dedup();
    p.importaciones.truncate(400);
    p.capacidades = capacidades(&p.importaciones);
    p
}

fn extraer_nativo(datos: &[u8], p: &mut Plugin) {
    match Object::parse(datos) {
        Ok(Object::Elf(e)) => {
            p.arquitectura = Some(goblin::elf::header::machine_to_str(e.header.e_machine).to_string());
            for s in e.syms.iter() {
                if s.is_function() && s.st_value != 0 {
                    if let Some(n) = e.strtab.get_at(s.st_name) {
                        if !n.is_empty() {
                            p.funciones.push(n.to_string());
                        }
                    }
                }
            }
            for s in e.dynsyms.iter() {
                if let Some(n) = e.dynstrtab.get_at(s.st_name) {
                    if n.is_empty() {
                        continue;
                    }
                    if s.is_import() {
                        p.importaciones.push(n.to_string());
                    } else if s.is_function() && s.st_value != 0 {
                        p.funciones.push(n.to_string());
                    }
                }
            }
        }
        Ok(Object::PE(pe)) => {
            p.arquitectura = Some(match pe.header.coff_header.machine {
                goblin::pe::header::COFF_MACHINE_X86_64 => "x86-64".into(),
                goblin::pe::header::COFF_MACHINE_X86 => "x86".into(),
                otra => format!("máquina 0x{otra:x}"),
            });
            for ex in &pe.exports {
                if let Some(n) = ex.name {
                    p.funciones.push(n.to_string());
                }
            }
            for im in &pe.imports {
                p.importaciones.push(format!("{}!{}", im.dll, im.name));
            }
        }
        Ok(Object::Mach(goblin::mach::Mach::Binary(m))) => {
            p.arquitectura = goblin::mach::cputype::get_arch_name_from_types(m.header.cputype, m.header.cpusubtype)
                .map(|s| s.to_string());
            if let Some(syms) = &m.symbols {
                for (nombre, nl) in syms.iter().flatten() {
                    if nl.n_value != 0 && !nombre.is_empty() {
                        p.funciones.push(nombre.trim_start_matches('_').to_string());
                    }
                }
            }
            if let Ok(imps) = m.imports() {
                for i in imps {
                    p.importaciones.push(i.name.to_string());
                }
            }
        }
        _ => {
            p.nota = Some("formato nativo no analizado para funciones".into());
        }
    }
}

/// Capacidades sensibles presentes, con las APIs que las delatan.
fn capacidades(importaciones: &[String]) -> Vec<String> {
    let bajas: Vec<String> = importaciones.iter().map(|s| s.to_lowercase()).collect();
    let mut out = Vec::new();
    for (cap, claves) in CAPACIDADES {
        let hits: Vec<&String> = importaciones
            .iter()
            .zip(&bajas)
            .filter(|(_, b)| claves.iter().any(|k| b.contains(k)))
            .map(|(orig, _)| orig)
            .take(6)
            .collect();
        if !hits.is_empty() {
            let lista: Vec<&str> = hits.iter().map(|s| s.as_str()).collect();
            out.push(format!("{cap}: {}", lista.join(", ")));
        }
    }
    out
}

fn informe(inf: &InformePlugins) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Plugins / código activo\n");
    let _ = writeln!(s, "{} elemento(s) de código encontrados. **capas no los ejecuta.**\n", inf.plugins.len());
    let _ = writeln!(s, "| Plugin | Tipo | Tamaño | Funciones | Capacidades sensibles |");
    let _ = writeln!(s, "|---|---|--:|--:|---|");
    for p in &inf.plugins {
        let caps = if p.capacidades.is_empty() {
            "—".to_string()
        } else {
            p.capacidades.iter().map(|c| c.split(':').next().unwrap_or("")).collect::<Vec<_>>().join(", ")
        };
        let _ = writeln!(s, "| {} | {} | {} | {} | {} |", p.nombre, p.tipo, humano(p.tamano), p.funciones.len(), caps);
    }
    for p in &inf.plugins {
        let _ = writeln!(s, "\n## {}\n", p.nombre);
        let _ = writeln!(s, "- Tipo: {}{}", p.tipo, p.arquitectura.as_ref().map(|a| format!(" · {a}")).unwrap_or_default());
        let _ = writeln!(s, "- Tamaño: {} · SHA-256: `{}`", humano(p.tamano), &p.sha256[..16]);
        if let Some(nota) = &p.nota {
            let _ = writeln!(s, "- {nota}");
        }
        if !p.capacidades.is_empty() {
            let _ = writeln!(s, "\n**⚠ Capacidades sensibles:**");
            for c in &p.capacidades {
                let _ = writeln!(s, "- {c}");
            }
        }
        if !p.funciones.is_empty() {
            let _ = writeln!(s, "\n**Funciones ({}):**", p.funciones.len());
            let _ = writeln!(s, "```\n{}\n```", muestra(&p.funciones, 60));
        }
        if !p.importaciones.is_empty() {
            let _ = writeln!(s, "**Importa ({}):**", p.importaciones.len());
            let _ = writeln!(s, "```\n{}\n```", muestra(&p.importaciones, 60));
        }
    }
    let _ = writeln!(s, "\n---\n*Informe de plugins — capas, de @angelazo. Detección y análisis, no bloqueo: capas no ejecuta el código.*");
    s
}

fn muestra(v: &[String], max: usize) -> String {
    let mut s = v.iter().take(max).cloned().collect::<Vec<_>>().join("\n");
    if v.len() > max {
        s.push_str(&format!("\n… y {} más", v.len() - max));
    }
    s
}
