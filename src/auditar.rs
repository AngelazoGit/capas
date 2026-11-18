//! Módulo de auditoría de paquetes (asset packs, mods…): sobre el árbol ya
//! extraído aplica reglas defensivas y emite un veredicto por paquete —
//! APROBADO / CUARENTENA / RECHAZADO— sin ejecutar nada.
//!
//! Reutiliza lo que el motor ya calculó: nombre original de cada entrada
//! (para detectar rutas de escape), tipo detectado por contenido, SHA-256,
//! tamaño y la categoría de clasificación (para ejecutables/código activo).

use std::fmt::Write as _;
use std::path::Path;

use serde::Serialize;

use crate::clasificar::{categoria, Categoria};
use crate::motor::Nodo;
use crate::recursos::humano;

/// Extensiones de recursos aceptadas en una revisión inicial (allowlist de la
/// guía; depende de la versión del juego, por eso es conservadora).
const ALLOWLIST: &[&str] = &[
    "json", "png", "jpg", "jpeg", "ogg", "wav", "model", "animation", "particle",
    "ui", "font", "atlas", "bin",
];

/// Extensiones de código activo / ejecutables que mandan el paquete a cuarentena.
const PELIGROSAS: &[&str] = &[
    "exe", "dll", "so", "dylib", "jar", "class", "bat", "cmd", "ps1", "vbs", "scr", "msi",
];

/// Campos recomendados del manifest de un paquete.
const CAMPOS_MANIFEST: &[&str] = &[
    "Group", "Name", "Version", "Description", "Authors", "Website",
    "Dependencies", "OptionalDependencies", "LoadBefore", "SubPlugins",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Veredicto {
    Aprobado,
    Cuarentena,
    Rechazado,
}

impl Veredicto {
    pub fn etiqueta(self) -> &'static str {
        match self {
            Veredicto::Aprobado => "APROBADO",
            Veredicto::Cuarentena => "CUARENTENA",
            Veredicto::Rechazado => "RECHAZADO",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Nivel {
    Info,
    Aviso,
    Rechazo,
}

#[derive(Serialize)]
pub struct Hallazgo {
    pub nivel: Nivel,
    pub regla: String,
    pub detalle: String,
}

#[derive(Serialize)]
pub struct Paquete {
    pub nombre: String,
    pub sha256: String,
    pub tamano: u64,
    pub archivos: usize,
    pub manifest_ok: bool,
    pub veredicto: Veredicto,
    pub hallazgos: Vec<Hallazgo>,
}

#[derive(Serialize)]
pub struct Auditoria {
    pub paquetes: Vec<Paquete>,
}

/// Audita cada paquete raíz del árbol y escribe `auditoria.md` / `.json`.
pub fn auditar(arbol: &[Nodo], raiz: &Path) -> std::io::Result<Auditoria> {
    let paquetes: Vec<Paquete> = arbol.iter().map(auditar_paquete).collect();
    let a = Auditoria { paquetes };
    std::fs::write(raiz.join("auditoria.md"), informe(&a))?;
    if let Ok(j) = serde_json::to_string_pretty(&a) {
        let _ = std::fs::write(raiz.join("auditoria.json"), j);
    }
    Ok(a)
}

fn auditar_paquete(raiz: &Nodo) -> Paquete {
    let mut h = Vec::new();
    let mut archivos = 0usize;
    let mut manifest_ok = false;

    recorrer(raiz, &mut |n| {
        archivos += 1;
        // 1) Rutas de escape (se comprueba sobre el nombre ORIGINAL de la entrada).
        if let Some(motivo) = ruta_escape(&n.nombre) {
            h.push(Hallazgo {
                nivel: Nivel::Rechazo,
                regla: "ruta-escape".into(),
                detalle: format!("{motivo}: «{}»", n.nombre),
            });
        }
        // 2) Código activo / ejecutables / librerías nativas.
        let ext = extension(&n.nombre);
        let cat = categoria(n.tipo, &n.nombre);
        if PELIGROSAS.contains(&ext.as_str()) || matches!(cat, Categoria::Ejecutable | Categoria::Bytecode) {
            h.push(Hallazgo {
                nivel: Nivel::Aviso,
                regla: "codigo-activo".into(),
                detalle: format!("{} ({})", n.nombre, n.descripcion),
            });
        }
        // 3) Manifest del paquete (en la raíz del pack).
        if es_manifest(&n.nombre) {
            match validar_manifest(&n.ruta_fisica) {
                Ok(faltan) => {
                    manifest_ok = true;
                    if !faltan.is_empty() {
                        h.push(Hallazgo {
                            nivel: Nivel::Info,
                            regla: "manifest-campos".into(),
                            detalle: format!("faltan campos recomendados: {}", faltan.join(", ")),
                        });
                    }
                }
                Err(e) => h.push(Hallazgo {
                    nivel: Nivel::Rechazo,
                    regla: "manifest-invalido".into(),
                    detalle: format!("{}: {e}", n.nombre),
                }),
            }
        }
        // 4) Allowlist de extensiones (solo archivos hoja reconocibles).
        else if n.hijos.is_empty()
            && !ext.is_empty()
            && !ALLOWLIST.contains(&ext.as_str())
            && !PELIGROSAS.contains(&ext.as_str())
        {
            h.push(Hallazgo {
                nivel: Nivel::Aviso,
                regla: "fuera-allowlist".into(),
                detalle: format!("extensión no reconocida: {} (.{ext})", n.nombre),
            });
        }
    });

    // El manifest solo se exige a paquetes contenedores (zip/carpeta con hijos).
    let es_contenedor = !raiz.hijos.is_empty();
    if es_contenedor && !manifest_ok {
        h.push(Hallazgo {
            nivel: Nivel::Rechazo,
            regla: "manifest-ausente".into(),
            detalle: "falta manifest.json en el paquete".into(),
        });
    }

    let veredicto = match h.iter().map(|x| x.nivel).max() {
        Some(Nivel::Rechazo) => Veredicto::Rechazado,
        Some(Nivel::Aviso) => Veredicto::Cuarentena,
        _ => Veredicto::Aprobado,
    };

    Paquete {
        nombre: raiz.nombre.clone(),
        sha256: raiz.sha256.clone(),
        tamano: raiz.tamano,
        archivos,
        manifest_ok,
        veredicto,
        hallazgos: h,
    }
}

fn recorrer(n: &Nodo, f: &mut impl FnMut(&Nodo)) {
    f(n);
    for h in &n.hijos {
        recorrer(h, f);
    }
}

/// Detecta rutas absolutas o navegación fuera de la carpeta (zip-slip).
fn ruta_escape(nombre: &str) -> Option<&'static str> {
    let n = nombre.replace('\\', "/");
    if n.starts_with('/') {
        return Some("ruta absoluta");
    }
    // Letra de unidad de Windows (C:\…).
    let b = n.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return Some("ruta absoluta");
    }
    if n.split('/').any(|seg| seg == "..") {
        return Some("navegación fuera de la carpeta");
    }
    None
}

fn extension(nombre: &str) -> String {
    nombre
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(nombre)
        .rsplit_once('.')
        .map(|(_, e)| e.to_lowercase())
        .unwrap_or_default()
}

fn es_manifest(nombre: &str) -> bool {
    nombre
        .rsplit(['/', '\\'])
        .next()
        .map(|b| b.eq_ignore_ascii_case("manifest.json"))
        .unwrap_or(false)
}

/// Valida que el manifest sea JSON y devuelve los campos recomendados que faltan.
fn validar_manifest(ruta: &Path) -> Result<Vec<&'static str>, String> {
    let datos = std::fs::read(ruta).map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_slice(&datos).map_err(|e| e.to_string())?;
    let obj = v.as_object().ok_or("el manifest no es un objeto JSON")?;
    // Búsqueda de claves sin distinguir mayúsculas.
    let tiene = |campo: &str| obj.keys().any(|k| k.eq_ignore_ascii_case(campo));
    if !tiene("Name") || !tiene("Version") {
        return Err("faltan campos obligatorios Name/Version".into());
    }
    Ok(CAMPOS_MANIFEST.iter().copied().filter(|c| !tiene(c)).collect())
}

fn informe(a: &Auditoria) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Auditoría de paquetes\n");
    let _ = writeln!(s, "{} paquete(s) auditados.\n", a.paquetes.len());
    let _ = writeln!(s, "| Paquete | Veredicto | Archivos | Tamaño | Manifest |");
    let _ = writeln!(s, "|---|---|--:|--:|:--:|");
    for p in &a.paquetes {
        let _ = writeln!(
            s,
            "| {} | **{}** | {} | {} | {} |",
            p.nombre,
            p.veredicto.etiqueta(),
            p.archivos,
            humano(p.tamano),
            if p.manifest_ok { "sí" } else { "no" }
        );
    }
    for p in &a.paquetes {
        let _ = writeln!(s, "\n## {} — {}\n", p.nombre, p.veredicto.etiqueta());
        let _ = writeln!(s, "- SHA-256: `{}`", p.sha256);
        let _ = writeln!(s, "- Tamaño: {} · Archivos: {}", humano(p.tamano), p.archivos);
        if p.hallazgos.is_empty() {
            let _ = writeln!(s, "- Sin hallazgos.");
            continue;
        }
        for h in &p.hallazgos {
            let marca = match h.nivel {
                Nivel::Rechazo => "⛔",
                Nivel::Aviso => "⚠",
                Nivel::Info => "ℹ",
            };
            let _ = writeln!(s, "- {marca} [{}] {}", h.regla, h.detalle);
        }
    }
    let _ = writeln!(
        s,
        "\n---\n**Aprobar solo si:** manifest válido, sin rutas de escape, sin ejecutables ni \
         librerías nativas, hash revisado, dependencias esperadas, tamaño razonable. Un hash \
         demuestra identidad, no inocencia: analiza en cuarentena con antivirus/sandbox y mantén \
         el juego actualizado. Auditoría de @angelazo."
    );
    s
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn detecta_rutas_de_escape() {
        assert!(ruta_escape("../secreto").is_some());
        assert!(ruta_escape("..\\secreto").is_some());
        assert!(ruta_escape("/etc/passwd").is_some());
        assert!(ruta_escape("C:\\Windows\\x").is_some());
        assert!(ruta_escape("assets/ok.png").is_none());
        assert!(ruta_escape("a..b/ok.json").is_none()); // ".." dentro de un nombre, no un segmento
    }
}
