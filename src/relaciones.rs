//! Relaciones entre archivos (grafo de familia). Genérico, sin marca de ningún
//! formato: si dentro de un paquete unos archivos se **referencian** entre sí o
//! forman un **conjunto** por nombre, se registran las relaciones y se ajusta la
//! confianza con la evidencia:
//!
//! - un archivo referenciado por un **manifest** → la referencia es Confirmada;
//!   el referenciado sube a CONFIRMADO (si no lo estaba ya).
//! - referenciado por otro archivo cualquiera → COMPATIBLE.
//! - mismo nombre base en la misma carpeta → relación de "familia" (conjunto).
//! - mismo SHA-256 → "duplicado de".
//!
//! Nada se ejecuta: solo se lee el contenido para buscar menciones de nombres.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::clasificar::Confianza;
use crate::detectar::Tipo;
use crate::idioma::{tfmt, tr};
use crate::motor::Nodo;

const MAX_LEER: u64 = 4 << 20; // no leer referrers enormes

#[derive(Serialize, Clone)]
pub struct Relacion {
    pub origen: String,
    pub tipo: &'static str, // "references" | "family" | "duplicate"
    pub destino: String,
    pub confirmada: bool,
}

#[derive(Serialize)]
pub struct Relaciones {
    pub relaciones: Vec<Relacion>,
}

struct Hoja {
    nombre: String,          // nombre base
    stem: String,            // sin extensión
    carpeta: String,         // carpeta de origen (del nombre original)
    sha: String,
    ruta: PathBuf,
    es_texto: bool,
    es_manifest: bool,
}

fn extension(n: &str) -> String {
    n.rsplit('.').next().filter(|e| *e != n).map(|e| e.to_lowercase()).unwrap_or_default()
}

fn es_textual(tipo: Tipo, ext: &str) -> bool {
    tipo == Tipo::Texto
        || matches!(ext, "json" | "xml" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf" | "txt" | "ui" | "csv" | "md")
}

fn es_manifest(base: &str) -> bool {
    let b = base.to_lowercase();
    b == "manifest.json" || b == "plugin.yml" || b == "plugin.yaml" || b == "package.json"
        || b == "pack.mcmeta" || b == "fabric.mod.json" || b.contains("manifest")
}

/// Construye las relaciones por paquete raíz, actualiza la confianza de los
/// referenciados y escribe `relaciones.md` / `.json`. Devuelve cuántas relaciones.
pub fn relacionar(arbol: &mut [Nodo], raiz: &Path) -> std::io::Result<usize> {
    let mut rels: Vec<Relacion> = Vec::new();
    // Ajustes de confianza a aplicar: ruta_fisica -> (nueva, evidencia).
    let mut subir: HashMap<PathBuf, (Confianza, String)> = HashMap::new();
    // Notas a añadir: ruta_fisica -> notas.
    let mut notas: HashMap<PathBuf, Vec<String>> = HashMap::new();

    for root in arbol.iter() {
        let mut hojas = Vec::new();
        recoge(root, &mut hojas);
        analizar_paquete(&hojas, &mut rels, &mut subir, &mut notas);
    }

    aplicar(arbol, &subir, &notas);

    if rels.is_empty() {
        return Ok(0);
    }
    let r = Relaciones { relaciones: rels };
    let _ = std::fs::write(raiz.join("relaciones.md"), informe(&r));
    if let Ok(j) = serde_json::to_string_pretty(&r) {
        let _ = std::fs::write(raiz.join("relaciones.json"), j);
    }
    Ok(r.relaciones.len())
}

fn recoge(n: &Nodo, out: &mut Vec<Hoja>) {
    if n.hijos.is_empty() && n.ruta_fisica.is_file() {
        let base = n.nombre.rsplit(['/', '\\']).next().unwrap_or(&n.nombre).to_string();
        let carpeta = n.nombre[..n.nombre.len() - base.len()].trim_end_matches(['/', '\\']).to_string();
        let stem = base.rsplit_once('.').map(|(a, _)| a).unwrap_or(&base).to_string();
        let ext = extension(&base);
        out.push(Hoja {
            es_texto: es_textual(n.tipo, &ext),
            es_manifest: es_manifest(&base),
            nombre: base.clone(),
            stem,
            carpeta,
            sha: n.sha256.clone(),
            ruta: n.ruta_fisica.clone(),
        });
    }
    for h in &n.hijos {
        recoge(h, out);
    }
}

fn analizar_paquete(
    hojas: &[Hoja],
    rels: &mut Vec<Relacion>,
    subir: &mut HashMap<PathBuf, (Confianza, String)>,
    notas: &mut HashMap<PathBuf, Vec<String>>,
) {
    // 1) Referencias: un archivo textual que menciona el nombre de otro.
    for (i, referrer) in hojas.iter().enumerate() {
        if !referrer.es_texto {
            continue;
        }
        let Ok(bytes) = leer(&referrer.ruta) else { continue };
        let texto = String::from_utf8_lossy(&bytes);
        for (j, dest) in hojas.iter().enumerate() {
            if i == j || dest.nombre.len() < 4 {
                continue;
            }
            // Referencia solo si menciona el nombre completo (evita falsos
            // positivos por nombres base compartidos; eso lo capta "familia").
            if texto.contains(&dest.nombre) {
                rels.push(Relacion {
                    origen: ruta_rel(referrer),
                    tipo: "references",
                    destino: ruta_rel(dest),
                    confirmada: referrer.es_manifest,
                });
                // Ajuste de confianza del referenciado.
                let (nueva, ev) = if referrer.es_manifest {
                    (Confianza::Confirmado, tfmt(tr("referenced by manifest {}", "referenciado por el manifest {}"), &[referrer.nombre.clone()]))
                } else {
                    (Confianza::Compatible, tfmt(tr("referenced by {}", "referenciado por {}"), &[referrer.nombre.clone()]))
                };
                mejor_confianza(subir, &dest.ruta, nueva, ev);
                notas.entry(dest.ruta.clone()).or_default().push(
                    tfmt(tr("referenced by {}", "referenciado por {}"), &[referrer.nombre.clone()]),
                );
            }
        }
    }

    // 2) Duplicados por SHA-256.
    let mut por_sha: HashMap<&str, Vec<&Hoja>> = HashMap::new();
    for h in hojas {
        por_sha.entry(h.sha.as_str()).or_default().push(h);
    }
    for grupo in por_sha.values().filter(|g| g.len() > 1) {
        for w in grupo.windows(2) {
            rels.push(Relacion { origen: ruta_rel(w[0]), tipo: "duplicate", destino: ruta_rel(w[1]), confirmada: true });
        }
    }

    // 3) Familia: mismo nombre base en la misma carpeta.
    let mut por_fam: HashMap<(String, String), Vec<&Hoja>> = HashMap::new();
    for h in hojas {
        por_fam.entry((h.carpeta.clone(), h.stem.to_lowercase())).or_default().push(h);
    }
    for grupo in por_fam.values().filter(|g| g.len() > 1) {
        for w in grupo.windows(2) {
            rels.push(Relacion { origen: ruta_rel(w[0]), tipo: "family", destino: ruta_rel(w[1]), confirmada: false });
        }
    }
}

fn mejor_confianza(subir: &mut HashMap<PathBuf, (Confianza, String)>, ruta: &Path, nueva: Confianza, ev: String) {
    subir
        .entry(ruta.to_path_buf())
        .and_modify(|(c, e)| {
            if nueva < *c {
                *c = nueva;
                *e = ev.clone();
            }
        })
        .or_insert((nueva, ev));
}

fn aplicar(arbol: &mut [Nodo], subir: &HashMap<PathBuf, (Confianza, String)>, notas: &HashMap<PathBuf, Vec<String>>) {
    for n in arbol.iter_mut() {
        if let Some((nueva, ev)) = subir.get(&n.ruta_fisica) {
            // No degradar algo ya Confirmado.
            if *nueva < n.confianza {
                n.confianza = *nueva;
                n.evidencia = ev.clone();
            }
        }
        if let Some(ns) = notas.get(&n.ruta_fisica) {
            for x in ns {
                if !n.notas.contains(x) {
                    n.notas.push(x.clone());
                }
            }
        }
        aplicar(&mut n.hijos, subir, notas);
    }
}

fn leer(p: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut v = Vec::new();
    std::fs::File::open(p)?.take(MAX_LEER).read_to_end(&mut v)?;
    Ok(v)
}

fn ruta_rel(h: &Hoja) -> String {
    if h.carpeta.is_empty() {
        h.nombre.clone()
    } else {
        format!("{}/{}", h.carpeta, h.nombre)
    }
}

fn informe(r: &Relaciones) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# {}\n", tr("File relations", "Relaciones entre archivos"));
    let _ = writeln!(s, "{}", tfmt(tr("{} relation(s).\n", "{} relación(es).\n"), &[r.relaciones.len().to_string()]));
    let etiqueta = |t: &str| match t {
        "references" => tr("references", "referencia a"),
        "duplicate" => tr("duplicate of", "duplicado de"),
        "family" => tr("family of", "familia de"),
        _ => "?",
    };
    for rel in &r.relaciones {
        let marca = if rel.confirmada { tr("[confirmed]", "[confirmada]") } else { tr("[compatible]", "[compatible]") };
        let _ = writeln!(s, "- `{}` {} `{}` {}", rel.origen, etiqueta(rel.tipo), rel.destino, marca);
    }
    let _ = writeln!(s, "\n---\n{}", tr("*Relations — capas, by @angelazo*", "*Relaciones — capas, de @angelazo*"));
    s
}
