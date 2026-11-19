//! Política operativa (Fase 3). A partir de la auditoría y la confianza decide
//! una acción por paquete: permitir / advertir / revisar / bloquear. Da un
//! código de salida para CI/CD. No mueve nada por sí sola: es la decisión; la
//! cuarentena la ejecuta el modo vigilancia o el propio operador.

use std::fmt::Write as _;
use std::path::Path;

use serde::Serialize;

use crate::auditar::{Auditoria, Veredicto};
use crate::clasificar::Confianza;
use crate::idioma::{tfmt, tr};
use crate::motor::Nodo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Accion {
    Permitir,
    Advertir,
    Revisar,
    Bloquear,
}

impl Accion {
    pub fn etiqueta(self) -> &'static str {
        match self {
            Accion::Permitir => tr("ALLOW", "PERMITIR"),
            Accion::Advertir => tr("WARN", "ADVERTIR"),
            Accion::Revisar => tr("REVIEW", "REVISAR"),
            Accion::Bloquear => tr("BLOCK", "BLOQUEAR"),
        }
    }
    /// Código de salida para CI/CD.
    pub fn codigo(self) -> i32 {
        match self {
            Accion::Permitir => 0,
            Accion::Advertir => 1,
            Accion::Revisar => 2,
            Accion::Bloquear => 3,
        }
    }
}

#[derive(Serialize)]
pub struct ResultadoPaquete {
    pub nombre: String,
    pub accion: Accion,
    pub motivo: String,
}

#[derive(Serialize)]
pub struct Politica {
    pub global: Accion,
    pub paquetes: Vec<ResultadoPaquete>,
}

/// Evalúa la política. Usa la auditoría si existe; si no, decide por confianza.
pub fn evaluar(auditoria: Option<&Auditoria>, arbol: &[Nodo]) -> Politica {
    // Mínimo global por confianza: si hay desconocidos, al menos advertir.
    let hay_desconocido = algun_desconocido(arbol);
    let piso = if hay_desconocido { Accion::Advertir } else { Accion::Permitir };

    let mut paquetes = Vec::new();
    match auditoria {
        Some(a) => {
            for p in &a.paquetes {
                let base = match p.veredicto {
                    Veredicto::Rechazado => Accion::Bloquear,
                    Veredicto::Cuarentena => Accion::Revisar,
                    Veredicto::Aprobado => Accion::Permitir,
                };
                let accion = base.max(piso);
                let motivo = tfmt(
                    tr("audit verdict {}{}", "veredicto de auditoría {}{}"),
                    &[
                        p.veredicto.etiqueta().to_string(),
                        if accion > base && hay_desconocido { tr(" + unknown-confidence files", " + archivos de confianza desconocida").to_string() } else { String::new() },
                    ],
                );
                paquetes.push(ResultadoPaquete { nombre: p.nombre.clone(), accion, motivo });
            }
        }
        None => {
            for n in arbol {
                let accion = if algun_desconocido(std::slice::from_ref(n)) { Accion::Advertir } else { Accion::Permitir };
                paquetes.push(ResultadoPaquete {
                    nombre: n.nombre.clone(),
                    accion,
                    motivo: tr("no audit; decided by confidence", "sin auditoría; decidido por confianza").to_string(),
                });
            }
        }
    }
    let global = paquetes.iter().map(|p| p.accion).max().unwrap_or(Accion::Permitir);
    Politica { global, paquetes }
}

fn algun_desconocido(nodos: &[Nodo]) -> bool {
    nodos.iter().any(|n| n.confianza == Confianza::Desconocido || algun_desconocido(&n.hijos))
}

pub fn escribir(raiz: &Path, pol: &Politica) -> std::io::Result<()> {
    let mut s = String::new();
    let _ = writeln!(s, "# {}\n", tr("Operational policy", "Política operativa"));
    let _ = writeln!(s, "{}", tfmt(tr("Overall action: **{}**\n", "Acción global: **{}**\n"), &[pol.global.etiqueta().to_string()]));
    let _ = writeln!(s, "| {} | {} | {} |", tr("Package", "Paquete"), tr("Action", "Acción"), tr("Reason", "Motivo"));
    let _ = writeln!(s, "|---|---|---|");
    for p in &pol.paquetes {
        let _ = writeln!(s, "| {} | **{}** | {} |", p.nombre, p.accion.etiqueta(), p.motivo);
    }
    let _ = writeln!(
        s,
        "\n---\n{}",
        tr(
            "Actions: ALLOW (ship), WARN (ship with note), REVIEW (manual check), BLOCK (do not ship). CI exit codes: 0/1/2/3. Policy by @angelazo.",
            "Acciones: PERMITIR, ADVERTIR, REVISAR, BLOQUEAR. Códigos de salida CI: 0/1/2/3. Política de @angelazo.",
        )
    );
    std::fs::write(raiz.join("politica.md"), s)?;
    if let Ok(j) = serde_json::to_string_pretty(pol) {
        let _ = std::fs::write(raiz.join("politica.json"), j);
    }
    Ok(())
}
