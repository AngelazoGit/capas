//! Ediciones del producto (monetización). Core es gratuito y completo para el
//! análisis; Pro y Studio reservan funciones. La edición se elige con
//! `--edicion` o la variable `CAPAS_EDICION`; en un producto real, aquí se
//! validaría una clave de licencia firmada en vez de confiar en la bandera.
//!
//! La edición mínima de cada función es una constante, así mover una función de
//! un plan a otro es un cambio de una línea.

use std::sync::atomic::{AtomicU8, Ordering};

use crate::idioma::{tfmt, tr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Edicion {
    Core = 0,
    Pro = 1,
    Studio = 2,
}

impl Edicion {
    pub fn nombre(self) -> &'static str {
        match self {
            Edicion::Core => "Core",
            Edicion::Pro => "Pro",
            Edicion::Studio => "Studio",
        }
    }
}

// ── Edición mínima de cada función reservada (fácil de reubicar) ──
pub const POLITICA: Edicion = Edicion::Pro; // Fase 3: política/cuarentena por reglas
pub const COMPARAR: Edicion = Edicion::Pro; // Fase 3: comparación entre versiones
pub const CI: Edicion = Edicion::Studio; // Fase 4: modo CI/CD (códigos de salida)
pub const API: Edicion = Edicion::Studio; // Fase 4: API local
pub const DESEMPAQUETAR: Edicion = Edicion::Pro; // Desempaquetado de bundles de motores

static ACTUAL: AtomicU8 = AtomicU8::new(0);

pub fn set(e: Edicion) {
    ACTUAL.store(e as u8, Ordering::Relaxed);
}

/// Resuelve la edición desde la bandera o el entorno.
///
/// SEGURIDAD: en el binario distribuido, `--edicion` y `CAPAS_EDICION` NO
/// desbloquean ediciones de pago — solo una licencia firmada lo hace. El
/// override manual queda tras la feature de compilación `override-edicion`,
/// pensada solo para desarrollo/pruebas (`cargo build --features override-edicion`).
pub fn resolver(bandera: Option<&str>) {
    #[cfg(feature = "override-edicion")]
    {
        let fuente = bandera.map(str::to_string).or_else(|| std::env::var("CAPAS_EDICION").ok());
        if let Some(s) = fuente {
            if let Some(e) = desde_str(&s) {
                set(e);
            }
        }
    }
    #[cfg(not(feature = "override-edicion"))]
    {
        let _ = bandera; // ignorado: la edición solo la concede la licencia
    }
}

pub fn desde_str(s: &str) -> Option<Edicion> {
    match s.trim().to_lowercase().as_str() {
        "core" | "free" | "gratis" => Some(Edicion::Core),
        "pro" => Some(Edicion::Pro),
        "studio" | "server" | "enterprise" => Some(Edicion::Studio),
        _ => None,
    }
}

pub fn actual() -> Edicion {
    match ACTUAL.load(Ordering::Relaxed) {
        2 => Edicion::Studio,
        1 => Edicion::Pro,
        _ => Edicion::Core,
    }
}

pub fn permite(minima: Edicion) -> bool {
    actual() >= minima
}

/// Mensaje de función bloqueada para la edición actual.
pub fn bloqueado(funcion: &str, minima: Edicion) -> String {
    tfmt(
        tr(
            "«{}» requires CAPAS {} — you are running CAPAS {}. Set --edicion {} (or CAPAS_EDICION).",
            "«{}» requiere CAPAS {} — estás en CAPAS {}. Usa --edicion {} (o CAPAS_EDICION).",
        ),
        &[
            funcion.to_string(),
            minima.nombre().to_string(),
            actual().nombre().to_string(),
            minima.nombre().to_lowercase(),
        ],
    )
}
