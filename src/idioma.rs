//! Idioma de la interfaz y los mensajes. Inglés por defecto; español opcional.

use std::sync::atomic::{AtomicU8, Ordering};

static LANG: AtomicU8 = AtomicU8::new(0); // 0 = inglés, 1 = español

/// Fija el idioma: `es = true` → español, si no inglés.
pub fn set_es(es: bool) {
    LANG.store(if es { 1 } else { 0 }, Ordering::Relaxed);
}

/// Autodetección desde el entorno (LANG/LC_ALL) si empieza por "es".
pub fn autodetectar() {
    let es = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .map(|v| v.to_lowercase().starts_with("es"))
        .unwrap_or(false);
    set_es(es);
}

pub fn es() -> bool {
    LANG.load(Ordering::Relaxed) == 1
}

/// Devuelve `en` o `es_txt` según el idioma activo.
pub fn tr(en: &'static str, es_txt: &'static str) -> &'static str {
    if es() { es_txt } else { en }
}

/// Formateo en runtime: sustituye cada `{}` de la plantilla por el siguiente
/// argumento, en orden. Permite plantillas traducibles con tr() (que `format!`
/// no admite porque exige un literal). Valores con formato especial (p. ej.
/// `{:.2}`) se preformatean a String antes de pasarlos.
pub fn tfmt(tpl: &str, args: &[String]) -> String {
    let mut out = String::with_capacity(tpl.len() + 16);
    let mut it = args.iter();
    let mut rest = tpl;
    while let Some(pos) = rest.find("{}") {
        out.push_str(&rest[..pos]);
        if let Some(a) = it.next() {
            out.push_str(a);
        }
        rest = &rest[pos + 2..];
    }
    out.push_str(rest);
    out
}
