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
