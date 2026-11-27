//! Escáner de secretos/credenciales incrustados: claves API conocidas (AWS,
//! Google, Stripe, GitHub, Slack), claves privadas PEM, JWTs y asignaciones del
//! tipo `password = "..."`. Trabaja sobre las cadenas ASCII del bloque. SIEMPRE
//! muestra el valor REDACTADO (prefijo + longitud), nunca el secreto entero.

/// Un hallazgo: qué es, una muestra redactada y dónde (offset en el bloque).
pub struct Hallazgo {
    pub tipo: &'static str,
    pub muestra: String,
    pub offset: usize,
}

fn es_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
fn es_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}
fn es_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

/// Longitud del run que cumple `pred` desde `i`.
fn largo(s: &[u8], i: usize, pred: fn(u8) -> bool) -> usize {
    let mut n = 0;
    while i + n < s.len() && pred(s[i + n]) {
        n += 1;
    }
    n
}

/// Muestra redactada: prefijo visible + longitud, el resto enmascarado.
fn redacta(tok: &[u8]) -> String {
    let s = String::from_utf8_lossy(tok);
    let pre: String = s.chars().take(4).collect();
    format!("{pre}…**** ({} chars)", s.chars().count())
}

/// Entropía de Shannon (bits/byte) de un trozo, para detectar tokens aleatorios.
fn entropia(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    let mut cuenta = [0u32; 256];
    for &x in b {
        cuenta[x as usize] += 1;
    }
    let n = b.len() as f64;
    -cuenta.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / n; p * p.log2() }).sum::<f64>()
}

/// Busca un patrón `prefijo` + `min` caracteres que cumplan `charset` a partir
/// de `i`. Devuelve el final del token si cuadra.
fn patron(s: &[u8], i: usize, prefijo: &[u8], min: usize, charset: fn(u8) -> bool) -> Option<usize> {
    if !s[i..].starts_with(prefijo) {
        return None;
    }
    let tras = i + prefijo.len();
    let n = largo(s, tras, charset);
    if n >= min {
        Some(tras + n)
    } else {
        None
    }
}

const PALABRAS_CLAVE: &[&[u8]] = &[b"password", b"passwd", b"api_key", b"apikey", b"secret", b"token", b"private_key", b"access_key"];

/// Escanea las cadenas ASCII del bloque en busca de secretos. `tope` acota.
pub fn escanear(d: &[u8], tope: usize) -> Vec<Hallazgo> {
    let mut hall = Vec::new();
    // Recorre runs ASCII imprimibles (como el extractor de cadenas).
    let mut i = 0;
    while i < d.len() {
        if !(0x20..0x7f).contains(&d[i]) {
            i += 1;
            continue;
        }
        let ini = i;
        while i < d.len() && (0x20..0x7f).contains(&d[i]) {
            i += 1;
        }
        let s = &d[ini..i];
        buscar_en(s, ini, &mut hall, tope);
        if hall.len() >= tope {
            break;
        }
    }
    hall
}

fn add(hall: &mut Vec<Hallazgo>, tope: usize, tipo: &'static str, tok: &[u8], off: usize) {
    if hall.len() < tope {
        hall.push(Hallazgo { tipo, muestra: redacta(tok), offset: off });
    }
}

/// Aplica los detectores a una cadena ASCII `s` que empieza en `base`.
fn buscar_en(s: &[u8], base: usize, hall: &mut Vec<Hallazgo>, tope: usize) {
    // Clave privada PEM (la cabecera basta para marcarla).
    if s.windows(11).any(|w| w == b"PRIVATE KEY") && s.windows(5).any(|w| w == b"-----") {
        add(hall, tope, "clave privada (PEM)", s, base);
    }
    // Recorre posiciones buscando prefijos de claves conocidas.
    for j in 0..s.len() {
        if hall.len() >= tope {
            return;
        }
        let rest = &s[j..];
        let off = base + j;
        if let Some(fin) = patron(s, j, b"AKIA", 16, es_alnum) {
            add(hall, tope, "AWS access key", &s[j..fin], off);
        } else if let Some(fin) = patron(s, j, b"AIza", 35, es_b64url) {
            add(hall, tope, "Google API key", &s[j..fin], off);
        } else if rest.starts_with(b"ghp_") || rest.starts_with(b"gho_") || rest.starts_with(b"ghs_") {
            let fin = j + 4 + largo(s, j + 4, es_alnum);
            if fin - j > 30 {
                add(hall, tope, "GitHub token", &s[j..fin], off);
            }
        } else if rest.starts_with(b"github_pat_") {
            let fin = j + 11 + largo(s, j + 11, |b| es_alnum(b) || b == b'_');
            if fin - j > 20 {
                add(hall, tope, "GitHub PAT", &s[j..fin], off);
            }
        } else if let Some(fin) = patron(s, j, b"sk_live_", 20, es_alnum).or_else(|| patron(s, j, b"rk_live_", 20, es_alnum)) {
            add(hall, tope, "Stripe secret key", &s[j..fin], off);
        } else if rest.starts_with(b"xoxb-") || rest.starts_with(b"xoxp-") || rest.starts_with(b"xoxa-") || rest.starts_with(b"xoxr-") {
            let fin = j + 5 + largo(s, j + 5, |b| es_alnum(b) || b == b'-');
            if fin - j > 15 {
                add(hall, tope, "Slack token", &s[j..fin], off);
            }
        } else if rest.starts_with(b"eyJ") {
            // JWT: eyJ... . ... . ...  (tres segmentos base64url)
            let seg1 = largo(s, j, es_b64url);
            if j + seg1 < s.len() && s[j + seg1] == b'.' {
                let seg2 = largo(s, j + seg1 + 1, es_b64url);
                if seg1 + seg2 > 30 && j + seg1 + 1 + seg2 < s.len() && s[j + seg1 + 1 + seg2] == b'.' {
                    let seg3 = largo(s, j + seg1 + seg2 + 2, es_b64url);
                    let fin = j + seg1 + seg2 + 2 + seg3;
                    add(hall, tope, "JWT", &s[j..fin], off);
                }
            }
        }
    }
    // Asignación tipo `clave = "valor largo y aleatorio"`.
    detectar_asignacion(s, base, hall, tope);
}

/// `palabra_clave ... = / : ... <token largo>` con entropía alta.
fn detectar_asignacion(s: &[u8], base: usize, hall: &mut Vec<Hallazgo>, tope: usize) {
    let bajo: Vec<u8> = s.iter().map(|b| b.to_ascii_lowercase()).collect();
    for kw in PALABRAS_CLAVE {
        let mut desde = 0;
        while let Some(pos) = bajo[desde..].windows(kw.len()).position(|w| w == *kw) {
            let p = desde + pos;
            desde = p + kw.len();
            // Busca separador = o : cerca (hasta 4 chars) y luego un token.
            let mut k = p + kw.len();
            while k < s.len() && (s[k] == b' ' || s[k] == b'"' || s[k] == b'\'' || s[k] == b'=' || s[k] == b':') && k < p + kw.len() + 6 {
                k += 1;
            }
            let fin = k + largo(s, k, |b| es_b64(b) || b == b'-' || b == b'_' || b == b'.');
            let tok = &s[k..fin];
            if tok.len() >= 12 && entropia(tok) > 3.2 {
                add(hall, tope, "posible credencial incrustada", tok, base + k);
                if hall.len() >= tope {
                    return;
                }
            }
        }
    }
}

/// Genera el texto del informe de secretos (o cadena vacía si no hay).
pub fn informe(hall: &[Hallazgo]) -> String {
    if hall.is_empty() {
        return String::new();
    }
    let mut s = String::from("# Posibles secretos/credenciales (valores redactados)\n\n");
    for h in hall {
        s.push_str(&format!("0x{:08x}  [{}]  {}\n", h.offset, h.tipo, h.muestra));
    }
    s
}

#[cfg(test)]
mod pruebas_secretos {
    use super::*;

    // Los tokens de ejemplo se ENSAMBLAN en runtime (no como literal contiguo)
    // para que el escaneo de secretos de GitHub no los marque: son de prueba,
    // no secretos reales.
    #[test]
    fn detecta_varios_secretos() {
        let aws = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let gh = format!("ghp{}{}", "_", "abcdefghijklmnopqrstuvwxyz0123456789");
        let d = format!("user config {aws} and token {gh} end");
        let h = escanear(d.as_bytes(), 100);
        assert!(h.iter().any(|x| x.tipo == "AWS access key"), "falta AWS: {:?}", h.iter().map(|x| x.tipo).collect::<Vec<_>>());
        assert!(h.iter().any(|x| x.tipo == "GitHub token"));
        // No debe filtrar el valor completo.
        assert!(h.iter().all(|x| !x.muestra.contains(&aws)), "no debe mostrar el secreto entero");
    }

    #[test]
    fn detecta_clave_privada_y_asignacion() {
        let pem = format!("-----BEGIN RSA {} KEY-----", "PRIVATE");
        let d = format!("{pem}\npassword=\"{}\"", "r4nd0m_v4lor_de_prueba_9xZqWvT");
        let h = escanear(d.as_bytes(), 100);
        assert!(h.iter().any(|x| x.tipo == "clave privada (PEM)"));
        assert!(h.iter().any(|x| x.tipo == "posible credencial incrustada"));
    }

    #[test]
    fn no_marca_texto_normal() {
        let d = b"the quick brown fox jumps over the lazy dog, hello world, this is fine";
        let h = escanear(d, 100);
        assert!(h.is_empty(), "no debe marcar texto normal: {:?}", h.iter().map(|x| x.tipo).collect::<Vec<_>>());
    }
}
