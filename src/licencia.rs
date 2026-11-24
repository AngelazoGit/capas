//! Validación de licencia offline (Ed25519). El binario lleva incrustada solo la
//! clave PÚBLICA y verifica la firma sin conexión: nadie puede emitir una
//! licencia válida sin la clave PRIVADA del vendedor. La licencia activa la
//! edición (Pro/Studio); si falta, es inválida o ha caducado, se queda en Core.
//!
//! Herramienta de vendedor (se ejecuta con la clave privada, que nunca va al
//! repo): generar el par de claves y firmar licencias por cliente.

use std::path::PathBuf;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::edicion::{self, Edicion};
use crate::idioma::{tfmt, tr};

/// Clave pública del vendedor (hex de 32 bytes).
///
/// MARCADOR: todo ceros = licencias desactivadas (todo queda en Core). Antes de
/// vender, ejecuta `capas --generar-clave <dir>`, pega aquí el valor PUBLICA_HEX
/// que imprime y recompila. Guarda la clave privada en secreto (nunca al repo):
/// con ella firmas las licencias de tus clientes con `capas --firmar-licencia`.
const PUBLICA_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize, Deserialize)]
pub struct Licencia {
    pub edicion: String,  // "pro" | "studio" | "core"
    pub titular: String,  // nombre o correo del cliente
    pub emitida: u64,     // epoch segundos
    pub expira: u64,      // epoch segundos, 0 = nunca
    #[serde(default)]
    pub id: String,
    pub firma: String,    // hex de la firma Ed25519
}

impl Licencia {
    /// Mensaje canónico que se firma/verifica (sin la firma).
    fn mensaje(&self) -> String {
        format!("capas-lic-v1|{}|{}|{}|{}|{}", self.edicion, self.titular, self.emitida, self.expira, self.id)
    }
}

fn ahora() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn de_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn a_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Verifica la licencia con la clave pública incrustada. Devuelve la edición
/// concedida o un error con el motivo.
pub fn verificar(lic: &Licencia) -> Result<Edicion, String> {
    if PUBLICA_HEX.bytes().all(|b| b == b'0') {
        return Err(tr("licensing not configured in this build", "licencias sin configurar en esta compilación").to_string());
    }
    let pub_b = de_hex(PUBLICA_HEX).filter(|v| v.len() == 32).ok_or_else(|| tr("no public key embedded", "sin clave pública incrustada").to_string())?;
    let vk = VerifyingKey::from_bytes(&pub_b.try_into().unwrap()).map_err(|_| tr("invalid public key", "clave pública inválida").to_string())?;
    let firma_b = de_hex(&lic.firma).filter(|v| v.len() == 64).ok_or_else(|| tr("malformed signature", "firma mal formada").to_string())?;
    let sig = Signature::from_bytes(&firma_b.try_into().unwrap());
    vk.verify(lic.mensaje().as_bytes(), &sig).map_err(|_| tr("invalid signature", "firma inválida").to_string())?;
    if lic.expira != 0 && ahora() > lic.expira {
        return Err(tr("license expired", "licencia caducada").to_string());
    }
    edicion::desde_str(&lic.edicion).ok_or_else(|| tr("unknown edition in license", "edición desconocida en la licencia").to_string())
}

/// Rutas por defecto donde buscar la licencia.
fn rutas_defecto() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            v.push(dir.join("capas.lic"));
        }
    }
    v.push(PathBuf::from("capas.lic"));
    if let Some(h) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        v.push(PathBuf::from(h).join(".config").join("capas").join("licencia.lic"));
    }
    v
}

/// Carga y aplica la licencia (bandera, variable CAPAS_LICENCIA, o rutas por
/// defecto). Si es válida, activa la edición. Imprime una línea con el resultado.
pub fn aplicar(bandera: Option<PathBuf>) {
    let ruta = bandera
        .or_else(|| std::env::var_os("CAPAS_LICENCIA").map(PathBuf::from))
        .or_else(|| rutas_defecto().into_iter().find(|p| p.is_file()));
    let Some(ruta) = ruta else { return };
    let Ok(datos) = std::fs::read_to_string(&ruta) else { return };
    // Un archivo que contiene una clave compacta "CAPAS-..." también vale.
    if datos.trim_start().starts_with("CAPAS-") {
        aplicar_clave(Some(datos.trim().to_string()));
        return;
    }
    let lic: Licencia = match serde_json::from_str(&datos) {
        Ok(l) => l,
        Err(_) => {
            eprintln!("{}", tfmt(tr("license: not readable ({})", "licencia: no legible ({})"), &[ruta.display().to_string()]));
            return;
        }
    };
    match verificar(&lic) {
        Ok(ed) => {
            edicion::set(ed);
            let cad = if lic.expira == 0 { tr("no expiry", "sin caducidad").to_string() } else { tfmt(tr("expires {}", "caduca {}"), &[lic.expira.to_string()]) };
            eprintln!("{}", tfmt(tr("license: CAPAS {} · {} · {}", "licencia: CAPAS {} · {} · {}"), &[ed.nombre().to_string(), lic.titular.clone(), cad]));
        }
        Err(e) => eprintln!("{}", tfmt(tr("license rejected: {} ({})", "licencia rechazada: {} ({})"), &[e, ruta.display().to_string()])),
    }
}

// ── Claves compactas "CAPAS-..." (para lotes y pegar a mano) ──────────────
// Una clave es un token autónomo y firmado: 24 bytes de datos + 64 de firma,
// en base64url, con prefijo CAPAS-. El binario la valida con la clave pública
// incrustada, sin conexión. Sirve para vender lotes pre-firmados.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_encode(d: &[u8]) -> String {
    let mut s = String::with_capacity(d.len().div_ceil(3) * 4);
    for c in d.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        let take = c.len() + 1;
        for i in 0..take {
            s.push(B64[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    s
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> { B64.iter().position(|&x| x == c).map(|p| p as u32) };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for c in bytes.chunks(4) {
        if c.len() < 2 {
            return None;
        }
        let mut n = 0u32;
        for (i, &ch) in c.iter().enumerate() {
            n |= val(ch)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if c.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if c.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn ed_byte(e: Edicion) -> u8 {
    e as u8
}
fn byte_ed(b: u8) -> Option<Edicion> {
    match b {
        0 => Some(Edicion::Core),
        1 => Some(Edicion::Pro),
        2 => Some(Edicion::Studio),
        _ => None,
    }
}

/// Datos firmados de una clave (24 bytes): versión, edición, emitida, expira, id.
fn mensaje_clave(ed: Edicion, emitida: u64, expira: u64, id: &[u8; 6]) -> [u8; 24] {
    let mut m = [0u8; 24];
    m[0] = 1; // versión del formato
    m[1] = ed_byte(ed);
    m[2..10].copy_from_slice(&emitida.to_le_bytes());
    m[10..18].copy_from_slice(&expira.to_le_bytes());
    m[18..24].copy_from_slice(id);
    m
}

/// Verifica una clave "CAPAS-..." contra una clave pública dada.
fn verificar_clave_pk(pub_hex: &str, token: &str) -> Result<Edicion, String> {
    if pub_hex.bytes().all(|b| b == b'0') {
        return Err(tr("licensing not configured in this build", "licencias sin configurar en esta compilación").to_string());
    }
    let cuerpo = token.trim().strip_prefix("CAPAS-").ok_or_else(|| tr("invalid key format", "formato de clave inválido").to_string())?;
    let payload = b64_decode(cuerpo).filter(|v| v.len() == 88).ok_or_else(|| tr("malformed key", "clave mal formada").to_string())?;
    let (m, firma_b) = payload.split_at(24);
    if m[0] != 1 {
        return Err(tr("unknown key version", "versión de clave desconocida").to_string());
    }
    let pub_b = de_hex(pub_hex).filter(|v| v.len() == 32).ok_or_else(|| tr("no public key embedded", "sin clave pública incrustada").to_string())?;
    let vk = VerifyingKey::from_bytes(&pub_b.try_into().unwrap()).map_err(|_| tr("invalid public key", "clave pública inválida").to_string())?;
    let sig = Signature::from_bytes(&firma_b.try_into().unwrap());
    vk.verify(m, &sig).map_err(|_| tr("invalid signature", "firma inválida").to_string())?;
    let expira = u64::from_le_bytes(m[10..18].try_into().unwrap());
    if expira != 0 && ahora() > expira {
        return Err(tr("key expired", "clave caducada").to_string());
    }
    byte_ed(m[1]).ok_or_else(|| tr("unknown edition in key", "edición desconocida en la clave").to_string())
}

/// Verifica una clave contra la clave pública incrustada.
pub fn verificar_clave(token: &str) -> Result<Edicion, String> {
    verificar_clave_pk(PUBLICA_HEX, token)
}

/// Aplica una clave pegada (bandera o variable CAPAS_CLAVE). Si es válida, activa
/// la edición.
pub fn aplicar_clave(bandera: Option<String>) {
    let Some(token) = bandera.or_else(|| std::env::var("CAPAS_CLAVE").ok()) else { return };
    match verificar_clave(&token) {
        Ok(ed) => {
            edicion::set(ed);
            eprintln!("{}", tfmt(tr("key: CAPAS {} activated", "clave: CAPAS {} activada"), &[ed.nombre().to_string()]));
        }
        Err(e) => eprintln!("{}", tfmt(tr("key rejected: {}", "clave rechazada: {}"), &[e])),
    }
}

// ── Herramienta de vendedor ──────────────────────────────────────────────

/// Firma una clave compacta "CAPAS-...". `dias` = 0 → sin caducidad.
pub fn firmar_clave(priv_hex: &str, edicion: &str, dias: u64) -> Result<String, String> {
    let ed = edicion::desde_str(edicion).ok_or_else(|| tr("edition must be core|pro|studio", "la edición debe ser core|pro|studio").to_string())?;
    let sk_b = de_hex(priv_hex.trim()).filter(|v| v.len() == 32).ok_or_else(|| tr("invalid private key", "clave privada inválida").to_string())?;
    let sk = SigningKey::from_bytes(&sk_b.try_into().unwrap());
    let emitida = ahora();
    let expira = if dias == 0 { 0 } else { emitida + dias * 86_400 };
    let mut id = [0u8; 6];
    getrandom::fill(&mut id).map_err(|e| e.to_string())?;
    let m = mensaje_clave(ed, emitida, expira, &id);
    let sig: Signature = sk.sign(&m);
    let mut payload = Vec::with_capacity(88);
    payload.extend_from_slice(&m);
    payload.extend_from_slice(&sig.to_bytes());
    Ok(format!("CAPAS-{}", b64_encode(&payload)))
}

/// Firma un LOTE de claves únicas (para subirlas a la pasarela).
pub fn firmar_lote(priv_hex: &str, edicion: &str, cantidad: u64, dias: u64) -> Result<Vec<String>, String> {
    (0..cantidad).map(|_| firmar_clave(priv_hex, edicion, dias)).collect()
}

/// Genera un par de claves Ed25519. Devuelve (privada_hex, pública_hex).
pub fn generar_clave() -> Result<(String, String), String> {
    let mut semilla = [0u8; 32];
    getrandom::fill(&mut semilla).map_err(|e| e.to_string())?;
    let sk = SigningKey::from_bytes(&semilla);
    let pk = sk.verifying_key();
    Ok((a_hex(&sk.to_bytes()), a_hex(&pk.to_bytes())))
}

/// Firma una licencia con la clave privada (hex). `dias` = 0 → sin caducidad.
pub fn firmar(priv_hex: &str, edicion: &str, titular: &str, dias: u64) -> Result<String, String> {
    let ed = edicion::desde_str(edicion).ok_or_else(|| tr("edition must be core|pro|studio", "la edición debe ser core|pro|studio").to_string())?;
    let sk_b = de_hex(priv_hex.trim()).filter(|v| v.len() == 32).ok_or_else(|| tr("invalid private key", "clave privada inválida").to_string())?;
    let sk = SigningKey::from_bytes(&sk_b.try_into().unwrap());
    let emitida = ahora();
    let expira = if dias == 0 { 0 } else { emitida + dias * 86_400 };
    let id = a_hex(&{
        let mut r = [0u8; 6];
        let _ = getrandom::fill(&mut r);
        r
    });
    let mut lic = Licencia { edicion: ed.nombre().to_lowercase(), titular: titular.to_string(), emitida, expira, id, firma: String::new() };
    let sig: Signature = sk.sign(lic.mensaje().as_bytes());
    lic.firma = a_hex(&sig.to_bytes());
    serde_json::to_string_pretty(&lic).map_err(|e| e.to_string())
}

#[cfg(test)]
mod pruebas_clave {
    use super::*;

    #[test]
    fn base64_ida_vuelta() {
        for n in [0usize, 1, 2, 3, 24, 88, 100] {
            let v: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(37)).collect();
            assert_eq!(b64_decode(&b64_encode(&v)).unwrap(), v, "n={n}");
        }
    }

    #[test]
    fn lote_firma_y_verifica() {
        let (priv_hex, pub_hex) = generar_clave().unwrap();
        let lote = firmar_lote(&priv_hex, "pro", 5, 0).unwrap();
        assert_eq!(lote.len(), 5);
        // Todas únicas y válidas con la pública correcta.
        let mut vistas = std::collections::HashSet::new();
        for t in &lote {
            assert!(t.starts_with("CAPAS-"));
            assert!(vistas.insert(t.clone()), "clave duplicada");
            assert_eq!(verificar_clave_pk(&pub_hex, t).unwrap(), Edicion::Pro);
        }
        // Con otra pública, falla.
        let (_, otra_pub) = generar_clave().unwrap();
        assert!(verificar_clave_pk(&otra_pub, &lote[0]).is_err());
        // Una clave manipulada falla (cambiamos un carácter del cuerpo).
        let mut bytes: Vec<char> = lote[0].chars().collect();
        let i = 20.min(bytes.len() - 1); // dentro del base64, no el último char
        bytes[i] = if bytes[i] == 'A' { 'B' } else { 'A' };
        let mala: String = bytes.into_iter().collect();
        assert!(verificar_clave_pk(&pub_hex, &mala).is_err());
        // Studio también.
        let st = firmar_clave(&priv_hex, "studio", 0).unwrap();
        assert_eq!(verificar_clave_pk(&pub_hex, &st).unwrap(), Edicion::Studio);
    }
}
