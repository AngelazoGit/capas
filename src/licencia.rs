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

// ── Herramienta de vendedor ──────────────────────────────────────────────

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
