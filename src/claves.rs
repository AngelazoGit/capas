//! Módulo de claves: recuperación de la contraseña de archivos ZIP cifrados
//! (ZipCrypto clásico y AES) para poder abrirlos y seguir pelándolos.
//!
//! Pensado para archivos que tienes derecho a abrir: tus propios ZIP con la
//! contraseña olvidada, retos CTF, análisis forense autorizado. Prueba, por
//! este orden: las contraseñas que indiques, una lista corta de contraseñas
//! habituales, un diccionario (archivo de texto) y, si lo activas, fuerza
//! bruta acotada. No descifra AES con contraseña fuerte: solo la encuentra si
//! está entre las candidatas que se prueban.

use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use anyhow::Result;
use rayon::prelude::*;

use crate::idioma::{tfmt, tr};
use crate::extraer::Hijo;

/// Configuración de la búsqueda de contraseñas.
#[derive(Clone, Default)]
pub struct Claves {
    /// Contraseñas indicadas a mano (tienen prioridad).
    pub explicitas: Vec<String>,
    /// Probar la lista incorporada de contraseñas habituales.
    pub comunes: bool,
    /// Diccionario: una contraseña por línea.
    pub diccionario: Option<PathBuf>,
    /// Fuerza bruta acotada (desactivada por defecto).
    pub fuerza: Option<FuerzaBruta>,
    /// Tope de intentos totales (protege de búsquedas infinitas).
    pub max_intentos: u64,
}

#[derive(Clone)]
pub struct FuerzaBruta {
    pub alfabeto: Vec<u8>,
    pub long_max: usize,
}

impl FuerzaBruta {
    /// Crea una fuerza bruta SOLO si hay alfabeto y una longitud máxima válida.
    /// Sin abecedario (o con longitud 0) devuelve `None`: no se puede activar.
    pub fn nuevo(alfabeto: &str, long_max: usize) -> Option<Self> {
        let mut a: Vec<u8> = alfabeto.bytes().collect();
        a.sort_unstable();
        a.dedup();
        if a.is_empty() || long_max == 0 {
            return None;
        }
        Some(FuerzaBruta { alfabeto: a, long_max })
    }
    /// Alfabetos predefinidos por nombre corto.
    pub fn alfabeto_por_nombre(nombre: &str) -> String {
        match nombre {
            "d" | "digitos" => "0123456789".into(),
            "l" | "minusculas" => "abcdefghijklmnopqrstuvwxyz".into(),
            "a" | "alfanumerico" => "abcdefghijklmnopqrstuvwxyz0123456789".into(),
            "A" | "completo" => {
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".into()
            }
            otro => otro.into(),
        }
    }
}

impl Claves {
    pub fn activa(&self) -> bool {
        !self.explicitas.is_empty() || self.comunes || self.diccionario.is_some() || self.fuerza.is_some()
    }

    /// Todas las contraseñas candidatas, en orden de prioridad y sin repetir.
    fn candidatas(&self) -> Vec<String> {
        let mut v = Vec::new();
        let mut vistas = std::collections::HashSet::new();
        let meter = |s: String, v: &mut Vec<String>, vistas: &mut std::collections::HashSet<String>| {
            if vistas.insert(s.clone()) {
                v.push(s);
            }
        };
        for c in &self.explicitas {
            meter(c.clone(), &mut v, &mut vistas);
        }
        if self.comunes {
            for c in COMUNES {
                meter((*c).to_string(), &mut v, &mut vistas);
            }
        }
        if let Some(d) = &self.diccionario {
            match std::fs::read_to_string(d) {
                Ok(t) => {
                    for linea in t.lines() {
                        let c = linea.trim_end_matches(['\r', '\n']);
                        if !c.is_empty() {
                            meter(c.to_string(), &mut v, &mut vistas);
                        }
                    }
                }
                Err(e) => eprintln!("  ! no se pudo leer el diccionario {}: {e}", d.display()),
            }
        }
        if let Some(fb) = &self.fuerza {
            generar_fuerza_bruta(fb, &mut |s| meter(s, &mut v, &mut vistas));
        }
        if self.max_intentos > 0 && v.len() as u64 > self.max_intentos {
            v.truncate(self.max_intentos as usize);
        }
        v
    }

    /// Candidatas para herramientas externas (7z/RAR/…): las que da el usuario +
    /// comunes + diccionario, SIN fuerza bruta (cada intento lanza un proceso).
    pub fn candidatas_externas(&self) -> Vec<String> {
        let mut v = Vec::new();
        let mut vistas = std::collections::HashSet::new();
        for c in &self.explicitas {
            if vistas.insert(c.clone()) {
                v.push(c.clone());
            }
        }
        if self.comunes {
            for c in COMUNES {
                if vistas.insert((*c).to_string()) {
                    v.push((*c).to_string());
                }
            }
        }
        if let Some(d) = &self.diccionario {
            if let Ok(t) = std::fs::read_to_string(d) {
                for l in t.lines() {
                    let c = l.trim_end_matches(['\r', '\n']);
                    if !c.is_empty() && vistas.insert(c.to_string()) {
                        v.push(c.to_string());
                    }
                }
            }
        }
        v.truncate(200); // acotado: cada intento ejecuta 7z
        v
    }

    /// Resuelve un ZIP: devuelve sus hijos y, si estaba cifrado y se encontró,
    /// la contraseña usada.
    pub fn abrir_zip(&self, d: &[u8], lim: u64, notas: &mut Vec<String>) -> Result<(Vec<Hijo>, Option<String>)> {
        let cifrado = cifrado_zip(d);
        if cifrado == Cifrado::No {
            return Ok((crate::extraer::zip(d, lim, notas)?, None));
        }
        // Aviso claro según el tipo de cifrado: recuperable o solo con contraseña.
        notas.push(aviso_cifrado(cifrado));
        if !self.activa() {
            notas.push(tr("Enable the Keys module (passwords / dictionary / common list) to open it.","Activa el módulo de Claves (contraseñas / diccionario / lista de habituales) para abrirlo.").into());
            return Ok((crate::extraer::zip(d, lim, notas)?, None));
        }
        let candidatas = self.candidatas();
        notas.push(tfmt(tr("Encrypted ZIP: trying {} candidate password(s)…","ZIP cifrado: probando {} contraseña(s) candidata(s)…"), &[candidatas.len().to_string()]));
        match buscar(d, &candidatas) {
            Some(clave) => {
                notas.push(tfmt(tr("✔ PASSWORD FOUND: «{}»","✔ CONTRASEÑA ENCONTRADA: «{}»"), &[clave.clone()]));
                let hijos = extraer_con_clave(d, &clave, lim, notas)?;
                Ok((hijos, Some(clave)))
            }
            None => {
                notas.push(tr("✘ password not found among the candidates","✘ contraseña no encontrada entre las candidatas").into());
                Ok((crate::extraer::zip(d, lim, notas)?, None))
            }
        }
    }
}

/// Aviso en lenguaje claro según el tipo de cifrado del ZIP.
pub fn aviso_cifrado(c: Cifrado) -> String {
    match c {
        Cifrado::ZipCrypto => tr(
            "ZipCrypto encryption (legacy, weak): it CAN be recovered WITHOUT the password if a known plaintext is available (an unencrypted copy of one of its files, or a predictable header). Otherwise, passwords from the Keys module are tried.",
            "Cifrado ZipCrypto (antiguo y débil): SE PUEDE recuperar SIN la contraseña si hay un texto plano conocido (una copia sin cifrar de uno de sus archivos, o una cabecera predecible). Si no, se prueban las contraseñas del módulo de Claves.",
        ).to_string(),
        Cifrado::Aes => tr(
            "AES encryption (strong): it canNOT be broken. The only way in is the password — tried from the Keys module (your passwords, common list, dictionary, or bounded brute force with an alphabet).",
            "Cifrado AES (fuerte): NO se puede romper. La única vía es la contraseña — se prueba desde el módulo de Claves (tus contraseñas, lista de habituales, diccionario o fuerza bruta acotada con abecedario).",
        ).to_string(),
        Cifrado::No => String::new(),
    }
}

/// Tipo de cifrado de un ZIP, para saber si se puede recuperar sin contraseña.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cifrado {
    /// Sin cifrar.
    No,
    /// ZipCrypto clásico: criptografía débil, recuperable con texto plano conocido.
    ZipCrypto,
    /// AES (WinZip): fuerte, solo se abre con la contraseña.
    Aes,
}

/// Detecta el cifrado de un ZIP leyendo su directorio central. Si hay mezcla,
/// AES manda (lo más fuerte marca el conjunto).
pub fn cifrado_zip(d: &[u8]) -> Cifrado {
    // Localiza el End Of Central Directory (firma PK\x05\x06) desde el final.
    let eocd = (0..d.len().saturating_sub(21)).rev().find(|&i| &d[i..i + 4] == b"PK\x05\x06");
    let (mut off, total) = match eocd {
        Some(e) => {
            let cd_off = u32::from_le_bytes(d[e + 16..e + 20].try_into().unwrap()) as usize;
            let n = u16::from_le_bytes(d[e + 10..e + 12].try_into().unwrap()) as usize;
            (cd_off, n)
        }
        None => return Cifrado::No,
    };
    let mut res = Cifrado::No;
    for _ in 0..total {
        if off + 46 > d.len() || &d[off..off + 4] != b"PK\x01\x02" {
            break;
        }
        let gp = u16::from_le_bytes(d[off + 8..off + 10].try_into().unwrap());
        let metodo = u16::from_le_bytes(d[off + 10..off + 12].try_into().unwrap());
        if gp & 1 != 0 {
            if metodo == 99 {
                return Cifrado::Aes; // lo más fuerte: no hace falta seguir
            }
            res = Cifrado::ZipCrypto;
        }
        let nl = u16::from_le_bytes(d[off + 28..off + 30].try_into().unwrap()) as usize;
        let el = u16::from_le_bytes(d[off + 30..off + 32].try_into().unwrap()) as usize;
        let cl = u16::from_le_bytes(d[off + 32..off + 34].try_into().unwrap()) as usize;
        off += 46 + nl + el + cl;
    }
    res
}

/// ¿El ZIP tiene al menos una entrada cifrada?
fn zip_cifrado(d: &[u8]) -> bool {
    let Ok(mut z) = zip::ZipArchive::new(std::io::Cursor::new(d)) else {
        return false;
    };
    (0..z.len()).any(|i| z.by_index_raw(i).map(|f| f.encrypted()).unwrap_or(false))
}

/// Índice de una entrada cifrada que sirva para validar contraseñas
/// (preferiblemente pequeña, para que cada intento sea rápido).
fn entrada_de_prueba(d: &[u8]) -> Option<usize> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(d)).ok()?;
    let mut mejor: Option<(usize, u64)> = None;
    for i in 0..z.len() {
        if let Ok(f) = z.by_index_raw(i) {
            if f.encrypted() && f.size() > 0 {
                let t = f.compressed_size();
                if mejor.map(|(_, m)| t < m).unwrap_or(true) {
                    mejor = Some((i, t));
                }
            }
        }
    }
    mejor.map(|(i, _)| i)
}

/// Prueba una contraseña contra la entrada de validación.
fn probar(d: &[u8], idx: usize, clave: &str) -> bool {
    let Ok(mut z) = zip::ZipArchive::new(std::io::Cursor::new(d)) else {
        return false;
    };
    match z.by_index_decrypt(idx, clave.as_bytes()) {
        Ok(mut f) => {
            // Leer la entrada entera: ZipCrypto valida por CRC y AES por MAC.
            let mut sumidero = Sumidero(0);
            std::io::copy(&mut f, &mut sumidero).is_ok()
        }
        Err(_) => false,
    }
}

struct Sumidero(u64);
impl std::io::Write for Sumidero {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Busca en paralelo la primera contraseña válida.
fn buscar(d: &[u8], candidatas: &[String]) -> Option<String> {
    let idx = entrada_de_prueba(d)?;
    let encontrada = AtomicBool::new(false);
    let resultado: Mutex<Option<(usize, String)>> = Mutex::new(None);
    candidatas
        .par_iter()
        .enumerate()
        .for_each(|(orden, clave)| {
            if encontrada.load(Ordering::Relaxed) {
                return;
            }
            if probar(d, idx, clave) {
                let mut r = resultado.lock().unwrap();
                // Conservar la de menor índice para respetar la prioridad.
                if r.as_ref().map(|(o, _)| orden < *o).unwrap_or(true) {
                    *r = Some((orden, clave.clone()));
                }
                encontrada.store(true, Ordering::Relaxed);
            }
        });
    resultado.into_inner().unwrap().map(|(_, c)| c)
}

/// Extrae todas las entradas usando la contraseña hallada.
fn extraer_con_clave(d: &[u8], clave: &str, lim: u64, notas: &mut Vec<String>) -> Result<Vec<Hijo>> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(d))?;
    let mut hijos = Vec::new();
    let mut total = 0u64;
    for i in 0..z.len() {
        let (nombre, cifrada, es_archivo) = match z.by_index_raw(i) {
            Ok(f) => (f.name().to_string(), f.encrypted(), f.is_file()),
            Err(e) => {
                notas.push(tfmt(tr("entry #{} not readable: {}","entrada #{} no legible: {}"), &[i.to_string(), e.to_string()]));
                continue;
            }
        };
        if !es_archivo {
            continue;
        }
        let restante = lim.saturating_sub(total);
        let res = if cifrada {
            z.by_index_decrypt(i, clave.as_bytes())
        } else {
            z.by_index(i)
        };
        match res {
            Ok(mut f) => {
                let mut datos = Vec::new();
                match (&mut f).take(restante + 1).read_to_end(&mut datos) {
                    Ok(_) if datos.len() as u64 > restante => {
                        notas.push(tfmt(tr("'{}': exceeds the limit of {} bytes","'{}': supera el límite de {} bytes"), &[nombre.clone(), restante.to_string()]))
                    }
                    Ok(_) => {
                        total += datos.len() as u64;
                        hijos.push(Hijo { nombre, datos });
                    }
                    Err(e) => notas.push(format!("'{nombre}': {e}")),
                }
            }
            Err(e) => notas.push(format!("'{nombre}': {e}")),
        }
    }
    Ok(hijos)
}

/// Genera combinaciones de fuerza bruta de longitud 1..=long_max.
fn generar_fuerza_bruta(fb: &FuerzaBruta, emitir: &mut impl FnMut(String)) {
    if fb.alfabeto.is_empty() {
        return;
    }
    for long in 1..=fb.long_max {
        let mut idx = vec![0usize; long];
        loop {
            let s: String = idx.iter().map(|&i| fb.alfabeto[i] as char).collect();
            emitir(s);
            // Incrementar como un contador en base |alfabeto|.
            let mut p = long;
            loop {
                if p == 0 {
                    break;
                }
                p -= 1;
                idx[p] += 1;
                if idx[p] < fb.alfabeto.len() {
                    break;
                }
                idx[p] = 0;
                if p == 0 {
                    // Se ha desbordado el dígito más significativo: fin de esta longitud.
                    p = usize::MAX;
                    break;
                }
            }
            if p == usize::MAX {
                break;
            }
        }
    }
}

/// Lista corta de contraseñas habituales (recuperación de archivos propios y CTF).
const COMUNES: &[&str] = &[
    "123456", "password", "12345678", "123456789", "12345", "1234", "1234567", "qwerty",
    "abc123", "111111", "123123", "admin", "letmein", "welcome", "monkey", "dragon",
    "master", "login", "000000", "1234567890", "password1", "qwerty123", "iloveyou",
    "sunshine", "princess", "football", "666666", "121212", "qwertyuiop", "superman",
    "zip", "secret", "infected", "malware", "virus", "root", "toor", "pass",
    "test", "test123", "changeme", "default", "123qwe", "1q2w3e4r", "1qaz2wsx",
    "p@ssw0rd", "P@ssw0rd", "Password1", "Password123", "passw0rd", "hello", "hola",
    "contraseña", "clave", "7777777", "654321", "101010", "222222", "soccer", "flower",
    "ninja", "shadow", "michael", "jordan", "trustno1", "batman", "access", "google",
    "mustang", "pokemon", "starwars", "minecraft", "roblox", "fortnite", "unlock",
];

#[cfg(test)]
mod pruebas_fuerza {
    use super::*;

    fn fx(n: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(n)).unwrap()
    }

    #[test]
    fn detecta_zipcrypto_vs_aes() {
        assert_eq!(cifrado_zip(&fx("zipcrypto.zip")), Cifrado::ZipCrypto);
        assert_eq!(cifrado_zip(&fx("aes.zip")), Cifrado::Aes);
        // Un ZIP normal no está cifrado.
        assert_eq!(cifrado_zip(&fx("plano_zip.zip")), Cifrado::No);
    }

    #[test]
    fn fuerza_bruta_no_se_activa_sin_abecedario() {
        assert!(FuerzaBruta::nuevo("", 4).is_none());
        assert!(FuerzaBruta::nuevo("abc", 0).is_none());
        assert!(FuerzaBruta::nuevo("abc", 2).is_some());
    }
    #[test]
    fn candidatas_externas_nunca_usan_fuerza_bruta() {
        let c = Claves { explicitas: vec!["hola".into()], comunes: false, diccionario: None, fuerza: FuerzaBruta::nuevo("ab", 3), max_intentos: 1000 };
        assert!(c.fuerza.is_some());
        assert_eq!(c.candidatas_externas(), vec!["hola".to_string()]);
    }
}
