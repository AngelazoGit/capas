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
    pub fn nuevo(alfabeto: &str, long_max: usize) -> Self {
        let mut a: Vec<u8> = alfabeto.bytes().collect();
        a.sort_unstable();
        a.dedup();
        FuerzaBruta { alfabeto: a, long_max }
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

    /// Resuelve un ZIP: devuelve sus hijos y, si estaba cifrado y se encontró,
    /// la contraseña usada.
    pub fn abrir_zip(&self, d: &[u8], lim: u64, notas: &mut Vec<String>) -> Result<(Vec<Hijo>, Option<String>)> {
        if !zip_cifrado(d) {
            return Ok((crate::extraer::zip(d, lim, notas)?, None));
        }
        if !self.activa() {
            notas.push("ZIP protegido con contraseña: activa el módulo de claves (--clave / --diccionario / --comunes) para abrirlo".into());
            return Ok((crate::extraer::zip(d, lim, notas)?, None));
        }
        let candidatas = self.candidatas();
        notas.push(format!("ZIP cifrado: probando {} contraseña(s) candidata(s)…", candidatas.len()));
        match buscar(d, &candidatas) {
            Some(clave) => {
                notas.push(format!("✔ CONTRASEÑA ENCONTRADA: «{clave}»"));
                let hijos = extraer_con_clave(d, &clave, lim, notas)?;
                Ok((hijos, Some(clave)))
            }
            None => {
                notas.push("✘ contraseña no encontrada entre las candidatas".into());
                Ok((crate::extraer::zip(d, lim, notas)?, None))
            }
        }
    }
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
                notas.push(format!("entrada #{i} no legible: {e}"));
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
                        notas.push(format!("'{nombre}': supera el límite de {restante} bytes"))
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
