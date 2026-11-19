//! Índice SQLite: fuente de verdad del análisis. Con el SHA-256 como clave, un
//! mismo archivo es una fila aunque aparezca en varias carpetas o análisis. Al
//! apuntar a una base persistente (--indice), reanalizar actualiza sin duplicar
//! y permite consultar y comparar entre versiones.

use std::path::Path;

use rusqlite::{params, Connection};

use crate::auditar::{Auditoria, Nivel};
use crate::clasificar::categoria;
use crate::motor::Nodo;
use crate::relaciones::Relacion;

const ESQUEMA: &str = "
CREATE TABLE IF NOT EXISTS files (
    sha256 TEXT PRIMARY KEY, nombre TEXT, ruta TEXT, tamano INTEGER,
    formato TEXT, categoria TEXT, confianza TEXT, evidencia TEXT,
    entropia REAL, capa INTEGER, visto_utc TEXT
);
CREATE TABLE IF NOT EXISTS containers (
    parent_sha TEXT, child_sha TEXT, profundidad INTEGER, ruta_interna TEXT,
    UNIQUE(parent_sha, child_sha, ruta_interna)
);
CREATE TABLE IF NOT EXISTS relations (
    origen TEXT, tipo TEXT, destino TEXT, confirmada INTEGER,
    UNIQUE(origen, tipo, destino)
);
CREATE TABLE IF NOT EXISTS findings (
    sha256 TEXT, severidad TEXT, regla TEXT, evidencia TEXT,
    UNIQUE(sha256, regla, evidencia)
);
CREATE TABLE IF NOT EXISTS runs (
    fecha_utc TEXT, version TEXT, raiz TEXT, archivos INTEGER
);
CREATE INDEX IF NOT EXISTS idx_files_cat ON files(categoria);
CREATE INDEX IF NOT EXISTS idx_files_conf ON files(confianza);
";

pub struct Resumen {
    pub archivos: usize,
    pub total_db: usize,
}

/// Escribe (o actualiza) la base. Devuelve los archivos de esta corrida y el
/// total de archivos únicos (por SHA) acumulados en la base.
pub fn escribir(
    db: &Path,
    arbol: &[Nodo],
    relaciones: &[Relacion],
    auditoria: Option<&Auditoria>,
) -> rusqlite::Result<Resumen> {
    let mut con = Connection::open(db)?;
    con.execute_batch(ESQUEMA)?;
    let ahora = marca_tiempo();
    let tx = con.transaction()?;
    let total;
    {
        let mut ins_file = tx.prepare(
            "INSERT INTO files (sha256,nombre,ruta,tamano,formato,categoria,confianza,evidencia,entropia,capa,visto_utc)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(sha256) DO UPDATE SET
               nombre=excluded.nombre, formato=excluded.formato, categoria=excluded.categoria,
               confianza=excluded.confianza, evidencia=excluded.evidencia, visto_utc=excluded.visto_utc",
        )?;
        let mut ins_cont = tx.prepare(
            "INSERT OR IGNORE INTO containers (parent_sha,child_sha,profundidad,ruta_interna) VALUES (?1,?2,?3,?4)",
        )?;
        let mut t = 0usize;
        for nodo in arbol {
            recorrer(nodo, &mut ins_file, &mut ins_cont, &ahora, &mut t)?;
        }
        total = t;

        let mut ins_rel =
            tx.prepare("INSERT OR IGNORE INTO relations (origen,tipo,destino,confirmada) VALUES (?1,?2,?3,?4)")?;
        for r in relaciones {
            ins_rel.execute(params![r.origen, r.tipo, r.destino, r.confirmada as i64])?;
        }

        if let Some(a) = auditoria {
            let mut ins_find =
                tx.prepare("INSERT OR IGNORE INTO findings (sha256,severidad,regla,evidencia) VALUES (?1,?2,?3,?4)")?;
            for p in &a.paquetes {
                for h in &p.hallazgos {
                    let sev = match h.nivel {
                        Nivel::Rechazo => "rechazo",
                        Nivel::Aviso => "aviso",
                        Nivel::Info => "info",
                    };
                    ins_find.execute(params![p.sha256, sev, h.regla, h.detalle])?;
                }
            }
        }

        tx.execute(
            "INSERT INTO runs (fecha_utc,version,raiz,archivos) VALUES (?1,?2,?3,?4)",
            params![ahora, crate::VERSION, db.display().to_string(), total as i64],
        )?;
    }
    tx.commit()?;
    let total_db: i64 = con.query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))?;
    Ok(Resumen { archivos: total, total_db: total_db as usize })
}

fn recorrer(
    n: &Nodo,
    ins_file: &mut rusqlite::Statement,
    ins_cont: &mut rusqlite::Statement,
    ahora: &str,
    total: &mut usize,
) -> rusqlite::Result<()> {
    let cat = categoria(n.tipo, &n.nombre);
    let cambios = ins_file.execute(params![
        n.sha256,
        n.nombre.rsplit(['/', '\\']).next().unwrap_or(&n.nombre),
        n.directorio,
        n.tamano as i64,
        n.descripcion,
        cat.nombre(),
        n.confianza.clave(),
        n.evidencia,
        n.entropia,
        n.capa as i64,
        ahora,
    ])?;
    let _ = cambios;
    *total += 1;
    for h in &n.hijos {
        ins_cont.execute(params![n.sha256, h.sha256, h.capa as i64, h.nombre])?;
        recorrer(h, ins_file, ins_cont, ahora, total)?;
    }
    Ok(())
}

fn marca_tiempo() -> String {
    // UTC en segundos desde época (evita dependencias de fecha).
    let s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{s}")
}
