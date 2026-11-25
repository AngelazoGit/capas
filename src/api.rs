//! API local de solo lectura (Fase 4) sobre el índice SQLite. Sirve en
//! 127.0.0.1 para que paneles de servidor o herramientas de CI consuman el
//! inventario. No ejecuta nada ni escribe en la base.
//!
//! Rutas: GET /  (resumen) · /files · /relations · /findings · /runs

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::idioma::tr;

pub fn servir(db: PathBuf, puerto: u16) -> std::io::Result<()> {
    if !db.is_file() {
        eprintln!("{}: {}", tr("index not found", "no se encuentra el índice"), db.display());
        return Ok(());
    }
    let l = TcpListener::bind(("127.0.0.1", puerto))?;
    let con_token = std::env::var("CAPAS_API_TOKEN").ok().filter(|t| !t.is_empty()).is_some();
    eprintln!(
        "{} http://127.0.0.1:{puerto}  (GET / · /files · /relations · /findings · /runs)  — Ctrl-C",
        tr("Local read-only API at", "API local de solo lectura en"),
    );
    eprintln!(
        "  {}",
        if con_token {
            tr("auth: CAPAS_API_TOKEN required (?token= or Authorization: Bearer)", "auth: se exige CAPAS_API_TOKEN (?token= o Authorization: Bearer)")
        } else {
            tr("auth: none — set CAPAS_API_TOKEN to require a token", "auth: ninguna — define CAPAS_API_TOKEN para exigir token")
        },
    );
    for stream in l.incoming().flatten() {
        let mut stream = stream;
        let _ = atender(&mut stream, &db);
    }
    Ok(())
}

fn atender(stream: &mut std::net::TcpStream, db: &Path) -> std::io::Result<()> {
    let mut lector = BufReader::new(&mut *stream);
    let mut linea = String::new();
    lector.read_line(&mut linea)?;
    // "GET /ruta?token=... HTTP/1.1"
    let objetivo = linea.split_whitespace().nth(1).unwrap_or("/").to_string();
    let ruta = objetivo.split('?').next().unwrap_or("/").to_string();
    let token_query = objetivo.split_once('?').and_then(|(_, q)| {
        q.split('&').find_map(|kv| kv.strip_prefix("token=").map(|v| v.to_string()))
    });
    // Leer cabeceras (solo nos interesa Authorization: Bearer <token>).
    let mut token_auth = None;
    loop {
        let mut l = String::new();
        if lector.read_line(&mut l)? == 0 || l == "\r\n" || l == "\n" {
            break;
        }
        if let Some(v) = l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("authorization")) {
            token_auth = v.1.trim().strip_prefix("Bearer ").map(|t| t.trim().to_string());
        }
    }
    // Autenticación opcional: si CAPAS_API_TOKEN está definido, se exige.
    let (codigo, cuerpo) = if let Some(req) = std::env::var("CAPAS_API_TOKEN").ok().filter(|t| !t.is_empty()) {
        let dado = token_auth.or(token_query);
        if dado.as_deref() == Some(req.as_str()) {
            resolver_consulta(db, &ruta)
        } else {
            (401, json!({"error": "unauthorized"}).to_string())
        }
    } else {
        resolver_consulta(db, &ruta)
    };
    let estado = match codigo {
        200 => "200 OK",
        401 => "401 Unauthorized",
        404 => "404 Not Found",
        _ => "500 Internal Server Error",
    };
    // Sin `Access-Control-Allow-Origin: *`: así una web no puede leer el índice
    // desde el navegador del usuario. Herramientas locales/CI no necesitan CORS.
    let resp = format!(
        "HTTP/1.1 {estado}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{cuerpo}",
        cuerpo.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

fn resolver_consulta(db: &Path, ruta: &str) -> (u16, String) {
    match consulta(db, ruta) {
        Ok(Some(v)) => (200, serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into())),
        Ok(None) => (404, json!({"error": "not found"}).to_string()),
        Err(e) => (500, json!({"error": e.to_string()}).to_string()),
    }
}

fn consulta(db: &Path, ruta: &str) -> rusqlite::Result<Option<Value>> {
    let con = Connection::open(db)?;
    let v = match ruta {
        "/" => {
            let archivos: i64 = con.query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))?;
            let por_conf = agrupar(&con, "SELECT confianza, COUNT(*) FROM files GROUP BY confianza")?;
            let por_cat = agrupar(&con, "SELECT categoria, COUNT(*) FROM files GROUP BY categoria")?;
            let runs: i64 = con.query_row("SELECT COUNT(*) FROM runs", [], |r| r.get(0))?;
            json!({"files": archivos, "by_confidence": por_conf, "by_category": por_cat, "runs": runs})
        }
        "/files" => filas(
            &con,
            "SELECT sha256,nombre,ruta,tamano,formato,categoria,confianza,evidencia,entropia,capa FROM files ORDER BY categoria,nombre",
            &["sha256", "nombre", "ruta", "tamano", "formato", "categoria", "confianza", "evidencia", "entropia", "capa"],
        )?,
        "/relations" => filas(&con, "SELECT origen,tipo,destino,confirmada FROM relations", &["origen", "tipo", "destino", "confirmada"])?,
        "/findings" => filas(&con, "SELECT sha256,severidad,regla,evidencia FROM findings", &["sha256", "severidad", "regla", "evidencia"])?,
        "/runs" => filas(&con, "SELECT fecha_utc,version,raiz,archivos FROM runs ORDER BY rowid DESC", &["fecha_utc", "version", "raiz", "archivos"])?,
        _ => return Ok(None),
    };
    Ok(Some(v))
}

fn agrupar(con: &Connection, sql: &str) -> rusqlite::Result<Value> {
    let mut st = con.prepare(sql)?;
    let mut obj = serde_json::Map::new();
    let filas = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    for f in filas {
        let (k, n) = f?;
        obj.insert(k, json!(n));
    }
    Ok(Value::Object(obj))
}

fn filas(con: &Connection, sql: &str, cols: &[&str]) -> rusqlite::Result<Value> {
    let mut st = con.prepare(sql)?;
    let n = cols.len();
    let filas = st.query_map([], |r| {
        let mut o = serde_json::Map::new();
        for (i, c) in cols.iter().enumerate() {
            // Cada columna puede ser texto o número; probamos ambos.
            let v: Value = r
                .get::<_, String>(i)
                .map(Value::from)
                .or_else(|_| r.get::<_, i64>(i).map(Value::from))
                .or_else(|_| r.get::<_, f64>(i).map(Value::from))
                .unwrap_or(Value::Null);
            o.insert((*c).to_string(), v);
        }
        let _ = n;
        Ok(Value::Object(o))
    })?;
    let mut v = Vec::new();
    for f in filas {
        v.push(f?);
    }
    Ok(Value::Array(v))
}
