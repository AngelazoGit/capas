//! Puente MCP (Model Context Protocol): expone las capacidades de CAPAS como
//! *tools* por stdio (JSON-RPC 2.0, mensajes separados por saltos de línea).
//!
//! CAPAS no llama a ninguna IA: es la IA (a través de su cliente MCP —
//! Claude Desktop, un cliente con OpenAI, o uno local con Ollama) quien llama
//! a estas herramientas. El análisis sigue siendo 100% local.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::analisis::{self, Opciones};
use crate::motor::Nodo;
use crate::recursos::{Herramientas, Sistema};
use crate::VERSION;

const PROTOCOLO: &str = "2024-11-05";
const TOPE_NODOS: usize = 400;

/// Bucle del servidor: lee peticiones JSON-RPC de stdin y responde por stdout.
pub fn servir(sis: Sistema, herr: Herramientas) -> anyhow::Result<()> {
    let stdin = io::stdin();
    let mut out = io::stdout();
    eprintln!("capas MCP server v{VERSION} — stdio · {} tools ready", definicion_tools().as_array().map(|a| a.len()).unwrap_or(0));
    for linea in stdin.lock().lines() {
        let linea = linea?;
        if linea.trim().is_empty() {
            continue;
        }
        if let Some(resp) = responder(&linea, &sis, &herr) {
            writeln!(out, "{resp}")?;
            out.flush()?;
        }
    }
    Ok(())
}

/// Procesa un mensaje JSON-RPC. Devuelve la respuesta (None para notificaciones).
fn responder(linea: &str, sis: &Sistema, herr: &Herramientas) -> Option<String> {
    let v: Value = serde_json::from_str(linea).ok()?;
    let metodo = v.get("method")?.as_str()?;
    let id = v.get("id").cloned();

    let resultado: Result<Value, (i64, String)> = match metodo {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOLO,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "capas", "version": VERSION }
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": definicion_tools() })),
        "tools/call" => llamar_tool(v.get("params"), sis, herr),
        _ => Err((-32601, format!("method not found: {metodo}"))),
    };

    // Las notificaciones (sin id) no llevan respuesta.
    let id = id?;
    Some(match resultado {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }).to_string(),
        Err((code, msg)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } }).to_string(),
    })
}

/// Esquema de las herramientas que anunciamos al cliente.
fn definicion_tools() -> Value {
    json!([
        {
            "name": "capas_analyze_file",
            "description": "Analyze a file or folder locally, layer by layer: identify formats by content, extract/decompile each layer and return the block tree with confidence levels. Never executes the file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute path to the file or folder to analyze." },
                    "max_depth": { "type": "integer", "description": "Maximum layer depth (1-32, default 12)." },
                    "classify": { "type": "boolean", "description": "Also gather files by category (default false)." },
                    "audit": { "type": "boolean", "description": "Also audit asset packs/mods (default false)." },
                    "use_external_tools": { "type": "boolean", "description": "Use installed reverse-engineering tools for deeper analysis (default false)." }
                },
                "required": ["path"]
            }
        },
        {
            "name": "capas_list_formats",
            "description": "List the file formats CAPAS recognizes (729 extensions across 11 categories) and what it can do with each (detect/explore/extract/preview/analyze/rebuild).",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "capas_inspect_output",
            "description": "Read a previous analysis output folder (its informe.json) and return a summary: block count and top-level items.",
            "inputSchema": {
                "type": "object",
                "properties": { "folder": { "type": "string", "description": "Path to a CAPAS output folder containing informe.json." } },
                "required": ["folder"]
            }
        }
    ])
}

fn llamar_tool(params: Option<&Value>, sis: &Sistema, herr: &Herramientas) -> Result<Value, (i64, String)> {
    let p = params.ok_or((-32602, "missing params".to_string()))?;
    let nombre = p.get("name").and_then(|x| x.as_str()).ok_or((-32602, "missing tool name".to_string()))?;
    let args = p.get("arguments").cloned().unwrap_or_else(|| json!({}));

    let salida = match nombre {
        "capas_analyze_file" => tool_analizar(&args, sis, herr),
        "capas_list_formats" => Ok(tool_formatos()),
        "capas_inspect_output" => tool_inspeccionar(&args),
        otro => return Err((-32602, format!("unknown tool: {otro}"))),
    };

    Ok(match salida {
        Ok(texto) => json!({ "content": [ { "type": "text", "text": texto } ] }),
        Err(e) => json!({ "content": [ { "type": "text", "text": format!("Error: {e}") } ], "isError": true }),
    })
}

fn tool_analizar(args: &Value, sis: &Sistema, herr: &Herramientas) -> Result<String, String> {
    let ruta = args.get("path").and_then(|v| v.as_str()).ok_or("missing 'path'")?;
    let p = PathBuf::from(ruta);
    if !p.exists() {
        return Err(format!("path not found: {ruta}"));
    }
    let mut op = Opciones::para(sis);
    if let Some(d) = args.get("max_depth").and_then(|v| v.as_u64()) {
        op.profundidad = d.clamp(1, 32) as usize;
    }
    op.clasificar = args.get("classify").and_then(|v| v.as_bool()).unwrap_or(false);
    op.auditar = args.get("audit").and_then(|v| v.as_bool()).unwrap_or(false);
    op.indice = false;
    op.agrupar = false;
    op.reconstruir = false;

    let usar_ext = args.get("use_external_tools").and_then(|v| v.as_bool()).unwrap_or(false);
    let h = if usar_ext { herr.clone() } else { Herramientas::default() };
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|x| x.as_nanos()).unwrap_or(0);
    let salida = std::env::temp_dir().join(format!("capas-mcp-{nanos}"));

    let r = analisis::ejecutar(&[p], &salida, &op, h, sis, None, Arc::new(AtomicBool::new(false))).map_err(|e| format!("{e:#}"))?;

    let mut contador = 0usize;
    let arbol: Vec<Value> = r.arbol.iter().map(|n| resumir(n, &mut contador)).collect();
    let out = json!({
        "report": r.raiz.join("informe.md").display().to_string(),
        "report_json": r.raiz.join("informe.json").display().to_string(),
        "blocks": r.bloques,
        "bytes_extracted": r.bytes,
        "nodes_truncated": contador > TOPE_NODOS,
        "tree": arbol,
    });
    serde_json::to_string_pretty(&out).map_err(|e| e.to_string())
}

fn resumir(n: &Nodo, contador: &mut usize) -> Value {
    *contador += 1;
    if *contador > TOPE_NODOS {
        return json!({ "name": n.nombre, "truncated": true });
    }
    let hijos: Vec<Value> = n.hijos.iter().map(|h| resumir(h, contador)).collect();
    json!({
        "name": n.nombre,
        "type": n.tipo.nombre(),
        "layer": n.capa,
        "confidence": n.confianza.clave(),
        "size": n.tamano,
        "incomplete": n.incompleto,
        "children": hijos,
    })
}

fn tool_formatos() -> String {
    let cats: [(&str, u32); 11] = [
        ("Archives, packages & disk images", 81),
        ("Executables & libraries", 28),
        ("Bytecode & VMs", 16),
        ("Images", 51),
        ("Audio", 38),
        ("Video", 29),
        ("Documents", 49),
        ("Source code & scripts", 131),
        ("Game, 3D, engines & ROMs", 172),
        ("Data, databases, certs, fonts & AI models", 103),
        ("Text, subtitles & notes", 31),
    ];
    let total: u32 = cats.iter().map(|(_, n)| *n).sum();
    let v = json!({
        "total_extensions": total,
        "categories": cats.iter().map(|(n, c)| json!({ "category": n, "extensions": c })).collect::<Vec<_>>(),
        "actions": ["detect", "explore", "extract", "preview", "analyze", "rebuild"],
        "note": "CAPAS detects by content, not by extension. Support depends on the format; not every action applies to every file."
    });
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

fn tool_inspeccionar(args: &Value) -> Result<String, String> {
    let folder = args.get("folder").and_then(|v| v.as_str()).ok_or("missing 'folder'")?;
    let p = Path::new(folder).join("informe.json");
    let txt = std::fs::read_to_string(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
    let v: Value = serde_json::from_str(&txt).map_err(|e| e.to_string())?;
    fn contar(v: &Value, c: &mut usize) {
        if let Some(a) = v.as_array() {
            for n in a {
                contar(n, c);
            }
        } else if let Some(o) = v.as_object() {
            *c += 1;
            if let Some(h) = o.get("hijos") {
                contar(h, c);
            }
        }
    }
    let mut c = 0;
    contar(&v, &mut c);
    let top: Vec<String> = v
        .as_array()
        .map(|a| a.iter().filter_map(|n| n.get("nombre").and_then(|x| x.as_str()).map(String::from)).collect())
        .unwrap_or_default();
    serde_json::to_string_pretty(&json!({ "blocks": c, "top_level": top })).map_err(|e| e.to_string())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn sis() -> Sistema {
        Sistema::detectar()
    }

    #[test]
    fn initialize_y_lista() {
        let s = sis();
        let h = Herramientas::default();
        let init = responder(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#, &s, &h).unwrap();
        assert!(init.contains("serverInfo"));
        assert!(init.contains("capas"));
        let lista = responder(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#, &s, &h).unwrap();
        assert!(lista.contains("capas_analyze_file"));
        assert!(lista.contains("capas_list_formats"));
    }

    #[test]
    fn notificacion_no_responde() {
        let s = sis();
        let h = Herramientas::default();
        assert!(responder(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, &s, &h).is_none());
    }

    #[test]
    fn tool_formatos_devuelve_contenido() {
        let s = sis();
        let h = Herramientas::default();
        let r = responder(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"capas_list_formats","arguments":{}}}"#, &s, &h).unwrap();
        assert!(r.contains("729") && r.contains("content"));
    }
}
