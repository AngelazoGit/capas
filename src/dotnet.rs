//! Lector NATIVO de ensamblados .NET (CLI/CLR, ECMA-335): detecta el PE con
//! cabecera COM (directorio de datos 14), localiza los metadatos, parsea las
//! corrientes `#~` (tablas) y `#Strings`, y lista espacios de nombres, clases,
//! campos y métodos — como `ildasm`, pero sin .NET instalado. No decompila a C#
//! completo todavía: da la ESTRUCTURA (muy útil para Unity Assembly-CSharp.dll).

use anyhow::{anyhow, bail, Result};
use std::fmt::Write as _;

/// ¿Es un ensamblado .NET? PE con directorio de datos COM (índice 14) no vacío.
pub fn es_dotnet(d: &[u8]) -> bool {
    goblin::pe::PE::parse(d)
        .ok()
        .and_then(|pe| pe.header.optional_header)
        .and_then(|oh| oh.data_directories.get_clr_runtime_header().copied())
        .map(|dd| dd.virtual_address != 0 && dd.size != 0)
        .unwrap_or(false)
}

/// Mapa RVA → offset de fichero usando las secciones del PE.
struct Mapa {
    secs: Vec<(u32, u32, u32)>, // (virtual_address, virtual_size_or_raw, pointer_to_raw)
}
impl Mapa {
    fn nuevo(pe: &goblin::pe::PE) -> Self {
        let secs = pe
            .sections
            .iter()
            .map(|s| (s.virtual_address, s.virtual_size.max(s.size_of_raw_data), s.pointer_to_raw_data))
            .collect();
        Mapa { secs }
    }
    fn off(&self, rva: u32) -> Option<usize> {
        for &(va, sz, ptr) in &self.secs {
            if rva >= va && rva < va + sz {
                return Some((ptr + (rva - va)) as usize);
            }
        }
        None
    }
}

fn u16le(d: &[u8], o: usize) -> u32 {
    u16::from_le_bytes([d[o], d[o + 1]]) as u32
}
fn u32le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

/// Lee una cadena ASCII/UTF-8 terminada en NUL del heap #Strings.
fn cadena(strings: &[u8], idx: u32) -> String {
    let i = idx as usize;
    if i >= strings.len() {
        return String::new();
    }
    let fin = strings[i..].iter().position(|&b| b == 0).map(|p| i + p).unwrap_or(strings.len());
    String::from_utf8_lossy(&strings[i..fin]).into_owned()
}

/// Tabla con tamaños de índice ya calculados.
struct Tablas {
    rows: [u32; 64],
    s_str: usize, // tamaño del índice #Strings (2 o 4)
    s_guid: usize,
    s_blob: usize,
}
impl Tablas {
    /// Índice a una tabla concreta: 2 bytes si tiene < 2^16 filas, si no 4.
    fn s_tab(&self, tabla: usize) -> usize {
        if self.rows[tabla] >= (1 << 16) { 4 } else { 2 }
    }
    /// Índice codificado: 2 bytes si la mayor de las tablas referenciadas cabe en
    /// 2^(16-bits), si no 4.
    fn s_cod(&self, tablas: &[usize], bits: u32) -> usize {
        let maxr = tablas.iter().map(|&t| self.rows[t]).max().unwrap_or(0);
        if (maxr as u64) < (1u64 << (16 - bits)) { 2 } else { 4 }
    }
}

// Ids de tabla que usamos.
const T_MODULE: usize = 0x00;
const T_TYPEREF: usize = 0x01;
const T_TYPEDEF: usize = 0x02;
const T_FIELDPTR: usize = 0x03;
const T_FIELD: usize = 0x04;
const T_METHODPTR: usize = 0x05;
const T_METHODDEF: usize = 0x06;

/// Tamaño en bytes de una fila de la tabla `t`, según los tamaños de índice.
/// Solo se definen las tablas 0x00..=0x06 (las que preceden a MethodDef).
fn tam_fila(t: &Tablas, tabla: usize) -> Option<usize> {
    // Índices codificados que necesitamos.
    let resolution_scope = t.s_cod(&[T_MODULE, 0x1A /*ModuleRef*/, 0x23 /*AssemblyRef*/, T_TYPEREF], 2);
    let typedef_or_ref = t.s_cod(&[T_TYPEDEF, T_TYPEREF, 0x1B /*TypeSpec*/], 2);
    Some(match tabla {
        T_MODULE => 2 + t.s_str + 3 * t.s_guid,
        T_TYPEREF => resolution_scope + 2 * t.s_str,
        T_TYPEDEF => 4 + 2 * t.s_str + typedef_or_ref + t.s_tab(T_FIELD) + t.s_tab(T_METHODDEF),
        T_FIELDPTR => t.s_tab(T_FIELD),
        T_FIELD => 2 + t.s_str + t.s_blob,
        T_METHODPTR => t.s_tab(T_METHODDEF),
        T_METHODDEF => 4 + 2 + 2 + t.s_str + t.s_blob + t.s_tab(0x08 /*Param*/),
        _ => return None,
    })
}

/// Parsea y lista la estructura de un ensamblado .NET.
pub fn listar(d: &[u8]) -> Result<String> {
    let pe = goblin::pe::PE::parse(d).map_err(|e| anyhow!("PE: {e}"))?;
    let oh = pe.header.optional_header.ok_or_else(|| anyhow!("PE sin cabecera opcional"))?;
    let cli = oh.data_directories.get_clr_runtime_header().copied().ok_or_else(|| anyhow!("no es .NET (sin cabecera COM)"))?;
    let mapa = Mapa::nuevo(&pe);

    // Cabecera CLI (COR20): MetaData RVA+Size en el offset 8.
    let cli_off = mapa.off(cli.virtual_address).ok_or_else(|| anyhow!("RVA CLI fuera de rango"))?;
    if cli_off + 16 > d.len() {
        bail!("cabecera CLI truncada");
    }
    let md_rva = u32le(d, cli_off + 8);
    let md_off = mapa.off(md_rva).ok_or_else(|| anyhow!("RVA de metadatos fuera de rango"))?;

    // Raíz de metadatos: magia BSJB.
    if md_off + 20 > d.len() || u32le(d, md_off) != 0x424A5342 {
        bail!("firma de metadatos BSJB no encontrada");
    }
    let ver_len = u32le(d, md_off + 12) as usize;
    let mut p = md_off + 16 + ((ver_len + 3) & !3); // versión alineada a 4
    // Flags(2) + Streams(2)
    let n_streams = u16le(d, p + 2);
    p += 4;

    // Cabeceras de corrientes: localiza #~ y #Strings.
    let (mut tilde_off, mut tilde_sz, mut str_off, mut str_sz) = (0usize, 0usize, 0usize, 0usize);
    for _ in 0..n_streams {
        if p + 8 > d.len() {
            break;
        }
        let off = u32le(d, p) as usize;
        let sz = u32le(d, p + 4) as usize;
        p += 8;
        let ini = p;
        let fin = d[ini..].iter().position(|&b| b == 0).map(|x| ini + x).unwrap_or(ini);
        let nombre = String::from_utf8_lossy(&d[ini..fin]).into_owned();
        p = fin + 1;
        p = (p + 3) & !3; // alinear a 4
        match nombre.as_str() {
            "#~" | "#-" => {
                tilde_off = md_off + off;
                tilde_sz = sz;
            }
            "#Strings" => {
                str_off = md_off + off;
                str_sz = sz;
            }
            _ => {}
        }
    }
    if tilde_off == 0 || str_off == 0 {
        bail!("faltan las corrientes #~ o #Strings");
    }
    let strings = d.get(str_off..(str_off + str_sz).min(d.len())).unwrap_or(&[]);

    // Cabecera de #~: Reserved(4), Major(1), Minor(1), HeapSizes(1), Reserved(1),
    // Valid(8), Sorted(8), luego un u32 de recuento por cada tabla presente.
    let heap = d[tilde_off + 6];
    let valid = u64::from_le_bytes(d[tilde_off + 8..tilde_off + 16].try_into().unwrap());
    let mut q = tilde_off + 24;
    let mut rows = [0u32; 64];
    for t in 0..64 {
        if valid & (1 << t) != 0 {
            rows[t] = u32le(d, q);
            q += 4;
        }
    }
    let tablas = Tablas {
        rows,
        s_str: if heap & 0x01 != 0 { 4 } else { 2 },
        s_guid: if heap & 0x02 != 0 { 4 } else { 2 },
        s_blob: if heap & 0x04 != 0 { 4 } else { 2 },
    };

    // `q` apunta al inicio de las filas. Avanza hasta cada tabla objetivo.
    let base = q;
    let mut off_tabla = [0usize; 64];
    let mut cur = base;
    for t in 0..=T_METHODDEF {
        off_tabla[t] = cur;
        if rows[t] > 0 {
            let tf = tam_fila(&tablas, t).ok_or_else(|| anyhow!("tabla {t:#x} no soportada"))?;
            cur += tf * rows[t] as usize;
        }
    }

    // Lee un índice (2 o 4 bytes) y una cadena del heap.
    let leer_idx = |pos: usize, tam: usize| -> u32 {
        if tam == 4 { u32le(d, pos) } else { u16le(d, pos) }
    };

    // --- Field: nombres ---
    let tf_field = tam_fila(&tablas, T_FIELD).unwrap();
    let nombre_field = |i: u32| -> String {
        // i es 1-based.
        if i == 0 || i > rows[T_FIELD] {
            return String::new();
        }
        let base = off_tabla[T_FIELD] + (i as usize - 1) * tf_field;
        let idx = leer_idx(base + 2, tablas.s_str); // Flags(2) luego Name
        cadena(strings, idx)
    };
    // --- MethodDef: nombres + flags ---
    let tf_method = tam_fila(&tablas, T_METHODDEF).unwrap();
    let nombre_method = |i: u32| -> (String, u32) {
        if i == 0 || i > rows[T_METHODDEF] {
            return (String::new(), 0);
        }
        let base = off_tabla[T_METHODDEF] + (i as usize - 1) * tf_method;
        // RVA(4) + ImplFlags(2) + Flags(2) + Name + Signature + ParamList
        let flags = u16le(d, base + 6);
        let idx = leer_idx(base + 8, tablas.s_str);
        (cadena(strings, idx), flags)
    };

    // --- TypeDef: nombre, namespace, rangos de campos/métodos ---
    let tf_type = tam_fila(&tablas, T_TYPEDEF).unwrap();
    let typedef_or_ref = tablas.s_cod(&[T_TYPEDEF, T_TYPEREF, 0x1B], 2);
    let s_field = tablas.s_tab(T_FIELD);
    let s_method = tablas.s_tab(T_METHODDEF);
    let leer_type = |i: u32| -> (String, String, u32, u32) {
        let base = off_tabla[T_TYPEDEF] + (i as usize - 1) * tf_type;
        let mut o = base + 4; // Flags(4)
        let nombre = cadena(strings, leer_idx(o, tablas.s_str));
        o += tablas.s_str;
        let ns = cadena(strings, leer_idx(o, tablas.s_str));
        o += tablas.s_str;
        o += typedef_or_ref; // Extends
        let field0 = leer_idx(o, s_field);
        o += s_field;
        let method0 = leer_idx(o, s_method);
        (ns, nombre, field0, method0)
    };

    let mut out = String::new();
    let _ = writeln!(out, "// .NET / CLI — estructura ({} tipos, {} métodos, {} campos)\n", rows[T_TYPEDEF], rows[T_METHODDEF], rows[T_FIELD]);
    let n_types = rows[T_TYPEDEF];
    for i in 1..=n_types {
        let (ns, nombre, f0, m0) = leer_type(i);
        // El rango llega hasta el inicio del siguiente tipo (o el fin de la tabla).
        let (f1, m1) = if i < n_types {
            let (_, _, nf, nm) = leer_type(i + 1);
            (nf, nm)
        } else {
            (rows[T_FIELD] + 1, rows[T_METHODDEF] + 1)
        };
        // El tipo <Module> (índice 1, sin nombre real) se muestra igual.
        let fqn = if ns.is_empty() { nombre.clone() } else { format!("{ns}.{nombre}") };
        let _ = writeln!(out, "type {fqn}");
        for f in f0..f1 {
            let n = nombre_field(f);
            if !n.is_empty() {
                let _ = writeln!(out, "    field {n}");
            }
        }
        for m in m0..m1 {
            let (n, flags) = nombre_method(m);
            if !n.is_empty() {
                let estatico = if flags & 0x0010 != 0 { "static " } else { "" };
                let _ = writeln!(out, "    method {estatico}{n}()");
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod pruebas_dotnet {
    use super::*;

    fn fx(n: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(n)).unwrap()
    }

    #[test]
    fn lista_tipos_y_miembros_de_un_ensamblado() {
        let d = fx("dotnet_saludo.dll");
        assert!(es_dotnet(&d), "debe detectarse como .NET");
        let s = listar(&d).expect("debe listar la estructura");
        assert!(s.contains("Capas.Demo.Saludo"), "falta la clase:\n{s}");
        assert!(s.contains("field Veces"), "falta el campo:\n{s}");
        assert!(s.contains("method Mensaje()"), "falta el método:\n{s}");
        assert!(s.contains("method static Suma()"), "falta el método estático:\n{s}");
    }
}
