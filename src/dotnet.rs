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

// Lecturas acotadas: con un .NET malformado devuelven 0 en vez de entrar en
// pánico (entrada no confiable).
fn u16le(d: &[u8], o: usize) -> u32 {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as u32).unwrap_or(0)
}
fn u32le(d: &[u8], o: usize) -> u32 {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0)
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
    let (mut us_off, mut us_sz) = (0usize, 0usize);
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
            "#US" => {
                us_off = md_off + off;
                us_sz = sz;
            }
            _ => {}
        }
    }
    if tilde_off == 0 || str_off == 0 {
        bail!("faltan las corrientes #~ o #Strings");
    }
    let strings = d.get(str_off..(str_off + str_sz).min(d.len())).unwrap_or(&[]);
    let us = d.get(us_off..(us_off + us_sz).min(d.len())).unwrap_or(&[]);

    // Cabecera de #~: Reserved(4), Major(1), Minor(1), HeapSizes(1), Reserved(1),
    // Valid(8), Sorted(8), luego un u32 de recuento por cada tabla presente.
    if tilde_off + 24 > d.len() {
        bail!("corriente #~ truncada");
    }
    let heap = d[tilde_off + 6];
    let valid = ((u32le(d, tilde_off + 8) as u64) | ((u32le(d, tilde_off + 12) as u64) << 32)) as u64;
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
    let nombre_method = |i: u32| -> (String, u32, u32) {
        if i == 0 || i > rows[T_METHODDEF] {
            return (String::new(), 0, 0);
        }
        let base = off_tabla[T_METHODDEF] + (i as usize - 1) * tf_method;
        // RVA(4) + ImplFlags(2) + Flags(2) + Name + Signature + ParamList
        let rva = u32le(d, base);
        let flags = u16le(d, base + 6);
        let idx = leer_idx(base + 8, tablas.s_str);
        (cadena(strings, idx), flags, rva)
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
            let (n, flags, rva) = nombre_method(m);
            if !n.is_empty() {
                let estatico = if flags & 0x0010 != 0 { "static " } else { "" };
                let _ = writeln!(out, "    method {estatico}{n}()");
                for linea in desensamblar(d, &mapa, us, rva) {
                    let _ = writeln!(out, "    {linea}");
                }
            }
        }
    }
    Ok(out)
}

/// Entero comprimido de ECMA-335 (1/2/4 bytes). Devuelve (valor, bytes).
fn comprimido(d: &[u8], o: usize) -> Option<(u32, usize)> {
    let b0 = *d.get(o)? as u32;
    if b0 & 0x80 == 0 {
        Some((b0, 1))
    } else if b0 & 0xc0 == 0x80 {
        Some((((b0 & 0x3f) << 8) | *d.get(o + 1)? as u32, 2))
    } else if b0 & 0xe0 == 0xc0 {
        Some((((b0 & 0x1f) << 24) | ((*d.get(o + 1)? as u32) << 16) | ((*d.get(o + 2)? as u32) << 8) | *d.get(o + 3)? as u32, 4))
    } else {
        None
    }
}

/// Literal de cadena del heap #US a partir de un token ldstr (0x70xxxxxx).
fn us_literal(us: &[u8], token: u32) -> Option<String> {
    let off = (token & 0x00ff_ffff) as usize;
    let (len, n) = comprimido(us, off)?;
    let len = len as usize;
    if len == 0 {
        return Some(String::new());
    }
    // len incluye el byte final de marca; los chars son UTF-16LE.
    let datos = us.get(off + n..off + n + len - 1)?;
    let u16s: Vec<u16> = datos.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Some(String::from_utf16_lossy(&u16s))
}

/// Operando de un opcode CIL: tamaño en bytes o una marca (token/str/switch).
const OP_NONE: u8 = 0;
const OP_TOK: u8 = 40; // token de 4 bytes (método/campo/tipo)
const OP_STR: u8 = 50; // token ldstr (4 bytes, → #US)
const OP_SW: u8 = 60; // switch (4 + 4*n)

/// (nombre, operando) de un opcode de 1 byte. None = desconocido (se detiene).
fn op1(b: u8) -> Option<(&'static str, u8)> {
    Some(match b {
        0x00 => ("nop", OP_NONE), 0x01 => ("break", OP_NONE),
        0x02 => ("ldarg.0", OP_NONE), 0x03 => ("ldarg.1", OP_NONE), 0x04 => ("ldarg.2", OP_NONE), 0x05 => ("ldarg.3", OP_NONE),
        0x06 => ("ldloc.0", OP_NONE), 0x07 => ("ldloc.1", OP_NONE), 0x08 => ("ldloc.2", OP_NONE), 0x09 => ("ldloc.3", OP_NONE),
        0x0a => ("stloc.0", OP_NONE), 0x0b => ("stloc.1", OP_NONE), 0x0c => ("stloc.2", OP_NONE), 0x0d => ("stloc.3", OP_NONE),
        0x0e => ("ldarg.s", 1), 0x0f => ("ldarga.s", 1), 0x10 => ("starg.s", 1),
        0x11 => ("ldloc.s", 1), 0x12 => ("ldloca.s", 1), 0x13 => ("stloc.s", 1),
        0x14 => ("ldnull", OP_NONE), 0x15 => ("ldc.i4.m1", OP_NONE),
        0x16 => ("ldc.i4.0", OP_NONE), 0x17 => ("ldc.i4.1", OP_NONE), 0x18 => ("ldc.i4.2", OP_NONE),
        0x19 => ("ldc.i4.3", OP_NONE), 0x1a => ("ldc.i4.4", OP_NONE), 0x1b => ("ldc.i4.5", OP_NONE),
        0x1c => ("ldc.i4.6", OP_NONE), 0x1d => ("ldc.i4.7", OP_NONE), 0x1e => ("ldc.i4.8", OP_NONE),
        0x1f => ("ldc.i4.s", 1), 0x20 => ("ldc.i4", 4), 0x21 => ("ldc.i8", 8),
        0x22 => ("ldc.r4", 4), 0x23 => ("ldc.r8", 8),
        0x25 => ("dup", OP_NONE), 0x26 => ("pop", OP_NONE),
        0x27 => ("jmp", OP_TOK), 0x28 => ("call", OP_TOK), 0x29 => ("calli", OP_TOK), 0x2a => ("ret", OP_NONE),
        0x2b => ("br.s", 1), 0x2c => ("brfalse.s", 1), 0x2d => ("brtrue.s", 1),
        0x2e..=0x37 => ("b??.s", 1), // beq.s..bgt.un.s
        0x38 => ("br", 4), 0x39 => ("brfalse", 4), 0x3a => ("brtrue", 4),
        0x3b..=0x44 => ("b??", 4),
        0x45 => ("switch", OP_SW),
        0x46..=0x51 => ("ldind/stind", OP_NONE),
        0x58 => ("add", OP_NONE), 0x59 => ("sub", OP_NONE), 0x5a => ("mul", OP_NONE), 0x5b => ("div", OP_NONE),
        0x5c => ("div.un", OP_NONE), 0x5d => ("rem", OP_NONE), 0x5e => ("rem.un", OP_NONE), 0x5f => ("and", OP_NONE),
        0x60 => ("or", OP_NONE), 0x61 => ("xor", OP_NONE), 0x62 => ("shl", OP_NONE), 0x63 => ("shr", OP_NONE),
        0x64 => ("shr.un", OP_NONE), 0x65 => ("neg", OP_NONE), 0x66 => ("not", OP_NONE),
        0x52..=0x57 => ("stind", OP_NONE),
        0x67..=0x6e => ("conv", OP_NONE),
        0x6f => ("callvirt", OP_TOK), 0x70 => ("cpobj", OP_TOK), 0x71 => ("ldobj", OP_TOK),
        0x72 => ("ldstr", OP_STR), 0x73 => ("newobj", OP_TOK), 0x74 => ("castclass", OP_TOK),
        0x75 => ("isinst", OP_TOK), 0x76 => ("conv.r.un", OP_NONE),
        0x79 => ("unbox", OP_TOK), 0x7a => ("throw", OP_NONE),
        0x7b => ("ldfld", OP_TOK), 0x7c => ("ldflda", OP_TOK), 0x7d => ("stfld", OP_TOK),
        0x7e => ("ldsfld", OP_TOK), 0x7f => ("ldsflda", OP_TOK), 0x80 => ("stsfld", OP_TOK),
        0x81 => ("stobj", OP_TOK), 0x82..=0x8b => ("conv.ovf", OP_NONE),
        0x8c => ("box", OP_TOK), 0x8d => ("newarr", OP_TOK), 0x8e => ("ldlen", OP_NONE), 0x8f => ("ldelema", OP_TOK),
        0x90..=0x9a => ("ldelem", OP_NONE), 0x9b..=0xa2 => ("stelem", OP_NONE),
        0xa3 => ("ldelem", OP_TOK), 0xa4 => ("stelem", OP_TOK), 0xa5 => ("unbox.any", OP_TOK),
        0xb3..=0xc3 => ("conv.ovf", OP_NONE),
        0xc6 => ("ckfinite", OP_NONE),
        0xd0 => ("ldtoken", OP_TOK), 0xd1..=0xd9 => ("conv/shr", OP_NONE),
        0xdc => ("endfinally", OP_NONE), 0xdd => ("leave", 4), 0xde => ("leave.s", 1), 0xdf => ("stind.i", OP_NONE),
        0xe0 => ("conv.u", OP_NONE),
        _ => return None,
    })
}

/// Opcodes de 2 bytes (prefijo 0xFE).
fn op2(b: u8) -> Option<(&'static str, u8)> {
    Some(match b {
        0x00 => ("arglist", OP_NONE), 0x01 => ("ceq", OP_NONE), 0x02 => ("cgt", OP_NONE), 0x03 => ("cgt.un", OP_NONE),
        0x04 => ("clt", OP_NONE), 0x05 => ("clt.un", OP_NONE), 0x06 => ("ldftn", OP_TOK), 0x07 => ("ldvirtftn", OP_TOK),
        0x09 => ("ldarg", 2), 0x0a => ("ldarga", 2), 0x0b => ("starg", 2), 0x0c => ("ldloc", 2), 0x0d => ("ldloca", 2), 0x0e => ("stloc", 2),
        0x0f => ("localloc", OP_NONE), 0x11 => ("endfilter", OP_NONE), 0x12 => ("unaligned.", 1), 0x13 => ("volatile.", OP_NONE),
        0x14 => ("tail.", OP_NONE), 0x15 => ("initobj", OP_TOK), 0x16 => ("constrained.", OP_TOK), 0x17 => ("cpblk", OP_NONE),
        0x18 => ("initblk", OP_NONE), 0x1a => ("rethrow", OP_NONE), 0x1c => ("sizeof", OP_TOK), 0x1d => ("refanytype", OP_NONE), 0x1e => ("readonly.", OP_NONE),
        _ => return None,
    })
}

/// Desensambla el cuerpo CIL de un método (por su RVA). Resuelve ldstr → literal.
fn desensamblar(d: &[u8], mapa: &Mapa, us: &[u8], rva: u32) -> Vec<String> {
    let mut out = Vec::new();
    if rva == 0 {
        return out;
    }
    let Some(off) = mapa.off(rva) else { return out };
    let Some(&cab) = d.get(off) else { return out };
    // Cabecera del cuerpo: fina ((b&3)==2, tamaño=b>>2) o gorda ((b&3)==3).
    let (code_off, code_len) = if cab & 0x03 == 0x02 {
        (off + 1, (cab >> 2) as usize)
    } else if cab & 0x03 == 0x03 {
        let tam = u32le(d, off + 4) as usize;
        let cab_tam = ((u16le(d, off) >> 12) * 4) as usize; // tamaño de cabecera en dwords*4
        (off + cab_tam.max(12), tam)
    } else {
        return out;
    };
    let Some(il) = d.get(code_off..(code_off + code_len).min(d.len())) else { return out };
    let mut p = 0;
    let mut n = 0;
    while p < il.len() && n < 4000 {
        n += 1;
        let ip = p;
        let b = il[p];
        p += 1;
        let (nombre, opd) = if b == 0xfe {
            let Some(&b2) = il.get(p) else { break };
            p += 1;
            match op2(b2) {
                Some(x) => x,
                None => {
                    out.push(format!("    IL_{ip:04x}: .byte 0xfe 0x{b2:02x} (desconocido)"));
                    break;
                }
            }
        } else {
            match op1(b) {
                Some(x) => x,
                None => {
                    out.push(format!("    IL_{ip:04x}: .byte 0x{b:02x} (desconocido)"));
                    break;
                }
            }
        };
        // Operando.
        let extra = match opd {
            OP_NONE => String::new(),
            OP_SW => {
                let cnt = u32le(il, p) as usize;
                p += 4 + 4 * cnt.min((il.len().saturating_sub(p)) / 4);
                format!(" ({cnt} casos)")
            }
            OP_STR => {
                let tok = u32le(il, p);
                p += 4;
                match us_literal(us, tok) {
                    Some(s) => format!(" {:?}", s),
                    None => format!(" (str 0x{tok:08x})"),
                }
            }
            OP_TOK => {
                let tok = u32le(il, p);
                p += 4;
                format!(" token 0x{tok:08x}")
            }
            1 => { let v = *il.get(p).unwrap_or(&0); p += 1; format!(" {v}") }
            4 => { let v = u32le(il, p); p += 4; format!(" {v}") }
            8 => { p += 8; String::new() }
            _ => String::new(),
        };
        out.push(format!("    IL_{ip:04x}: {nombre}{extra}"));
    }
    out
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
        // Fase 2: cuerpo CIL desensamblado, con ldstr resuelto y la suma.
        assert!(s.contains("ldstr \"hola\""), "falta el ldstr resuelto:\n{s}");
        assert!(s.contains("IL_0002: add"), "falta la instrucción add:\n{s}");
    }

    #[test]
    fn no_entra_en_panico_con_basura() {
        let d = fx("dotnet_saludo.dll");
        for n in 0..d.len() {
            let _ = listar(&d[..n]); // truncado en cada punto: nunca debe panic
        }
        let _ = listar(&[0xffu8; 2000]);
        let _ = listar(&[]);
    }
}
