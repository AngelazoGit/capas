//! Lectores NATIVOS de código intermedio (sin JDK, wabt, jadx ni Python):
//! WebAssembly → WAT, clases Java → listado tipo `javap -c -p`, Android DEX →
//! clases/métodos + bytecode Dalvik, y `.pyc` → desensamblado tipo `dis`.

use std::fmt::Write as _;

use anyhow::{anyhow, bail, Result};

use crate::pyc_tablas::{self as pt, TablaPy};

// ───────────────────────────── WebAssembly ─────────────────────────────

/// Binario .wasm → formato de texto WAT (como `wasm2wat`).
pub fn wasm_a_wat(d: &[u8]) -> Result<String> {
    wasmprinter::print_bytes(d).map_err(|e| anyhow!("wasm: {e}"))
}

// ───────────────────────────── Java .class ─────────────────────────────

/// Descriptor JVM (`Ljava/lang/String;`, `[I`…) → tipo Java legible.
pub fn tipo_java(desc: &str) -> String {
    let mut dims = 0;
    let mut s = desc;
    while let Some(r) = s.strip_prefix('[') {
        dims += 1;
        s = r;
    }
    let base = match s.chars().next() {
        Some('B') => "byte".to_string(),
        Some('C') => "char".to_string(),
        Some('D') => "double".to_string(),
        Some('F') => "float".to_string(),
        Some('I') => "int".to_string(),
        Some('J') => "long".to_string(),
        Some('S') => "short".to_string(),
        Some('Z') => "boolean".to_string(),
        Some('V') => "void".to_string(),
        Some('L') => s[1..].trim_end_matches(';').replace('/', "."),
        _ => s.replace('/', "."),
    };
    format!("{base}{}", "[]".repeat(dims))
}

/// Separa los parámetros de un descriptor de método `(…)R`.
pub fn params_java(desc: &str) -> (Vec<String>, String) {
    let Some(ini) = desc.find('(') else { return (Vec::new(), tipo_java(desc)) };
    let Some(fin) = desc.find(')') else { return (Vec::new(), tipo_java(desc)) };
    let p = &desc[ini + 1..fin];
    let mut v = Vec::new();
    let b = p.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let st = i;
        while i < b.len() && b[i] == b'[' {
            i += 1;
        }
        if i < b.len() && b[i] == b'L' {
            while i < b.len() && b[i] != b';' {
                i += 1;
            }
        }
        i += 1;
        v.push(tipo_java(&p[st..i.min(p.len())]));
    }
    (v, tipo_java(&desc[fin + 1..]))
}

fn mods_java(bits: u16, metodo: bool) -> String {
    let mut m = Vec::new();
    if bits & 0x0001 != 0 { m.push("public"); }
    if bits & 0x0002 != 0 { m.push("private"); }
    if bits & 0x0004 != 0 { m.push("protected"); }
    if bits & 0x0008 != 0 { m.push("static"); }
    if bits & 0x0010 != 0 { m.push("final"); }
    if metodo {
        if bits & 0x0020 != 0 { m.push("synchronized"); }
        if bits & 0x0100 != 0 { m.push("native"); }
        if bits & 0x0400 != 0 { m.push("abstract"); }
    } else {
        if bits & 0x0040 != 0 { m.push("volatile"); }
        if bits & 0x0080 != 0 { m.push("transient"); }
    }
    if m.is_empty() { String::new() } else { format!("{} ", m.join(" ")) }
}

/// `Invokevirtual` → `invokevirtual`, `IconstM1` → `iconst_m1`, `Iconst0` → `iconst_0`.
fn mnemonico_jvm(variante: &str) -> String {
    let mut s = String::new();
    for (i, ch) in variante.chars().enumerate() {
        if i > 0 && ch.is_ascii_uppercase() {
            s.push('_');
        }
        s.push(ch.to_ascii_lowercase());
    }
    if s.contains("const") && s.ends_with(|c: char| c.is_ascii_digit()) && !s.ends_with("_m1") {
        let d = s.pop().unwrap();
        s.push('_');
        s.push(d);
    }
    s
}

fn cargable(l: &cafebabe::constant_pool::Loadable) -> String {
    use cafebabe::constant_pool::{LiteralConstant as Lc, Loadable};
    match l {
        Loadable::LiteralConstant(Lc::String(s)) => format!("{s:?}"),
        Loadable::LiteralConstant(Lc::Integer(i)) => format!("{i}"),
        Loadable::LiteralConstant(Lc::Long(i)) => format!("{i}L"),
        Loadable::LiteralConstant(Lc::Float(f)) => format!("{f}f"),
        Loadable::LiteralConstant(Lc::Double(f)) => format!("{f}d"),
        Loadable::LiteralConstant(Lc::StringBytes(b)) => format!("<{} bytes>", b.len()),
        Loadable::ClassInfo(c) => format!("class {}", c.replace('/', ".")),
        Loadable::MethodType(t) => format!("MethodType {t}"),
        otro => format!("{otro:?}"),
    }
}

/// Texto de una instrucción JVM con sus operandos resueltos.
fn instr_jvm(off: usize, op: &cafebabe::bytecode::Opcode) -> String {
    use cafebabe::bytecode::Opcode as O;
    let dbg = format!("{op:?}");
    let variante = dbg.split(|c: char| c == '(' || c == ' ').next().unwrap_or("").to_string();
    let m = mnemonico_jvm(&variante);
    let miembro = |r: &cafebabe::constant_pool::MemberRef| {
        format!("{}.{}:{}", r.class_name.replace('/', "."), r.name_and_type.name, r.name_and_type.descriptor)
    };
    let salto = |j: i32| format!("{}", off as i64 + j as i64);
    let arg = match op {
        O::Getfield(r) | O::Getstatic(r) | O::Putfield(r) | O::Putstatic(r) | O::Invokespecial(r)
        | O::Invokestatic(r) | O::Invokevirtual(r) => miembro(r),
        O::Invokeinterface(r, n) => format!("{}, {n}", miembro(r)),
        O::Invokedynamic(i) => format!("#{}:{}:{}", i.attr_index, i.name_and_type.name, i.name_and_type.descriptor),
        O::Ldc(l) | O::LdcW(l) | O::Ldc2W(l) => cargable(l),
        O::New(c) => c.replace('/', "."),
        O::Aload(n) | O::Astore(n) | O::Iload(n) | O::Istore(n) | O::Lload(n) | O::Lstore(n) | O::Fload(n)
        | O::Fstore(n) | O::Dload(n) | O::Dstore(n) | O::Ret(n) => n.to_string(),
        O::Iinc(n, c) => format!("{n}, {c}"),
        O::Bipush(n) => n.to_string(),
        O::Sipush(n) => n.to_string(),
        O::Goto(j) | O::Jsr(j) | O::IfAcmpeq(j) | O::IfAcmpne(j) | O::IfIcmpeq(j) | O::IfIcmpge(j)
        | O::IfIcmpgt(j) | O::IfIcmple(j) | O::IfIcmplt(j) | O::IfIcmpne(j) | O::Ifeq(j) | O::Ifge(j)
        | O::Ifgt(j) | O::Ifle(j) | O::Iflt(j) | O::Ifne(j) | O::Ifnonnull(j) | O::Ifnull(j) => salto(*j),
        O::Tableswitch(t) => {
            let mut s = format!("{{ // {} a {}", t.low, t.high);
            for (k, j) in t.jumps.iter().enumerate() {
                let _ = write!(s, "\n                 {:>6}: {}", t.low as i64 + k as i64, salto(*j));
            }
            let _ = write!(s, "\n                default: {} }}", salto(t.default));
            s
        }
        O::Lookupswitch(t) => {
            let mut s = format!("{{ // {}", t.match_offsets.len());
            for (k, j) in &t.match_offsets {
                let _ = write!(s, "\n                 {k:>6}: {}", salto(*j));
            }
            let _ = write!(s, "\n                default: {} }}", salto(t.default));
            s
        }
        O::Newarray(t) => format!("{t:?}").to_lowercase(),
        O::Anewarray(t) | O::Checkcast(t) | O::Instanceof(t) => objeto_arr(t),
        O::Multianewarray(t, n) => format!("{}, {n}", objeto_arr(t)),
        _ => String::new(),
    };
    if arg.is_empty() { m } else { format!("{m:<15} {arg}") }
}

fn objeto_arr(t: &cafebabe::constant_pool::ObjectArrayType) -> String {
    use cafebabe::constant_pool::ObjectArrayType as T;
    match t {
        T::BinaryName(n) => n.replace('/', "."),
        T::ArrayType(d) => tipo_java(&d.to_string()),
    }
}

/// Clase Java (.class) → listado legible equivalente a `javap -c -p`,
/// con la lista de cadenas del constant pool al final.
pub fn clase_java(d: &[u8]) -> Result<String> {
    use cafebabe::attributes::AttributeData;
    let mut opts = cafebabe::ParseOptions::default();
    let clase = match cafebabe::parse_class_with_options(d, &opts) {
        Ok(c) => c,
        Err(_) => {
            // Bytecode raro u ofuscado: al menos la estructura, sin instrucciones.
            opts.parse_bytecode(false);
            cafebabe::parse_class_with_options(d, &opts).map_err(|e| anyhow!("class: {e}"))?
        }
    };
    let mut s = String::new();
    let java = match clase.major_version {
        45..=48 => format!("1.{}", clase.major_version - 44),
        v => (v.saturating_sub(44)).to_string(),
    };
    let _ = writeln!(s, "// Compilado para Java {java} (major {}.{})", clase.major_version, clase.minor_version);
    let mut fuente = None;
    for a in &clase.attributes {
        if let AttributeData::SourceFile(f) = &a.data {
            fuente = Some(f.to_string());
        }
    }
    if let Some(f) = &fuente {
        let _ = writeln!(s, "// Fuente: {f}");
    }
    let bits = clase.access_flags.bits();
    let tipo = if bits & 0x2000 != 0 { "@interface" } else if bits & 0x0200 != 0 { "interface" } else if bits & 0x4000 != 0 { "enum" } else { "class" };
    let mut cab = format!("{}{tipo} {}", mods_java(bits & !0x0020, false), clase.this_class.to_string().replace('/', "."));
    if let Some(sup) = &clase.super_class {
        let sup = sup.to_string().replace('/', ".");
        if sup != "java.lang.Object" {
            let _ = write!(cab, " extends {sup}");
        }
    }
    if !clase.interfaces.is_empty() {
        let l: Vec<String> = clase.interfaces.iter().map(|i| i.to_string().replace('/', ".")).collect();
        let _ = write!(cab, " {} {}", if tipo == "interface" { "extends" } else { "implements" }, l.join(", "));
    }
    let _ = writeln!(s, "{cab} {{");
    for f in &clase.fields {
        let _ = writeln!(s, "  {}{} {};", mods_java(f.access_flags.bits(), false), tipo_java(&f.descriptor.to_string()), f.name);
    }
    if !clase.fields.is_empty() {
        s.push('\n');
    }
    for m in &clase.methods {
        let desc = m.descriptor.to_string();
        let (ps, ret) = params_java(&desc);
        let nombre_clase = clase.this_class.to_string();
        let corto = nombre_clase.rsplit('/').next().unwrap_or(&nombre_clase).to_string();
        let firma = match m.name.as_ref() {
            "<init>" => format!("{}{}({})", mods_java(m.access_flags.bits(), true), corto, ps.join(", ")),
            "<clinit>" => "static {}".to_string(),
            n => format!("{}{} {}({})", mods_java(m.access_flags.bits(), true), ret, n, ps.join(", ")),
        };
        let _ = writeln!(s, "  {firma};");
        let _ = writeln!(s, "    descriptor: {desc}");
        for a in &m.attributes {
            if let AttributeData::Code(c) = &a.data {
                let _ = writeln!(s, "    Code: stack={}, locals={}, bytes={}", c.max_stack, c.max_locals, c.code.len());
                match &c.bytecode {
                    Some(bc) => {
                        for (off, op) in &bc.opcodes {
                            let _ = writeln!(s, "      {off:>5}: {}", instr_jvm(*off, op));
                        }
                    }
                    None => {
                        let _ = writeln!(s, "      (bytecode no decodificable: {} bytes)", c.code.len());
                    }
                }
                for e in &c.exception_table {
                    let _ = writeln!(
                        s,
                        "      try {}..{} -> {} catch {}",
                        e.start_pc,
                        e.end_pc,
                        e.handler_pc,
                        e.catch_type.as_deref().map(|c| c.replace('/', ".")).unwrap_or_else(|| "any".into())
                    );
                }
            }
        }
        s.push('\n');
    }
    let _ = writeln!(s, "}}");
    // Cadenas del constant pool (útiles para triaje: URLs, claves, mensajes).
    let mut cadenas: Vec<String> = clase
        .constantpool_iter()
        .filter_map(|it| match it {
            cafebabe::constant_pool::ConstantPoolItem::LiteralConstant(cafebabe::constant_pool::LiteralConstant::String(t)) => Some(t.to_string()),
            _ => None,
        })
        .collect();
    cadenas.sort();
    cadenas.dedup();
    if !cadenas.is_empty() {
        let _ = writeln!(s, "\n// Cadenas literales ({}):", cadenas.len());
        for c in cadenas {
            let _ = writeln!(s, "//   {c:?}");
        }
    }
    Ok(s)
}

// ───────────────────────────── Android DEX ─────────────────────────────

/// Android DEX → clases, campos, métodos y bytecode Dalvik (listado).
pub fn dex(d: &[u8]) -> Result<String> {
    let dx = dex::DexReader::from_vec(d.to_vec()).map_err(|e| anyhow!("dex: {e}"))?;
    let mut s = String::new();
    let h = dx.header();
    let ver = d.get(4..7).map(|v| String::from_utf8_lossy(v).into_owned()).unwrap_or_default();
    let _ = writeln!(s, "// DEX versión {ver} · {} clases · {} métodos · {} cadenas", h.class_defs_size(), h.method_ids_size(), h.string_ids_size());
    let mut n = 0usize;
    for c in dx.classes() {
        let Ok(c) = c else { continue };
        n += 1;
        let nombre = tipo_java(&c.jtype().to_string());
        let mut cab = format!("{}class {nombre}", mods_java(c.access_flags().bits() as u16, false));
        if let Some(sc) = c.super_class() {
            if let Ok(t) = dx.get_type(sc) {
                let t = tipo_java(&t.to_string());
                if t != "java.lang.Object" {
                    let _ = write!(cab, " extends {t}");
                }
            }
        }
        if !c.interfaces().is_empty() {
            let l: Vec<String> = c.interfaces().iter().map(|t| tipo_java(&t.to_string())).collect();
            let _ = write!(cab, " implements {}", l.join(", "));
        }
        let _ = writeln!(s, "\n{cab} {{");
        if let Some(f) = c.source_file() {
            let _ = writeln!(s, "  // fuente: {f}");
        }
        for f in c.fields() {
            let _ = writeln!(s, "  {}{} {};", mods_java(f.access_flags().bits() as u16, false), tipo_java(&f.jtype().to_string()), f.name());
        }
        for m in c.methods() {
            let ps: Vec<String> = m.params().iter().map(|t| tipo_java(&t.to_string())).collect();
            let _ = writeln!(s, "  {}{} {}({});", mods_java(m.access_flags().bits() as u16, true), tipo_java(&m.return_type().to_string()), m.name(), ps.join(", "));
            if let Some(code) = m.code() {
                let _ = writeln!(s, "    registros={} entradas={}", code.registers_size(), code.ins_size());
                s.push_str(&dalvik(code.insns(), &dx));
            }
        }
        let _ = writeln!(s, "}}");
    }
    if n == 0 {
        bail!("dex sin clases legibles");
    }
    Ok(s)
}

/// Formato de cada opcode Dalvik: (mnemónico, formato). Formatos según
/// https://source.android.com/docs/core/runtime/instruction-formats
fn op_dalvik(op: u8) -> (&'static str, &'static str) {
    match op {
        0x00 => ("nop", "10x"), 0x01 => ("move", "12x"), 0x02 => ("move/from16", "22x"), 0x03 => ("move/16", "32x"),
        0x04 => ("move-wide", "12x"), 0x05 => ("move-wide/from16", "22x"), 0x06 => ("move-wide/16", "32x"),
        0x07 => ("move-object", "12x"), 0x08 => ("move-object/from16", "22x"), 0x09 => ("move-object/16", "32x"),
        0x0a => ("move-result", "11x"), 0x0b => ("move-result-wide", "11x"), 0x0c => ("move-result-object", "11x"),
        0x0d => ("move-exception", "11x"), 0x0e => ("return-void", "10x"), 0x0f => ("return", "11x"),
        0x10 => ("return-wide", "11x"), 0x11 => ("return-object", "11x"), 0x12 => ("const/4", "11n"),
        0x13 => ("const/16", "21s"), 0x14 => ("const", "31i"), 0x15 => ("const/high16", "21h"),
        0x16 => ("const-wide/16", "21s"), 0x17 => ("const-wide/32", "31i"), 0x18 => ("const-wide", "51l"),
        0x19 => ("const-wide/high16", "21h"), 0x1a => ("const-string", "21c"), 0x1b => ("const-string/jumbo", "31c"),
        0x1c => ("const-class", "21c"), 0x1d => ("monitor-enter", "11x"), 0x1e => ("monitor-exit", "11x"),
        0x1f => ("check-cast", "21c"), 0x20 => ("instance-of", "22c"), 0x21 => ("array-length", "12x"),
        0x22 => ("new-instance", "21c"), 0x23 => ("new-array", "22c"), 0x24 => ("filled-new-array", "35c"),
        0x25 => ("filled-new-array/range", "3rc"), 0x26 => ("fill-array-data", "31t"), 0x27 => ("throw", "11x"),
        0x28 => ("goto", "10t"), 0x29 => ("goto/16", "20t"), 0x2a => ("goto/32", "30t"),
        0x2b => ("packed-switch", "31t"), 0x2c => ("sparse-switch", "31t"),
        0x2d => ("cmpl-float", "23x"), 0x2e => ("cmpg-float", "23x"), 0x2f => ("cmpl-double", "23x"),
        0x30 => ("cmpg-double", "23x"), 0x31 => ("cmp-long", "23x"),
        0x32 => ("if-eq", "22t"), 0x33 => ("if-ne", "22t"), 0x34 => ("if-lt", "22t"), 0x35 => ("if-ge", "22t"),
        0x36 => ("if-gt", "22t"), 0x37 => ("if-le", "22t"), 0x38 => ("if-eqz", "21t"), 0x39 => ("if-nez", "21t"),
        0x3a => ("if-ltz", "21t"), 0x3b => ("if-gez", "21t"), 0x3c => ("if-gtz", "21t"), 0x3d => ("if-lez", "21t"),
        0x44 => ("aget", "23x"), 0x45 => ("aget-wide", "23x"), 0x46 => ("aget-object", "23x"), 0x47 => ("aget-boolean", "23x"),
        0x48 => ("aget-byte", "23x"), 0x49 => ("aget-char", "23x"), 0x4a => ("aget-short", "23x"),
        0x4b => ("aput", "23x"), 0x4c => ("aput-wide", "23x"), 0x4d => ("aput-object", "23x"), 0x4e => ("aput-boolean", "23x"),
        0x4f => ("aput-byte", "23x"), 0x50 => ("aput-char", "23x"), 0x51 => ("aput-short", "23x"),
        0x52 => ("iget", "22c"), 0x53 => ("iget-wide", "22c"), 0x54 => ("iget-object", "22c"), 0x55 => ("iget-boolean", "22c"),
        0x56 => ("iget-byte", "22c"), 0x57 => ("iget-char", "22c"), 0x58 => ("iget-short", "22c"),
        0x59 => ("iput", "22c"), 0x5a => ("iput-wide", "22c"), 0x5b => ("iput-object", "22c"), 0x5c => ("iput-boolean", "22c"),
        0x5d => ("iput-byte", "22c"), 0x5e => ("iput-char", "22c"), 0x5f => ("iput-short", "22c"),
        0x60 => ("sget", "21c"), 0x61 => ("sget-wide", "21c"), 0x62 => ("sget-object", "21c"), 0x63 => ("sget-boolean", "21c"),
        0x64 => ("sget-byte", "21c"), 0x65 => ("sget-char", "21c"), 0x66 => ("sget-short", "21c"),
        0x67 => ("sput", "21c"), 0x68 => ("sput-wide", "21c"), 0x69 => ("sput-object", "21c"), 0x6a => ("sput-boolean", "21c"),
        0x6b => ("sput-byte", "21c"), 0x6c => ("sput-char", "21c"), 0x6d => ("sput-short", "21c"),
        0x6e => ("invoke-virtual", "35c"), 0x6f => ("invoke-super", "35c"), 0x70 => ("invoke-direct", "35c"),
        0x71 => ("invoke-static", "35c"), 0x72 => ("invoke-interface", "35c"),
        0x74 => ("invoke-virtual/range", "3rc"), 0x75 => ("invoke-super/range", "3rc"), 0x76 => ("invoke-direct/range", "3rc"),
        0x77 => ("invoke-static/range", "3rc"), 0x78 => ("invoke-interface/range", "3rc"),
        0x7b => ("neg-int", "12x"), 0x7c => ("not-int", "12x"), 0x7d => ("neg-long", "12x"), 0x7e => ("not-long", "12x"),
        0x7f => ("neg-float", "12x"), 0x80 => ("neg-double", "12x"), 0x81 => ("int-to-long", "12x"), 0x82 => ("int-to-float", "12x"),
        0x83 => ("int-to-double", "12x"), 0x84 => ("long-to-int", "12x"), 0x85 => ("long-to-float", "12x"),
        0x86 => ("long-to-double", "12x"), 0x87 => ("float-to-int", "12x"), 0x88 => ("float-to-long", "12x"),
        0x89 => ("float-to-double", "12x"), 0x8a => ("double-to-int", "12x"), 0x8b => ("double-to-long", "12x"),
        0x8c => ("double-to-float", "12x"), 0x8d => ("int-to-byte", "12x"), 0x8e => ("int-to-char", "12x"),
        0x8f => ("int-to-short", "12x"),
        0x90..=0xaf => (BIN23[(op - 0x90) as usize], "23x"),
        0xb0..=0xcf => (BIN2ADDR[(op - 0xb0) as usize], "12x"),
        0xd0..=0xd7 => (LIT16[(op - 0xd0) as usize], "22s"),
        0xd8..=0xe2 => (LIT8[(op - 0xd8) as usize], "22b"),
        0xfa => ("invoke-polymorphic", "45cc"), 0xfb => ("invoke-polymorphic/range", "4rcc"),
        0xfc => ("invoke-custom", "35c"), 0xfd => ("invoke-custom/range", "3rc"),
        0xfe => ("const-method-handle", "21c"), 0xff => ("const-method-type", "21c"),
        _ => ("unused", "10x"),
    }
}

const BIN23: [&str; 32] = [
    "add-int", "sub-int", "mul-int", "div-int", "rem-int", "and-int", "or-int", "xor-int", "shl-int", "shr-int", "ushr-int",
    "add-long", "sub-long", "mul-long", "div-long", "rem-long", "and-long", "or-long", "xor-long", "shl-long", "shr-long", "ushr-long",
    "add-float", "sub-float", "mul-float", "div-float", "rem-float", "add-double", "sub-double", "mul-double", "div-double", "rem-double",
];
const BIN2ADDR: [&str; 32] = [
    "add-int/2addr", "sub-int/2addr", "mul-int/2addr", "div-int/2addr", "rem-int/2addr", "and-int/2addr", "or-int/2addr", "xor-int/2addr",
    "shl-int/2addr", "shr-int/2addr", "ushr-int/2addr", "add-long/2addr", "sub-long/2addr", "mul-long/2addr", "div-long/2addr",
    "rem-long/2addr", "and-long/2addr", "or-long/2addr", "xor-long/2addr", "shl-long/2addr", "shr-long/2addr", "ushr-long/2addr",
    "add-float/2addr", "sub-float/2addr", "mul-float/2addr", "div-float/2addr", "rem-float/2addr", "add-double/2addr",
    "sub-double/2addr", "mul-double/2addr", "div-double/2addr", "rem-double/2addr",
];
const LIT16: [&str; 8] = ["add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16", "rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16"];
const LIT8: [&str; 11] = ["add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8", "rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8", "shl-int/lit8", "shr-int/lit8", "ushr-int/lit8"];

/// Longitud (en unidades de 16 bits) de cada formato Dalvik.
fn largo_formato(f: &str) -> usize {
    match f.as_bytes()[0] {
        b'1' => 1,
        b'2' => 2,
        b'3' => 3,
        b'4' => 4,
        b'5' => 5,
        _ => 1,
    }
}

/// Resuelve el índice de una instrucción 21c/22c/31c/35c/3rc a texto.
fn ref_dalvik<S: AsRef<[u8]>>(op: u8, idx: u32, dx: &dex::Dex<S>) -> String {
    match op {
        0x1a | 0x1b => dx.get_string(idx).map(|s| format!("{:?}", s.to_string())).unwrap_or_else(|_| format!("string@{idx}")),
        0x1c | 0x1f | 0x20 | 0x22 | 0x23 | 0x24 | 0x25 => {
            dx.get_type(idx).map(|t| tipo_java(&t.to_string())).unwrap_or_else(|_| format!("type@{idx}"))
        }
        0x52..=0x6d => dx
            .get_field_item(idx as u64)
            .ok()
            .and_then(|f| {
                let c = dx.get_type(*f.class_idx() as u32).ok()?;
                let n = dx.get_string(*f.name_idx()).ok()?;
                let t = dx.get_type(*f.type_idx() as u32).ok()?;
                Some(format!("{}.{}:{}", tipo_java(&c.to_string()), n, tipo_java(&t.to_string())))
            })
            .unwrap_or_else(|| format!("field@{idx}")),
        0x6e..=0x78 | 0xfa | 0xfb => dx
            .get_method_item(idx as u64)
            .ok()
            .and_then(|m| {
                let c = dx.get_type(m.class_idx() as u32).ok()?;
                let n = dx.get_string(m.name_idx()).ok()?;
                Some(format!("{}.{}", tipo_java(&c.to_string()), n))
            })
            .unwrap_or_else(|| format!("method@{idx}")),
        _ => format!("@{idx}"),
    }
}

fn dalvik<S: AsRef<[u8]>>(ins: &[u16], dx: &dex::Dex<S>) -> String {
    let mut s = String::new();
    let mut i = 0usize;
    let mut cuenta = 0usize;
    while i < ins.len() {
        let w = ins[i];
        let op = (w & 0xff) as u8;
        // Pseudo-instrucciones de datos (tablas de switch / arrays): se saltan.
        if op == 0x00 && w != 0 {
            let tam = match w {
                0x0100 => ins.get(i + 1).map(|n| 4 + *n as usize * 2).unwrap_or(1),
                0x0200 => ins.get(i + 1).map(|n| 2 + *n as usize * 4).unwrap_or(1),
                0x0300 => {
                    let ancho = *ins.get(i + 1).unwrap_or(&0) as usize;
                    let n = ins.get(i + 2).copied().unwrap_or(0) as usize | (ins.get(i + 3).copied().unwrap_or(0) as usize) << 16;
                    4 + (n * ancho + 1) / 2
                }
                _ => 1,
            };
            let _ = writeln!(s, "      {i:04x}: (datos, {tam} unidades)");
            i += tam.max(1);
            continue;
        }
        let (m, f) = op_dalvik(op);
        let lg = largo_formato(f);
        let u = |k: usize| ins.get(i + k).copied().unwrap_or(0) as u32;
        let a8 = (w >> 8) as u32;
        let (a4, b4) = ((w >> 8) & 0xf, (w >> 12) & 0xf);
        let txt = match f {
            "10x" => String::new(),
            "12x" => format!("v{a4}, v{b4}"),
            "11n" => format!("v{a4}, #{}", ((b4 as i8) << 4) >> 4),
            "11x" => format!("v{a8}"),
            "10t" => format!("{:04x}", (i as i64 + (a8 as u8 as i8) as i64) as usize),
            "20t" => format!("{:04x}", (i as i64 + (u(1) as u16 as i16) as i64) as usize),
            "30t" => format!("{:04x}", (i as i64 + (u(1) | u(2) << 16) as i32 as i64) as usize),
            "22x" => format!("v{a8}, v{}", u(1)),
            "32x" => format!("v{}, v{}", u(1), u(2)),
            "21t" => format!("v{a8}, {:04x}", (i as i64 + (u(1) as u16 as i16) as i64) as usize),
            "21s" => format!("v{a8}, #{}", u(1) as u16 as i16),
            "21h" => format!("v{a8}, #0x{:x}", u(1) << 16),
            "21c" => format!("v{a8}, {}", ref_dalvik(op, u(1), dx)),
            "23x" => format!("v{a8}, v{}, v{}", u(1) & 0xff, u(1) >> 8),
            "22b" => format!("v{a8}, v{}, #{}", u(1) & 0xff, (u(1) >> 8) as u8 as i8),
            "22t" => format!("v{a4}, v{b4}, {:04x}", (i as i64 + (u(1) as u16 as i16) as i64) as usize),
            "22s" => format!("v{a4}, v{b4}, #{}", u(1) as u16 as i16),
            "22c" => format!("v{a4}, v{b4}, {}", ref_dalvik(op, u(1), dx)),
            "31i" => format!("v{a8}, #{}", (u(1) | u(2) << 16) as i32),
            "31t" => format!("v{a8}, {:04x}", (i as i64 + (u(1) | u(2) << 16) as i32 as i64) as usize),
            "31c" => format!("v{a8}, {}", ref_dalvik(op, u(1) | u(2) << 16, dx)),
            "35c" | "45cc" => {
                let n = (w >> 12) as usize;
                let g = (w >> 8) & 0xf;
                let r = u(2);
                let regs = [r & 0xf, (r >> 4) & 0xf, (r >> 8) & 0xf, (r >> 12) & 0xf, g as u32];
                let l: Vec<String> = regs.iter().take(n.min(5)).map(|x| format!("v{x}")).collect();
                format!("{{{}}}, {}", l.join(", "), ref_dalvik(op, u(1), dx))
            }
            "3rc" | "4rcc" => {
                let n = a8;
                let c = u(2);
                format!("{{v{c} .. v{}}}, {}", c + n.saturating_sub(1), ref_dalvik(op, u(1), dx))
            }
            "51l" => {
                let v = (u(1) as u64) | (u(2) as u64) << 16 | (u(3) as u64) << 32 | (u(4) as u64) << 48;
                format!("v{a8}, #{}", v as i64)
            }
            _ => String::new(),
        };
        let _ = writeln!(s, "      {i:04x}: {m:<24} {txt}");
        i += lg;
        cuenta += 1;
        if cuenta > 200_000 {
            let _ = writeln!(s, "      ... truncado");
            break;
        }
    }
    s
}

// ───────────────────────────── Python .pyc ─────────────────────────────

/// Objeto deserializado del formato `marshal` de CPython.
#[derive(Clone, Debug)]
pub enum Py {
    Nada,
    None,
    Bool(bool),
    Ellipsis,
    StopIter,
    Int(i64),
    Grande(String),
    Float(f64),
    Complejo(f64, f64),
    Bytes(Vec<u8>),
    Str(String),
    Tupla(Vec<Py>),
    Lista(Vec<Py>),
    Dict(Vec<(Py, Py)>),
    Conjunto(Vec<Py>),
    Slice(Box<(Py, Py, Py)>),
    Codigo(Box<CodigoPy>),
}

#[derive(Clone, Debug, Default)]
pub struct CodigoPy {
    pub argcount: i64,
    pub posonly: i64,
    pub kwonly: i64,
    pub flags: i64,
    pub code: Vec<u8>,
    pub consts: Vec<Py>,
    pub names: Vec<String>,
    /// Variables locales (≤3.10: varnames; ≥3.11: localsplusnames).
    pub locales: Vec<String>,
    pub cellvars: Vec<String>,
    pub freevars: Vec<String>,
    pub filename: String,
    pub name: String,
    pub qualname: String,
    pub firstlineno: i64,
    /// Tabla de excepciones (≥3.11): (inicio, fin, destino, profundidad, lasti), en bytes.
    pub excepciones: Vec<(usize, usize, usize, usize, bool)>,
}

/// Decodifica `co_exceptiontable` (≥3.11), como `dis._parse_exception_table`.
fn tabla_excepciones(b: &[u8]) -> Vec<(usize, usize, usize, usize, bool)> {
    let mut v = Vec::new();
    let mut i = 0;
    let mut var = |i: &mut usize| -> Option<usize> {
        let mut x = *b.get(*i)? as usize;
        *i += 1;
        let mut val = x & 63;
        while x & 64 != 0 {
            val <<= 6;
            x = *b.get(*i)? as usize;
            *i += 1;
            val |= x & 63;
        }
        Some(val)
    };
    while i < b.len() {
        let (Some(ini), Some(lon), Some(dst), Some(dl)) = (var(&mut i), var(&mut i), var(&mut i), var(&mut i)) else { break };
        v.push((ini * 2, ini * 2 + lon * 2, dst * 2, dl >> 1, dl & 1 == 1));
    }
    v
}

struct Marshal<'a> {
    d: &'a [u8],
    p: usize,
    refs: Vec<Py>,
    menor: u8, // versión menor de Python 3 (6..=14)
    prof: usize,
}

impl<'a> Marshal<'a> {
    fn u8(&mut self) -> Result<u8> {
        let b = *self.d.get(self.p).ok_or_else(|| anyhow!("pyc truncado"))?;
        self.p += 1;
        Ok(b)
    }
    fn i32(&mut self) -> Result<i32> {
        let b = self.d.get(self.p..self.p + 4).ok_or_else(|| anyhow!("pyc truncado"))?;
        self.p += 4;
        Ok(i32::from_le_bytes(b.try_into().unwrap()))
    }
    fn bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let b = self.d.get(self.p..self.p + n).ok_or_else(|| anyhow!("pyc truncado"))?;
        self.p += n;
        Ok(b.to_vec())
    }
    fn texto(&mut self, n: usize) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.bytes(n)?).into_owned())
    }
    fn n(&mut self) -> Result<usize> {
        let n = self.i32()?;
        if n < 0 || n as usize > self.d.len() * 2 + 16 {
            bail!("pyc: longitud inválida {n}");
        }
        Ok(n as usize)
    }
    fn lista_str(&mut self) -> Result<Vec<String>> {
        Ok(match self.obj()? {
            Py::Tupla(v) | Py::Lista(v) => v.into_iter().map(|x| match x {
                Py::Str(s) => s,
                Py::Bytes(b) => String::from_utf8_lossy(&b).into_owned(),
                o => format!("{o:?}"),
            }).collect(),
            _ => Vec::new(),
        })
    }
    fn str(&mut self) -> Result<String> {
        Ok(match self.obj()? {
            Py::Str(s) => s,
            Py::Bytes(b) => String::from_utf8_lossy(&b).into_owned(),
            _ => String::new(),
        })
    }
    fn obj(&mut self) -> Result<Py> {
        self.prof += 1;
        if self.prof > 200 {
            bail!("pyc: anidación excesiva");
        }
        let r = self.obj_interno();
        self.prof -= 1;
        r
    }
    fn obj_interno(&mut self) -> Result<Py> {
        let c = self.u8()?;
        let guarda = c & 0x80 != 0;
        let t = c & 0x7f;
        // Reserva el hueco de la referencia ANTES de leer el contenido (como CPython).
        let slot = if guarda && t != b'r' {
            self.refs.push(Py::Nada);
            Some(self.refs.len() - 1)
        } else {
            None
        };
        let v = match t {
            b'0' => Py::Nada,
            b'N' => Py::None,
            b'F' => Py::Bool(false),
            b'T' => Py::Bool(true),
            b'.' => Py::Ellipsis,
            b'S' => Py::StopIter,
            b'i' => Py::Int(self.i32()? as i64),
            b'I' => {
                let b = self.bytes(8)?;
                Py::Int(i64::from_le_bytes(b.try_into().unwrap()))
            }
            b'l' => {
                let n = self.i32()?;
                let neg = n < 0;
                let k = n.unsigned_abs() as usize;
                let mut v: u128 = 0;
                let mut desborde = false;
                let mut digitos = Vec::with_capacity(k);
                for _ in 0..k {
                    let b = self.bytes(2)?;
                    digitos.push(u16::from_le_bytes([b[0], b[1]]) as u128);
                }
                for (i, d) in digitos.iter().enumerate() {
                    if i >= 8 {
                        desborde = true;
                        break;
                    }
                    v |= d << (15 * i);
                }
                if desborde || v > i64::MAX as u128 {
                    Py::Grande(format!("{}{}", if neg { "-" } else { "" }, entero_grande(&digitos)))
                } else {
                    Py::Int(if neg { -(v as i64) } else { v as i64 })
                }
            }
            b'g' => {
                let b = self.bytes(8)?;
                Py::Float(f64::from_le_bytes(b.try_into().unwrap()))
            }
            b'f' => {
                let n = self.u8()? as usize;
                Py::Float(self.texto(n)?.parse().unwrap_or(f64::NAN))
            }
            b'y' => {
                let a = self.bytes(8)?;
                let b = self.bytes(8)?;
                Py::Complejo(f64::from_le_bytes(a.try_into().unwrap()), f64::from_le_bytes(b.try_into().unwrap()))
            }
            b'x' => {
                let n = self.u8()? as usize;
                let a = self.texto(n)?.parse().unwrap_or(f64::NAN);
                let n = self.u8()? as usize;
                let b = self.texto(n)?.parse().unwrap_or(f64::NAN);
                Py::Complejo(a, b)
            }
            b's' => {
                let n = self.n()?;
                Py::Bytes(self.bytes(n)?)
            }
            b't' | b'u' | b'a' | b'A' => {
                let n = self.n()?;
                Py::Str(self.texto(n)?)
            }
            b'z' | b'Z' => {
                let n = self.u8()? as usize;
                Py::Str(self.texto(n)?)
            }
            b'r' => {
                let i = self.n()?;
                self.refs.get(i).cloned().unwrap_or(Py::Nada)
            }
            b'(' | b'[' | b'<' | b'>' => {
                let n = self.n()?;
                let mut v = Vec::with_capacity(n.min(1 << 16));
                for _ in 0..n {
                    v.push(self.obj()?);
                }
                match t {
                    b'(' => Py::Tupla(v),
                    b'[' => Py::Lista(v),
                    _ => Py::Conjunto(v),
                }
            }
            b')' => {
                let n = self.u8()? as usize;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(self.obj()?);
                }
                Py::Tupla(v)
            }
            b'{' => {
                let mut v = Vec::new();
                loop {
                    let k = self.obj()?;
                    if matches!(k, Py::Nada) {
                        break;
                    }
                    let val = self.obj()?;
                    v.push((k, val));
                }
                Py::Dict(v)
            }
            b':' => {
                let a = self.obj()?;
                let b = self.obj()?;
                let c = self.obj()?;
                Py::Slice(Box::new((a, b, c)))
            }
            b'c' => Py::Codigo(Box::new(self.codigo()?)),
            otro => bail!("pyc: tipo marshal desconocido 0x{otro:02x} en {}", self.p - 1),
        };
        if let Some(i) = slot {
            self.refs[i] = v.clone();
        }
        Ok(v)
    }
    fn codigo(&mut self) -> Result<CodigoPy> {
        let m = self.menor;
        let mut c = CodigoPy { argcount: self.i32()? as i64, ..Default::default() };
        if m >= 8 {
            c.posonly = self.i32()? as i64;
        }
        c.kwonly = self.i32()? as i64;
        if m < 11 {
            let _nlocals = self.i32()?;
        }
        let _stack = self.i32()?;
        c.flags = self.i32()? as i64;
        c.code = match self.obj()? {
            Py::Bytes(b) => b,
            _ => Vec::new(),
        };
        c.consts = match self.obj()? {
            Py::Tupla(v) | Py::Lista(v) => v,
            _ => Vec::new(),
        };
        c.names = self.lista_str()?;
        if m >= 11 {
            c.locales = self.lista_str()?;
            let _kinds = self.obj()?;
        } else {
            c.locales = self.lista_str()?;
            c.freevars = self.lista_str()?;
            c.cellvars = self.lista_str()?;
        }
        c.filename = self.str()?;
        c.name = self.str()?;
        if m >= 11 {
            c.qualname = self.str()?;
        } else {
            c.qualname = c.name.clone();
        }
        c.firstlineno = self.i32()? as i64;
        let _tabla_lineas = self.obj()?;
        if m >= 11 {
            if let Py::Bytes(t) = self.obj()? {
                c.excepciones = tabla_excepciones(&t);
            }
        }
        Ok(c)
    }
}

/// Dígitos base 2^15 (little-endian) → decimal exacto, sin límite de tamaño.
fn entero_grande(dig: &[u128]) -> String {
    let mut n: Vec<u32> = dig.iter().map(|d| *d as u32).collect();
    let mut dec = Vec::new();
    while n.iter().any(|&x| x != 0) {
        let mut resto: u64 = 0;
        for x in n.iter_mut().rev() {
            let cur = (resto << 15) | *x as u64;
            *x = (cur / 10) as u32;
            resto = cur % 10;
        }
        dec.push((b'0' + resto as u8) as char);
    }
    if dec.is_empty() {
        "0".into()
    } else {
        dec.iter().rev().collect()
    }
}

/// Representación corta de una constante para el listado.
pub fn repr_py(o: &Py) -> String {
    match o {
        Py::Nada => "NULL".into(),
        Py::None => "None".into(),
        Py::Bool(b) => if *b { "True".into() } else { "False".into() },
        Py::Ellipsis => "...".into(),
        Py::StopIter => "StopIteration".into(),
        Py::Int(i) => i.to_string(),
        Py::Grande(s) => s.clone(),
        Py::Float(f) => format!("{f:?}"),
        Py::Complejo(a, b) => format!("({a}+{b}j)"),
        Py::Bytes(b) => {
            let t: String = b.iter().take(60).map(|&c| if (0x20..0x7f).contains(&c) && c != b'\'' && c != b'\\' { (c as char).to_string() } else { format!("\\x{c:02x}") }).collect();
            format!("b'{t}{}'", if b.len() > 60 { "…" } else { "" })
        }
        Py::Str(s) => {
            let corto: String = s.chars().take(200).collect();
            format!("{corto:?}{}", if s.chars().count() > 200 { "…" } else { "" })
        }
        Py::Tupla(v) => {
            let l: Vec<String> = v.iter().take(30).map(repr_py).collect();
            if v.len() == 1 { format!("({},)", l[0]) } else { format!("({})", l.join(", ")) }
        }
        Py::Lista(v) => format!("[{}]", v.iter().take(30).map(repr_py).collect::<Vec<_>>().join(", ")),
        Py::Conjunto(v) => format!("frozenset({{{}}})", v.iter().take(30).map(repr_py).collect::<Vec<_>>().join(", ")),
        Py::Dict(v) => format!("{{{}}}", v.iter().take(30).map(|(k, x)| format!("{}: {}", repr_py(k), repr_py(x))).collect::<Vec<_>>().join(", ")),
        Py::Slice(s) => format!("slice({}, {}, {})", repr_py(&s.0), repr_py(&s.1), repr_py(&s.2)),
        Py::Codigo(c) => format!("<code {}>", c.qualname),
    }
}

/// Cabecera de un .pyc → (tabla de opcodes, versión menor, desplazamiento del marshal).
pub fn cabecera_pyc(d: &[u8]) -> Result<(&'static TablaPy, u8, usize)> {
    if d.len() < 16 || d[2] != b'\r' || d[3] != b'\n' {
        bail!("no es un .pyc de Python 3");
    }
    let magic = u16::from_le_bytes([d[0], d[1]]);
    let t = pt::por_magic(magic).ok_or_else(|| anyhow!("número mágico de .pyc no soportado: {magic} (Python < 3.6 o desconocido)"))?;
    let menor: u8 = t.version[2..].parse().unwrap_or(0);
    // 3.7+: magic + flags + (mtime,size | hash) = 16 bytes. 3.6: 12 bytes.
    let off = if menor >= 7 { 16 } else { 12 };
    Ok((t, menor, off))
}

/// Deserializa el objeto código raíz de un .pyc.
pub fn leer_pyc(d: &[u8]) -> Result<(&'static TablaPy, CodigoPy)> {
    let (t, menor, off) = cabecera_pyc(d)?;
    let mut m = Marshal { d, p: off, refs: Vec::new(), menor, prof: 0 };
    match m.obj()? {
        Py::Codigo(c) => Ok((t, *c)),
        _ => bail!("el .pyc no contiene un objeto código"),
    }
}

fn nombre_local(c: &CodigoPy, i: usize) -> String {
    c.locales.get(i).cloned().unwrap_or_else(|| format!("<local {i}>"))
}

fn nombre_libre(c: &CodigoPy, menor: u8, i: usize) -> String {
    if menor >= 11 {
        return nombre_local(c, i);
    }
    c.cellvars.iter().chain(c.freevars.iter()).nth(i).cloned().unwrap_or_else(|| format!("<celda {i}>"))
}

/// Instrucción decodificada de bytecode CPython.
pub struct InstrPy {
    pub off: usize,
    pub op: u8,
    pub nombre: &'static str,
    pub arg: Option<u32>,
    pub texto: String,
    pub salto: Option<usize>,
}

/// Decodifica el bytecode de un objeto código (wordcode, ≥3.6).
pub fn instrucciones_py(c: &CodigoPy, t: &TablaPy, menor: u8) -> Vec<InstrPy> {
    let mut v = Vec::new();
    let code = &c.code;
    let mut i = 0usize;
    let mut ext: u32 = 0;
    while i + 1 < code.len() {
        let op = code[i];
        let raw = code[i + 1] as u32;
        let nombre = t.nombres[op as usize];
        if nombre == "EXTENDED_ARG" {
            ext = (ext | raw) << 8;
            i += 2;
            continue;
        }
        let arg = if op >= t.have_arg { Some(ext | raw) } else { None };
        ext = 0;
        let caches = t.cache[op as usize] as usize;
        let fl = t.flags[op as usize];
        let mut salto = None;
        let texto = match arg {
            None => String::new(),
            Some(a) => {
                let a = a as usize;
                if fl & pt::F_CONST != 0 {
                    c.consts.get(a).map(repr_py).unwrap_or_else(|| format!("<const {a}>"))
                } else if fl & pt::F_NAME != 0 {
                    let (idx, extra) = match (nombre, menor) {
                        ("LOAD_GLOBAL", 11..) => (a >> 1, if a & 1 == 1 { "NULL + " } else { "" }),
                        ("LOAD_ATTR", 12..) => (a >> 1, if a & 1 == 1 { "NULL|self + " } else { "" }),
                        ("LOAD_SUPER_ATTR", 12..) => (a >> 2, ""),
                        _ => (a, ""),
                    };
                    format!("{extra}{}", c.names.get(idx).cloned().unwrap_or_else(|| format!("<name {idx}>")))
                } else if fl & pt::F_LOCAL != 0 {
                    if menor >= 13 && (nombre.contains("FAST_LOAD_FAST") || nombre.contains("FAST_STORE_FAST") || nombre == "STORE_FAST_STORE_FAST" || nombre == "LOAD_FAST_BORROW_LOAD_FAST_BORROW") {
                        format!("{}, {}", nombre_local(c, a >> 4), nombre_local(c, a & 15))
                    } else {
                        nombre_local(c, a)
                    }
                } else if fl & pt::F_FREE != 0 {
                    nombre_libre(c, menor, a)
                } else if fl & pt::F_COMPARE != 0 {
                    let idx = match menor {
                        13.. => a >> 5,
                        12 => a >> 4,
                        _ => a,
                    };
                    t.cmp_op.get(idx).map(|s| s.to_string()).unwrap_or_else(|| a.to_string())
                } else if fl & pt::F_JREL != 0 {
                    let base = i + 2 + caches * 2;
                    let paso = if menor >= 10 { a * 2 } else { a };
                    let dest = if nombre.contains("BACKWARD") { base.saturating_sub(paso) } else { base + paso };
                    salto = Some(dest);
                    format!("to {dest}")
                } else if fl & pt::F_JABS != 0 {
                    let dest = if menor >= 10 { a * 2 } else { a };
                    salto = Some(dest);
                    format!("to {dest}")
                } else {
                    a.to_string()
                }
            }
        };
        v.push(InstrPy { off: i, op, nombre: if nombre.is_empty() { "<desconocido>" } else { nombre }, arg, texto, salto });
        i += 2 + caches * 2;
    }
    v
}

fn listar_codigo(s: &mut String, c: &CodigoPy, t: &TablaPy, menor: u8, nivel: usize) {
    let pre = "  ".repeat(nivel);
    let _ = writeln!(
        s,
        "\n{pre}# ── {} (línea {}) · args={} posonly={} kwonly={} flags=0x{:x}",
        c.qualname, c.firstlineno, c.argcount, c.posonly, c.kwonly, c.flags
    );
    if !c.locales.is_empty() {
        let _ = writeln!(s, "{pre}#    locales: {}", c.locales.join(", "));
    }
    if !c.names.is_empty() {
        let _ = writeln!(s, "{pre}#    nombres: {}", c.names.join(", "));
    }
    let ins = instrucciones_py(c, t, menor);
    let destinos: std::collections::HashSet<usize> = ins.iter().filter_map(|x| x.salto).collect();
    for x in &ins {
        let marca = if destinos.contains(&x.off) { ">>" } else { "  " };
        match x.arg {
            Some(a) => {
                let _ = writeln!(s, "{pre}  {marca}{:>5} {:<28} {:>4} ({})", x.off, x.nombre, a, x.texto);
            }
            None => {
                let _ = writeln!(s, "{pre}  {marca}{:>5} {}", x.off, x.nombre);
            }
        }
    }
    for k in &c.consts {
        if let Py::Codigo(h) = k {
            listar_codigo(s, h, t, menor, nivel + 1);
        }
    }
}

/// .pyc → desensamblado completo (todas las funciones/clases anidadas),
/// equivalente a `python -m dis`, sin necesitar Python instalado.
pub fn pyc(d: &[u8]) -> Result<String> {
    let (t, menor, _) = cabecera_pyc(d)?;
    let (_, c) = leer_pyc(d)?;
    let mut s = String::new();
    let _ = writeln!(s, "# Python {} · archivo original: {}", t.version, c.filename);
    listar_codigo(&mut s, &c, t, menor, 0);
    Ok(s)
}
