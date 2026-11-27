//! Lector NATIVO de bytecode Lua (PUC-Lua 5.4) y detección de LuaJIT.
//! Parsea la cabecera y el árbol de prototipos, y lista funciones, constantes
//! (sobre todo las cadenas, muy útiles para reversing) e instrucciones
//! desensambladas (como `luac -l`). No reconstruye Lua fuente completo todavía.

use anyhow::{anyhow, bail, Result};
use std::fmt::Write as _;

/// ¿Es bytecode Lua precompilado o LuaJIT?
pub fn es_lua(d: &[u8]) -> bool {
    d.starts_with(b"\x1bLua") || d.starts_with(b"\x1bLJ")
}

/// Nombres de los 83 opcodes de Lua 5.4, en orden.
const OPS54: &[&str] = &[
    "MOVE", "LOADI", "LOADF", "LOADK", "LOADKX", "LOADFALSE", "LFALSESKIP", "LOADTRUE", "LOADNIL",
    "GETUPVAL", "SETUPVAL", "GETTABUP", "GETTABLE", "GETI", "GETFIELD", "SETTABUP", "SETTABLE",
    "SETI", "SETFIELD", "NEWTABLE", "SELF", "ADDI", "ADDK", "SUBK", "MULK", "MODK", "POWK", "DIVK",
    "IDIVK", "BANDK", "BORK", "BXORK", "SHRI", "SHLI", "ADD", "SUB", "MUL", "MOD", "POW", "DIV",
    "IDIV", "BAND", "BOR", "BXOR", "SHL", "SHR", "MMBIN", "MMBINI", "MMBINK", "UNM", "BNOT", "NOT",
    "LEN", "CONCAT", "CLOSE", "TBC", "JMP", "EQ", "LT", "LE", "EQK", "EQI", "LTI", "LEI", "GTI",
    "GEI", "TEST", "TESTSET", "CALL", "TAILCALL", "RETURN", "RETURN0", "RETURN1", "FORLOOP",
    "FORPREP", "TFORPREP", "TFORCALL", "TFORLOOP", "SETLIST", "CLOSURE", "VARARG", "VARARGPREP",
    "EXTRAARG",
];

/// Lector con cursor sobre los bytes del chunk.
struct Lec<'a> {
    d: &'a [u8],
    p: usize,
    tam_int: usize,
    tam_num: usize,
}
impl<'a> Lec<'a> {
    fn byte(&mut self) -> Result<u8> {
        let b = *self.d.get(self.p).ok_or_else(|| anyhow!("fin de datos"))?;
        self.p += 1;
        Ok(b)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self.d.get(self.p..self.p + n).ok_or_else(|| anyhow!("fin de datos"))?;
        self.p += n;
        Ok(s)
    }
    /// Entero de tamaño variable de Lua 5.4: grupos de 7 bits, big-endian; el
    /// último byte lleva el bit 0x80 puesto.
    fn varint(&mut self) -> Result<u64> {
        let mut x = 0u64;
        loop {
            let b = self.byte()?;
            x = (x << 7) | (b & 0x7f) as u64;
            if b & 0x80 != 0 {
                return Ok(x);
            }
        }
    }
    /// Cadena de Lua 5.4: longitud varint (0 = nula; si no, long = varint-1).
    fn cadena(&mut self) -> Result<Option<String>> {
        let n = self.varint()?;
        if n == 0 {
            return Ok(None);
        }
        let len = (n - 1) as usize;
        let s = self.bytes(len)?;
        Ok(Some(String::from_utf8_lossy(s).into_owned()))
    }
    fn u32le(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn entero(&mut self) -> Result<i64> {
        let b = self.bytes(self.tam_int)?;
        let mut v = [0u8; 8];
        v[..self.tam_int.min(8)].copy_from_slice(&b[..self.tam_int.min(8)]);
        Ok(i64::from_le_bytes(v))
    }
    fn numero(&mut self) -> Result<f64> {
        let b = self.bytes(self.tam_num)?;
        if self.tam_num == 8 {
            Ok(f64::from_le_bytes(b.try_into().unwrap()))
        } else {
            Ok(0.0)
        }
    }
}

/// Desensambla una instrucción de 5.4: opcode + campos A/B/C o Bx.
fn instr54(i: u32) -> String {
    let op = (i & 0x7f) as usize;
    let nombre = OPS54.get(op).copied().unwrap_or("??");
    let a = (i >> 7) & 0xff;
    let b = (i >> 16) & 0xff;
    let c = (i >> 24) & 0xff;
    let bx = (i >> 15) & 0x1ffff;
    // Modos que usan Bx (una constante/salto grande) frente a A B C.
    match nombre {
        "LOADK" | "LOADKX" | "CLOSURE" | "GETFIELD" | "FORLOOP" | "FORPREP" | "TFORPREP" | "TFORLOOP" => {
            format!("{nombre:<10} {a} {bx}")
        }
        _ => format!("{nombre:<10} {a} {b} {c}"),
    }
}

/// Parsea un prototipo (función) recursivamente y lo escribe en `out`.
fn funcion(l: &mut Lec, out: &mut String, prof: usize, idx: usize) -> Result<()> {
    if prof > 200 {
        bail!("anidamiento de funciones excesivo"); // evita desbordar la pila con bytecode malicioso
    }
    let sangria = "  ".repeat(prof);
    let _fuente = l.cadena()?; // source (suele ser nula salvo en main)
    let _lineini = l.varint()?;
    let _linefin = l.varint()?;
    let numparams = l.byte()?;
    let vararg = l.byte()?;
    let maxstack = l.byte()?;

    // Código.
    let sizecode = l.varint()? as usize;
    if sizecode > 10_000_000 {
        bail!("tamaño de código irrazonable");
    }
    let mut codigo = Vec::with_capacity(sizecode.min(4096));
    for _ in 0..sizecode {
        codigo.push(l.u32le()?);
    }

    // Constantes.
    let sizek = l.varint()? as usize;
    let mut consts = Vec::with_capacity(sizek.min(4096));
    for _ in 0..sizek {
        let tt = l.byte()?;
        let v = match tt {
            0 => "nil".to_string(),
            1 => "false".to_string(),
            17 => "true".to_string(),
            3 => format!("{}", l.entero()?),             // int
            19 => format!("{}", l.numero()?),            // float
            4 | 20 => format!("{:?}", l.cadena()?.unwrap_or_default()), // string (con comillas)
            otro => bail!("constante desconocida: tipo {otro}"),
        };
        consts.push(v);
    }

    // Upvalues: (instack, idx, kind) por cada uno.
    let sizeup = l.varint()? as usize;
    for _ in 0..sizeup {
        let _ = l.bytes(3)?;
    }

    // Encabezado de la función.
    let etiqueta = if prof == 0 { "main".to_string() } else { format!("function #{idx}") };
    let _ = writeln!(
        out,
        "{sangria}{etiqueta}: {numparams} params{}, {maxstack} slots, {} instr, {} consts",
        if vararg != 0 { " (vararg)" } else { "" },
        codigo.len(),
        consts.len(),
    );
    for (n, v) in consts.iter().enumerate() {
        let _ = writeln!(out, "{sangria}  const[{n}] = {v}");
    }
    for (n, &i) in codigo.iter().enumerate() {
        let _ = writeln!(out, "{sangria}  {:>4}  {}", n + 1, instr54(i));
    }

    // Prototipos anidados (funciones internas).
    let sizep = l.varint()? as usize;
    for k in 0..sizep {
        funcion(l, out, prof + 1, k)?;
    }

    // Depuración: lineinfo, abslineinfo, locvars, upvalue names (se saltan).
    let sizelineinfo = l.varint()? as usize;
    let _ = l.bytes(sizelineinfo)?;
    let sizeabs = l.varint()? as usize;
    for _ in 0..sizeabs {
        let _ = l.varint()?; // pc
        let _ = l.varint()?; // line
    }
    let sizelocvars = l.varint()? as usize;
    for _ in 0..sizelocvars {
        let _ = l.cadena()?; // nombre
        let _ = l.varint()?; // startpc
        let _ = l.varint()?; // endpc
    }
    let sizeupnames = l.varint()? as usize;
    for _ in 0..sizeupnames {
        let _ = l.cadena()?;
    }
    Ok(())
}

/// Lista la estructura del bytecode Lua. Soporta PUC-Lua 5.4 por completo;
/// para LuaJIT u otras versiones, devuelve un error claro (de momento).
pub fn listar(d: &[u8]) -> Result<String> {
    if d.starts_with(b"\x1bLJ") {
        bail!("LuaJIT: formato distinto, aún no soportado (usa cadenas incrustadas)");
    }
    if !d.starts_with(b"\x1bLua") {
        bail!("no es bytecode Lua");
    }
    let ver = *d.get(4).ok_or_else(|| anyhow!("cabecera corta"))?;
    if ver != 0x54 {
        bail!("solo se soporta Lua 5.4 (versión {:#x})", ver);
    }
    // Cabecera: ESC"Lua"(4) ver(1) format(1) LUAC_DATA(6) instsize(1) intsize(1)
    // numsize(1) LUAC_INT(intsize) LUAC_NUM(numsize).
    let mut l = Lec { d, p: 0, tam_int: 8, tam_num: 8 };
    let _ = l.bytes(4 + 1 + 1 + 6)?; // firma + versión + formato + LUAC_DATA
    let _instsize = l.byte()?;
    l.tam_int = l.byte()? as usize;
    l.tam_num = l.byte()? as usize;
    let _ = l.bytes(l.tam_int)?; // LUAC_INT
    let _ = l.bytes(l.tam_num)?; // LUAC_NUM
    let _sizeupvalues_main = l.byte()?; // byte de upvalues del main

    let mut out = String::new();
    let _ = writeln!(out, "// Lua 5.4 — bytecode (desensamblado nativo por CAPAS)\n");
    funcion(&mut l, &mut out, 0, 0)?;
    Ok(out)
}

#[cfg(test)]
mod pruebas_lua {
    use super::*;

    fn fx(n: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(n)).unwrap()
    }

    #[test]
    fn desensambla_lua54() {
        let d = fx("lua54_demo.luac");
        assert!(es_lua(&d), "debe detectarse como Lua");
        let s = listar(&d).expect("debe desensamblar");
        // La cadena constante del script debe aparecer.
        assert!(s.contains("hola capas"), "falta la cadena constante:\n{s}");
        // La función anidada (suma) usa ADD.
        assert!(s.contains("ADD"), "falta la instrucción ADD:\n{s}");
        // Debe haber una función anidada (la main + la interna).
        assert!(s.contains("function #0"), "falta la función anidada:\n{s}");
    }

    #[test]
    fn no_entra_en_panico_con_basura() {
        let d = fx("lua54_demo.luac");
        for n in 0..d.len() {
            let _ = listar(&d[..n]); // truncado: nunca debe panic
        }
        // Cabecera válida + basura detrás.
        let mut malo = d[..16.min(d.len())].to_vec();
        malo.extend_from_slice(&[0xffu8; 500]);
        let _ = listar(&malo);
    }
}
