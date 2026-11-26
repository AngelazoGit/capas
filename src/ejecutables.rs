//! Capa de código nativo: cabeceras, segmentos, secciones, símbolos,
//! importaciones y desensamblado INTEGRADO de x86/x86-64 (iced-x86),
//! ARM64, ARM/Thumb (yaxpeax-arm) y MIPS (yaxpeax-mips). Sin objdump/readelf.

use std::collections::HashMap;
use std::fmt::Write as _;

use crate::idioma::{tfmt, tr};
use goblin::{elf, mach, pe, Object};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

pub struct Informe {
    pub cabeceras: String,
    pub desensamblado: Option<String>,
    pub arquitectura: String,
    pub notas: Vec<String>,
}

/// Conjunto de instrucciones a desensamblar.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Isa {
    X86(u32),
    A64,
    Arm,
    Thumb,
    Mips { be: bool },
}

struct Seccion<'a> {
    nombre: String,
    va: u64,
    datos: &'a [u8],
}

pub fn analizar(d: &[u8], max_instr: usize) -> anyhow::Result<Informe> {
    let mut c = String::new();
    let mut notas = Vec::new();
    let mut ejec: Vec<Seccion> = Vec::new();
    let mut simbolos: HashMap<u64, String> = HashMap::new();
    let isa: Option<Isa>;
    // Regiones ARM/Thumb/datos según los símbolos de mapeo $a/$t/$d del ELF.
    let mut modos: Vec<(u64, u8)> = Vec::new();
    let arquitectura: String;
    let entrada: u64;

    match Object::parse(d)? {
        Object::Elf(e) => {
            arquitectura = elf::header::machine_to_str(e.header.e_machine).to_string();
            isa = match e.header.e_machine {
                elf::header::EM_X86_64 => Some(Isa::X86(64)),
                elf::header::EM_386 => Some(Isa::X86(32)),
                elf::header::EM_AARCH64 => Some(Isa::A64),
                elf::header::EM_ARM => Some(if e.entry & 1 == 1 { Isa::Thumb } else { Isa::Arm }),
                elf::header::EM_MIPS => Some(Isa::Mips { be: !e.little_endian }),
                _ => None,
            };
            entrada = e.entry & !1;
            writeln!(c, "== ELF ==")?;
            writeln!(c, "{}", tfmt(tr("Architecture : {} ({} bits)","Arquitectura : {} ({} bits)"), &[arquitectura.clone(), (if e.is_64 { 64 } else { 32 }).to_string()]))?;
            writeln!(c, "{}", tfmt(tr("Type         : {}","Tipo         : {}"), &[elf::header::et_to_str(e.header.e_type).to_string()]))?;
            writeln!(c, "{}", tfmt(tr("Entry        : 0x{}","Entrada      : 0x{}"), &[format!("{:x}", e.entry)]))?;
            if let Some(i) = e.interpreter {
                writeln!(c, "{}", tfmt(tr("Interpreter  : {}","Intérprete   : {}"), &[i.to_string()]))?;
            }
            writeln!(c, "{}", tfmt(tr("Endianness   : {}","Endianness   : {}"), &[(if e.little_endian { "little" } else { "big" }).to_string()]))?;
            writeln!(c, "{}", tfmt(tr("OS/ABI       : {}","OS/ABI       : {}"), &[e.header.e_ident[elf::header::EI_OSABI].to_string()]))?;
            if let Some(so) = e.soname {
                writeln!(c, "SONAME       : {so}")?;
            }
            writeln!(c, "\n-- {} --", tr("Program headers (segments)","Cabeceras de programa (segmentos)"))?;
            for ph in &e.program_headers {
                let fl = format!("{}{}{}", if ph.is_read() { "R" } else { "-" }, if ph.is_write() { "W" } else { "-" }, if ph.is_executable() { "X" } else { "-" });
                writeln!(
                    c,
                    "  {:<14} off=0x{:<8x} va=0x{:<12x} archivo={:<10} memoria={:<10} {fl}",
                    elf::program_header::pt_to_str(ph.p_type),
                    ph.p_offset,
                    ph.p_vaddr,
                    ph.p_filesz,
                    ph.p_memsz
                )?;
            }
            if let Some(dy) = &e.dynamic {
                writeln!(c, "{}", tfmt(tr("\n-- Dynamic section ({} entries) --","\n-- Sección dinámica ({} entradas) --"), &[dy.dyns.len().to_string()]))?;
                for de in dy.dyns.iter().take(200) {
                    let etiqueta = elf::dynamic::tag_to_str(de.d_tag);
                    let val = if matches!(de.d_tag, elf::dynamic::DT_NEEDED | elf::dynamic::DT_SONAME | elf::dynamic::DT_RPATH | elf::dynamic::DT_RUNPATH) {
                        e.dynstrtab.get_at(de.d_val as usize).unwrap_or("?").to_string()
                    } else {
                        format!("0x{:x}", de.d_val)
                    };
                    writeln!(c, "  {etiqueta:<20} {val}")?;
                }
            }
            let nrel = e.dynrelas.len() + e.dynrels.len() + e.pltrelocs.len();
            writeln!(c, "{}", tfmt(tr("\nDynamic relocations: {}","\nReubicaciones dinámicas: {}"), &[nrel.to_string()]))?;
            for sh in &e.section_headers {
                if sh.sh_type == elf::section_header::SHT_NOTE {
                    let n = e.shdr_strtab.get_at(sh.sh_name).unwrap_or("?");
                    if n == ".note.gnu.build-id" {
                        if let Some(b) = d.get(sh.sh_offset as usize + 16..(sh.sh_offset + sh.sh_size) as usize) {
                            let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
                            writeln!(c, "Build ID: {h}")?;
                        }
                    }
                }
            }
            writeln!(c, "\n-- {} --", tr("Dynamic libraries","Bibliotecas dinámicas"))?;
            for l in &e.libraries {
                writeln!(c, "  {l}")?;
            }
            writeln!(c, "\n-- {} --", tr("Sections","Secciones"))?;
            for sh in &e.section_headers {
                let n = e.shdr_strtab.get_at(sh.sh_name).unwrap_or("?");
                writeln!(
                    c,
                    "  {:<24} va=0x{:<12x} off=0x{:<10x} tam={:<10} {}",
                    n,
                    sh.sh_addr,
                    sh.sh_offset,
                    sh.sh_size,
                    if sh.is_executable() { "EJEC" } else { "" }
                )?;
                if sh.is_executable() && sh.sh_type != elf::section_header::SHT_NOBITS {
                    let (o, s) = (sh.sh_offset as usize, sh.sh_size as usize);
                    if let Some(datos) = d.get(o..o + s) {
                        ejec.push(Seccion { nombre: n.to_string(), va: sh.sh_addr, datos });
                    }
                }
            }
            let mut imp = Vec::new();
            for s in e.dynsyms.iter() {
                let n = e.dynstrtab.get_at(s.st_name).unwrap_or("");
                if n.is_empty() {
                    continue;
                }
                if s.is_import() {
                    imp.push(n.to_string());
                } else if s.st_value != 0 {
                    simbolos.insert(s.st_value, n.to_string());
                }
            }
            for s in e.syms.iter() {
                let n = e.strtab.get_at(s.st_name).unwrap_or("");
                if e.header.e_machine == elf::header::EM_ARM && n.starts_with('$') {
                    let m = match n.as_bytes().get(1) {
                        Some(b'a') => b'a',
                        Some(b't') => b't',
                        Some(b'd') => b'd',
                        _ => 0,
                    };
                    if m != 0 && (n.len() == 2 || n.as_bytes()[2] == b'.') {
                        modos.push((s.st_value, m));
                    }
                    continue;
                }
                if !n.is_empty() && s.st_value != 0 && s.is_function() {
                    simbolos.insert(s.st_value & if e.header.e_machine == elf::header::EM_ARM { !1 } else { !0 }, n.to_string());
                    if e.header.e_machine == elf::header::EM_ARM && modos.is_empty() {
                        // sin símbolos de mapeo: la paridad de cada función dice su modo
                    }
                }
            }
            if e.header.e_machine == elf::header::EM_ARM && modos.is_empty() {
                for s in e.syms.iter().filter(|s| s.is_function() && s.st_value != 0) {
                    modos.push((s.st_value & !1, if s.st_value & 1 == 1 { b't' } else { b'a' }));
                }
            }
            modos.sort();
            if e.syms.is_empty() {
                notas.push(tr("binary without symbol table (stripped)","binario sin tabla de símbolos (stripped)").into());
            }
            imp.sort();
            imp.dedup();
            writeln!(c, "{}", tfmt(tr("\n-- Imported symbols ({}) --","\n-- Símbolos importados ({}) --"), &[imp.len().to_string()]))?;
            for n in &imp {
                writeln!(c, "  {n}")?;
            }
        }
        Object::PE(p) => {
            let m = p.header.coff_header.machine;
            arquitectura = match m {
                pe::header::COFF_MACHINE_X86_64 => "x86-64".into(),
                pe::header::COFF_MACHINE_X86 => "x86".into(),
                pe::header::COFF_MACHINE_ARM64 => "ARM64".into(),
                pe::header::COFF_MACHINE_ARMNT => "ARM".into(),
                otra => format!("máquina 0x{otra:x}"),
            };
            isa = match m {
                pe::header::COFF_MACHINE_X86_64 => Some(Isa::X86(64)),
                pe::header::COFF_MACHINE_X86 => Some(Isa::X86(32)),
                pe::header::COFF_MACHINE_ARM64 => Some(Isa::A64),
                pe::header::COFF_MACHINE_ARMNT => Some(Isa::Thumb),
                _ => None,
            };
            let base = p.image_base as u64;
            entrada = base + p.entry as u64;
            writeln!(c, "== PE ==")?;
            writeln!(c, "{}", tfmt(tr("Architecture : {}","Arquitectura : {}"), &[arquitectura.clone()]))?;
            writeln!(c, "{}", tfmt(tr("Type         : {}","Tipo         : {}"), &[(if p.is_lib { "DLL" } else { "EXE" }).to_string()]))?;
            writeln!(c, "{}", tfmt(tr("Image base   : 0x{}","Image base   : 0x{}"), &[format!("{base:x}")]))?;
            writeln!(c, "{}", tfmt(tr("Entry        : 0x{}","Entrada      : 0x{}"), &[format!("{entrada:x}")]))?;
            if let Some(oh) = p.header.optional_header {
                if oh.data_directories.get_clr_runtime_header().is_some() {
                    notas.push(tr(".NET / CLR: use ILSpy or dnSpy to decompile to C#",".NET / CLR: usa ILSpy o dnSpy para decompilar a C#").into());
                    writeln!(c, "{}", tr(".NET assembly (CLR)","Ensamblado .NET (CLR)"))?;
                }
            }
            writeln!(c, "\n-- {} --", tr("Sections","Secciones"))?;
            for s in &p.sections {
                let n = s.name().unwrap_or("?").to_string();
                let x = s.characteristics & pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0;
                writeln!(
                    c,
                    "  {:<10} va=0x{:<10x} raw=0x{:<10x} tam={:<10} {}",
                    n,
                    s.virtual_address,
                    s.pointer_to_raw_data,
                    s.size_of_raw_data,
                    if x { "EJEC" } else { "" }
                )?;
                if n.starts_with("UPX") {
                    notas.push(tr("packed with UPX: run `upx -d` for another layer","empaquetado con UPX: ejecuta `upx -d` para otra capa").into());
                }
                if x {
                    let (o, t) = (s.pointer_to_raw_data as usize, s.size_of_raw_data as usize);
                    if let Some(datos) = d.get(o..o + t) {
                        ejec.push(Seccion { nombre: n, va: base + s.virtual_address as u64, datos });
                    }
                }
            }
            writeln!(c, "{}", tfmt(tr("\n-- Imports ({}) --","\n-- Importaciones ({}) --"), &[p.imports.len().to_string()]))?;
            for i in &p.imports {
                writeln!(c, "  {:<28} {}", i.dll, i.name)?;
                simbolos.insert(base + i.rva as u64, format!("{}!{}", i.dll, i.name));
            }
            writeln!(c, "{}", tfmt(tr("\n-- Exports ({}) --","\n-- Exportaciones ({}) --"), &[p.exports.len().to_string()]))?;
            for e in &p.exports {
                let n = e.name.unwrap_or("<ordinal>");
                writeln!(c, "  0x{:x}  {n}", base + e.rva as u64)?;
                simbolos.insert(base + e.rva as u64, n.to_string());
            }
        }
        Object::Mach(mach::Mach::Binary(m)) => {
            arquitectura = mach::cputype::get_arch_name_from_types(m.header.cputype, m.header.cpusubtype)
                .unwrap_or("desconocida")
                .to_string();
            isa = match m.header.cputype {
                mach::cputype::CPU_TYPE_X86_64 => Some(Isa::X86(64)),
                mach::cputype::CPU_TYPE_X86 => Some(Isa::X86(32)),
                mach::cputype::CPU_TYPE_ARM64 | mach::cputype::CPU_TYPE_ARM64_32 => Some(Isa::A64),
                mach::cputype::CPU_TYPE_ARM => Some(Isa::Arm),
                _ => None,
            };
            entrada = m.entry;
            writeln!(c, "== Mach-O ==")?;
            writeln!(c, "{}", tfmt(tr("Architecture : {}","Arquitectura : {}"), &[arquitectura.clone()]))?;
            writeln!(c, "{}", tfmt(tr("Entry        : 0x{}","Entrada      : 0x{}"), &[format!("{:x}", m.entry)]))?;
            writeln!(c, "\n-- {} --", tr("Libraries","Bibliotecas"))?;
            for l in &m.libs {
                writeln!(c, "  {l}")?;
            }
            writeln!(c, "\n-- {} --", tr("Segments / sections","Segmentos / secciones"))?;
            for seg in &m.segments {
                for (s, datos) in seg.sections()? {
                    let n = format!("{},{}", s.segname().unwrap_or("?"), s.name().unwrap_or("?"));
                    let x = s.flags & 0x8000_0400 != 0; // PURE_INSTRUCTIONS | SOME_INSTRUCTIONS
                    writeln!(c, "  {:<28} va=0x{:<12x} tam={:<10} {}", n, s.addr, s.size, if x { "EJEC" } else { "" })?;
                    if x {
                        ejec.push(Seccion { nombre: n, va: s.addr, datos });
                    }
                }
            }
            if let Some(syms) = &m.symbols {
                for (n, nl) in syms.iter().flatten() {
                    if nl.n_value != 0 && !n.is_empty() {
                        simbolos.insert(nl.n_value, n.to_string());
                    }
                }
            }
            if let Ok(imps) = m.imports() {
                writeln!(c, "{}", tfmt(tr("\n-- Imports ({}) --","\n-- Importaciones ({}) --"), &[imps.len().to_string()]))?;
                for i in imps {
                    writeln!(c, "  {:<28} {}", i.dylib, i.name)?;
                }
            }
        }
        _ => anyhow::bail!("formato ejecutable no soportado por el analizador interno"),
    }

    writeln!(c, "{}", tfmt(tr("\n-- Symbols with address ({}) --","\n-- Símbolos con dirección ({}) --"), &[simbolos.len().to_string()]))?;
    let mut ord: Vec<_> = simbolos.iter().collect();
    ord.sort();
    for (a, n) in ord.iter().take(20_000) {
        writeln!(c, "  0x{a:012x}  {n}")?;
    }

    let desensamblado = match isa {
        Some(Isa::X86(b)) if !ejec.is_empty() => Some(desensamblar(b, &ejec, &simbolos, entrada, max_instr)),
        Some(i) if !ejec.is_empty() => Some(desensamblar_yax(i, &ejec, &simbolos, &modos, entrada, max_instr)),
        Some(_) => None,
        None => {
            notas.push(tfmt(tr("architecture {}: no built-in disassembler, objdump is used if installed","arquitectura {}: sin desensamblador interno, se usa objdump si está instalado"), &[arquitectura.clone()]));
            None
        }
    };

    Ok(Informe { cabeceras: c, desensamblado, arquitectura, notas })
}

fn desensamblar(
    bits: u32,
    secciones: &[Seccion],
    simbolos: &HashMap<u64, String>,
    entrada: u64,
    max: usize,
) -> String {
    let mut s = String::new();
    let mut fmt = IntelFormatter::new();
    fmt.options_mut().set_first_operand_char_index(10);
    let mut total = 0;
    let mut ins = Instruction::default();
    let mut texto = String::new();
    for sec in secciones {
        let _ = writeln!(s, "\n; ===== sección {} @ 0x{:x} ({} bytes) =====", sec.nombre, sec.va, sec.datos.len());
        let mut dec = Decoder::with_ip(bits, sec.datos, sec.va, DecoderOptions::NONE);
        while dec.can_decode() {
            if total >= max {
                let _ = writeln!(s, "\n; ... truncado tras {max} instrucciones (usa --max-instrucciones)");
                return s;
            }
            dec.decode_out(&mut ins);
            let ip = ins.ip();
            if ip == entrada {
                let _ = writeln!(s, "\n; ---- PUNTO DE ENTRADA ----");
            }
            if let Some(n) = simbolos.get(&ip) {
                let _ = writeln!(s, "\n{n}:");
            }
            texto.clear();
            fmt.format(&ins, &mut texto);
            let ini = (ip - sec.va) as usize;
            let bytes = &sec.datos[ini..ini + ins.len()];
            let hex: String = bytes.iter().take(10).map(|b| format!("{b:02x}")).collect();
            let destino = if ins.is_call_near() || ins.is_jmp_near() || ins.is_jcc_short_or_near() {
                simbolos.get(&ins.near_branch_target()).map(|n| format!("   ; <{n}>")).unwrap_or_default()
            } else if ins.is_ip_rel_memory_operand() {
                simbolos.get(&ins.ip_rel_memory_address()).map(|n| format!("   ; [{n}]")).unwrap_or_default()
            } else {
                String::new()
            };
            let _ = writeln!(s, "  {ip:012x}  {hex:<20} {texto}{destino}");
            total += 1;
        }
    }
    s
}

/// Decodifica UNA instrucción no-x86 en `datos`. Devuelve (texto, longitud).
fn decodificar_yax(isa: Isa, datos: &[u8]) -> (String, usize) {
    use yaxpeax_arch::{Decoder, Reader, U8Reader};
    match isa {
        Isa::A64 => {
            let dec = yaxpeax_arm::armv8::a64::InstDecoder::default();
            let mut r = U8Reader::new(datos);
            match dec.decode(&mut r) {
                Ok(i) => (i.to_string(), 4),
                Err(_) => (format!(".word 0x{:08x}", u32::from_le_bytes(datos[..4.min(datos.len())].try_into().unwrap_or([0; 4]))), 4),
            }
        }
        Isa::Arm | Isa::Thumb => {
            let dec = if isa == Isa::Thumb { yaxpeax_arm::armv7::InstDecoder::default_thumb() } else { yaxpeax_arm::armv7::InstDecoder::default() };
            let mut r = U8Reader::new(datos);
            match dec.decode(&mut r) {
                Ok(i) => {
                    let n = <U8Reader as Reader<u32, u8>>::total_offset(&mut r) as usize;
                    (i.to_string(), n.max(2))
                }
                Err(_) => (format!(".inst ({})", if isa == Isa::Thumb { "thumb" } else { "arm" }), if isa == Isa::Thumb { 2 } else { 4 }),
            }
        }
        Isa::Mips { be } => {
            use yaxpeax_arch02::Decoder as _;
            let mut w = [0u8; 4];
            w.copy_from_slice(&datos[..4]);
            if be {
                w.reverse();
            }
            let dec = yaxpeax_mips::MipsDecoder::default();
            let mut r = yaxpeax_arch02::U8Reader::new(&w);
            match dec.decode(&mut r) {
                Ok(i) => (i.to_string(), 4),
                Err(_) => (format!(".word 0x{:08x}", u32::from_le_bytes(w)), 4),
            }
        }
        Isa::X86(_) => (String::new(), 1),
    }
}

/// Desensamblado integrado para ARM64, ARM, Thumb y MIPS.
fn desensamblar_yax(isa: Isa, secciones: &[Seccion], simbolos: &HashMap<u64, String>, modos: &[(u64, u8)], entrada: u64, max: usize) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "; desensamblado integrado ({isa:?}) — CAPAS");
    let mut total = 0;
    for sec in secciones {
        let _ = writeln!(s, "\n; ===== sección {} @ 0x{:x} ({} bytes) =====", sec.nombre, sec.va, sec.datos.len());
        let mut off = 0usize;
        while off + 2 <= sec.datos.len() {
            if total >= max {
                let _ = writeln!(s, "\n; ... truncado tras {max} instrucciones (usa --max-instrucciones)");
                return s;
            }
            let ip = sec.va + off as u64;
            if ip == entrada {
                let _ = writeln!(s, "\n; ---- PUNTO DE ENTRADA ----");
            }
            if let Some(n) = simbolos.get(&ip).or_else(|| simbolos.get(&(ip | 1))) {
                let _ = writeln!(s, "\n{n}:");
            }
            // ARM: el modo (ARM/Thumb/datos) lo marca el último símbolo de mapeo.
            let mut isa_aqui = isa;
            let mut es_dato = false;
            if matches!(isa, Isa::Arm | Isa::Thumb) && !modos.is_empty() {
                let k = modos.partition_point(|(a, _)| *a <= ip);
                if k > 0 {
                    match modos[k - 1].1 {
                        b't' => isa_aqui = Isa::Thumb,
                        b'a' => isa_aqui = Isa::Arm,
                        _ => es_dato = true,
                    }
                }
            }
            let paso_min = if isa_aqui == Isa::Thumb { 2 } else { 4 };
            let resto = &sec.datos[off..];
            if resto.len() < paso_min {
                break;
            }
            let (mut txt, n) = if es_dato {
                (format!(".word 0x{:08x}", u32::from_le_bytes(resto[..4.min(resto.len())].try_into().unwrap_or([0; 4]))), 4)
            } else {
                decodificar_yax(isa_aqui, resto)
            };
            let n = n.clamp(paso_min, 4).min(resto.len());
            // Destino absoluto de los saltos (ARM64: "$±0x…"; MIPS: desde la palabra).
            if let Some(dest) = destino_salto(isa_aqui, ip, &resto[..n], &txt) {
                let nom = simbolos.get(&dest).map(|x| format!(" <{x}>")).unwrap_or_default();
                txt = format!("{txt}   ; -> 0x{dest:x}{nom}");
            }
            let hex: String = resto[..n].iter().map(|b| format!("{b:02x}")).collect();
            let _ = writeln!(s, "  {ip:012x}  {hex:<10} {txt}");
            off += n;
            total += 1;
        }
    }
    s
}

/// Dirección absoluta de destino de un salto relativo, si se puede calcular.
fn destino_salto(isa: Isa, ip: u64, bytes: &[u8], txt: &str) -> Option<u64> {
    match isa {
        Isa::A64 | Isa::Arm => {
            let i = txt.find("$+0x").map(|i| (i, 1i64)).or_else(|| txt.find("$-0x").map(|i| (i, -1i64)))?;
            let hex: String = txt[i.0 + 4..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            let v = i64::from_str_radix(&hex, 16).ok()?;
            Some((ip as i64 + i.1 * v) as u64)
        }
        Isa::Mips { be } => {
            let mut w = [0u8; 4];
            w.copy_from_slice(bytes.get(..4)?);
            let p = if be { u32::from_be_bytes(w) } else { u32::from_le_bytes(w) };
            let op = p >> 26;
            match op {
                1 | 4..=7 | 20..=23 => Some((ip as i64 + 4 + (((p & 0xffff) as u16 as i16 as i64) << 2)) as u64),
                2 | 3 => Some(((ip + 4) & 0xffff_ffff_f000_0000) | ((p & 0x03ff_ffff) as u64) << 2),
                _ => None,
            }
        }
        _ => None,
    }
}
