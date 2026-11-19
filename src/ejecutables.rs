//! Capa de código nativo: cabeceras, secciones, símbolos, importaciones y
//! desensamblado x86/x86-64 integrado (iced-x86).

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
    let bits: Option<u32>;
    let arquitectura: String;
    let entrada: u64;

    match Object::parse(d)? {
        Object::Elf(e) => {
            arquitectura = elf::header::machine_to_str(e.header.e_machine).to_string();
            bits = match e.header.e_machine {
                elf::header::EM_X86_64 => Some(64),
                elf::header::EM_386 => Some(32),
                _ => None,
            };
            entrada = e.entry;
            writeln!(c, "== ELF ==")?;
            writeln!(c, "{}", tfmt(tr("Architecture : {} ({} bits)","Arquitectura : {} ({} bits)"), &[arquitectura.clone(), (if e.is_64 { 64 } else { 32 }).to_string()]))?;
            writeln!(c, "{}", tfmt(tr("Type         : {}","Tipo         : {}"), &[elf::header::et_to_str(e.header.e_type).to_string()]))?;
            writeln!(c, "{}", tfmt(tr("Entry        : 0x{}","Entrada      : 0x{}"), &[format!("{:x}", e.entry)]))?;
            if let Some(i) = e.interpreter {
                writeln!(c, "{}", tfmt(tr("Interpreter  : {}","Intérprete   : {}"), &[i.to_string()]))?;
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
                if !n.is_empty() && s.st_value != 0 && s.is_function() {
                    simbolos.insert(s.st_value, n.to_string());
                }
            }
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
            bits = match m {
                pe::header::COFF_MACHINE_X86_64 => Some(64),
                pe::header::COFF_MACHINE_X86 => Some(32),
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
            bits = match m.header.cputype {
                mach::cputype::CPU_TYPE_X86_64 => Some(64),
                mach::cputype::CPU_TYPE_X86 => Some(32),
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

    let desensamblado = match bits {
        Some(b) if !ejec.is_empty() => Some(desensamblar(b, &ejec, &simbolos, entrada, max_instr)),
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
