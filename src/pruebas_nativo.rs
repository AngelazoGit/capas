//! Pruebas del motor NATIVO con archivos reales (tests/fixtures/): ningún test
//! depende de 7-Zip, unrar, JDK, Python, wabt ni objdump instalados.

use std::io::{Cursor, Write};
use std::path::PathBuf;

use crate::{codigo, decompilar, detectar, ejecutables, nativo};

const SIN_LIMITE: u64 = 1 << 30;

fn ruta(n: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(n)
}

fn fx(n: &str) -> Vec<u8> {
    std::fs::read(ruta(n)).unwrap_or_else(|e| panic!("falta la muestra {n}: {e}"))
}

// ───────────────────────────── contenedores ─────────────────────────────

#[test]
fn siete_z_plano() {
    let a = nativo::siete_z(&fx("plano.7z"), SIN_LIMITE, &[]).unwrap();
    assert!(a.clave.is_none());
    let l = a.hijos.iter().find(|h| h.nombre.ends_with("leeme.txt")).expect("leeme.txt");
    assert_eq!(l.datos, b"hola desde capas\n");
    assert!(a.hijos.iter().any(|h| h.nombre.ends_with("Banco.class")));
}

#[test]
fn siete_z_cifrado_halla_la_clave() {
    let cand = vec!["mala".to_string(), "gamesgx.net".to_string()];
    let a = nativo::siete_z(&fx("cifrado.7z"), SIN_LIMITE, &cand).unwrap();
    assert_eq!(a.clave.as_deref(), Some("gamesgx.net"));
    assert!(a.hijos.iter().any(|h| h.nombre.ends_with("leeme.txt") && h.datos == b"hola desde capas\n"));
}

#[test]
fn siete_z_cifrado_sin_clave_no_se_abre() {
    assert!(nativo::siete_z(&fx("cifrado.7z"), SIN_LIMITE, &[]).is_err());
}

#[test]
fn siete_z_respeta_el_limite_anti_bomba() {
    assert!(nativo::siete_z(&fx("plano.7z"), 8, &[]).is_err());
}

#[test]
fn rar_cifrado_con_clave_candidata() {
    let cand = vec!["x".to_string(), "unrar".to_string()];
    let a = nativo::rar(&ruta("crypted.rar"), SIN_LIMITE, &cand).unwrap();
    assert_eq!(a.clave.as_deref(), Some("unrar"));
    assert!(!a.hijos.is_empty());
}

#[test]
fn rar_solido() {
    let a = nativo::rar(&ruta("solid.rar"), SIN_LIMITE, &[]).unwrap();
    assert!(!a.hijos.is_empty());
}

#[test]
fn cab() {
    let h = nativo::cab(&fx("paquete.cab"), SIN_LIMITE).unwrap();
    assert!(h.iter().any(|x| x.nombre.ends_with("leeme.txt") && x.datos == b"hola desde capas\n"), "{:?}", h.iter().map(|x| &x.nombre).collect::<Vec<_>>());
    assert!(h.iter().any(|x| x.nombre.ends_with("Banco.class")));
}

#[test]
fn ole_msi_con_cab_incrustado_y_nombres_codificados() {
    // Compound File como un MSI: un flujo con nombre codificado (U+3800…) y un CAB dentro.
    let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    // "AB" codificado al estilo MSI: T[10]='A', T[11]='B' → 0x3800 + (10 | 11 << 6)
    let codificado: String = [char::from_u32(0x3800 + (10 | (11 << 6))).unwrap()].iter().collect();
    cf.create_stream(format!("/{codificado}")).unwrap().write_all(b"tabla").unwrap();
    cf.create_stream("/datos.cab").unwrap().write_all(&fx("paquete.cab")).unwrap();
    let bytes = cf.into_inner().into_inner();
    assert_eq!(detectar::detectar(&bytes), detectar::Tipo::Ole);
    let h = nativo::ole(&bytes, SIN_LIMITE).unwrap();
    assert!(h.iter().any(|x| x.nombre == "AB" && x.datos == b"tabla"), "nombres: {:?}", h.iter().map(|x| &x.nombre).collect::<Vec<_>>());
    let cab = h.iter().find(|x| x.nombre == "datos.cab").unwrap();
    assert_eq!(detectar::detectar(&cab.datos), detectar::Tipo::Cab);
}

// ───────────────────────────── código ─────────────────────────────

#[test]
fn wasm_a_wat() {
    let t = codigo::wasm_a_wat(&fx("modulo.wasm")).unwrap();
    assert!(t.contains("i32.add") && t.contains("(export \"suma\""), "{t}");
}

#[test]
fn java_listado_tipo_javap() {
    let t = codigo::clase_java(&fx("Banco.class")).unwrap();
    assert!(t.contains("public boolean ingresar(java.lang.String, int);"), "{t}");
    assert!(t.contains("invokeinterface"));
    assert!(t.contains("\"s3cr3t\""));
}

#[test]
fn java_decompilado_legible() {
    let t = decompilar::java(&fx("Banco.class")).unwrap();
    for esperado in [
        "package com.ejemplo.banco;",
        "public boolean ingresar(String cuenta, int cantidad) {",
        "throw new IllegalArgumentException(\"cantidad no válida: \" + cantidad);",
        "this.operaciones++;",
        "while (i < 10) {",
        "s += i * 3;",
        "datos[i] ^ ",
        "l.removeIf(x -> x.startsWith(\"#\"));",
        "String[] fijos = new String[]{\"a\", \"b\", \"c\"};",
        "? 1 : 2;",
    ] {
        assert!(t.contains(esperado), "falta «{esperado}» en:\n{t}");
    }
    assert!(!t.contains("goto"), "quedan saltos sin estructurar:\n{t}");
}

#[test]
fn pyc_desensamblado_exacto() {
    let t = codigo::pyc(&fx("py312.pyc")).unwrap();
    assert!(t.contains("# Python 3.12"));
    assert!(t.contains("BINARY_OP"));
    assert!(t.contains("CHECK_EXC_MATCH"));
}

#[test]
fn pyc_decompilado_igual_en_38_312_314() {
    let mut cuerpos = Vec::new();
    for f in ["py38.pyc", "py312.pyc", "py314.pyc"] {
        let t = decompilar::python(&fx(f)).unwrap();
        let cuerpo: String = t.lines().skip(3).collect::<Vec<_>>().join("\n");
        for esperado in [
            "return [i ** 2 for i in range(10) if i % 2 == 0]",
            "return a < b <= c",
            "    try:\n        r = x()\n    except (KeyError, IndexError) as e:\n        print(e)\n        r = None\n    return r",
            "    try:\n        x()\n    finally:\n        print(\"fin\")",
            "return ({k: v for k, v in d.items()}, (n for n in d))",
        ] {
            assert!(cuerpo.contains(esperado), "{f}: falta «{esperado}» en:\n{cuerpo}");
        }
        cuerpos.push(cuerpo);
    }
    assert_eq!(cuerpos[0], cuerpos[1]);
    assert_eq!(cuerpos[1], cuerpos[2]);
}

#[test]
fn desensamblado_arm64_arm_mips() {
    for (f, esperado, salto) in [
        ("mini_a64.elf", "cmp w1, #0x0", "-> 0x400144"),
        ("mini_arm.elf", "cmp r1, 0x0", "-> 0x100e8"),
        ("mini_mips.elf", "blez a1, 0xc", "-> 0x400164"),
    ] {
        let i = ejecutables::analizar(&fx(f), 10_000).unwrap();
        let d = i.desensamblado.unwrap_or_default();
        assert!(d.contains("suma:"), "{f}: sin símbolo");
        assert!(d.contains(esperado) && d.contains(salto), "{f}:\n{d}");
    }
}
