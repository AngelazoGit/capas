//! Decompiladores NATIVOS a pseudo-fuente legible (sin CFR, jadx ni
//! decompyle3): reconstruyen expresiones simulando la pila de la máquina
//! virtual y recuperan `if/else`, `while` y `for` a partir de los saltos.
//!
//! No pretenden recompilar (para eso están CFR/jadx/pycdc si se instalan como
//! motores opcionales): buscan que el código se LEA. Lo que no se puede
//! estructurar se deja como `goto` etiquetado, sin perder nada.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;

use anyhow::{anyhow, Result};

use crate::codigo::{self, params_java, tipo_java, CodigoPy, Py};

// ═════════════════════ Árbol de sentencias + estructurador ═════════════════════

/// Condición negable.
#[derive(Clone, Debug)]
pub struct Cond {
    izq: String,
    op: &'static str, // ==, !=, <, >=, >, <=, "si" (verdadero), "no" (falso), "or", "and"
    der: String,
    partes: Vec<Cond>,
}

impl Cond {
    fn bin(izq: String, op: &'static str, der: String) -> Self {
        Cond { izq, op, der, partes: Vec::new() }
    }
    fn si(e: String) -> Self {
        Cond { izq: e, op: "si", der: String::new(), partes: Vec::new() }
    }
    fn no(e: String) -> Self {
        Cond { izq: e, op: "no", der: String::new(), partes: Vec::new() }
    }
    fn combinar(op: &'static str, a: Cond, b: Cond) -> Cond {
        let mut partes = Vec::new();
        for c in [a, b] {
            if c.op == op {
                partes.extend(c.partes);
            } else {
                partes.push(c);
            }
        }
        Cond { izq: String::new(), op, der: String::new(), partes }
    }
    fn neg(&self) -> Cond {
        if self.op == "or" || self.op == "and" {
            return Cond {
                izq: String::new(),
                op: if self.op == "or" { "and" } else { "or" },
                der: String::new(),
                partes: self.partes.iter().map(|p| p.neg()).collect(),
            };
        }
        let op = match self.op {
            "==" => "!=",
            "!=" => "==",
            "<" => ">=",
            ">=" => "<",
            ">" => "<=",
            "<=" => ">",
            "si" => "no",
            "no" => "si",
            "is" => "is not",
            "is not" => "is",
            "in" => "not in",
            "not in" => "in",
            o => o,
        };
        Cond { izq: self.izq.clone(), op, der: self.der.clone(), partes: Vec::new() }
    }
    fn texto(&self, py: bool) -> String {
        match self.op {
            "or" | "and" => {
                let sep = match (py, self.op) {
                    (true, o) => format!(" {o} "),
                    (false, "or") => " || ".into(),
                    _ => " && ".into(),
                };
                self.partes
                    .iter()
                    .map(|p| {
                        let t = p.texto(py);
                        // una disyunción dentro de una conjunción necesita paréntesis
                        if self.op == "and" && p.op == "or" { format!("({t})") } else { t }
                    })
                    .collect::<Vec<_>>()
                    .join(&sep)
            }
            "si" => self.izq.clone(),
            "no" => {
                if py {
                    if nivel(&self.izq) <= 4 { format!("not ({})", self.izq) } else { format!("not {}", self.izq) }
                } else {
                    format!("!{}", envolver(&self.izq))
                }
            }
            op => op_bin(&self.izq, op, &self.der),
        }
    }
}

#[derive(Clone, Debug)]
enum S {
    Txt(String),
    Etq(usize),
    Si(Cond, usize),
    Ir(usize),
    /// Cabecera de bucle for (Python): destino, iterable, etiqueta de salida.
    Para(String, String, usize),
    Bloque(String, Vec<S>),
    SiSino(String, Vec<S>, Vec<S>),
}

/// Operadores binarios por precedencia (Python y Java), de menor a mayor.
const OPS_PREC: &[(&str, u8)] = &[
    (" if ", 1), (" else ", 1), (" ? ", 1), (" : ", 1),
    (" or ", 2), (" || ", 2),
    (" and ", 3), (" && ", 3),
    (" is not ", 5), (" not in ", 5), (" instanceof ", 5), (" in ", 5), (" is ", 5), (" == ", 5), (" != ", 5),
    (" <= ", 5), (" >= ", 5), (" << ", 9), (" >>> ", 9), (" >> ", 9), (" < ", 5), (" > ", 5),
    (" | ", 6), (" ^ ", 7), (" & ", 8),
    (" + ", 10), (" - ", 10),
    (" ** ", 13), (" // ", 11), (" * ", 11), (" / ", 11), (" % ", 11), (" @ ", 11),
];

fn prec_op(op: &str) -> u8 {
    let k = format!(" {} ", op.trim());
    OPS_PREC.iter().find(|(o, _)| *o == k).map(|x| x.1).unwrap_or(5)
}

/// Precedencia mínima de los operadores a nivel superior de `s`
/// (100 = atómico, 12 = unario/cast, 0 = lambda).
fn nivel(s: &str) -> u8 {
    let t = s.trim();
    if t.starts_with("lambda ") || t.contains(" -> ") && !t.starts_with('(') {
        return 0;
    }
    let b = t.as_bytes();
    let mut prof = 0i32;
    let mut min = 100u8;
    let mut comilla: Option<u8> = None;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if let Some(q) = comilla {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                comilla = None;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' | b'\'' => comilla = Some(c),
            b'(' | b'[' | b'{' => prof += 1,
            b')' | b']' | b'}' => prof -= 1,
            b' ' if prof == 0 => {
                for (o, p) in OPS_PREC {
                    if t[i..].starts_with(o) {
                        min = min.min(*p);
                        break;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    if min < 100 {
        return min;
    }
    if t.starts_with("not ") {
        return 4;
    }
    if t.starts_with('-') || t.starts_with('~') || t.starts_with('+') || t.starts_with('!') || t.starts_with("await ") {
        return 12;
    }
    // cast Java "(T) x"
    if t.starts_with('(') && !parentesis_cerrado(t) {
        return 12;
    }
    100
}

/// Paréntesis solo si hacen falta para usarlo como receptor/operando atómico.
fn envolver(s: &str) -> String {
    if nivel(s) >= 13 { s.to_string() } else { format!("({s})") }
}

/// `a op b` con los paréntesis justos según la precedencia.
fn op_bin(a: &str, op: &str, b: &str) -> String {
    let p = prec_op(op);
    let comparacion = p == 5;
    let potencia = op.trim() == "**";
    let izq = if nivel(a) < p || ((comparacion || potencia) && nivel(a) <= p) { format!("({a})") } else { a.to_string() };
    let der = if nivel(b) < p || (!potencia && nivel(b) <= p) { format!("({b})") } else { b.to_string() };
    format!("{izq} {} {der}", op.trim())
}

fn parentesis_cerrado(s: &str) -> bool {
    let mut n = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '(' => n += 1,
            ')' => {
                n -= 1;
                if n == 0 && i != s.len() - 1 {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

fn referencias(v: &[S], cuenta: &mut HashMap<usize, usize>) {
    for s in v {
        match s {
            S::Si(_, l) | S::Ir(l) | S::Para(_, _, l) => *cuenta.entry(*l).or_default() += 1,
            S::Bloque(_, b) => referencias(b, cuenta),
            S::SiSino(_, a, b) => {
                referencias(a, cuenta);
                referencias(b, cuenta);
            }
            _ => {}
        }
    }
}

fn pos_etq(v: &[S], l: usize, desde: usize) -> Option<usize> {
    (desde..v.len()).find(|&k| matches!(v[k], S::Etq(x) if x == l))
}

fn sin_etiquetas(v: &[S]) -> bool {
    !v.iter().any(|s| matches!(s, S::Etq(_)))
}

/// Dentro del cuerpo de un bucle: saltos a la cabecera → `continue`,
/// saltos a la salida → `break`.
fn saltos_de_bucle(v: Vec<S>, cab: usize, sal: usize, py: bool) -> Vec<S> {
    let fin = if py { "" } else { ";" };
    v.into_iter()
        .map(|s| match s {
            S::Ir(l) if l == cab => S::Txt(format!("continue{fin}")),
            S::Ir(l) if l == sal => S::Txt(format!("break{fin}")),
            S::Si(c, l) if l == cab || l == sal => {
                let k = if l == cab { "continue" } else { "break" };
                let cabecera = if py { format!("if {}", c.texto(true)) } else { format!("if ({})", c.texto(false)) };
                S::Bloque(cabecera, vec![S::Txt(format!("{k}{fin}"))])
            }
            S::Bloque(c, b) => S::Bloque(c, saltos_de_bucle(b, cab, sal, py)),
            S::SiSino(c, a, b) => S::SiSino(c, saltos_de_bucle(a, cab, sal, py), saltos_de_bucle(b, cab, sal, py)),
            otro => otro,
        })
        .collect()
}

fn cuenta_en(v: &[S], l: usize) -> usize {
    let mut c = HashMap::new();
    referencias(v, &mut c);
    c.get(&l).copied().unwrap_or(0)
}

/// Convierte saltos en bloques if / if-else / while / for, repitiendo hasta
/// que no queda patrón aplicable. `py` elige la sintaxis.
fn estructurar(mut v: Vec<S>, fijas: &BTreeSet<usize>, py: bool) -> Vec<S> {
    loop {
        let mut cuenta = HashMap::new();
        referencias(&v, &mut cuenta);
        let rc = |l: usize| cuenta.get(&l).copied().unwrap_or(0) + if fijas.contains(&l) { 1 } else { 0 };
        let mut cambio = false;
        // Fase 1: condiciones compuestas (and/or), de izquierda a derecha.
        let mut i = 0;
        while i < v.len() {
            if let (S::Si(c1, l1), Some(S::Si(c2, l2))) = (v[i].clone(), v.get(i + 1).cloned()) {
                // if a and b: dos saltos seguidos al mismo destino → uno con "or"
                if l1 == l2 {
                    v[i] = S::Si(Cond::combinar("or", c1, c2), l1);
                    v.remove(i + 1);
                    cambio = true;
                    break;
                }
                // if a or b: Si(a, Lcuerpo) Si(!b, Lfin) Etq(Lcuerpo) → Si(!a and !b, Lfin)
                if matches!(v.get(i + 2), Some(S::Etq(x)) if *x == l1) && rc(l1) == 1 && l1 != l2 {
                    v[i] = S::Si(Cond::combinar("and", c1.neg(), c2), l2);
                    v.remove(i + 1);
                    v.remove(i + 1);
                    cambio = true;
                    break;
                }
            }
            i += 1;
        }
        if cambio {
            continue;
        }
        // Fase 2: estructuras, de dentro hacia fuera (de derecha a izquierda).
        let mut i = v.len();
        while i > 0 {
            i -= 1;
            // for (Python): Etq(L1) Para(t, it, L2) cuerpo Ir(L1) Etq(L2)
            if let S::Para(t, it, l2) = v[i].clone() {
                if i > 0 {
                    if let S::Etq(l1) = v[i - 1] {
                        if let Some(j) = pos_etq(&v, l2, i + 1) {
                            if j >= 1 && matches!(v[j - 1], S::Ir(x) if x == l1) && sin_etiquetas(&v[i + 1..j - 1]) && rc(l1) == 1 + cuenta_en(&v[i + 1..j - 1], l1) {
                                let cuerpo = estructurar(saltos_de_bucle(v[i + 1..j - 1].to_vec(), l1, l2, py), fijas, py);
                                let cab = format!("for {t} in {it}");
                                v.splice(i - 1..j, [S::Bloque(cab, cuerpo)]);
                                cambio = true;
                                break;
                            }
                        }
                    }
                }
            }
            // while: Etq(L1) Si(c, L2) cuerpo Ir(L1) Etq(L2)
            if let (S::Etq(l1), Some(S::Si(c, l2))) = (v[i].clone(), v.get(i + 1).cloned()) {
                if let Some(j) = pos_etq(&v, l2, i + 2) {
                    if j >= 1 && matches!(v[j - 1], S::Ir(x) if x == l1) && sin_etiquetas(&v[i + 2..j - 1]) && rc(l1) == 1 + cuenta_en(&v[i + 2..j - 1], l1) {
                        let cuerpo = estructurar(saltos_de_bucle(v[i + 2..j - 1].to_vec(), l1, l2, py), fijas, py);
                        let cab = format!("while {}", if py { c.neg().texto(true) } else { format!("({})", c.neg().texto(false)) });
                        v.splice(i..j, [S::Bloque(cab, cuerpo)]);
                        cambio = true;
                        break;
                    }
                }
            }
            // while invertido 3.12+: Si(!c, Lfin) Etq(Lb) cuerpo Si(!c, Lsal) Ir(Lb) Etq(Lsal) …
            if let (S::Si(c0, lfin), Some(S::Etq(lb))) = (v[i].clone(), v.get(i + 1).cloned()) {
                if let Some(j) = (i + 2..v.len()).find(|&k| matches!(&v[k], S::Ir(x) if *x == lb)) {
                    if let (Some(S::Si(c, lsal)), Some(S::Etq(e))) = (v.get(j - 1).cloned(), v.get(j + 1).cloned()) {
                        let cuerpo_ok = j >= i + 3 && sin_etiquetas(&v[i + 2..j - 1]);
                        let misma_cond = c.texto(py) == c0.texto(py);
                        // la salida del bucle y la del guardián coinciden (o solo difieren en un "return None" duplicado)
                        let salidas_ok = lsal == e && (lsal == lfin || {
                            let pf = pos_etq(&v, lfin, j + 1);
                            pf.map(|pf| v[j + 2..pf].iter().all(|x| matches!(x, S::Txt(t) if t == "return None")) && pf + 1 == v.len()).unwrap_or(false)
                        });
                        if cuerpo_ok && misma_cond && salidas_ok && rc(lb) == 1 + cuenta_en(&v[i + 2..j - 1], lb) {
                            let cuerpo = estructurar(saltos_de_bucle(v[i + 2..j - 1].to_vec(), lb, lsal, py), fijas, py);
                            let cab = if py { format!("while {}", c.neg().texto(true)) } else { format!("while ({})", c.neg().texto(false)) };
                            v.splice(i..=j, [S::Bloque(cab, cuerpo)]);
                            cambio = true;
                            break;
                        }
                    }
                }
            }
            // while invertido: Si(!c, Lfin) Etq(Lb) cuerpo Si(c, Lb) [Etq(Lfin)]
            if let (S::Si(c0, lfin), Some(S::Etq(lb))) = (v[i].clone(), v.get(i + 1).cloned()) {
                if let Some(j) = (i + 2..v.len()).find(|&k| matches!(&v[k], S::Si(_, x) if *x == lb)) {
                    if let S::Si(c, _) = v[j].clone() {
                        let rc_dentro = cuenta_en(&v[i + 2..j], lb);
                        if c.neg().texto(py) == c0.texto(py) && sin_etiquetas(&v[i + 2..j]) && rc(lb) == 1 + rc_dentro {
                            let cuerpo = estructurar(saltos_de_bucle(v[i + 2..j].to_vec(), lb, lfin, py), fijas, py);
                            let cab = if py { format!("while {}", c.texto(true)) } else { format!("while ({})", c.texto(false)) };
                            v.splice(i..=j, [S::Bloque(cab, cuerpo)]);
                            cambio = true;
                            break;
                        }
                    }
                }
            }
            // do-while: Etq(Lb) cuerpo Si(c, Lb)   (si hay guardián antes, lo resuelve el while invertido)
            let guardian = match (i > 0).then(|| v[i - 1].clone()) {
                Some(S::Si(c0, _)) => match v[i] {
                    S::Etq(lb) => (i + 1..v.len()).any(|k| match &v[k] {
                        S::Si(c, x) if *x == lb => c.neg().texto(py) == c0.texto(py),
                        S::Ir(x) if *x == lb => matches!(&v[k - 1], S::Si(c, _) if c.texto(py) == c0.texto(py)),
                        _ => false,
                    }),
                    _ => false,
                },
                _ => false,
            };
            if let (S::Etq(lb), false, false) = (v[i].clone(), matches!(v.get(i + 1), Some(S::Para(..))), guardian) {
                if let Some(j) = (i + 1..v.len()).find(|&k| matches!(&v[k], S::Si(_, x) if *x == lb)) {
                    if let S::Si(c, _) = v[j].clone() {
                        if sin_etiquetas(&v[i + 1..j]) && j > i + 1 && rc(lb) == 1 + cuenta_en(&v[i + 1..j], lb) {
                            let mut cuerpo = estructurar(saltos_de_bucle(v[i + 1..j].to_vec(), lb, usize::MAX, py), fijas, py);
                            let salir = if py { format!("if {}", c.neg().texto(true)) } else { format!("if ({})", c.neg().texto(false)) };
                            cuerpo.push(S::Bloque(salir, vec![S::Txt(if py { "break".into() } else { "break;".into() })]));
                            let cab = if py { "while True".to_string() } else { "while (true)".to_string() };
                            v.splice(i..=j, [S::Bloque(cab, cuerpo)]);
                            cambio = true;
                            break;
                        }
                    }
                }
            }
            // bucle infinito: Etq(L1) cuerpo Ir(L1)   (si no es la cabecera de un for)
            if let (S::Etq(l1), false, false) = (v[i].clone(), matches!(v.get(i + 1), Some(S::Para(..))), guardian) {
                if let Some(j) = (i + 1..v.len()).find(|&k| matches!(v[k], S::Ir(x) if x == l1)) {
                    if rc(l1) == 1 + cuenta_en(&v[i + 1..j], l1) {
                        if sin_etiquetas(&v[i + 1..j]) && j > i + 1 {
                            let salida = match v.get(j + 1) {
                                Some(S::Etq(x)) => *x,
                                _ => usize::MAX,
                            };
                            let cuerpo = estructurar(saltos_de_bucle(v[i + 1..j].to_vec(), l1, salida, py), fijas, py);
                            let cab = if py { "while True".to_string() } else { "while (true)".to_string() };
                            v.splice(i..=j, [S::Bloque(cab, cuerpo)]);
                            cambio = true;
                            break;
                        }
                    }
                }
            }
            // if / if-else  (salvo que sea la cabecera de un while: Etq(L1) Si … Ir(L1) Etq(L))
            if let S::Si(c, l) = v[i].clone() {
                let cabeza_while = |j: usize| i > 0 && matches!((&v[i - 1], &v[j - 1]), (S::Etq(a), S::Ir(b)) if a == b);
                if let Some(j) = pos_etq(&v, l, i + 1).filter(|&j| j > i + 1 && !cabeza_while(j)).or_else(|| pos_etq(&v, l, i + 1).filter(|&j| j == i + 1)) {
                    if sin_etiquetas(&v[i + 1..j]) {
                        // if-else: … Ir(L2) Etq(L) B Etq(L2)
                        if j > i + 1 && rc(l) == 1 {
                            if let S::Ir(l2) = v[j - 1] {
                                if let Some(k) = pos_etq(&v, l2, j + 1) {
                                    if sin_etiquetas(&v[j + 1..k]) && k > j + 1 {
                                        let a = estructurar(v[i + 1..j - 1].to_vec(), fijas, py);
                                        let b = estructurar(v[j + 1..k].to_vec(), fijas, py);
                                        let cab = if py { format!("if {}", c.neg().texto(true)) } else { format!("if ({})", c.neg().texto(false)) };
                                        v.splice(i..k, [S::SiSino(cab, a, b)]);
                                        if rc(l2) <= 1 {
                                            v.remove(i + 1);
                                        }
                                        cambio = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if j > i + 1 {
                            let a = estructurar(v[i + 1..j].to_vec(), fijas, py);
                            let cab = if py { format!("if {}", c.neg().texto(true)) } else { format!("if ({})", c.neg().texto(false)) };
                            v.splice(i..j, [S::Bloque(cab, a)]);
                            if rc(l) <= 1 {
                                v.remove(i + 1);
                            }
                            cambio = true;
                            break;
                        }
                    }
                }
            }
            // if sin cuerpo: Si(c, L) Etq(L)
            if let (S::Si(c, l), Some(S::Etq(l2))) = (v[i].clone(), v.get(i + 1).cloned()) {
                if l == l2 {
                    let cab = if py { format!("if {}", c.neg().texto(true)) } else { format!("if ({})", c.neg().texto(false)) };
                    v[i] = S::Bloque(cab, Vec::new());
                    cambio = true;
                    break;
                }
            }
            // goto al siguiente: sobra
            if let S::Ir(l) = v[i] {
                if matches!(v.get(i + 1), Some(S::Etq(x)) if *x == l) {
                    v.remove(i);
                    cambio = true;
                    break;
                }
            }
        }
        // etiquetas que ya nadie usa
        let mut cuenta = HashMap::new();
        referencias(&v, &mut cuenta);
        let antes = v.len();
        v.retain(|s| !matches!(s, S::Etq(l) if cuenta.get(l).copied().unwrap_or(0) == 0 && !fijas.contains(l)));
        if v.len() != antes {
            cambio = true;
        }
        if !cambio {
            return v;
        }
    }
}

fn pintar(v: &[S], nivel: usize, py: bool, s: &mut String) {
    let pre = "    ".repeat(nivel);
    let goto = |l: usize| if py { format!("goto L{l}  # salto sin estructurar") } else { format!("goto L{l};") };
    if py && v.is_empty() {
        let _ = writeln!(s, "{pre}pass");
    }
    for x in v {
        match x {
            S::Txt(t) => {
                for l in t.lines() {
                    let _ = writeln!(s, "{pre}{l}");
                }
            }
            S::Etq(l) => {
                let _ = writeln!(s, "{}L{l}:", "    ".repeat(nivel.saturating_sub(1)));
            }
            S::Si(c, l) => {
                if py {
                    let _ = writeln!(s, "{pre}if {}: {}", c.texto(true), goto(*l));
                } else {
                    let _ = writeln!(s, "{pre}if ({}) {}", c.texto(false), goto(*l));
                }
            }
            S::Ir(l) => {
                let _ = writeln!(s, "{pre}{}", goto(*l));
            }
            S::Para(t, it, l) => {
                let _ = writeln!(s, "{pre}for {t} in {it}:  # fin en L{l}");
            }
            S::Bloque(c, b) => {
                if py {
                    let _ = writeln!(s, "{pre}{c}:");
                    pintar(b, nivel + 1, py, s);
                } else {
                    let _ = writeln!(s, "{pre}{c} {{");
                    pintar(b, nivel + 1, py, s);
                    let _ = writeln!(s, "{pre}}}");
                }
            }
            S::SiSino(c, a, b) => {
                if py {
                    let _ = writeln!(s, "{pre}{c}:");
                    pintar(a, nivel + 1, py, s);
                    // else: if → elif
                    if b.len() == 1 {
                        if let S::Bloque(c2, b2) | S::SiSino(c2, b2, _) = &b[0] {
                            if c2.starts_with("if ") {
                                let _ = writeln!(s, "{pre}el{c2}:");
                                pintar(b2, nivel + 1, py, s);
                                if let S::SiSino(_, _, b3) = &b[0] {
                                    let _ = writeln!(s, "{pre}else:");
                                    pintar(b3, nivel + 1, py, s);
                                }
                                continue;
                            }
                        }
                    }
                    let _ = writeln!(s, "{pre}else:");
                    pintar(b, nivel + 1, py, s);
                } else {
                    let _ = writeln!(s, "{pre}{c} {{");
                    pintar(a, nivel + 1, py, s);
                    let _ = writeln!(s, "{pre}}} else {{");
                    pintar(b, nivel + 1, py, s);
                    let _ = writeln!(s, "{pre}}}");
                }
            }
        }
    }
}

// ═══════════════════════════════════ JAVA ═══════════════════════════════════

#[derive(Clone, Debug)]
enum VJ {
    /// expresión, ¿es booleana?, ¿tiene efectos (llamada)?
    E(String, bool, bool),
    Nuevo(String),
    Arr(String, String, Vec<String>),
    Cmp(String, String),
}

fn corto(c: &str) -> String {
    let c = c.replace('/', ".");
    c.rsplit('.').next().unwrap_or(&c).replace('$', ".")
}

fn tipo_corto(desc: &str) -> String {
    let t = tipo_java(desc);
    let dims = t.matches("[]").count();
    let base = t.trim_end_matches("[]");
    format!("{}{}", if base.contains('.') { corto(base) } else { base.to_string() }, "[]".repeat(dims))
}

struct Java<'a> {
    lambdas: &'a HashMap<String, String>,
    pila: Vec<usize>,
    arena: Vec<VJ>,
    clase: String,
    estatico: bool,
    es_ctor: bool,
    nombres: HashMap<u16, Vec<(u16, u16, String, String)>>, // slot -> [(ini, fin, nombre, tipo)]
    params: HashMap<u16, (String, String)>,
    declaradas: BTreeSet<String>,
    bootstrap: &'a [cafebabe::attributes::BootstrapMethodEntry<'a>],
    imports: &'a mut BTreeSet<String>,
}

impl<'a> Java<'a> {
    fn push(&mut self, v: VJ) {
        self.arena.push(v);
        self.pila.push(self.arena.len() - 1);
    }
    fn pop_id(&mut self) -> usize {
        self.pila.pop().unwrap_or_else(|| {
            self.arena.push(VJ::E("<?>".into(), false, false));
            self.arena.len() - 1
        })
    }
    fn txt(&self, id: usize) -> String {
        match &self.arena[id] {
            VJ::E(s, _, _) => s.clone(),
            VJ::Nuevo(c) => format!("new {}", corto(c)),
            VJ::Arr(t, n, el) => {
                if !el.is_empty() {
                    format!("new {t}[]{{{}}}", el.join(", "))
                } else {
                    format!("new {t}[{n}]")
                }
            }
            VJ::Cmp(a, b) => format!("compare({a}, {b})"),
        }
    }
    fn pop(&mut self) -> String {
        let id = self.pop_id();
        self.txt(id)
    }
    fn pop_op(&mut self) -> String {
        envolver(&self.pop())
    }
    fn clase_ref(&mut self, c: &str) -> String {
        let full = c.replace('/', ".");
        if let Some((paq, _)) = full.rsplit_once('.') {
            let propio = self.clase.replace('/', ".");
            let propio_paq = propio.rsplit_once('.').map(|x| x.0).unwrap_or("");
            if paq != "java.lang" && paq != propio_paq {
                self.imports.insert(full.split('$').next().unwrap_or(&full).to_string());
            }
        }
        corto(c)
    }
    fn local(&self, slot: u16, pc: usize) -> (String, Option<String>) {
        if let Some(v) = self.nombres.get(&slot) {
            for (ini, fin, n, t) in v {
                if pc as u32 + 4 >= *ini as u32 && (pc as u32) < *ini as u32 + *fin as u32 + 4 {
                    return (n.clone(), Some(t.clone()));
                }
            }
            if let Some((_, _, n, t)) = v.first() {
                return (n.clone(), Some(t.clone()));
            }
        }
        if !self.estatico && slot == 0 {
            return ("this".into(), None);
        }
        if let Some((n, t)) = self.params.get(&slot) {
            return (n.clone(), Some(t.clone()));
        }
        (format!("v{slot}"), None)
    }
}

const OPS_JVM: &[(&str, &str)] = &[
    ("add", "+"), ("sub", "-"), ("mul", "*"), ("div", "/"), ("rem", "%"), ("shl", "<<"), ("shr", ">>"),
    ("ushr", ">>>"), ("and", "&"), ("or", "|"), ("xor", "^"),
];

/// `x = x + 1;` → `x++;`  ·  `x = x op y;` → `x op= y;`
fn compactar_asignacion(t: &str) -> Option<String> {
    let t2 = t.strip_suffix(';')?;
    let (izq, der) = t2.split_once(" = ")?;
    if izq.contains(' ') && !izq.starts_with("this.") {
        return None;
    }
    for op in [" + ", " - ", " * ", " / ", " % ", " & ", " | ", " ^ ", " << ", " >> ", " >>> "] {
        if let Some(resto) = der.strip_prefix(izq).and_then(|r| r.strip_prefix(op)) {
            let resto = resto.trim();
            let resto = if resto.starts_with('(') && resto.ends_with(')') && parentesis_cerrado(resto) { &resto[1..resto.len() - 1] } else { resto };
            let o = op.trim();
            if resto == "1" && (o == "+" || o == "-") {
                return Some(format!("{izq}{o}{o};"));
            }
            return Some(format!("{izq} {o}= {resto};"));
        }
    }
    None
}

/// Retoques de legibilidad sobre el árbol: asignaciones compuestas y
/// `if (c) { t = a; } else { t = b; }` → `t = c ? a : b;` (con t temporal).
fn pulir_java(v: Vec<S>) -> Vec<S> {
    let mut out: Vec<S> = Vec::new();
    for s in v {
        match s {
            S::Txt(t) => out.push(S::Txt(compactar_asignacion(&t).unwrap_or(t))),
            S::Bloque(c, b) => out.push(S::Bloque(c, pulir_java(b))),
            S::SiSino(c, a, b) => {
                let a = pulir_java(a);
                let b = pulir_java(b);
                if let ([S::Txt(x)], [S::Txt(y)]) = (a.as_slice(), b.as_slice()) {
                    if let (Some((n1, v1)), Some((n2, v2))) = (x.strip_suffix(';').and_then(|x| x.split_once(" = ")), y.strip_suffix(';').and_then(|y| y.split_once(" = "))) {
                        if n1 == n2 && n1.starts_with("$t") {
                            let cond = c.trim_start_matches("if (").trim_end_matches(')');
                            out.push(S::Txt(format!("{n1} = {} ? {v1} : {v2};", envolver(cond))));
                            continue;
                        }
                    }
                }
                out.push(S::SiSino(c, a, b));
            }
            otro => out.push(otro),
        }
    }
    // inlinea temporales de un solo uso: "$tN = X;" seguido de una sentencia que usa $tN
    let mut i = 0;
    while i + 1 < out.len() {
        if let (S::Txt(a), S::Txt(b)) = (&out[i], &out[i + 1]) {
            if let Some((n, v)) = a.strip_suffix(';').and_then(|a| a.split_once(" = ")) {
                if n.starts_with("$t") && b.matches(n).count() == 1 {
                    let nuevo = b.replace(n, v);
                    out[i + 1] = S::Txt(nuevo);
                    out.remove(i);
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// Decompila un método a pseudo-Java.
fn metodo_java(
    clase: &cafebabe::ClassFile,
    m: &cafebabe::MethodInfo,
    bootstrap: &[cafebabe::attributes::BootstrapMethodEntry],
    imports: &mut BTreeSet<String>,
    lambdas: &HashMap<String, String>,
) -> String {
    use cafebabe::attributes::AttributeData;
    use cafebabe::bytecode::Opcode as O;

    let desc = m.descriptor.to_string();
    let (ps, ret) = params_java(&desc);
    let estatico = m.access_flags.bits() & 0x0008 != 0;
    let nombre_clase = clase.this_class.to_string();
    let mut out = String::new();

    let Some(code) = m.attributes.iter().find_map(|a| if let AttributeData::Code(c) = &a.data { Some(c) } else { None }) else {
        return out;
    };
    let Some(bc) = &code.bytecode else {
        return "    // (bytecode no decodificable)\n".into();
    };

    // Nombres de variables: LocalVariableTable si existe; si no, parámetros p1..pn.
    let mut nombres: HashMap<u16, Vec<(u16, u16, String, String)>> = HashMap::new();
    for a in &code.attributes {
        if let AttributeData::LocalVariableTable(t) = &a.data {
            for e in t {
                nombres.entry(e.index).or_default().push((e.start_pc, e.length, e.name.to_string(), tipo_corto(&e.descriptor.to_string())));
            }
        }
    }
    let mut params = HashMap::new();
    let mut slot: u16 = if estatico { 0 } else { 1 };
    let pdesc = desc[1..desc.find(')').unwrap_or(1)].to_string();
    let mut tipos_p = Vec::new();
    {
        let b = pdesc.as_bytes();
        let mut i = 0;
        while i < b.len() {
            let st = i;
            while b[i] == b'[' {
                i += 1;
            }
            if b[i] == b'L' {
                while b[i] != b';' {
                    i += 1;
                }
            }
            i += 1;
            tipos_p.push(pdesc[st..i].to_string());
        }
    }
    let mut firma_p = Vec::new();
    for (k, t) in tipos_p.iter().enumerate() {
        let n = nombres.get(&slot).and_then(|v| v.first()).map(|x| x.2.clone()).unwrap_or_else(|| format!("p{}", k + 1));
        params.insert(slot, (n.clone(), tipo_corto(t)));
        firma_p.push(format!("{} {n}", tipo_corto(t)));
        slot += if t == "J" || t == "D" { 2 } else { 1 };
    }
    let _ = ps;

    let mut j = Java {
        lambdas,
        pila: Vec::new(),
        arena: Vec::new(),
        clase: nombre_clase.clone(),
        estatico,
        es_ctor: m.name == "<init>",
        nombres,
        params,
        declaradas: BTreeSet::new(),
        bootstrap,
        imports,
    };

    // Etiquetas: destinos de saltos, switch y manejadores de excepción.
    let mut etiquetas: BTreeSet<usize> = BTreeSet::new();
    let mut fijas: BTreeSet<usize> = BTreeSet::new();
    for (off, op) in &bc.opcodes {
        let off = *off as i64;
        match op {
            O::Goto(x) | O::Jsr(x) | O::IfAcmpeq(x) | O::IfAcmpne(x) | O::IfIcmpeq(x) | O::IfIcmpge(x) | O::IfIcmpgt(x)
            | O::IfIcmple(x) | O::IfIcmplt(x) | O::IfIcmpne(x) | O::Ifeq(x) | O::Ifge(x) | O::Ifgt(x) | O::Ifle(x)
            | O::Iflt(x) | O::Ifne(x) | O::Ifnonnull(x) | O::Ifnull(x) => {
                etiquetas.insert((off + *x as i64) as usize);
            }
            O::Tableswitch(t) => {
                for x in t.jumps.iter().chain([&t.default]) {
                    etiquetas.insert((off + *x as i64) as usize);
                    fijas.insert((off + *x as i64) as usize);
                }
            }
            O::Lookupswitch(t) => {
                for x in t.match_offsets.iter().map(|p| &p.1).chain([&t.default]) {
                    etiquetas.insert((off + *x as i64) as usize);
                    fijas.insert((off + *x as i64) as usize);
                }
            }
            _ => {}
        }
    }
    let mut manejadores: HashMap<usize, String> = HashMap::new();
    let mut inicios_try: HashMap<usize, Vec<String>> = HashMap::new();
    let mut lineas: Vec<S> = Vec::new();
    for e in &code.exception_table {
        let h = e.handler_pc as usize;
        etiquetas.insert(h);
        fijas.insert(h);
        manejadores.insert(h, e.catch_type.as_deref().map(corto).unwrap_or_else(|| "Throwable".into()));
        inicios_try.entry(e.start_pc as usize).or_default().push(format!("// try {{   (hasta L{}; catch {} → L{h})", e.end_pc, e.catch_type.as_deref().map(corto).unwrap_or_else(|| "any".into())));
    }
    let mut pila_en: HashMap<usize, Vec<String>> = HashMap::new();
    let mut tmp = 0usize;
    let ultimo = bc.opcodes.last().map(|x| x.0).unwrap_or(0);

    let mut st = |l: &mut Vec<S>, t: String| l.push(S::Txt(t));
    for (idx, (off, op)) in bc.opcodes.iter().enumerate() {
        let off = *off;
        if etiquetas.contains(&off) {
            // fusiona la pila que llega por salto
            if !j.pila.is_empty() && pila_en.contains_key(&off) {
                let previos = pila_en[&off].clone();
                for (id, n) in j.pila.clone().into_iter().zip(previos) {
                    let v = j.txt(id);
                    lineas.push(S::Txt(format!("{n} = {v};")));
                }
            } else if !j.pila.is_empty() && !pila_en.contains_key(&off) {
                let mut nombres_tmp = Vec::new();
                for id in j.pila.clone() {
                    tmp += 1;
                    let n = format!("$t{tmp}");
                    let v = j.txt(id);
                    lineas.push(S::Txt(format!("{n} = {v};")));
                    nombres_tmp.push(n);
                }
                pila_en.insert(off, nombres_tmp);
            }
            j.pila.clear();
            lineas.push(S::Etq(off));
            if let Some(ns) = pila_en.get(&off).cloned() {
                for n in ns {
                    j.push(VJ::E(n, false, false));
                }
            }
            if let Some(t) = manejadores.get(&off).cloned() {
                j.push(VJ::E(format!("/*{t}*/ $ex"), false, false));
            }
        }
        if let Some(v) = inicios_try.remove(&off) {
            for t in v {
                lineas.push(S::Txt(t));
            }
        }
        let salto = |x: i32| (off as i64 + x as i64) as usize;
        let dbg = format!("{op:?}");
        let var = dbg.split(|c: char| c == '(' || c == ' ').next().unwrap_or("").to_string();
        let vl = var.to_lowercase();
        match op {
            O::Nop => {}
            O::AconstNull => j.push(VJ::E("null".into(), false, false)),
            O::IconstM1 => j.push(VJ::E("-1".into(), false, false)),
            O::Iconst0 | O::Lconst0 => j.push(VJ::E("0".into(), false, false)),
            O::Iconst1 | O::Lconst1 => j.push(VJ::E("1".into(), false, false)),
            O::Iconst2 => j.push(VJ::E("2".into(), false, false)),
            O::Iconst3 => j.push(VJ::E("3".into(), false, false)),
            O::Iconst4 => j.push(VJ::E("4".into(), false, false)),
            O::Iconst5 => j.push(VJ::E("5".into(), false, false)),
            O::Fconst0 | O::Dconst0 => j.push(VJ::E("0.0".into(), false, false)),
            O::Fconst1 | O::Dconst1 => j.push(VJ::E("1.0".into(), false, false)),
            O::Fconst2 => j.push(VJ::E("2.0".into(), false, false)),
            O::Bipush(n) => j.push(VJ::E(n.to_string(), false, false)),
            O::Sipush(n) => j.push(VJ::E(n.to_string(), false, false)),
            O::Ldc(l) | O::LdcW(l) | O::Ldc2W(l) => {
                use cafebabe::constant_pool::{LiteralConstant as Lc, Loadable};
                let t = match l {
                    Loadable::LiteralConstant(Lc::String(s)) => format!("{s:?}"),
                    Loadable::LiteralConstant(Lc::Integer(i)) => i.to_string(),
                    Loadable::LiteralConstant(Lc::Long(i)) => format!("{i}L"),
                    Loadable::LiteralConstant(Lc::Float(f)) => format!("{f}f"),
                    Loadable::LiteralConstant(Lc::Double(f)) => format!("{f}"),
                    Loadable::ClassInfo(c) => format!("{}.class", j.clase_ref(c)),
                    otro => format!("/*{otro:?}*/"),
                };
                j.push(VJ::E(t, false, false));
            }
            O::Iload(n) | O::Lload(n) | O::Fload(n) | O::Dload(n) | O::Aload(n) => {
                let (nm, t) = j.local(*n, off);
                let b = t.as_deref() == Some("boolean");
                j.push(VJ::E(nm, b, false));
            }
            O::Istore(n) | O::Lstore(n) | O::Fstore(n) | O::Dstore(n) | O::Astore(n) => {
                let v = j.pop();
                let (nm, t) = j.local(*n, off + 2);
                let decl = if !j.declaradas.contains(&nm) && !j.params.values().any(|p| p.0 == nm) && nm != "this" {
                    j.declaradas.insert(nm.clone());
                    format!("{} ", t.unwrap_or_else(|| "var".into()))
                } else {
                    String::new()
                };
                if v.starts_with("/*") && v.ends_with("$ex") {
                    // variable del catch
                    let t = v.trim_start_matches("/*").split("*/").next().unwrap_or("Throwable").to_string();
                    st(&mut lineas, format!("// }} catch ({t} {nm}) {{"));
                } else {
                    st(&mut lineas, format!("{decl}{nm} = {v};"));
                }
            }
            O::Iinc(n, c) => {
                let (nm, _) = j.local(*n, off);
                let t = match c {
                    1 => format!("{nm}++;"),
                    -1 => format!("{nm}--;"),
                    c if *c < 0 => format!("{nm} -= {};", -c),
                    c => format!("{nm} += {c};"),
                };
                st(&mut lineas, t);
            }
            _ if OPS_JVM.iter().any(|(k, _)| vl.len() == k.len() + 1 && &vl[1..] == *k && "ilfd".contains(&vl[..1])) => {
                let o = OPS_JVM.iter().find(|(k, _)| &vl[1..] == *k).unwrap().1;
                let b = j.pop();
                let a = j.pop();
                j.push(VJ::E(op_bin(&a, o, &b), false, false));
            }
            O::Ineg | O::Lneg | O::Fneg | O::Dneg => {
                let a = j.pop_op();
                j.push(VJ::E(format!("-{a}"), false, false));
            }
            O::I2l | O::F2l | O::D2l => {
                let a = j.pop_op();
                j.push(VJ::E(format!("(long) {a}"), false, false));
            }
            O::I2f | O::L2f | O::D2f => {
                let a = j.pop_op();
                j.push(VJ::E(format!("(float) {a}"), false, false));
            }
            O::I2d | O::L2d | O::F2d => {
                let a = j.pop_op();
                j.push(VJ::E(format!("(double) {a}"), false, false));
            }
            O::L2i | O::F2i | O::D2i => {
                let a = j.pop_op();
                j.push(VJ::E(format!("(int) {a}"), false, false));
            }
            O::I2b => {
                let a = j.pop_op();
                j.push(VJ::E(format!("(byte) {a}"), false, false));
            }
            O::I2c => {
                let a = j.pop_op();
                j.push(VJ::E(format!("(char) {a}"), false, false));
            }
            O::I2s => {
                let a = j.pop_op();
                j.push(VJ::E(format!("(short) {a}"), false, false));
            }
            O::Lcmp | O::Fcmpl | O::Fcmpg | O::Dcmpl | O::Dcmpg => {
                let b = j.pop();
                let a = j.pop();
                j.push(VJ::Cmp(a, b));
            }
            O::Ifeq(x) | O::Ifne(x) | O::Iflt(x) | O::Ifge(x) | O::Ifgt(x) | O::Ifle(x) => {
                let op_c = match op {
                    O::Ifeq(_) => "==",
                    O::Ifne(_) => "!=",
                    O::Iflt(_) => "<",
                    O::Ifge(_) => ">=",
                    O::Ifgt(_) => ">",
                    _ => "<=",
                };
                let id = j.pop_id();
                let c = match j.arena[id].clone() {
                    VJ::Cmp(a, b) => Cond::bin(a, op_c, b),
                    VJ::E(e, true, _) if op_c == "==" => Cond::no(e),
                    VJ::E(e, true, _) if op_c == "!=" => Cond::si(e),
                    _ => Cond::bin(j.txt(id), op_c, "0".into()),
                };
                lineas.push(S::Si(c, salto(*x)));
            }
            O::IfIcmpeq(x) | O::IfIcmpne(x) | O::IfIcmplt(x) | O::IfIcmpge(x) | O::IfIcmpgt(x) | O::IfIcmple(x)
            | O::IfAcmpeq(x) | O::IfAcmpne(x) => {
                let op_c = match op {
                    O::IfIcmpeq(_) | O::IfAcmpeq(_) => "==",
                    O::IfIcmpne(_) | O::IfAcmpne(_) => "!=",
                    O::IfIcmplt(_) => "<",
                    O::IfIcmpge(_) => ">=",
                    O::IfIcmpgt(_) => ">",
                    _ => "<=",
                };
                let b = j.pop();
                let a = j.pop();
                lineas.push(S::Si(Cond::bin(a, op_c, b), salto(*x)));
            }
            O::Ifnull(x) => {
                let a = j.pop();
                lineas.push(S::Si(Cond::bin(a, "==", "null".into()), salto(*x)));
            }
            O::Ifnonnull(x) => {
                let a = j.pop();
                lineas.push(S::Si(Cond::bin(a, "!=", "null".into()), salto(*x)));
            }
            O::Goto(x) => {
                let dest = salto(*x);
                if !j.pila.is_empty() {
                    // valor que viaja por el salto (operador ternario, etc.)
                    let mut ns = Vec::new();
                    let previos = pila_en.get(&dest).cloned();
                    for (k, id) in j.pila.clone().into_iter().enumerate() {
                        let n = previos.as_ref().and_then(|p| p.get(k).cloned()).unwrap_or_else(|| {
                            tmp += 1;
                            format!("$t{tmp}")
                        });
                        let v = j.txt(id);
                        lineas.push(S::Txt(format!("{n} = {v};")));
                        ns.push(n);
                    }
                    pila_en.entry(dest).or_insert(ns);
                    j.pila.clear();
                }
                lineas.push(S::Ir(dest));
            }
            O::Getstatic(r) => {
                let c = if r.class_name == j.clase { corto(&r.class_name) } else { j.clase_ref(&r.class_name) };
                let b = r.name_and_type.descriptor == "Z";
                j.push(VJ::E(format!("{c}.{}", r.name_and_type.name), b, false));
            }
            O::Getfield(r) => {
                let o = j.pop_op();
                let b = r.name_and_type.descriptor == "Z";
                j.push(VJ::E(format!("{o}.{}", r.name_and_type.name), b, false));
            }
            O::Putstatic(r) => {
                let v = j.pop();
                let c = if r.class_name == j.clase { corto(&r.class_name) } else { j.clase_ref(&r.class_name) };
                st(&mut lineas, format!("{c}.{} = {v};", r.name_and_type.name));
            }
            O::Putfield(r) => {
                let v = j.pop();
                let o = j.pop_op();
                st(&mut lineas, format!("{o}.{} = {v};", r.name_and_type.name));
            }
            O::Invokevirtual(r) | O::Invokeinterface(r, _) | O::Invokespecial(r) | O::Invokestatic(r) => {
                let d = r.name_and_type.descriptor.to_string();
                let (pt, rt) = params_java(&d);
                let mut args: Vec<String> = (0..pt.len()).map(|_| j.pop()).collect();
                args.reverse();
                let nombre = r.name_and_type.name.to_string();
                let es_static = matches!(op, O::Invokestatic(_));
                let mut res: Option<String> = None;
                if es_static {
                    let c = if r.class_name == j.clase { String::new() } else { format!("{}.", j.clase_ref(&r.class_name)) };
                    res = Some(format!("{c}{nombre}({})", args.join(", ")));
                } else {
                    let rid = j.pop_id();
                    if nombre == "<init>" {
                        match j.arena[rid].clone() {
                            VJ::Nuevo(c) => {
                                let txt = format!("new {}({})", j.clase_ref(&c), args.join(", "));
                                // la copia (dup) que queda en la pila pasa a ser el objeto construido
                                if let Some(p) = j.pila.iter().rposition(|&x| matches!(&j.arena[x], VJ::Nuevo(c2) if *c2 == c)) {
                                    let id2 = j.pila[p];
                                    j.arena[id2] = VJ::E(txt, false, true);
                                } else {
                                    st(&mut lineas, format!("{txt};"));
                                }
                            }
                            _ => {
                                let recv = j.txt(rid);
                                if recv == "this" && j.es_ctor {
                                    let kw = if r.class_name == j.clase { "this" } else { "super" };
                                    if !(kw == "super" && args.is_empty() && r.class_name == "java/lang/Object") {
                                        st(&mut lineas, format!("{kw}({});", args.join(", ")));
                                    }
                                } else {
                                    st(&mut lineas, format!("{recv}.<init>({});", args.join(", ")));
                                }
                            }
                        }
                    } else {
                        let recv = envolver(&j.txt(rid));
                        let pre = if matches!(op, O::Invokespecial(_)) && recv == "this" && r.class_name != j.clase { "super".to_string() } else { recv };
                        res = Some(format!("{pre}.{nombre}({})", args.join(", ")));
                    }
                }
                if let Some(x) = res {
                    if rt == "void" {
                        st(&mut lineas, format!("{x};"));
                    } else {
                        j.push(VJ::E(x, rt == "boolean", true));
                    }
                }
            }
            O::Invokedynamic(i) => {
                let d = i.name_and_type.descriptor.to_string();
                let (pt, rt) = params_java(&d);
                let mut args: Vec<String> = (0..pt.len()).map(|_| j.pop()).collect();
                args.reverse();
                let bm = j.bootstrap.get(i.attr_index as usize);
                let nombre_bm = bm.map(|b| b.method.member_ref.name.to_string()).unwrap_or_default();
                let txt = if i.name_and_type.name == "makeConcatWithConstants" {
                    // receta: \u{1} = argumento, \u{2} = constante
                    let receta = bm.and_then(|b| b.arguments.first()).and_then(|a| match a {
                        cafebabe::constant_pool::BootstrapArgument::LiteralConstant(cafebabe::constant_pool::LiteralConstant::String(s)) => Some(s.to_string()),
                        _ => None,
                    });
                    match receta {
                        Some(r) => {
                            let mut partes = Vec::new();
                            let mut lit = String::new();
                            let mut it = args.iter();
                            for ch in r.chars() {
                                if ch == '\u{1}' {
                                    if !lit.is_empty() {
                                        partes.push(format!("{lit:?}"));
                                        lit.clear();
                                    }
                                    partes.push(it.next().map(|a| envolver(a)).unwrap_or_default());
                                } else {
                                    lit.push(ch);
                                }
                            }
                            if !lit.is_empty() {
                                partes.push(format!("{lit:?}"));
                            }
                            if partes.len() == 1 && !partes[0].starts_with('"') {
                                format!("\"\" + {}", partes[0])
                            } else {
                                partes.join(" + ")
                            }
                        }
                        None => args.iter().map(|a| envolver(a)).collect::<Vec<_>>().join(" + "),
                    }
                } else if nombre_bm == "metafactory" || nombre_bm == "altMetafactory" {
                    let imp = bm.and_then(|b| b.arguments.get(1)).and_then(|a| match a {
                        cafebabe::constant_pool::BootstrapArgument::MethodHandle(h) => Some((h.class_name.to_string(), h.member_ref.name.to_string())),
                        _ => None,
                    });
                    match imp {
                        Some((_, n)) if n.starts_with("lambda$") && j.lambdas.contains_key(&n) && args.is_empty() => j.lambdas[&n].clone(),
                        Some((c, n)) if n.starts_with("lambda$") => format!("/* λ */ {}::{}{}", corto(&c), n, if args.is_empty() { String::new() } else { format!(" /*captura: {}*/", args.join(", ")) }),
                        Some((c, n)) => format!("{}::{}", corto(&c), if n == "<init>" { "new".into() } else { n }),
                        None => format!("/* invokedynamic {} */", i.name_and_type.name),
                    }
                } else {
                    format!("/* invokedynamic {}({}) */", i.name_and_type.name, args.join(", "))
                };
                if rt == "void" {
                    st(&mut lineas, format!("{txt};"));
                } else {
                    j.push(VJ::E(txt, false, true));
                }
            }
            O::New(c) => j.push(VJ::Nuevo(c.to_string())),
            O::Newarray(t) => {
                let n = j.pop();
                j.push(VJ::Arr(format!("{t:?}").to_lowercase().replace("integer", "int"), n, Vec::new()));
            }
            O::Anewarray(t) => {
                let n = j.pop();
                let tn = match t {
                    cafebabe::constant_pool::ObjectArrayType::BinaryName(b) => j.clase_ref(b),
                    cafebabe::constant_pool::ObjectArrayType::ArrayType(d) => tipo_corto(&d.to_string()),
                };
                j.push(VJ::Arr(tn, n, Vec::new()));
            }
            O::Multianewarray(t, dims) => {
                let mut ds: Vec<String> = (0..*dims).map(|_| j.pop()).collect();
                ds.reverse();
                let tn = match t {
                    cafebabe::constant_pool::ObjectArrayType::BinaryName(b) => corto(b),
                    cafebabe::constant_pool::ObjectArrayType::ArrayType(d) => tipo_corto(&d.to_string()),
                };
                let base = tn.trim_end_matches("[]").to_string();
                let extra = tn.matches("[]").count().saturating_sub(*dims as usize);
                j.push(VJ::E(format!("new {base}{}{}", ds.iter().map(|d| format!("[{d}]")).collect::<String>(), "[]".repeat(extra)), false, false));
            }
            O::Arraylength => {
                let a = j.pop_op();
                j.push(VJ::E(format!("{a}.length"), false, false));
            }
            O::Iaload | O::Laload | O::Faload | O::Daload | O::Aaload | O::Baload | O::Caload | O::Saload => {
                let i = j.pop();
                let a = j.pop_op();
                j.push(VJ::E(format!("{a}[{i}]"), false, false));
            }
            O::Iastore | O::Lastore | O::Fastore | O::Dastore | O::Aastore | O::Bastore | O::Castore | O::Sastore => {
                let v = j.pop();
                let i = j.pop();
                let aid = j.pop_id();
                let inicializador = matches!(&j.arena[aid], VJ::Arr(_, _, el) if el.len().to_string() == i) && j.pila.contains(&aid);
                if inicializador {
                    if let VJ::Arr(_, _, el) = &mut j.arena[aid] {
                        el.push(v);
                    }
                } else {
                    let a = envolver(&j.txt(aid));
                    st(&mut lineas, format!("{a}[{i}] = {v};"));
                }
            }
            O::Checkcast(t) => {
                let a = j.pop_op();
                let tn = match t {
                    cafebabe::constant_pool::ObjectArrayType::BinaryName(b) => j.clase_ref(b),
                    cafebabe::constant_pool::ObjectArrayType::ArrayType(d) => tipo_corto(&d.to_string()),
                };
                j.push(VJ::E(format!("({tn}) {a}"), false, false));
            }
            O::Instanceof(t) => {
                let a = j.pop_op();
                let tn = match t {
                    cafebabe::constant_pool::ObjectArrayType::BinaryName(b) => j.clase_ref(b),
                    cafebabe::constant_pool::ObjectArrayType::ArrayType(d) => tipo_corto(&d.to_string()),
                };
                j.push(VJ::E(format!("{a} instanceof {tn}"), true, false));
            }
            O::Athrow => {
                let a = j.pop();
                st(&mut lineas, format!("throw {a};"));
            }
            O::Ireturn | O::Lreturn | O::Freturn | O::Dreturn | O::Areturn => {
                let mut a = j.pop();
                if ret == "boolean" && (a == "0" || a == "1") {
                    a = if a == "1" { "true".into() } else { "false".into() };
                }
                st(&mut lineas, format!("return {a};"));
            }
            O::Return => {
                if off != ultimo || idx + 1 != bc.opcodes.len() {
                    st(&mut lineas, "return;".into());
                }
            }
            O::Pop | O::Pop2 => {
                let id = j.pop_id();
                if let VJ::E(t, _, true) = &j.arena[id] {
                    st(&mut lineas, format!("{t};"));
                }
            }
            O::Dup => {
                if let Some(&t) = j.pila.last() {
                    j.pila.push(t);
                }
            }
            O::DupX1 => {
                let a = j.pop_id();
                let b = j.pop_id();
                j.pila.extend([a, b, a]);
            }
            O::DupX2 => {
                let a = j.pop_id();
                let b = j.pop_id();
                let c = j.pop_id();
                j.pila.extend([a, c, b, a]);
            }
            O::Dup2 => {
                let n = j.pila.len();
                if n >= 2 {
                    let (a, b) = (j.pila[n - 2], j.pila[n - 1]);
                    j.pila.extend([a, b]);
                }
            }
            O::Swap => {
                let a = j.pop_id();
                let b = j.pop_id();
                j.pila.extend([a, b]);
            }
            O::Monitorenter => {
                let a = j.pop();
                st(&mut lineas, format!("synchronized ({a}) {{  // monitorenter"));
            }
            O::Monitorexit => {
                let _ = j.pop();
                st(&mut lineas, "}  // monitorexit".into());
            }
            O::Tableswitch(t) => {
                let x = j.pop();
                let mut s = format!("switch ({x}) {{");
                for (k, d) in t.jumps.iter().enumerate() {
                    let _ = write!(s, "\n    case {}: goto L{};", t.low as i64 + k as i64, salto(*d));
                }
                let _ = write!(s, "\n    default: goto L{};\n}}", salto(t.default));
                st(&mut lineas, s);
            }
            O::Lookupswitch(t) => {
                let x = j.pop();
                let mut s = format!("switch ({x}) {{");
                for (k, d) in &t.match_offsets {
                    let _ = write!(s, "\n    case {k}: goto L{};", salto(*d));
                }
                let _ = write!(s, "\n    default: goto L{};\n}}", salto(t.default));
                st(&mut lineas, s);
            }
            otro => st(&mut lineas, format!("/* {} */", format!("{otro:?}").to_lowercase())),
        }
    }

    let cuerpo = pulir_java(estructurar(lineas, &fijas, false));
    let mut s = String::new();
    pintar(&cuerpo, 2, false, &mut s);
    let mods = {
        let b = m.access_flags.bits();
        let mut v = Vec::new();
        if b & 1 != 0 { v.push("public"); }
        if b & 2 != 0 { v.push("private"); }
        if b & 4 != 0 { v.push("protected"); }
        if b & 8 != 0 { v.push("static"); }
        if b & 0x10 != 0 { v.push("final"); }
        if b & 0x20 != 0 { v.push("synchronized"); }
        if v.is_empty() { String::new() } else { format!("{} ", v.join(" ")) }
    };
    let cab = match m.name.as_ref() {
        "<init>" => format!("{mods}{}({})", corto(&nombre_clase), firma_p.join(", ")),
        "<clinit>" => "static".to_string(),
        n => format!("{mods}{} {n}({})", tipo_corto(&desc[desc.find(')').unwrap_or(0) + 1..]), firma_p.join(", ")),
    };
    let _ = ret;
    let _ = writeln!(out, "    {cab} {{");
    out.push_str(&s);
    let _ = writeln!(out, "    }}");
    out
}

fn registrar_imports(desc: &str, clase: &cafebabe::ClassFile, imports: &mut BTreeSet<String>) {
    let propio = clase.this_class.to_string().replace('/', ".");
    let paq_propio = propio.rsplit_once('.').map(|x| x.0.to_string()).unwrap_or_default();
    let mut resto = desc;
    while let Some(i) = resto.find('L') {
        let Some(f) = resto[i..].find(';') else { break };
        let c = resto[i + 1..i + f].replace('/', ".");
        resto = &resto[i + f + 1..];
        if let Some((paq, _)) = c.rsplit_once('.') {
            if paq != "java.lang" && paq != paq_propio {
                imports.insert(c.split('$').next().unwrap_or(&c).to_string());
            }
        }
    }
}

/// Clase Java (.class) → pseudo-fuente Java.
pub fn java(d: &[u8]) -> Result<String> {
    use cafebabe::attributes::AttributeData;
    let clase = cafebabe::parse_class(d).map_err(|e| anyhow!("class: {e}"))?;
    let vacio = Vec::new();
    let bootstrap = clase
        .attributes
        .iter()
        .find_map(|a| if let AttributeData::BootstrapMethods(b) = &a.data { Some(b) } else { None })
        .unwrap_or(&vacio);
    let mut imports = BTreeSet::new();
    let mut cuerpo = String::new();
    for f in &clase.fields {
        let b = f.access_flags.bits();
        let mut mods = Vec::new();
        if b & 1 != 0 { mods.push("public"); }
        if b & 2 != 0 { mods.push("private"); }
        if b & 4 != 0 { mods.push("protected"); }
        if b & 8 != 0 { mods.push("static"); }
        if b & 0x10 != 0 { mods.push("final"); }
        let valor = f.attributes.iter().find_map(|a| match &a.data {
            AttributeData::ConstantValue(cafebabe::constant_pool::LiteralConstant::String(s)) => Some(format!(" = {s:?}")),
            AttributeData::ConstantValue(cafebabe::constant_pool::LiteralConstant::Integer(i)) => Some(format!(" = {i}")),
            AttributeData::ConstantValue(cafebabe::constant_pool::LiteralConstant::Long(i)) => Some(format!(" = {i}L")),
            _ => None,
        });
        let _ = writeln!(cuerpo, "    {}{} {}{};", if mods.is_empty() { String::new() } else { format!("{} ", mods.join(" ")) }, tipo_corto(&f.descriptor.to_string()), f.name, valor.unwrap_or_default());
    }
    if !clase.fields.is_empty() {
        cuerpo.push('\n');
    }
    // 1ª pasada: lambdas sintéticas de una sola expresión → se muestran en línea.
    let mut lambdas: HashMap<String, String> = HashMap::new();
    let vacias = HashMap::new();
    for m in clase.methods.iter().filter(|m| m.name.starts_with("lambda$")) {
        let t = metodo_java(&clase, m, bootstrap, &mut BTreeSet::new(), &vacias);
        let lineas: Vec<&str> = t.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        if lineas.len() == 3 && lineas[2] == "}" {
            let cab = lineas[0];
            let params: Vec<&str> = cab[cab.find('(').unwrap_or(0) + 1..cab.rfind(')').unwrap_or(0)]
                .split(", ")
                .filter(|s| !s.is_empty())
                .map(|p| p.rsplit(' ').next().unwrap_or(p))
                .collect();
            let cuerpo = lineas[1].trim_end_matches(';');
            let expr = cuerpo.strip_prefix("return ").unwrap_or(cuerpo);
            let ps = if params.len() == 1 { params[0].to_string() } else { format!("({})", params.join(", ")) };
            lambdas.insert(m.name.to_string(), format!("{ps} -> {expr}"));
        }
    }
    for m in &clase.methods {
        if lambdas.contains_key(m.name.as_ref()) {
            continue; // ya aparece en línea donde se usa
        }
        cuerpo.push_str(&metodo_java(&clase, m, bootstrap, &mut imports, &lambdas));
        cuerpo.push('\n');
    }
    // imports de los tipos de campos y firmas
    for f in &clase.fields {
        registrar_imports(&f.descriptor.to_string(), &clase, &mut imports);
    }
    for m in &clase.methods {
        registrar_imports(&m.descriptor.to_string(), &clase, &mut imports);
    }
    let nombre = clase.this_class.to_string().replace('/', ".");
    let (paq, simple) = nombre.rsplit_once('.').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((String::new(), nombre.clone()));
    let mut s = String::new();
    let _ = writeln!(s, "// Decompilado por CAPAS (motor nativo) — pseudo-fuente para LEER; para recompilar usa CFR/Procyon.");
    if !paq.is_empty() {
        let _ = writeln!(s, "package {paq};\n");
    }
    for i in &imports {
        let _ = writeln!(s, "import {i};");
    }
    if !imports.is_empty() {
        s.push('\n');
    }
    let b = clase.access_flags.bits();
    let tipo = if b & 0x0200 != 0 { "interface" } else if b & 0x4000 != 0 { "enum" } else { "class" };
    let mut cab = format!("{}{}{tipo} {}", if b & 1 != 0 { "public " } else { "" }, if b & 0x0400 != 0 && tipo == "class" { "abstract " } else if b & 0x10 != 0 { "final " } else { "" }, simple.replace('$', "."));
    if let Some(sup) = &clase.super_class {
        let su = sup.to_string();
        if su != "java/lang/Object" && tipo == "class" {
            let _ = write!(cab, " extends {}", corto(&su));
        }
    }
    if !clase.interfaces.is_empty() {
        let l: Vec<String> = clase.interfaces.iter().map(|i| corto(&i.to_string())).collect();
        let _ = write!(cab, " {} {}", if tipo == "interface" { "extends" } else { "implements" }, l.join(", "));
    }
    let _ = writeln!(s, "{cab} {{\n");
    s.push_str(&cuerpo);
    let _ = writeln!(s, "}}");
    Ok(s)
}

// ══════════════════════════════════ PYTHON ══════════════════════════════════

/// .pyc → pseudo-fuente Python.
pub fn python(d: &[u8]) -> Result<String> {
    let (t, c) = codigo::leer_pyc(d)?;
    let menor: u8 = t.version[2..].parse().unwrap_or(0);
    let mut s = String::new();
    let _ = writeln!(s, "# Decompilado por CAPAS (motor nativo) desde Python {} — pseudo-fuente para LEER.", t.version);
    let _ = writeln!(s, "# Archivo original: {}\n", c.filename);
    let cuerpo = PyDec::new(&c, t, menor).cuerpo();
    pintar(&cuerpo, 0, true, &mut s);
    Ok(s)
}

#[derive(Clone, Debug)]
enum VP {
    Nulo,
    E(String),
    Cod(Box<CodigoPy>),
    /// función creada con MAKE_FUNCTION (código, valores por defecto)
    Func(Box<CodigoPy>, Vec<String>),
    /// función o clase decorada: decoradores (exterior primero) + objeto
    Deco(Vec<String>, Box<VP>),
    /// clase creada con __build_class__ (cabecera, cuerpo)
    Clase(String, Vec<S>),
    /// elemento actual de un for (lo consume el STORE siguiente)
    Item,
    BuildClass,
}

const BINOPS: [&str; 27] = [
    "+", "&", "//", "<<", "@", "*", "%", "|", "**", ">>", "-", "/", "^", "+=", "&=", "//=", "<<=", "@=", "*=", "%=", "|=", "**=",
    ">>=", "-=", "/=", "^=", "[]",
];

fn op_antiguo(n: &str) -> Option<(&'static str, bool)> {
    let tabla: &[(&str, &'static str)] = &[
        ("ADD", "+"), ("SUBTRACT", "-"), ("MULTIPLY", "*"), ("TRUE_DIVIDE", "/"), ("FLOOR_DIVIDE", "//"), ("MODULO", "%"),
        ("POWER", "**"), ("LSHIFT", "<<"), ("RSHIFT", ">>"), ("AND", "&"), ("OR", "|"), ("XOR", "^"), ("MATRIX_MULTIPLY", "@"),
    ];
    let (inplace, base) = if let Some(b) = n.strip_prefix("INPLACE_") {
        (true, b)
    } else if let Some(b) = n.strip_prefix("BINARY_") {
        (false, b)
    } else {
        return None;
    };
    tabla.iter().find(|(k, _)| *k == base).map(|(_, o)| (*o, inplace))
}

fn tupla_a_lista(t: &str) -> Vec<String> {
    let t = t.trim();
    let t = t.strip_prefix('(').and_then(|x| x.strip_suffix(')')).unwrap_or(t);
    let mut v = Vec::new();
    let mut prof = 0i32;
    let mut cur = String::new();
    let mut com: Option<char> = None;
    for ch in t.chars() {
        if let Some(q) = com {
            cur.push(ch);
            if ch == q {
                com = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                com = Some(ch);
                cur.push(ch);
            }
            '(' | '[' | '{' => {
                prof += 1;
                cur.push(ch);
            }
            ')' | ']' | '}' => {
                prof -= 1;
                cur.push(ch);
            }
            ',' if prof == 0 => {
                v.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        v.push(cur.trim().to_string());
    }
    v
}

fn sin_comillas(s: &str) -> String {
    s.trim().trim_matches(|c| c == '"' || c == '\'').to_string()
}

struct PyDec<'a> {
    c: &'a CodigoPy,
    t: &'static crate::pyc_tablas::TablaPy,
    menor: u8,
    pila: Vec<VP>,
    kwnames: Vec<String>,
    /// comprensiones en curso: marcador → (tipo, elementos añadidos)
    comps: HashMap<String, (char, Vec<String>)>,
    ncomp: usize,
    /// cuerpo de una comprensión ≤3.11 (devuelve la expresión plegada)
    comp_externa: bool,
    /// comparación encadenada a < b <= c: (b, ¿la siguiente comparación abre cadena?)
    cad_b: Option<String>,
    cad_pend: Option<String>,
    cad_izq: Option<String>,
}

impl<'a> PyDec<'a> {
    fn new(c: &'a CodigoPy, t: &'static crate::pyc_tablas::TablaPy, menor: u8) -> Self {
        PyDec { c, t, menor, pila: Vec::new(), kwnames: Vec::new(), comps: HashMap::new(), ncomp: 0, comp_externa: false, cad_b: None, cad_pend: None, cad_izq: None }
    }
    fn pop(&mut self) -> VP {
        self.pila.pop().unwrap_or(VP::E("<?>".into()))
    }
    fn pop_e(&mut self) -> String {
        loop {
            match self.pila.pop() {
                Some(VP::Nulo) => continue,
                Some(v) => return self.txt(&v),
                None => return "<?>".into(),
            }
        }
    }
    fn txt(&self, v: &VP) -> String {
        match v {
            VP::Nulo => "NULL".into(),
            VP::E(s) => s.clone(),
            VP::Cod(c) => format!("<code {}>", c.qualname),
            VP::Func(c, d) => {
                if c.name == "<lambda>" {
                    self.lambda(c, d)
                } else {
                    c.qualname.clone()
                }
            }
            VP::Deco(d, f) => format!("{}({})", d.join("("), self.txt(f)) + &")".repeat(d.len().saturating_sub(1)),
            VP::Clase(c, _) => c.trim_start_matches("class ").to_string(),
            VP::Item => "<item>".into(),
            VP::BuildClass => "__build_class__".into(),
        }
    }
    fn args_de(&self, c: &CodigoPy, defaults: &[String]) -> String {
        let n = (c.argcount + c.kwonly) as usize;
        let mut v: Vec<String> = c.locales.iter().take(n).cloned().collect();
        let pos = c.argcount as usize;
        let k = defaults.len().min(pos);
        for (i, d) in defaults.iter().rev().take(k).enumerate() {
            let idx = pos - 1 - i;
            if let Some(a) = v.get_mut(idx) {
                *a = format!("{a}={d}");
            }
        }
        let mut extra = n;
        let mut estrella = None;
        if c.flags & 0x04 != 0 {
            estrella = Some(format!("*{}", c.locales.get(extra).cloned().unwrap_or_else(|| "args".into())));
            extra += 1;
        } else if c.kwonly > 0 {
            estrella = Some("*".into());
        }
        if let Some(e) = estrella {
            v.insert(pos.min(v.len()), e);
        }
        if c.posonly > 0 && (c.posonly as usize) <= v.len() {
            v.insert(c.posonly as usize, "/".into());
        }
        if c.flags & 0x08 != 0 {
            v.push(format!("**{}", c.locales.get(extra).cloned().unwrap_or_else(|| "kwargs".into())));
        }
        v.join(", ")
    }
    fn lambda(&self, c: &CodigoPy, d: &[String]) -> String {
        let cuerpo = PyDec::new(c, self.t, self.menor).cuerpo();
        let expr = match cuerpo.as_slice() {
            [S::Txt(t)] if t.starts_with("return ") => t[7..].to_string(),
            [] => "None".into(),
            _ => "...".into(),
        };
        let a = self.args_de(c, d);
        if a.is_empty() { format!("lambda: {expr}") } else { format!("lambda {a}: {expr}") }
    }
    fn nombre_local(&self, i: usize) -> String {
        self.c.locales.get(i).cloned().unwrap_or_else(|| format!("_{i}"))
    }
    fn es_modulo(&self) -> bool {
        self.c.name == "<module>" || self.c.locales.is_empty() && self.c.argcount == 0 && self.c.flags & 0x02 == 0
    }

    /// Comprensión ≤3.11 (código <listcomp>/<genexpr>…): texto con el iterable dado.
    fn comprension(&self, c: &CodigoPy, iterable: &str) -> Option<String> {
        let tipo = match c.name.as_str() {
            "<listcomp>" => '[',
            "<setcomp>" => '{',
            "<dictcomp>" => 'd',
            "<genexpr>" => '(',
            _ => return None,
        };
        let mut sub = PyDec::new(c, self.t, self.menor);
        sub.comp_externa = true;
        let cuerpo = sub.cuerpo();
        let mut texto = None;
        for x in &cuerpo {
            if let S::Txt(t) = x {
                if let Some(r) = t.strip_prefix("§compexpr§") {
                    texto = Some(r.to_string());
                }
            }
        }
        let interior = texto?.replace(".0", iterable);
        Some(match tipo {
            '[' => format!("[{interior}]"),
            '{' | 'd' => format!("{{{interior}}}"),
            _ => format!("({interior})"),
        })
    }

    fn cuerpo(mut self) -> Vec<S> {
        let ins = codigo::instrucciones_py(self.c, self.t, self.menor);
        let pos = |off: usize| ins.iter().position(|y| y.off == off);
        let mut etiquetas: BTreeSet<usize> = ins.iter().filter_map(|x| x.salto).collect();
        let mut l: Vec<S> = Vec::new();
        let mut pila_en: HashMap<usize, Vec<VP>> = HashMap::new();
        let mut boolop: Vec<(usize, String, &'static str, usize)> = Vec::new();
        let mut decl_global: BTreeSet<String> = BTreeSet::new();
        let mut saltar_hasta: Option<usize> = None;

        // Manejadores de excepción (≥3.11): pila inicial y regiones de limpieza a omitir.
        let mut manejador: HashMap<usize, (usize, bool)> = HashMap::new();
        let mut inicio_try: BTreeSet<usize> = BTreeSet::new();
        let mut rango_try: HashMap<usize, (usize, usize)> = HashMap::new(); // destino -> (ini, fin)
        let mut fin_try: BTreeSet<usize> = BTreeSet::new();
        // pila de manejadores abiertos: true = finally, false = except
        let mut manejos: Vec<bool> = Vec::new();
        let mut bloques_le310: Vec<char> = Vec::new();
        let mut manejadores_le310: BTreeSet<usize> = BTreeSet::new();
        let mut omitir: BTreeSet<usize> = BTreeSet::new();
        for &(ini, _fin, dst, prof, lasti) in &self.c.excepciones {
            manejador.entry(dst).or_insert((prof, lasti));
            etiquetas.insert(dst);
            if let Some(p) = pos(dst) {
                let primero = ins[p].nombre;
                if primero == "PUSH_EXC_INFO" {
                    let e = rango_try.entry(dst).or_insert((ini, _fin));
                    e.0 = e.0.min(ini);
                    e.1 = e.1.max(_fin);
                } else {
                    // limpieza generada por el compilador (re-lanzar, borrar el "as e"…)
                    let mut q = p;
                    while q < ins.len() {
                        let n = ins[q].nombre;
                        let limpio = matches!(n, "COPY" | "POP_EXCEPT" | "RERAISE" | "LOAD_CONST" | "STORE_FAST" | "STORE_NAME" | "DELETE_FAST" | "DELETE_NAME" | "SWAP" | "POP_TOP" | "CALL_INTRINSIC_1" | "NOP" | "CLEANUP_THROW" | "JUMP_BACKWARD_NO_INTERRUPT" | "END_SEND" | "END_ASYNC_FOR");
                        if !limpio {
                            break;
                        }
                        omitir.insert(ins[q].off);
                        if matches!(n, "RERAISE" | "JUMP_BACKWARD_NO_INTERRUPT" | "END_ASYNC_FOR") {
                            break;
                        }
                        q += 1;
                    }
                }
            }
        }

        for &(ini, fin) in rango_try.values() {
            inicio_try.insert(ini);
            fin_try.insert(fin);
        }
        let mut i = 0usize;
        while i < ins.len() {
            let x = &ins[i];
            // cierre de bloques try cuyo rango termina aquí
            while let Some(&f) = fin_try.iter().next() {
                if f > x.off {
                    break;
                }
                fin_try.remove(&f);
                l.push(S::Txt("§/try§".into()));
            }
            if let Some(h) = saltar_hasta {
                if x.off < h {
                    i += 1;
                    continue;
                }
                saltar_hasta = None;
            }
            if omitir.contains(&x.off) {
                i += 1;
                continue;
            }
            // cierre de and/or pendientes que convergen aquí
            while let Some(&(dst, _, _, prof)) = boolop.last() {
                if dst != x.off || self.pila.len() != prof + 1 {
                    break;
                }
                let (_, izq, op, _) = boolop.pop().unwrap();
                let der = self.pop_e();
                self.pila.push(VP::E(op_bin(&izq, op, &der)));
                etiquetas.remove(&x.off);
            }
            if inicio_try.contains(&x.off) {
                l.push(S::Txt("§try§".into()));
            }
            if let Some(&(prof, lasti)) = manejador.get(&x.off) {
                self.pila.clear();
                for k in 0..prof {
                    self.pila.push(VP::E(format!("$s{k}")));
                }
                if lasti {
                    self.pila.push(VP::E("$lasti".into()));
                }
                self.pila.push(VP::E("$exc".into()));
            }
            if etiquetas.contains(&x.off) {
                if let Some(p) = pila_en.get(&x.off).cloned() {
                    if self.pila.is_empty() {
                        self.pila = p;
                    }
                }
                l.push(S::Etq(x.off));
                if manejadores_le310.contains(&x.off) {
                    // ≤3.10: entrada a un manejador
                    let f = es_finally(&ins, i);
                    manejos.push(f);
                    l.push(S::Txt(if f { "§except§finally".into() } else { "§except§".into() }));
                }
            }
            let n = x.nombre;
            let a = x.arg.unwrap_or(0) as usize;
            match n {
                "POP_EXCEPT" => {
                    if let Some(p) = manejos.iter().rposition(|f| !f) {
                        manejos.truncate(p);
                        l.push(S::Txt("§/except§".into()));
                    }
                }
                "RERAISE" | "END_FINALLY" => {
                    if manejos.last() == Some(&true) {
                        manejos.pop();
                        l.push(S::Txt("§/except§".into()));
                    }
                }
                "POP_BLOCK" => {
                    if bloques_le310.pop() == Some('t') {
                        l.push(S::Txt("§/try§".into()));
                    }
                }
                "SETUP_LOOP" => bloques_le310.push('l'),
                "NOP" | "RESUME" | "CACHE" | "PRECALL" | "EXTENDED_ARG" | "MAKE_CELL" | "COPY_FREE_VARS" | "END_FOR" | "POP_ITER"
                | "NOT_TAKEN" | "GEN_START" | "BEGIN_FINALLY" | "CALL_FINALLY" | "POP_FINALLY" | "INTERPRETER_EXIT" | "CLEANUP_THROW"
                | "END_SEND" | "EXIT_INIT_CHECK" | "TO_BOOL" | "WITH_EXCEPT_START" | "BREAK_LOOP" => {}
                "RETURN_GENERATOR" => {
                    self.pila.push(VP::E("$gen".into()));
                }
                "PUSH_EXC_INFO" => {
                    let e = self.pop();
                    self.pila.push(VP::E("$prev".into()));
                    self.pila.push(e);
                    let f = es_finally(&ins, i);
                    manejos.push(f);
                    l.push(S::Txt(if f { "§except§finally".into() } else { "§except§".into() }));
                }
                "SETUP_FINALLY" | "SETUP_EXCEPT" | "SETUP_ASYNC_WITH" => {
                    if let Some(d) = x.salto {
                        let mut p = self.pila.clone();
                        p.extend([VP::E("$tb".into()), VP::E("$val".into()), VP::E("$exc".into())]);
                        pila_en.insert(d, p);
                        if n != "SETUP_ASYNC_WITH" {
                            l.push(S::Txt("§try§".into()));
                            bloques_le310.push('t');
                            manejadores_le310.insert(d);
                        } else {
                            bloques_le310.push('w');
                        }
                    }
                }
                "SETUP_WITH" | "BEFORE_WITH" | "BEFORE_ASYNC_WITH" => {
                    let m = self.pop_e();
                    self.pila.push(VP::E("$exit".into()));
                    self.pila.push(VP::E(format!("§with§{m}")));
                    if n == "SETUP_WITH" {
                        bloques_le310.push('w');
                        if let Some(d) = x.salto {
                            let mut p = self.pila.clone();
                            p.pop();
                            p.extend([VP::E("$tb".into()), VP::E("$val".into()), VP::E("$exc".into())]);
                            pila_en.insert(d, p);
                        }
                    }
                }
                "CHECK_EXC_MATCH" => {
                    let t = self.pop_e();
                    self.pila.push(VP::E(format!("§excmatch§{t}")));
                }
                "JUMP_IF_NOT_EXC_MATCH" => {
                    let t = self.pop_e();
                    let _ = self.pop();
                    poner_tipo_except(&mut l, &t, &mut manejos);
                }
                "LOAD_ASSERTION_ERROR" => self.pila.push(VP::E("AssertionError".into())),
                "SETUP_ANNOTATIONS" => {}
                "POP_TOP" => {
                    if let Some(v) = self.pila.pop() {
                        match v {
                            VP::E(t) if t.starts_with("§with§") => l.push(S::Txt(format!("with {}:  # bloque with", t.trim_start_matches("§with§")))),
                            VP::E(t) if t.starts_with('§') || t.starts_with('$') || t == "None" => {}
                            VP::E(t) if t.ends_with(')') || t.starts_with("await ") || t.starts_with("(yield") || t.starts_with("yield") => {
                                let t = if t.starts_with("(yield") { t[1..t.len() - 1].to_string() } else { t };
                                l.push(S::Txt(t));
                            }
                            _ => {}
                        }
                    }
                }
                "PUSH_NULL" => self.pila.push(VP::Nulo),
                "LOAD_CONST" | "RETURN_CONST" | "LOAD_SMALL_INT" => {
                    let v = if n == "LOAD_SMALL_INT" {
                        VP::E(a.to_string())
                    } else {
                        match self.c.consts.get(a) {
                            Some(Py::Codigo(k)) => VP::Cod(k.clone()),
                            Some(k) => VP::E(codigo::repr_py(k)),
                            None => VP::E("<const>".into()),
                        }
                    };
                    if n == "RETURN_CONST" {
                        let t = self.txt(&v);
                        if !(t == "None" && (self.es_modulo() || i + 1 == ins.len())) {
                            l.push(S::Txt(format!("return {t}")));
                        }
                        self.pila.clear();
                    } else {
                        self.pila.push(v);
                    }
                }
                "LOAD_NAME" | "LOAD_GLOBAL" | "LOAD_FAST" | "LOAD_DEREF" | "LOAD_CLASSDEREF" | "LOAD_FAST_CHECK" | "LOAD_FROM_DICT_OR_DEREF"
                | "LOAD_FROM_DICT_OR_GLOBALS" | "LOAD_CLOSURE" | "LOAD_FAST_BORROW" => {
                    let nombre = x.texto.trim_start_matches("NULL + ").to_string();
                    let con_null = x.texto.starts_with("NULL + ");
                    if con_null && self.menor < 13 {
                        self.pila.push(VP::Nulo);
                    }
                    self.pila.push(VP::E(nombre));
                    if con_null && self.menor >= 13 {
                        self.pila.push(VP::Nulo);
                    }
                }
                "LOAD_FAST_AND_CLEAR" => self.pila.push(VP::E("§guardado§".into())),
                "LOAD_FAST_LOAD_FAST" | "LOAD_FAST_BORROW_LOAD_FAST_BORROW" => {
                    self.pila.push(VP::E(self.nombre_local(a >> 4)));
                    self.pila.push(VP::E(self.nombre_local(a & 15)));
                }
                "LOAD_ATTR" | "LOAD_METHOD" => {
                    let metodo = n == "LOAD_METHOD" || x.texto.starts_with("NULL|self + ");
                    let attr = x.texto.trim_start_matches("NULL|self + ").to_string();
                    let o = self.pop_e();
                    self.pila.push(VP::E(format!("{}.{attr}", envolver(&o))));
                    if metodo {
                        self.pila.push(VP::Nulo);
                    }
                }
                "LOAD_SUPER_ATTR" => {
                    let _ = self.pop();
                    let _ = self.pop();
                    let _ = self.pop();
                    self.pila.push(VP::E(format!("super().{}", x.texto)));
                    if a & 1 == 1 {
                        self.pila.push(VP::Nulo);
                    }
                }
                "STORE_NAME" | "STORE_GLOBAL" | "STORE_FAST" | "STORE_DEREF" => {
                    let destino = x.texto.clone();
                    if n == "STORE_GLOBAL" && !self.es_modulo() && decl_global.insert(destino.clone()) {
                        l.push(S::Txt(format!("global {destino}")));
                    }
                    let v = self.pop();
                    self.asignar(&mut l, destino, v);
                }
                "STORE_FAST_STORE_FAST" => {
                    let v1 = self.pop();
                    self.asignar(&mut l, self.nombre_local(a >> 4), v1);
                    let v2 = self.pop();
                    self.asignar(&mut l, self.nombre_local(a & 15), v2);
                }
                "STORE_FAST_LOAD_FAST" => {
                    let v = self.pop();
                    self.asignar(&mut l, self.nombre_local(a >> 4), v);
                    self.pila.push(VP::E(self.nombre_local(a & 15)));
                }
                "STORE_ATTR" => {
                    let o = self.pop_e();
                    let v = self.pop();
                    self.asignar(&mut l, format!("{}.{}", envolver(&o), x.texto), v);
                }
                "STORE_SUBSCR" => {
                    let k = self.pop_e();
                    let o = self.pop_e();
                    let v = self.pop();
                    self.asignar(&mut l, format!("{}[{k}]", envolver(&o)), v);
                }
                "DELETE_NAME" | "DELETE_FAST" | "DELETE_GLOBAL" | "DELETE_DEREF" => l.push(S::Txt(format!("del {}", x.texto))),
                "DELETE_ATTR" => {
                    let o = self.pop_e();
                    l.push(S::Txt(format!("del {}.{}", envolver(&o), x.texto)));
                }
                "DELETE_SUBSCR" => {
                    let k = self.pop_e();
                    let o = self.pop_e();
                    l.push(S::Txt(format!("del {}[{k}]", envolver(&o))));
                }
                "BINARY_SUBSCR" => {
                    let k = self.pop_e();
                    let o = self.pop_e();
                    let k = if k.starts_with('(') && k.ends_with(')') && parentesis_cerrado(&k) && tupla_a_lista(&k).len() > 1 { k[1..k.len() - 1].to_string() } else { k };
                    self.pila.push(VP::E(format!("{}[{k}]", envolver(&o))));
                }
                "BUILD_SLICE" => {
                    let mut v: Vec<String> = (0..a).map(|_| self.pop_e()).collect();
                    v.reverse();
                    let v: Vec<String> = v.into_iter().map(|x| if x == "None" { String::new() } else { x }).collect();
                    self.pila.push(VP::E(v.join(":")));
                }
                "BINARY_SLICE" => {
                    let fin = self.pop_e();
                    let ini = self.pop_e();
                    let o = self.pop_e();
                    let f = |s: String| if s == "None" { String::new() } else { s };
                    self.pila.push(VP::E(format!("{}[{}:{}]", envolver(&o), f(ini), f(fin))));
                }
                "STORE_SLICE" => {
                    let fin = self.pop_e();
                    let ini = self.pop_e();
                    let o = self.pop_e();
                    let v = self.pop();
                    self.asignar(&mut l, format!("{}[{ini}:{fin}]", envolver(&o)), v);
                }
                "BINARY_OP" => {
                    let b = self.pop_e();
                    let o = self.pop_e();
                    let op = BINOPS.get(a).copied().unwrap_or("?");
                    if op == "[]" {
                        self.pila.push(VP::E(format!("{}[{b}]", envolver(&o))));
                    } else if op.ends_with('=') {
                        self.pila.push(VP::E(format!("§aug§{o}§{op}§{b}")));
                    } else {
                        self.pila.push(VP::E(op_bin(&o, op, &b)));
                    }
                }
                _ if op_antiguo(n).is_some() => {
                    let (op, inplace) = op_antiguo(n).unwrap();
                    let b = self.pop_e();
                    let o = self.pop_e();
                    if inplace {
                        self.pila.push(VP::E(format!("§aug§{o}§{op}=§{b}")));
                    } else {
                        self.pila.push(VP::E(op_bin(&o, op, &b)));
                    }
                }
                "UNARY_NEGATIVE" | "UNARY_POSITIVE" | "UNARY_INVERT" => {
                    let o = self.pop_e();
                    let s = match n {
                        "UNARY_NEGATIVE" => "-",
                        "UNARY_POSITIVE" => "+",
                        _ => "~",
                    };
                    self.pila.push(VP::E(format!("{s}{}", if nivel(&o) < 12 { format!("({o})") } else { o })));
                }
                "UNARY_NOT" => {
                    let o = self.pop_e();
                    self.pila.push(VP::E(if nivel(&o) <= 4 { format!("not ({o})") } else { format!("not {o}") }));
                }
                "CALL_INTRINSIC_1" => match a {
                    3 => {}                                   // STOPITERATION_ERROR
                    5 => {
                        let o = self.pop_e();
                        self.pila.push(VP::E(format!("+{o}")));
                    }
                    6 => {
                        let o = self.pop_e();
                        self.pila.push(VP::E(format!("({},)", o.trim_start_matches('[').trim_end_matches(']'))));
                    }
                    2 => {
                        let m = self.pop_e();
                        l.push(S::Txt(format!("from {} import *", m.trim_start_matches("§import§"))));
                    }
                    _ => {}
                },
                "COMPARE_OP" | "IS_OP" | "CONTAINS_OP" => {
                    let b = self.pop_e();
                    let o = self.pop_e();
                    if let Some(izq) = self.cad_izq.take() {
                        // eslabón siguiente de a < b <= c
                        let op = match n {
                            "IS_OP" => if a == 1 { "is not".to_string() } else { "is".to_string() },
                            "CONTAINS_OP" => if a == 1 { "not in".to_string() } else { "in".to_string() },
                            _ => x.texto.trim_start_matches("bool(").trim_end_matches(')').to_string(),
                        };
                        let t = format!("{izq} {op} {}", if nivel(&b) <= 5 { format!("({b})") } else { b });
                        if let Some(bb) = self.cad_b.take() {
                            self.cad_pend = Some(bb);
                        }
                        self.pila.push(VP::E(t));
                        i += 1;
                        continue;
                    }
                    let es_cadena = self.cad_b.take();
                    let op = match n {
                        "IS_OP" => if a == 1 { "is not".to_string() } else { "is".to_string() },
                        "CONTAINS_OP" => if a == 1 { "not in".to_string() } else { "in".to_string() },
                        _ => x.texto.trim_start_matches("bool(").trim_end_matches(')').to_string(),
                    };
                    if op == "exception match" {
                        self.pila.push(VP::E(format!("§excmatch§{b}")));
                    } else {
                        self.pila.push(VP::E(op_bin(&o, &op, &b)));
                        if let Some(bb) = es_cadena {
                            self.cad_pend = Some(bb);
                        }
                    }
                }
                "BUILD_TUPLE" | "BUILD_LIST" | "BUILD_SET" => {
                    let mut v: Vec<String> = (0..a).map(|_| self.pop_e()).collect();
                    v.reverse();
                    if a == 0 && n != "BUILD_TUPLE" {
                        // posible comprensión: marcador que se resuelve al plegar el bucle
                        self.ncomp += 1;
                        let m = format!("§c{}§", self.ncomp);
                        self.comps.insert(m.clone(), (if n == "BUILD_LIST" { '[' } else { '{' }, Vec::new()));
                        self.pila.push(VP::E(m));
                    } else {
                        let t = match n {
                            "BUILD_TUPLE" => if v.len() == 1 { format!("({},)", v[0]) } else { format!("({})", v.join(", ")) },
                            "BUILD_LIST" => format!("[{}]", v.join(", ")),
                            _ => format!("{{{}}}", v.join(", ")),
                        };
                        self.pila.push(VP::E(t));
                    }
                }
                "LIST_EXTEND" | "SET_UPDATE" | "DICT_UPDATE" | "DICT_MERGE" | "LIST_TO_TUPLE" => {
                    if n == "LIST_TO_TUPLE" {
                        let v = self.pop_e();
                        let v = self.resolver_marcadores(&v);
                        self.pila.push(VP::E(format!("({},)", v.trim_start_matches('[').trim_end_matches(']'))));
                    } else {
                        let ext = self.pop_e();
                        let base = self.pop_e();
                        let base = if base.starts_with("§c") {
                            self.comps.remove(&base);
                            match n {
                                "LIST_EXTEND" => "[]".to_string(),
                                _ => "{}".to_string(),
                            }
                        } else {
                            base
                        };
                        let interior = match n {
                            "DICT_UPDATE" | "DICT_MERGE" => format!("**{ext}"),
                            _ => {
                                let e = ext.trim();
                                if (e.starts_with('(') || e.starts_with('[')) && !e.contains(" for ") {
                                    tupla_a_lista(e).join(", ")
                                } else {
                                    format!("*{e}")
                                }
                            }
                        };
                        let b = base.trim();
                        let (ab, cb) = if n == "LIST_EXTEND" { ('[', ']') } else { ('{', '}') };
                        let dentro = &b[1..b.len().saturating_sub(1).max(1)];
                        let nuevo = if dentro.trim().is_empty() { format!("{ab}{interior}{cb}") } else { format!("{ab}{dentro}, {interior}{cb}") };
                        self.pila.push(VP::E(nuevo));
                    }
                }
                "LIST_APPEND" | "SET_ADD" | "MAP_ADD" => {
                    let v = self.pop_e();
                    let (k, v) = if n == "MAP_ADD" {
                        let k = self.pop_e();
                        (Some(k), v)
                    } else {
                        (None, v)
                    };
                    // el iterador del for no está en la pila simulada: la lista está a profundidad a-1
                    let idx = (self.pila.len() + 1).saturating_sub(a).min(self.pila.len().saturating_sub(1));
                    let marca = match self.pila.get(idx) {
                        Some(VP::E(m)) if m.starts_with("§c") => m.clone(),
                        _ => {
                            self.ncomp += 1;
                            let m = format!("§c{}§", self.ncomp);
                            if let Some(e) = self.pila.get_mut(idx) {
                                *e = VP::E(m.clone());
                            }
                            m
                        }
                    };
                    let tipo = match n {
                        "LIST_APPEND" => '[',
                        "SET_ADD" => '{',
                        _ => 'd',
                    };
                    let elem = match k {
                        Some(k) => format!("{k}: {v}"),
                        None => v,
                    };
                    self.comps.entry(marca.clone()).or_insert((tipo, Vec::new())).0 = tipo;
                    l.push(S::Txt(format!("§append§{marca}§{elem}")));
                }
                "BUILD_MAP" => {
                    let mut v: Vec<String> = (0..a)
                        .map(|_| {
                            let val = self.pop_e();
                            let k = self.pop_e();
                            format!("{k}: {val}")
                        })
                        .collect();
                    v.reverse();
                    if a == 0 {
                        self.ncomp += 1;
                        let m = format!("§c{}§", self.ncomp);
                        self.comps.insert(m.clone(), ('d', Vec::new()));
                        self.pila.push(VP::E(m));
                    } else {
                        self.pila.push(VP::E(format!("{{{}}}", v.join(", "))));
                    }
                }
                "BUILD_CONST_KEY_MAP" => {
                    let claves = tupla_a_lista(&self.pop_e());
                    let mut vals: Vec<String> = (0..a).map(|_| self.pop_e()).collect();
                    vals.reverse();
                    let v: Vec<String> = claves.iter().zip(vals).map(|(k, v)| format!("{k}: {v}")).collect();
                    self.pila.push(VP::E(format!("{{{}}}", v.join(", "))));
                }
                "BUILD_STRING" => {
                    let mut v: Vec<String> = (0..a).map(|_| self.pop_e()).collect();
                    v.reverse();
                    let mut s = String::from("f\"");
                    for p in v {
                        if let Some(r) = p.strip_prefix("§fmt§") {
                            s.push_str(r);
                        } else if p.starts_with('"') && p.ends_with('"') {
                            s.push_str(&p[1..p.len() - 1].replace('{', "{{").replace('}', "}}"));
                        } else {
                            let _ = write!(s, "{{{p}}}");
                        }
                    }
                    s.push('"');
                    self.pila.push(VP::E(s));
                }
                "FORMAT_VALUE" | "FORMAT_SIMPLE" | "FORMAT_WITH_SPEC" | "CONVERT_VALUE" => {
                    let spec = if n == "FORMAT_WITH_SPEC" || (n == "FORMAT_VALUE" && a & 4 == 4) {
                        let sp = self.pop_e();
                        let sp = if let Some(r) = sp.strip_prefix("§fmt§") { r.to_string() } else { sin_comillas(&sp) };
                        format!(":{sp}")
                    } else {
                        String::new()
                    };
                    let conv = match (n, a & 3) {
                        ("FORMAT_VALUE" | "CONVERT_VALUE", 1) => "!s",
                        ("FORMAT_VALUE" | "CONVERT_VALUE", 2) => "!r",
                        ("FORMAT_VALUE" | "CONVERT_VALUE", 3) => "!a",
                        _ => "",
                    };
                    let v = self.pop_e();
                    if n == "CONVERT_VALUE" {
                        self.pila.push(VP::E(format!("§conv§{v}{conv}")));
                    } else {
                        let (v, conv2) = match v.strip_prefix("§conv§") {
                            Some(r) => {
                                let (e, c) = r.rsplit_once('!').map(|(e, c)| (e.to_string(), format!("!{c}"))).unwrap_or((r.to_string(), String::new()));
                                (e, c)
                            }
                            None => (v, conv.to_string()),
                        };
                        self.pila.push(VP::E(format!("§fmt§{{{v}{conv2}{spec}}}")));
                    }
                }
                "KW_NAMES" => {
                    self.kwnames = match self.c.consts.get(a) {
                        Some(Py::Tupla(v)) => v.iter().map(|k| sin_comillas(&codigo::repr_py(k))).collect(),
                        _ => Vec::new(),
                    };
                }
                "CALL" | "CALL_FUNCTION" | "CALL_METHOD" | "CALL_FUNCTION_KW" | "CALL_KW" | "CALL_FUNCTION_EX" => {
                    let mut kw = std::mem::take(&mut self.kwnames);
                    if n == "CALL_FUNCTION_KW" || n == "CALL_KW" {
                        kw = tupla_a_lista(&self.pop_e()).into_iter().map(|s| sin_comillas(&s)).collect();
                    }
                    let mut args: Vec<VP> = Vec::new();
                    let mut textos: Vec<String>;
                    if n == "CALL_FUNCTION_EX" {
                        let kwargs = if a & 1 == 1 { Some(self.pop_e()) } else { None };
                        let pos = self.pop_e();
                        textos = if pos.starts_with('(') && !pos.contains(" for ") { tupla_a_lista(&pos) } else { vec![format!("*{pos}")] };
                        if let Some(k) = kwargs {
                            if k.starts_with('{') && k.ends_with('}') && !k.contains("**") {
                                for par in tupla_a_lista(&format!("({})", &k[1..k.len() - 1])) {
                                    if let Some((kk, vv)) = par.split_once(": ") {
                                        textos.push(format!("{}={vv}", sin_comillas(kk)));
                                    }
                                }
                            } else {
                                textos.push(format!("**{}", k.trim_start_matches("{**").trim_end_matches('}')));
                            }
                        }
                    } else {
                        for _ in 0..a {
                            args.push(self.pop());
                        }
                        args.reverse();
                        textos = args.iter().map(|v| self.txt(v)).collect();
                        let nkw = kw.len().min(textos.len());
                        let base = textos.len() - nkw;
                        for (k, nombre) in kw.iter().enumerate().take(nkw) {
                            textos[base + k] = format!("{nombre}={}", textos[base + k]);
                        }
                    }
                    // invocable según la convención de llamada de cada versión
                    let (invocable, extra) = match n {
                        "CALL_FUNCTION" | "CALL_FUNCTION_KW" => (self.pop(), None),
                        "CALL_FUNCTION_EX" if self.menor < 11 => (self.pop(), None),
                        _ => {
                            let arriba = self.pop();
                            let abajo = self.pop();
                            match (abajo, arriba) {
                                (VP::Nulo, f) => (f, None),
                                (f, VP::Nulo) => (f, None),
                                (f, s) => (f, Some(s)),
                            }
                        }
                    };
                    if let Some(s) = extra {
                        textos.insert(0, self.txt(&s));
                        args.insert(0, s);
                    }
                    match invocable {
                        VP::BuildClass => {
                            if let Some(VP::Func(cod, _)) = args.first() {
                                let nombre = textos.get(1).map(|t| sin_comillas(t)).unwrap_or_default();
                                let bases = textos[2.min(textos.len())..].join(", ");
                                let cab = format!("class {nombre}{}", if bases.is_empty() { String::new() } else { format!("({bases})") });
                                let mut cuerpo = PyDec::new(cod, self.t, self.menor).cuerpo();
                                cuerpo.retain(|s| {
                                    !matches!(s, S::Txt(t) if t.starts_with("__module__ =") || t.starts_with("__qualname__ =") || t.starts_with("__firstlineno__ =")
                                        || t.starts_with("__static_attributes__ =") || t.starts_with("__classdictcell__ =") || t == "return __class__" || t.starts_with("__classcell__"))
                                });
                                self.pila.push(VP::Clase(cab, cuerpo));
                            } else {
                                self.pila.push(VP::E(format!("__build_class__({})", textos.join(", "))));
                            }
                        }
                        VP::Func(cod, _) if args.len() == 1 && matches!(cod.name.as_str(), "<listcomp>" | "<setcomp>" | "<dictcomp>" | "<genexpr>") => {
                            let it = textos[0].trim_start_matches("§iter§").to_string();
                            let t = self.comprension(&cod, &it).unwrap_or_else(|| format!("{}({it})", cod.name));
                            self.pila.push(VP::E(t));
                        }
                        f if args.len() == 1 && kw.is_empty() && matches!(args[0], VP::Func(..) | VP::Deco(..) | VP::Clase(..)) && n != "CALL_FUNCTION_EX" => {
                            // decorador
                            let deco = self.txt(&f);
                            let interno = args.pop().unwrap();
                            let nuevo = match interno {
                                VP::Deco(mut d, o) => {
                                    d.insert(0, deco);
                                    VP::Deco(d, o)
                                }
                                o => VP::Deco(vec![deco], Box::new(o)),
                            };
                            self.pila.push(nuevo);
                        }
                        otro => {
                            let f = self.txt(&otro);
                            let textos: Vec<String> = textos.into_iter().map(|t| t.trim_start_matches("§iter§").to_string()).collect();
                            self.pila.push(VP::E(format!("{}({})", envolver(&f), textos.join(", "))));
                        }
                    }
                }
                "LOAD_BUILD_CLASS" => self.pila.push(VP::BuildClass),
                "MAKE_FUNCTION" => {
                    let mut tope = self.pop();
                    if self.menor < 11 {
                        // ≤3.10: nombre cualificado encima del código
                        if let VP::E(_) = tope {
                            tope = self.pop();
                        }
                    }
                    let cod = match tope {
                        VP::Cod(c) => c,
                        _ => Box::default(),
                    };
                    let mut defaults = Vec::new();
                    if self.menor < 13 {
                        if a & 0x08 != 0 {
                            let _ = self.pop();
                        }
                        if a & 0x04 != 0 {
                            let _ = self.pop();
                        }
                        if a & 0x02 != 0 {
                            let _ = self.pop();
                        }
                        if a & 0x01 != 0 {
                            defaults = tupla_a_lista(&self.pop_e());
                        }
                    }
                    self.pila.push(VP::Func(cod, defaults));
                }
                "SET_FUNCTION_ATTRIBUTE" => {
                    let f = self.pop();
                    let v = self.pop_e();
                    let f = match f {
                        VP::Func(c, _) if a == 1 => VP::Func(c, tupla_a_lista(&v)),
                        otro => otro,
                    };
                    self.pila.push(f);
                }
                "RETURN_VALUE" => {
                    let v = self.pop();
                    let t = self.txt(&v);
                    if self.comp_externa && (t.starts_with("§c") || t.starts_with('[') || t.starts_with('{')) {
                        // fin de comprensión ≤3.11: el plegado ya dejó su texto
                    } else if !(t == "None" && (self.es_modulo() || i + 1 == ins.len())) && !matches!(v, VP::Clase(..)) {
                        l.push(S::Txt(format!("return {t}")));
                    }
                    self.pila.clear();
                }
                "YIELD_VALUE" => {
                    let v = self.pop_e();
                    if self.c.name == "<genexpr>" {
                        l.push(S::Txt(format!("§append§§cgen§§{v}")));
                        self.pila.push(VP::E("None".into()));
                    } else {
                        self.pila.push(VP::E(if v == "None" { "(yield)".into() } else { format!("(yield {v})") }));
                    }
                }
                "GET_AWAITABLE" | "GET_YIELD_FROM_ITER" => {
                    let v = self.pop_e();
                    let pal = if n == "GET_AWAITABLE" { "await" } else { "yield from" };
                    self.pila.push(VP::E(format!("{pal} {}", if nivel(&v) < 13 { format!("({v})") } else { v })));
                    // salta la maquinaria SEND/YIELD_VALUE/RESUME del await
                    let mut q = i + 1;
                    if ins.get(q).map(|y| y.nombre == "LOAD_CONST" && y.texto == "None").unwrap_or(false) {
                        q += 1;
                        match ins.get(q).map(|y| y.nombre) {
                            Some("YIELD_FROM") => {
                                i = q + 1;
                                continue;
                            }
                            Some("SEND") => {
                                if let Some(k) = (q..ins.len()).find(|&k| ins[k].nombre == "END_SEND") {
                                    i = k + 1;
                                    continue;
                                }
                                if let Some(dst) = ins[q].salto.and_then(pos) {
                                    i = dst;
                                    continue;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "SEND" | "YIELD_FROM" | "ASYNC_GEN_WRAP" | "CALL_INTRINSIC_2" | "GET_ANEXT" | "END_ASYNC_FOR" => {}
                "RAISE_VARARGS" => {
                    let t = match a {
                        0 => "raise".to_string(),
                        1 => format!("raise {}", self.pop_e()),
                        _ => {
                            let c = self.pop_e();
                            let e = self.pop_e();
                            format!("raise {e} from {c}")
                        }
                    };
                    l.push(S::Txt(t));
                    self.pila.clear();
                }
                "IMPORT_NAME" => {
                    let _desde = self.pop_e();
                    let _nivel = self.pop_e();
                    self.pila.push(VP::E(format!("§import§{}", x.texto)));
                }
                "IMPORT_FROM" => {
                    let m = match self.pila.last() {
                        Some(VP::E(t)) => t.clone(),
                        _ => String::new(),
                    };
                    self.pila.push(VP::E(format!("§from§{}§{}", m.trim_start_matches("§import§"), x.texto)));
                }
                "IMPORT_STAR" => {
                    let m = self.pop_e();
                    l.push(S::Txt(format!("from {} import *", m.trim_start_matches("§import§"))));
                }
                "GET_ITER" | "GET_AITER" => {
                    let it = self.pop_e();
                    self.pila.push(VP::E(format!("§iter§{it}")));
                }
                "FOR_ITER" => {
                    let it = self.pop_e();
                    let it = it.trim_start_matches("§iter§").to_string();
                    let mut salida = x.salto.unwrap_or(0);
                    if self.menor >= 12 {
                        if let Some(p) = pos(salida) {
                            if ins[p].nombre == "END_FOR" {
                                let mut q = p + 1;
                                while q < ins.len() && matches!(ins[q].nombre, "POP_TOP" | "POP_ITER" | "NOT_TAKEN") {
                                    q += 1;
                                }
                                if let Some(y) = ins.get(q) {
                                    salida = y.off;
                                }
                            }
                        }
                    }
                    etiquetas.insert(salida);
                    if !self.pila.is_empty() {
                        pila_en.entry(salida).or_insert_with(|| self.pila.clone());
                    }
                    l.push(S::Para("<item>".into(), it, salida));
                    self.pila.push(VP::Item);
                }
                "UNPACK_SEQUENCE" | "UNPACK_EX" => {
                    let v = self.pop();
                    let total = if n == "UNPACK_EX" { (a & 0xff) + 1 + (a >> 8) } else { a };
                    let mut dest = Vec::new();
                    let mut j = i + 1;
                    while j < ins.len() && dest.len() < total && ins[j].nombre.starts_with("STORE_") {
                        match ins[j].nombre {
                            "STORE_ATTR" | "STORE_SUBSCR" | "STORE_FAST_LOAD_FAST" => break,
                            "STORE_FAST_STORE_FAST" => {
                                let b = ins[j].arg.unwrap_or(0) as usize;
                                dest.push(self.nombre_local(b >> 4));
                                dest.push(self.nombre_local(b & 15));
                            }
                            _ => dest.push(ins[j].texto.clone()),
                        }
                        j += 1;
                    }
                    if dest.len() == total {
                        if n == "UNPACK_EX" {
                            let k = a & 0xff;
                            dest[k] = format!("*{}", dest[k]);
                        }
                        self.asignar(&mut l, dest.join(", "), v);
                        i = j;
                        continue;
                    }
                    let base = self.txt(&v);
                    for k in (0..total).rev() {
                        self.pila.push(VP::E(format!("{}[{k}]", envolver(&base))));
                    }
                }
                "COPY" | "DUP_TOP" if {
                    let sig = ins.get(i + 1).map(|y| y.nombre).unwrap_or("");
                    let sig2 = ins.get(i + 2).map(|y| y.nombre).unwrap_or("");
                    (n == "DUP_TOP" && sig == "ROT_THREE" && matches!(sig2, "COMPARE_OP" | "IS_OP" | "CONTAINS_OP"))
                } => {
                    // ≤3.10: a b DUP_TOP ROT_THREE COMPARE_OP → cadena
                    if let Some(VP::E(b)) = self.pila.last() {
                        self.cad_b = Some(b.clone());
                    }
                    i += 2;
                    continue;
                }
                "SWAP" if a == 2 && ins.get(i + 1).map(|y| y.nombre == "COPY" && y.arg == Some(2)).unwrap_or(false)
                    && ins.get(i + 2).map(|y| matches!(y.nombre, "COMPARE_OP" | "IS_OP" | "CONTAINS_OP")).unwrap_or(false) => {
                    // ≥3.11: a b SWAP 2 COPY 2 COMPARE_OP → cadena
                    if let Some(VP::E(b)) = self.pila.last() {
                        self.cad_b = Some(b.clone());
                    }
                    i += 2;
                    continue;
                }
                "COPY" | "DUP_TOP" => {
                    let k = if n == "DUP_TOP" { 1 } else { a.max(1) };
                    // patrón and/or (≥3.12): COPY 1; [TO_BOOL]; POP_JUMP_IF_*; POP_TOP
                    if k == 1 {
                        let mut q = i + 1;
                        if ins.get(q).map(|y| y.nombre == "TO_BOOL").unwrap_or(false) {
                            q += 1;
                        }
                        let mut r = q + 1;
                        if ins.get(r).map(|y| y.nombre == "NOT_TAKEN").unwrap_or(false) {
                            r += 1;
                        }
                        if let (Some(jmp), Some(pt)) = (ins.get(q), ins.get(r)) {
                            if matches!(jmp.nombre, "POP_JUMP_IF_FALSE" | "POP_JUMP_IF_TRUE" | "POP_JUMP_FORWARD_IF_FALSE" | "POP_JUMP_FORWARD_IF_TRUE") && pt.nombre == "POP_TOP" && jmp.salto.map(|d| d > jmp.off).unwrap_or(false) {
                                if let Some(b) = self.cad_pend.take() {
                                    let izq = self.pop_e();
                                    self.cad_izq = Some(izq);
                                    self.pila.push(VP::E(b));
                                    omitir_cadena(&ins, jmp.salto.unwrap(), &mut omitir);
                                    i = r + 1;
                                    continue;
                                }
                                let izq = self.pop_e();
                                let op = if jmp.nombre.ends_with("FALSE") { "and" } else { "or" };
                                boolop.push((jmp.salto.unwrap(), izq, op, self.pila.len()));
                                i = r + 1;
                                continue;
                            }
                        }
                    }
                    if let Some(v) = self.pila.get(self.pila.len().saturating_sub(k)).cloned() {
                        self.pila.push(v);
                    }
                }
                "DUP_TOP_TWO" => {
                    let n2 = self.pila.len();
                    if n2 >= 2 {
                        let (p, q) = (self.pila[n2 - 2].clone(), self.pila[n2 - 1].clone());
                        self.pila.push(p);
                        self.pila.push(q);
                    }
                }
                "SWAP" | "ROT_TWO" => {
                    let k = if n == "ROT_TWO" { 2 } else { a.max(2) };
                    let n2 = self.pila.len();
                    if n2 >= k {
                        self.pila.swap(n2 - 1, n2 - k);
                    }
                }
                "ROT_THREE" | "ROT_FOUR" => {
                    let k = if n == "ROT_THREE" { 3 } else { 4 };
                    if self.pila.len() >= k {
                        let t = self.pila.pop().unwrap();
                        let p = self.pila.len() + 1 - k;
                        self.pila.insert(p, t);
                    }
                }
                "JUMP_IF_FALSE_OR_POP" | "JUMP_IF_TRUE_OR_POP" if self.cad_pend.is_some() => {
                    let b = self.cad_pend.take().unwrap();
                    let izq = self.pop_e();
                    self.cad_izq = Some(izq);
                    self.pila.push(VP::E(b));
                    if let Some(d) = x.salto {
                        omitir_cadena(&ins, d, &mut omitir);
                    }
                }
                "JUMP_IF_FALSE_OR_POP" | "JUMP_IF_TRUE_OR_POP" => {
                    let izq = self.pop_e();
                    let op = if n.contains("FALSE") { "and" } else { "or" };
                    if let Some(d) = x.salto {
                        boolop.push((d, izq, op, self.pila.len()));
                    }
                }
                "POP_JUMP_IF_FALSE" | "POP_JUMP_IF_TRUE" | "POP_JUMP_IF_NONE" | "POP_JUMP_IF_NOT_NONE" | "POP_JUMP_FORWARD_IF_FALSE"
                | "POP_JUMP_FORWARD_IF_TRUE" | "POP_JUMP_BACKWARD_IF_FALSE" | "POP_JUMP_BACKWARD_IF_TRUE" | "POP_JUMP_FORWARD_IF_NONE"
                | "POP_JUMP_FORWARD_IF_NOT_NONE" | "POP_JUMP_BACKWARD_IF_NONE" | "POP_JUMP_BACKWARD_IF_NOT_NONE" => {
                    let v = self.pop_e();
                    let dest = x.salto.unwrap_or(0);
                    if let Some(t) = v.strip_prefix("§excmatch§") {
                        poner_tipo_except(&mut l, t, &mut manejos);
                        // el salto va al siguiente "except" o a re-lanzar
                    } else {
                        let c = if n.ends_with("NOT_NONE") {
                            Cond::bin(v, "is not", "None".into())
                        } else if n.ends_with("NONE") {
                            Cond::bin(v, "is", "None".into())
                        } else if n.contains("TRUE") {
                            Cond::si(v)
                        } else {
                            Cond::no(v)
                        };
                        if !self.pila.is_empty() {
                            pila_en.entry(dest).or_insert_with(|| self.pila.clone());
                        }
                        l.push(S::Si(c, dest));
                    }
                }
                "JUMP_FORWARD" | "JUMP_ABSOLUTE" | "JUMP_BACKWARD" | "JUMP_BACKWARD_NO_INTERRUPT" | "JUMP" | "JUMP_NO_INTERRUPT" | "CONTINUE_LOOP" => {
                    let dest = x.salto.unwrap_or(0);
                    // a < b <= c: el atajo (L1) solo limpia la copia de b y converge en dest
                    if let (Some(&(l1, _, _, prof)), Some(sig)) = (boolop.last(), ins.get(i + 1)) {
                        let limpieza = ins.get(i + 2).map(|y| y.nombre == "POP_TOP").unwrap_or(false)
                            && matches!(sig.nombre, "SWAP" | "ROT_TWO")
                            && ins.get(i + 3).map(|y| y.off == dest).unwrap_or(false);
                        if sig.off == l1 && limpieza && self.pila.len() == prof + 1 {
                            let (_, izq, op, _) = boolop.pop().unwrap();
                            let der = self.pop_e();
                            let _ = self.pila.pop(); // la copia de b
                            let ultimo_izq = izq.rsplit(' ').next().unwrap_or("").to_string();
                            let primero_der = der.split(' ').next().unwrap_or("").to_string();
                            let t = if op == "and" && !ultimo_izq.is_empty() && ultimo_izq == primero_der && nivel(&izq) == 5 && nivel(&der) == 5 {
                                format!("{izq} {}", der.splitn(2, ' ').nth(1).unwrap_or(""))
                            } else {
                                op_bin(&izq, op, &der)
                            };
                            self.pila.push(VP::E(t));
                            i += 3;
                            continue;
                        }
                    }
                    if !self.pila.is_empty() {
                        pila_en.entry(dest).or_insert_with(|| self.pila.clone());
                    }
                    l.push(S::Ir(dest));
                    self.pila.clear();
                }
                "LOAD_LOCALS" => self.pila.push(VP::E("locals()".into())),
                "PRINT_EXPR" => {
                    let v = self.pop_e();
                    l.push(S::Txt(v));
                }
                "LOAD_SPECIAL" => {
                    let o = self.pop_e();
                    self.pila.push(VP::E(format!("§with§{o}")));
                    self.pila.push(VP::Nulo);
                }
                "MATCH_CLASS" | "MATCH_MAPPING" | "MATCH_SEQUENCE" | "MATCH_KEYS" | "GET_LEN" => {
                    l.push(S::Txt(format!("# {n} (match/case)")));
                }
                otro => {
                    l.push(S::Txt(format!("# {otro} {}", x.texto)));
                }
            }
            i += 1;
        }
            let v = estructurar(bloques_try(l, true), &BTreeSet::new(), true);
        let v = self.plegar_comprensiones(v);
        if self.comp_externa {
            return v;
        }
        let mut v = Self::limpiar(v);
        // el "return None" implícito del final sobra
        if matches!(v.last(), Some(S::Txt(t)) if t == "return None") {
            v.pop();
        }
        v
    }

    /// Sustituye marcadores de comprensión por su texto plegado (o por `[]`).
    fn resolver_marcadores(&self, t: &str) -> String {
        let mut s = t.to_string();
        for (m, (tipo, el)) in &self.comps {
            if s.contains(m.as_str()) {
                let rep = match (tipo, el.first()) {
                    (_, Some(e)) => e.clone(),
                    ('[', None) => "[]".into(),
                    ('d', None) => "{}".into(),
                    (_, None) => "set()".into(),
                };
                s = s.replace(m.as_str(), &rep);
            }
        }
        s
    }

    /// Bloques `for` cuyo cuerpo solo añade a una comprensión → `[e for x in it if c]`.
    fn plegar_comprensiones(&mut self, v: Vec<S>) -> Vec<S> {
        fn partes(v: &[S], conds: &mut Vec<String>, fors: &mut Vec<String>) -> Option<(String, String)> {
            match v {
                [S::Txt(t)] if t.starts_with("§append§") => parse_append(t),
                [S::Bloque(c, b)] if c.starts_with("if ") => {
                    conds.push(c[3..].to_string());
                    partes(b, conds, fors)
                }
                [S::Bloque(c, b)] if c.starts_with("for ") => {
                    fors.push(c.clone());
                    partes(b, conds, fors)
                }
                // "if c: continue" + resto  →  condición negada
                [S::Bloque(c, b), resto @ ..] if c.starts_with("if ") && matches!(b.as_slice(), [S::Txt(t)] if t == "continue") => {
                    let t = c[3..].trim();
                    let txt = if let Some(r) = t.strip_prefix("not (").and_then(|r| r.strip_suffix(')')) {
                        r.to_string()
                    } else if let Some(r) = t.strip_prefix("not ") {
                        r.to_string()
                    } else if nivel(t) <= 4 {
                        format!("not ({t})")
                    } else {
                        format!("not {t}")
                    };
                    conds.push(txt);
                    partes(resto, conds, fors)
                }
                _ => None,
            }
        }
        let mut out = Vec::new();
        for s in v {
            match s {
                S::Bloque(c, b) if c.starts_with("for ") => {
                    let b2 = self.plegar_comprensiones(b.clone());
                    let mut conds = Vec::new();
                    let mut fors = vec![c.clone()];
                    if let Some((m, e)) = partes(&b2, &mut conds, &mut fors) {
                        let mut txt = e.clone();
                        for f in &fors {
                            txt.push(' ');
                            txt.push_str(f);
                        }
                        for k in &conds {
                            txt.push_str(" if ");
                            txt.push_str(k);
                        }
                        if m == "§cgen§" {
                            out.push(S::Txt(format!("§compexpr§{txt}")));
                            continue;
                        }
                        let tipo = self.comps.get(&m).map(|x| x.0).unwrap_or('[');
                        if self.comp_externa {
                            out.push(S::Txt(format!("§compexpr§{txt}")));
                        }
                        let rep = match tipo {
                            '[' => format!("[{txt}]"),
                            _ => format!("{{{txt}}}"),
                        };
                        self.comps.insert(m, (tipo, vec![rep]));
                    } else {
                        out.push(S::Bloque(c, b2));
                    }
                }
                S::Bloque(c, b) => {
                    let b = self.plegar_comprensiones(b);
                    out.push(S::Bloque(c, b));
                }
                S::SiSino(c, a, b) => {
                    let a = self.plegar_comprensiones(a);
                    let b = self.plegar_comprensiones(b);
                    out.push(S::SiSino(c, a, b));
                }
                otro => out.push(otro),
            }
        }
        // aplica los textos plegados a todas las líneas
        fn aplicar(v: Vec<S>, f: &dyn Fn(&str) -> String) -> Vec<S> {
            v.into_iter()
                .map(|s| match s {
                    S::Txt(t) if t.starts_with("§append§") => S::Txt(t),
                    S::Txt(t) => S::Txt(f(&t)),
                    S::Bloque(c, b) => S::Bloque(f(&c), aplicar(b, f)),
                    S::SiSino(c, a, b) => S::SiSino(f(&c), aplicar(a, f), aplicar(b, f)),
                    S::Si(c, l) => S::Si(Cond { izq: f(&c.izq), op: c.op, der: f(&c.der), partes: c.partes.clone() }, l),
                    S::Para(t, it, l) => S::Para(t, f(&it), l),
                    otro => otro,
                })
                .collect()
        }
        let comps = self.comps.clone();
        let res = move |t: &str| -> String {
            let mut s = t.to_string();
            for (m, (tipo, el)) in &comps {
                if s.contains(m.as_str()) {
                    let rep = match (tipo, el.first()) {
                        (_, Some(e)) => e.clone(),
                        ('[', None) => "[]".into(),
                        ('d', None) => "{}".into(),
                        (_, None) => "set()".into(),
                    };
                    s = s.replace(m.as_str(), &rep);
                }
            }
            s
        };
        aplicar(out, &res)
    }

    /// Limpieza final (una sola vez, al final): restos de comprensiones no
    /// plegadas y del `e = None; del e` que el compilador añade tras `except … as e`.
    fn limpiar(v: Vec<S>) -> Vec<S> {
        let mut limpio: Vec<S> = Vec::new();
        for s in v {
            let s = match s {
                S::Bloque(c, b) => S::Bloque(c, Self::limpiar(b)),
                S::SiSino(c, a, b) => S::SiSino(c, Self::limpiar(a), Self::limpiar(b)),
                otro => otro,
            };
            if let S::Txt(t) = &s {
                if t.contains("§guardado§") || t.starts_with("§compexpr§") {
                    continue;
                }
                if let Some((_, e)) = parse_append(t) {
                    limpio.push(S::Txt(format!("$comp.append({e})")));
                    continue;
                }
                if let Some(nom) = t.strip_prefix("del ") {
                    if matches!(limpio.last(), Some(S::Txt(p)) if *p == format!("{nom} = None")) {
                        limpio.pop();
                        continue;
                    }
                }
            }
            limpio.push(s);
        }
        limpio
    }

    fn asignar(&mut self, l: &mut Vec<S>, destino: String, v: VP) {
        match v {
            VP::Item => {
                if let Some(S::Para(t, _, _)) = l.iter_mut().rev().find(|s| matches!(s, S::Para(t, _, _) if t == "<item>")) {
                    *t = destino;
                    return;
                }
                l.push(S::Txt(format!("{destino} = <item>")));
            }
            VP::Func(c, d) => {
                if c.name == "<lambda>" {
                    let t = self.lambda(&c, &d);
                    l.push(S::Txt(format!("{destino} = {t}")));
                    return;
                }
                let asincrona = c.flags & 0x80 != 0 || c.flags & 0x200 != 0;
                let cab = format!("{}def {destino}({})", if asincrona { "async " } else { "" }, self.args_de(&c, &d));
                let cuerpo = PyDec::new(&c, self.t, self.menor).cuerpo();
                l.push(S::Bloque(cab, cuerpo));
            }
            VP::Clase(cab, cuerpo) => {
                l.push(S::Bloque(cab, cuerpo));
            }
            VP::Deco(decos, o) => {
                for d in &decos {
                    l.push(S::Txt(format!("@{d}")));
                }
                self.asignar(l, destino, *o);
            }
            VP::E(t) if t.starts_with("§with§") => {
                l.push(S::Txt(format!("with {} as {destino}:  # bloque with", &t["§with§".len()..])));
            }
            VP::E(t) if t == "§guardado§" => {}
            VP::E(t) if t.starts_with("§import§") => {
                let m = t.trim_start_matches("§import§");
                let raiz = m.split('.').next().unwrap_or(m);
                if destino == raiz || destino == m {
                    l.push(S::Txt(format!("import {m}")));
                } else {
                    l.push(S::Txt(format!("import {m} as {destino}")));
                }
            }
            VP::E(t) if t.starts_with("§from§") => {
                let p: Vec<&str> = t.split('§').filter(|s| !s.is_empty()).collect();
                let (m, n) = (p.get(1).copied().unwrap_or(""), p.get(2).copied().unwrap_or(""));
                let alias = if n == destino { String::new() } else { format!(" as {destino}") };
                if let Some(S::Txt(prev)) = l.last_mut() {
                    if prev.starts_with(&format!("from {m} import ")) && !prev.contains('*') {
                        prev.push_str(&format!(", {n}{alias}"));
                        return;
                    }
                }
                l.push(S::Txt(format!("from {m} import {n}{alias}")));
            }
            VP::E(t) if t.starts_with("§aug§") => {
                let p: Vec<&str> = t["§aug§".len()..].splitn(3, '§').collect();
                if p.len() == 3 && p[0] == destino {
                    l.push(S::Txt(format!("{destino} {} {}", p[1], p[2])));
                } else if p.len() == 3 {
                    l.push(S::Txt(format!("{destino} = {}", op_bin(p[0], p[1].trim_end_matches('='), p[2]))));
                }
            }
            VP::E(t) if t == "$exc" || t == "$val" => {
                if let Some(S::Txt(prev)) = l.iter_mut().rev().find(|s| matches!(s, S::Txt(t) if t.starts_with("§except§"))) {
                    if !prev.contains(" as ") {
                        if prev == "§except§" {
                            prev.push_str("BaseException");
                        }
                        prev.push_str(&format!(" as {destino}"));
                    }
                }
            }
            VP::E(t) if t.starts_with("§iter§") => l.push(S::Txt(format!("{destino} = iter({})", &t["§iter§".len()..]))),
            otro => {
                let t = self.txt(&otro);
                if t.starts_with('$') {
                    return;
                }
                l.push(S::Txt(format!("{destino} = {t}")));
            }
        }
    }
}

/// "§append§§c1§§expr" → ("§c1§", "expr")
fn parse_append(t: &str) -> Option<(String, String)> {
    let r = t.strip_prefix("§append§")?.strip_prefix('§')?;
    let (nombre, resto) = r.split_once('§')?;
    let e = resto.strip_prefix('§')?;
    Some((format!("§{nombre}§"), e.to_string()))
}

/// Atajo de una comparación encadenada: `L1: ROT_TWO|SWAP 2; POP_TOP; [salto|return]`.
fn omitir_cadena(ins: &[codigo::InstrPy], l1: usize, omitir: &mut BTreeSet<usize>) {
    if let Some(p) = ins.iter().position(|y| y.off == l1) {
        if matches!(ins[p].nombre, "ROT_TWO" | "SWAP") && ins.get(p + 1).map(|y| y.nombre == "POP_TOP").unwrap_or(false) {
            omitir.insert(ins[p].off);
            omitir.insert(ins[p + 1].off);
            if let Some(y) = ins.get(p + 2) {
                // solo si es el final duplicado del atajo, no el punto donde convergen ambos caminos
                let destino = ins.iter().any(|z| z.salto == Some(y.off));
                if !destino && matches!(y.nombre, "RETURN_VALUE" | "JUMP_FORWARD" | "JUMP" | "JUMP_ABSOLUTE") {
                    omitir.insert(y.off);
                }
            }
        }
    }
}

/// Un manejador es `finally` si, hasta el re-lanzamiento, no compara tipos ni
/// cierra un `except` (POP_EXCEPT).
fn es_finally(ins: &[codigo::InstrPy], desde: usize) -> bool {
    for y in &ins[desde + 1..] {
        match y.nombre {
            "CHECK_EXC_MATCH" | "JUMP_IF_NOT_EXC_MATCH" | "POP_EXCEPT" => return false,
            "COMPARE_OP" if y.texto.contains("exception") => return false,
            "RERAISE" | "END_FINALLY" => return true,
            _ => {}
        }
    }
    false
}

/// Pone el tipo al `except` abierto o, si ya tenía, abre una cláusula nueva.
fn poner_tipo_except(l: &mut Vec<S>, t: &str, manejos: &mut Vec<bool>) {
    if manejos.last() == Some(&false) {
        if let Some(S::Txt(prev)) = l.iter_mut().rev().find(|s| matches!(s, S::Txt(t) if t.starts_with("§except§"))) {
            if prev == "§except§" {
                prev.push_str(t);
                return;
            }
        }
    }
    l.push(S::Txt(format!("§except§{t}")));
    manejos.push(false);
}

/// Convierte los marcadores §try§ / §except§ en bloques `try:` / `except …:` /
/// `finally:` cuando sus regiones son autocontenidas; si no, en comentarios.
fn bloques_try(v: Vec<S>, py: bool) -> Vec<S> {
    // las etiquetas que ningún salto usa (entradas de manejador) no cuentan
    let mut usadas = HashMap::new();
    referencias(&v, &mut usadas);
    let v: Vec<S> = v.into_iter().filter(|x| !matches!(x, S::Etq(l) if !usadas.contains_key(l))).collect();
    let mut v2: Vec<S> = Vec::new();
    for x in v {
        if let S::Txt(t) = &x {
            if let Some(nom) = t.strip_prefix("del ") {
                if matches!(v2.last(), Some(S::Txt(p)) if *p == format!("{nom} = None")) {
                    v2.pop();
                    continue;
                }
            }
        }
        v2.push(x);
    }
    let v = v2;
    let es = |s: &S, m: &str| matches!(s, S::Txt(t) if t == m);
    let empieza = |s: &S, m: &str| matches!(s, S::Txt(t) if t.starts_with(m));
    let mut cuenta_total = HashMap::new();
    referencias(&v, &mut cuenta_total);
    let mut out: Vec<S> = Vec::new();
    let mut i = 0;
    while i < v.len() {
        let abre = if es(&v[i], "§try§") {
            Some(("§try§", "§/try§"))
        } else if empieza(&v[i], "§except§") {
            Some(("§except§", "§/except§"))
        } else {
            None
        };
        if let Some((a, c)) = abre {
            let mut prof = 0;
            let mut j = None;
            for k in i..v.len() {
                let abre_k = if a == "§try§" { es(&v[k], a) } else { empieza(&v[k], a) };
                if abre_k {
                    prof += 1;
                } else if es(&v[k], c) {
                    prof -= 1;
                    if prof == 0 {
                        j = Some(k);
                        break;
                    }
                }
            }
            if let Some(j) = j {
                let region = &v[i + 1..j];
                let mut internas = BTreeSet::new();
                for x in region {
                    if let S::Etq(l) = x {
                        internas.insert(*l);
                    }
                }
                let mut cuenta_dentro = HashMap::new();
                referencias(region, &mut cuenta_dentro);
                let ok = internas.iter().all(|l| cuenta_dentro.get(l).copied().unwrap_or(0) == cuenta_total.get(l).copied().unwrap_or(0));
                if ok {
                    let cab = match &v[i] {
                        S::Txt(t) if t == "§try§" => "try".to_string(),
                        S::Txt(t) => {
                            let r = t.trim_start_matches("§except§");
                            if r == "finally" {
                                "finally".into()
                            } else if r.is_empty() {
                                "except".into()
                            } else {
                                format!("except {r}")
                            }
                        }
                        _ => String::new(),
                    };
                    let cuerpo = estructurar(bloques_try(region.to_vec(), py), &BTreeSet::new(), py);
                    out.push(S::Bloque(cab, cuerpo));
                    i = j + 1;
                    continue;
                }
            }
        }
        match &v[i] {
            S::Txt(t) if t == "§try§" => out.push(S::Txt("# try:".into())),
            S::Txt(t) if t == "§/try§" || t == "§/except§" => {}
            S::Txt(t) if t.starts_with("§except§") => {
                let r = t.trim_start_matches("§except§");
                out.push(S::Txt(if r == "finally" { "# finally:".into() } else { format!("# except {r}:") }));
            }
            otro => out.push(otro.clone()),
        }
        i += 1;
    }
    // un goto que solo salta por encima de los except/finally sobra
    let mut k = 0;
    while k < out.len() {
        if let S::Ir(l) = out[k] {
            let mut q = k + 1;
            while q < out.len() && matches!(&out[q], S::Bloque(c, _) if c.starts_with("except") || c == "finally") {
                q += 1;
            }
            if q > k + 1 && matches!(out.get(q), Some(S::Etq(x)) if *x == l) {
                out.remove(k);
                continue;
            }
        }
        k += 1;
    }
    // finally vacío (limpieza del "as e" en ≤3.8): fuera, y su try se desenvuelve
    let mut k = 0;
    while k < out.len() {
        let vacio = matches!(&out[k], S::Bloque(c, b) if c == "finally" && b.iter().all(|x| matches!(x, S::Txt(t) if t == "pass" || t.starts_with('$') || t.ends_with("= None") || t.starts_with("del "))));
        if vacio {
            out.remove(k);
            if k > 0 {
                if let S::Bloque(c, b) = out[k - 1].clone() {
                    if c == "try" {
                        out.splice(k - 1..k, b);
                        continue;
                    }
                }
            }
            continue;
        }
        k += 1;
    }
    // código del camino normal colocado entre el try y los except:
    //   try / M / except… / M  →  try / except… / M      (duplicado por el compilador)
    //   try / M / except…      →  try / except… / else: M
    let mut k = 0;
    while k < out.len() {
        if matches!(&out[k], S::Bloque(c, _) if c == "try") {
            if let Some(e1) = (k + 1..out.len()).find(|&q| matches!(&out[q], S::Bloque(c, _) if c.starts_with("except"))) {
                let medio: Vec<S> = out[k + 1..e1].to_vec();
                let mut e2 = e1;
                while e2 + 1 < out.len() && matches!(&out[e2 + 1], S::Bloque(c, _) if c.starts_with("except") || c == "finally") {
                    e2 += 1;
                }
                if !medio.is_empty() && medio.iter().all(|x| !matches!(x, S::Etq(_))) {
                    let txt = |x: &[S]| x.iter().map(|y| format!("{y:?}")).collect::<Vec<_>>();
                    let n = medio.len();
                    let despues: Vec<S> = out.get(e2 + 1..(e2 + 1 + n).min(out.len())).map(|x| x.to_vec()).unwrap_or_default();
                    // quita del final de cada except el duplicado del camino normal
                    for q in e1..=e2 {
                        if let S::Bloque(c, b) = &mut out[q] {
                            if c.starts_with("except") && b.len() >= n && txt(&b[b.len() - n..]) == txt(&medio) {
                                let l = b.len();
                                b.truncate(l - n);
                            }
                        }
                    }
                    if txt(&despues) == txt(&medio) {
                        out.drain(k + 1..e1);
                    } else {
                        let m: Vec<S> = out.drain(k + 1..e1).collect();
                        let pos = e2 + 1 - m.len();
                        let es_salto = matches!(m.as_slice(), [S::Ir(_)]);
                        if !es_salto {
                            // el resto de los except (que no terminan en return) también siguen tras el bloque
                            out.insert(pos, S::Bloque("else".into(), m));
                        } else {
                            out.insert(pos, m.into_iter().next().unwrap());
                        }
                    }
                }
            }
        }
        k += 1;
    }
    // finally duplicado en el camino normal: try / <F> / finally <F>  →  try / finally <F>
    let mut k = 0;
    while k < out.len() {
        if matches!(&out[k], S::Bloque(c, _) if c == "try") {
            if let Some(fpos) = (k + 1..out.len()).find(|&q| matches!(&out[q], S::Bloque(c, _) if c == "finally")) {
                if let S::Bloque(_, f) = out[fpos].clone() {
                    let n = f.len();
                    let medio: Vec<S> = out[k + 1..fpos].to_vec();
                    let txt = |x: &[S]| x.iter().map(|y| format!("{y:?}")).collect::<Vec<_>>();
                    if n > 0 && medio.len() >= n && txt(&medio[..n]) == txt(&f) {
                        let fin = out.remove(fpos);
                        out.drain(k + 1..k + 1 + n);
                        out.insert(k + 1, fin);
                    }
                }
            }
        }
        k += 1;
    }
    // try sin ningún except/finally detrás (solo quedaba la limpieza): se desenvuelve
    let mut k = 0;
    while k < out.len() {
        if let S::Bloque(c, b) = out[k].clone() {
            if c == "try" {
                let mut q = k + 1;
                while q < out.len() && matches!(out[q], S::Ir(_) | S::Etq(_)) {
                    q += 1;
                }
                let tiene_manejador = matches!(out.get(q), Some(S::Bloque(c2, _)) if c2.starts_with("except") || c2 == "finally");
                if !tiene_manejador {
                    out.splice(k..=k, b);
                    continue;
                }
            }
        }
        k += 1;
    }
    out
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn goto_al_siguiente_se_elimina() {
        let v = vec![
            S::Bloque("try".into(), vec![S::Txt("r = x()".into())]),
            S::Bloque("except E as e".into(), vec![S::Txt("print(e)".into())]),
            S::Ir(120),
            S::Etq(120),
            S::Txt("return r".into()),
        ];
        let r = estructurar(v, &BTreeSet::new(), true);
        assert!(!r.iter().any(|x| matches!(x, S::Ir(_))), "{r:?}");
    }
}
