import json, copy
vs = ["3.8","3.9","3.10","3.11","3.12","3.13","3.14"]
T = {v: json.load(open(f"t{v}.json")) for v in vs}
# 3.7 = 3.8 sin ROT_FOUR(6), BEGIN_FINALLY(53), END_ASYNC_FOR(54), CALL_FINALLY(162), POP_FINALLY(163)
#       y con BREAK_LOOP(80), CONTINUE_LOOP(119, jabs), SETUP_LOOP(120, jrel), SETUP_EXCEPT(121, jrel)
t37 = copy.deepcopy(T["3.8"]); t37["v"]="3.7"; t37["magic"]=3394
for i in (6,53,54,162,163): t37["names"][i]="<%d>"%i
t37["names"][80]="BREAK_LOOP"; t37["names"][119]="CONTINUE_LOOP"; t37["names"][120]="SETUP_LOOP"; t37["names"][121]="SETUP_EXCEPT"
t37["hasjrel"]=sorted((set(t37["hasjrel"])-{162})|{120,121}); t37["hasjabs"]=sorted(set(t37["hasjabs"])|{119})
# 3.6 = 3.7 sin LOAD_METHOD(160) ni CALL_METHOD(161)
t36 = copy.deepcopy(t37); t36["v"]="3.6"; t36["magic"]=3379
t36["names"][160]="<160>"; t36["names"][161]="<161>"; t36["hasname"]=[x for x in t36["hasname"] if x!=160]
T["3.7"]=t37; T["3.6"]=t36
orden = ["3.6","3.7"]+vs
def flags(t):
    f=[0]*256
    for bit,k in enumerate(["hasconst","hasname","haslocal","hasfree","hasjrel","hasjabs","hascompare"]):
        for i in t[k]:
            if i<256: f[i]|=1<<bit
    return f
o=["// GENERADO desde los módulos `opcode` reales de CPython 3.8–3.14 (3.6/3.7 derivadas",
   "// de 3.8). No editar a mano: ver docs/tools/ o regenerar con el script.",
   "#![allow(dead_code)]","",
   "pub const F_CONST: u8 = 1; pub const F_NAME: u8 = 2; pub const F_LOCAL: u8 = 4; pub const F_FREE: u8 = 8;",
   "pub const F_JREL: u8 = 16; pub const F_JABS: u8 = 32; pub const F_COMPARE: u8 = 64;","",
   "pub struct TablaPy { pub version: &'static str, pub magic: u16, pub have_arg: u8, pub nombres: [&'static str; 256], pub cache: [u8; 256], pub flags: [u8; 256], pub cmp_op: &'static [&'static str] }",""]
for v in orden:
    t=T[v]; n=[(x if not x.startswith("<") else "") for x in t["names"]]
    o.append(f"pub static PY{v.replace('.','')}: TablaPy = TablaPy {{ version: \"{v}\", magic: {t['magic']}, have_arg: {t['have_arg']},")
    o.append("  nombres: ["+", ".join(json.dumps(x) for x in n)+"],")
    o.append("  cache: ["+", ".join(str(c) for c in t["cache"])+"],")
    o.append("  flags: ["+", ".join(str(c) for c in flags(t))+"],")
    o.append("  cmp_op: &["+", ".join(json.dumps(x) for x in t["cmp_op"])+"] };")
o.append("")
o.append("/// Tabla por número mágico del .pyc (los rangos siguen importlib).")
o.append("pub fn por_magic(m: u16) -> Option<&'static TablaPy> {")
o.append("    Some(match m { 3370..=3379 => &PY36, 3390..=3399 => &PY37, 3400..=3419 => &PY38, 3420..=3429 => &PY39, 3430..=3449 => &PY310,")
o.append("        3450..=3499 => &PY311, 3500..=3549 => &PY312, 3550..=3599 => &PY313, 3600..=3699 => &PY314, _ => return None })")
o.append("}")
open("/home/user/capas/src/pyc_tablas.rs","w").write("\n".join(o)+"\n")
print("ok", len(open("/home/user/capas/src/pyc_tablas.rs").read()))
