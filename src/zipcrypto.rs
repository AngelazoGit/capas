//! Recuperación de ZipCrypto por texto plano conocido (ataque Biham–Kocher).
//! Reimplementación nativa en Rust del algoritmo de bkcrack (licencia zlib/libpng,
//! © Joachim Hotonnier); el algoritmo es público. Recupera el estado interno del
//! cifrador a partir de un texto plano conocido de UNA entrada STORED y, con él,
//! descifra TODAS las entradas sin la contraseña. Para archivos que tengas
//! derecho a abrir. No funciona sobre AES (eso es cifrado fuerte).
#![allow(clippy::needless_range_loop)]

use crate::extraer::Hijo;
use std::io::Read;

#[inline] fn lsb(x:u32)->u8 { x as u8 }
#[inline] fn msb(x:u32)->u8 { (x>>24) as u8 }
#[inline] const fn mask(begin:u32,end:u32)->u32 { (u32::MAX<<begin) & (u32::MAX>>(32-end)) }
#[inline] const fn maxdiff(x:u32)->u32 { mask(0,x).wrapping_add(0xff) }
pub const MULT:u32=0x08088405;
pub const MULTINV:u32=0xd94fa8cd;

pub struct Crc32Tab { crctab:[u32;256], crcinvtab:[u32;256] }
impl Crc32Tab {
    fn new()->Self{
        let mut crctab=[0u32;256]; let mut crcinvtab=[0u32;256];
        for b in 0..256u32 { let mut crc=b; for _ in 0..8 { crc = if crc&1!=0 {(crc>>1)^0xedb88320} else {crc>>1}; } crctab[b as usize]=crc; crcinvtab[(crc>>24) as usize]=(crc<<8)^b; }
        Crc32Tab{crctab,crcinvtab}
    }
    #[inline] pub fn crc32(&self,pval:u32,b:u8)->u32 { (pval>>8) ^ self.crctab[(lsb(pval)^b) as usize] }
    #[inline] pub fn crc32inv(&self,crc:u32,b:u8)->u32 { (crc<<8) ^ self.crcinvtab[msb(crc) as usize] ^ b as u32 }
    #[inline] fn yi_24_32(&self,zi:u32,zim1:u32)->u32 { (self.crc32inv(zi,0) ^ zim1) << 24 }
    #[inline] fn zim1_10_32(&self,zi_2_32:u32)->u32 { self.crc32inv(zi_2_32,0) & mask(10,32) }
}

pub struct KeystreamTab {
    tab:[u8;1<<14],
    inv:Vec<[Vec<u32>;64]>,   // [ki][zi_10_16>>10] -> zi_2_16
    exists:Vec<[bool;64]>,
}
impl KeystreamTab {
    fn new()->Self{
        let mut tab=[0u8;1<<14];
        let mut inv:Vec<[Vec<u32>;64]>=(0..256).map(|_| std::array::from_fn(|_| Vec::new())).collect();
        let mut exists:Vec<[bool;64]>=vec![[false;64];256];
        let mut z=0u32;
        while z < 1<<16 {
            let k=lsb(((z|2).wrapping_mul(z|3))>>8);
            tab[(z>>2) as usize]=k;
            inv[k as usize][(z>>10) as usize].push(z);
            exists[k as usize][(z>>10) as usize]=true;
            z+=4;
        }
        KeystreamTab{tab,inv,exists}
    }
    #[inline] fn byte(&self,zi:u32)->u8 { self.tab[((zi & mask(0,16))>>2) as usize] }
    #[inline] fn vec_2_16(&self,ki:u8,zi_10_16:u32)->&[u32] { &self.inv[ki as usize][((zi_10_16 & mask(0,16))>>10) as usize] }
    #[inline] fn has_2_16(&self,ki:u8,zi_10_16:u32)->bool { self.exists[ki as usize][((zi_10_16 & mask(0,16))>>10) as usize] }
}

pub struct MultTab { fib2:Vec<Vec<u8>>, fib3:Vec<Vec<u8>> }
impl MultTab {
    fn new()->Self{
        let mut fib2:Vec<Vec<u8>>=vec![Vec::new();256];
        let mut fib3:Vec<Vec<u8>>=vec![Vec::new();256];
        let mut prodinv=0u32;
        for x in 0..256u32 {
            let m=msb(prodinv);
            fib2[m as usize].push(x as u8);
            fib2[((m as u32+1)%256) as usize].push(x as u8);
            fib3[((m as u32+255)%256) as usize].push(x as u8);
            fib3[m as usize].push(x as u8);
            fib3[((m as u32+1)%256) as usize].push(x as u8);
            prodinv=prodinv.wrapping_add(MULTINV);
        }
        MultTab{fib2,fib3}
    }
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Keys { pub x:u32, pub y:u32, pub z:u32 }
impl Keys {
    pub fn inicial()->Self{ Keys{x:0x12345678,y:0x23456789,z:0x34567890} }
    pub fn de_password(t:&Tablas,pw:&[u8])->Self{ let mut k=Self::inicial(); for &b in pw { k.update(t,b);} k }
    #[inline] pub fn update(&mut self,t:&Tablas,p:u8){
        self.x=t.crc.crc32(self.x,p);
        self.y=(self.y.wrapping_add(lsb(self.x) as u32)).wrapping_mul(MULT).wrapping_add(1);
        self.z=t.crc.crc32(self.z,msb(self.y));
    }
    #[inline] pub fn getk(&self,t:&Tablas)->u8{ t.ks.byte(self.z) }
    #[inline] pub fn update_backward(&mut self,t:&Tablas,c:u8){
        self.z=t.crc.crc32inv(self.z,msb(self.y));
        self.y=(self.y.wrapping_sub(1)).wrapping_mul(MULTINV).wrapping_sub(lsb(self.x) as u32);
        self.x=t.crc.crc32inv(self.x, c ^ self.getk(t));
    }
    pub fn update_fwd_to(&mut self,t:&Tablas,ct:&[u8],cur:usize,target:usize){ for i in cur..target { let p=ct[i]^self.getk(t); self.update(t,p);} }
    pub fn update_back_to(&mut self,t:&Tablas,ct:&[u8],cur:usize,target:usize){ for i in (target..cur).rev(){ self.update_backward(t,ct[i]); } }
}

pub struct Tablas { pub crc:Crc32Tab, pub ks:KeystreamTab, pub mt:MultTab }
impl Tablas { pub fn new()->Self{ Tablas{crc:Crc32Tab::new(),ks:KeystreamTab::new(),mt:MultTab::new()} } }

pub struct Data<'a>{ pub ct:&'a[u8], pub pt:&'a[u8], pub ks:Vec<u8>, pub offset:usize, pub extra:Vec<(usize,u8)> }
impl<'a> Data<'a>{
    // ct incluye la cabecera de 12; offset_arg relativo a los datos (0 = inicio de datos)
    pub fn nueva(ct:&'a[u8], pt:&'a[u8], offset_arg:i32, extra:Vec<(i32,u8)>)->Self{
        let offset=(12i32+offset_arg) as usize;
        let ks:Vec<u8>=(0..pt.len()).map(|i| pt[i]^ct[offset+i]).collect();
        let extra=extra.into_iter().map(|(o,b)|((12i32+o) as usize,b)).collect();
        Data{ct,pt,ks,offset,extra}
    }
}

// ── Zreduction ──
pub fn zreduction(t:&Tablas, keystream:&[u8])->(Vec<u32>,usize){
    let mut index=keystream.len()-1;
    let mut zi:Vec<u32>=Vec::with_capacity(1<<22);
    for s in 0u32..(1<<22) { if t.ks.has_2_16(keystream[index], s<<10) { zi.push(s<<10); } }
    // reduce
    let track_thr=1usize<<16; let wait_thr=1usize<<8;
    let (mut tracking,mut best_copy,mut best_index,mut best_size)=(false,Vec::new(),index,track_thr);
    let (mut waiting,mut wait)=(false,0usize);
    let mut i=index;
    while i>=8 {
        let mut nxt:Vec<u32>=Vec::with_capacity(1<<22);
        let mut seen=vec![false; 1<<22];
        let mut num=0usize;
        for &zi_10_32 in &zi {
            for &zi_2_16 in t.ks.vec_2_16(keystream[i], zi_10_32) {
                let zim1=t.crc.zim1_10_32(zi_10_32|zi_2_16);
                if !seen[(zim1>>10) as usize] && t.ks.has_2_16(keystream[i-1], zim1) {
                    nxt.push(zim1); seen[(zim1>>10) as usize]=true;
                    num+=t.ks.vec_2_16(keystream[i-1], zim1).len();
                }
            }
        }
        if num<=best_size { tracking=true; best_index=i-1; best_size=num; waiting=false; }
        else if tracking {
            if best_index==i { std::mem::swap(&mut best_copy,&mut zi); if best_size<=wait_thr { waiting=true; wait=best_size*4; } }
            if waiting { wait-=1; if wait==0 { break; } }
        }
        std::mem::swap(&mut zi,&mut nxt);
        if i==0 {break;} i-=1;
    }
    if tracking { if best_index!=7 { std::mem::swap(&mut zi,&mut best_copy); } index=best_index; }
    else { index=7; }
    // generate: extiende [10,32) -> [2,32)
    let n=zi.len();
    for j in 0..n {
        let v=t.ks.vec_2_16(keystream[index], zi[j]).to_vec();
        for k in 1..v.len() { zi.push(zi[j]|v[k]); }
        if !v.is_empty(){ zi[j]|=v[0]; }
    }
    (zi,index)
}

// ── Attack ──
pub struct Attack<'a>{ t:&'a Tablas, d:&'a Data<'a>, index:usize, zlist:[u32;8], ylist:[u32;8], xlist:[u32;8], sols:Vec<Keys> }
impl<'a> Attack<'a>{
    pub fn new(t:&'a Tablas,d:&'a Data<'a>,zr_index:usize)->Self{
        Attack{t,d,index:zr_index+1-8,zlist:[0;8],ylist:[0;8],xlist:[0;8],sols:Vec::new()}
    }
    pub fn carryout(&mut self,z7_2_32:u32){ self.zlist[7]=z7_2_32; self.explore_z(7); }
    fn explore_z(&mut self,i:i32){
        if i!=0 {
            let i=i as usize;
            let zim1_10_32=self.t.crc.zim1_10_32(self.zlist[i]);
            let mut buf=[0u32;256]; let v=self.t.ks.vec_2_16(self.d.ks[self.index+i-1], zim1_10_32); let nb=v.len().min(256); buf[..nb].copy_from_slice(&v[..nb]);
            for &zim1_2_16 in &buf[..nb] {
                self.zlist[i-1]=zim1_10_32|zim1_2_16;
                self.zlist[i]&=mask(2,32);
                self.zlist[i]|=(self.t.crc.crc32inv(self.zlist[i],0) ^ self.zlist[i-1])>>8;
                if i<7 { self.ylist[i+1]=self.t.crc.yi_24_32(self.zlist[i+1],self.zlist[i]); }
                self.explore_z(i as i32-1);
            }
        } else {
            let mut y7_8_24=0u32;
            let mut prod=(MULTINV.wrapping_mul(msb(self.ylist[7]) as u32)<<24).wrapping_sub(MULTINV);
            while y7_8_24 < 1<<24 {
                for &y7_0_8 in &self.t.mt.fib3[msb(self.ylist[6]).wrapping_sub(msb(prod)) as usize] {
                    if prod.wrapping_add(MULTINV.wrapping_mul(y7_0_8 as u32)).wrapping_sub(self.ylist[6]&mask(24,32)) <= maxdiff(24) {
                        self.ylist[7]=(y7_0_8 as u32)|y7_8_24|(self.ylist[7]&mask(24,32));
                        self.explore_y(7);
                    }
                }
                y7_8_24+=1<<8; prod=prod.wrapping_add(MULTINV<<8);
            }
        }
    }
    fn explore_y(&mut self,i:i32){
        if i!=3 {
            let i=i as usize;
            let fy=(self.ylist[i].wrapping_sub(1)).wrapping_mul(MULTINV);
            let ffy=(fy.wrapping_sub(1)).wrapping_mul(MULTINV);
            let idx=msb(ffy.wrapping_sub(self.ylist[i-2]&mask(24,32))) as usize;
            let mut buf=[0u8;256]; let v=&self.t.mt.fib2[idx]; let nb=v.len().min(256); buf[..nb].copy_from_slice(&v[..nb]);
            for &xi_0_8 in &buf[..nb] {
                let yim1=fy.wrapping_sub(xi_0_8 as u32);
                if ffy.wrapping_sub(MULTINV.wrapping_mul(xi_0_8 as u32)).wrapping_sub(self.ylist[i-2]&mask(24,32)) <= maxdiff(24)
                   && msb(yim1)==msb(self.ylist[i-1]) {
                    self.ylist[i-1]=yim1; self.xlist[i]=xi_0_8 as u32; self.explore_y(i as i32-1);
                }
            }
        } else { self.test_x(); }
    }
    fn test_x(&mut self){
        for i in 5..=7 { self.xlist[i]=(self.t.crc.crc32(self.xlist[i-1], self.d.pt[self.index+i-1]) & mask(8,32)) | lsb(self.xlist[i]) as u32; }
        let mut x=self.xlist[7];
        for i in (3..=6).rev() { x=self.t.crc.crc32inv(x, self.d.pt[self.index+i]); }
        let y1_26_32=self.t.crc.yi_24_32(self.zlist[1],self.zlist[0]) & mask(26,32);
        if ((self.ylist[3].wrapping_sub(1)).wrapping_mul(MULTINV).wrapping_sub(lsb(x) as u32).wrapping_sub(1)).wrapping_mul(MULTINV).wrapping_sub(y1_26_32) > maxdiff(26) { return; }
        // forward
        let mut kf=Keys{x:self.xlist[7],y:self.ylist[7],z:self.zlist[7]};
        kf.update(self.t,self.d.pt[self.index+7]);
        let mut pi=self.index+8; let mut ci=self.d.offset+self.index+8;
        while pi<self.d.pt.len() {
            if (self.d.ct[ci]^kf.getk(self.t))!=self.d.pt[pi] { return; }
            kf.update(self.t,self.d.pt[pi]); pi+=1; ci+=1;
        }
        let mut idx_fwd=self.d.offset+self.d.pt.len();
        // backward
        let mut kb=Keys{x,y:self.ylist[3],z:self.zlist[3]};
        let mut p=self.index+3; let mut c=self.d.offset+self.index+3;
        while p>0 {
            p-=1; c-=1;
            kb.update_backward(self.t,self.d.ct[c]);
            if (self.d.ct[c]^kb.getk(self.t))!=self.d.pt[p] { return; }
        }
        let mut idx_bwd=self.d.offset;
        // extra
        for &(ei,eb) in &self.d.extra {
            let pb = if ei<idx_bwd { kb.update_back_to(self.t,self.d.ct,idx_bwd,ei); idx_bwd=ei; self.d.ct[idx_bwd]^kb.getk(self.t) }
                     else { kf.update_fwd_to(self.t,self.d.ct,idx_fwd,ei); idx_fwd=ei; self.d.ct[idx_fwd]^kf.getk(self.t) };
            if pb!=eb { return; }
        }
        kb.update_back_to(self.t,self.d.ct,idx_bwd,0);
        self.sols.push(kb);
    }
}

pub fn atacar(t:&Tablas,d:&Data)->Vec<Keys>{
    use rayon::prelude::*;
    let (cands,index)=zreduction(t,&d.ks);
    let hallado=std::sync::atomic::AtomicBool::new(false);
    cands.par_chunks(512).flat_map_iter(|trozo|{
        let mut a=Attack::new(t,d,index);
        for &z in trozo { if hallado.load(std::sync::atomic::Ordering::Relaxed){break;} a.carryout(z); if !a.sols.is_empty(){ hallado.store(true,std::sync::atomic::Ordering::Relaxed); break; } }
        a.sols.into_iter()
    }).collect()
}


// ── Integración: parseo de entradas y descifrado con las claves recuperadas ──

struct Entrada { nombre:String, metodo:u16, cifrada:bool, datos_off:usize, csize:usize, crc:u32, gp:u16, modtime:u16 }

fn u16le(d:&[u8],o:usize)->usize{ u16::from_le_bytes(d[o..o+2].try_into().unwrap()) as usize }
fn u32le(d:&[u8],o:usize)->usize{ u32::from_le_bytes(d[o..o+4].try_into().unwrap()) as usize }

/// Enumera las entradas leyendo el directorio central (robusto ante data
/// descriptors, offsets, etc.).
fn entradas_locales(d:&[u8])->Vec<Entrada>{
    let mut v=Vec::new();
    // localizar End Of Central Directory
    let Some(e)=(0..d.len().saturating_sub(21)).rev().find(|&i| &d[i..i+4]==b"PK\x05\x06") else { return v };
    let total=u16le(d,e+10);
    let mut off=u32le(d,e+16);
    for _ in 0..total {
        if off+46>d.len() || &d[off..off+4]!=b"PK\x01\x02" { break; }
        let gp=u16le(d,off+8) as u16; let metodo=u16le(d,off+10) as u16;
        let modtime=u16le(d,off+12) as u16;
        let crc=u32le(d,off+16) as u32;
        let csize=u32le(d,off+20);
        let nl=u16le(d,off+28); let el=u16le(d,off+30); let cl=u16le(d,off+32);
        let lho=u32le(d,off+42);
        let nombre=String::from_utf8_lossy(&d[off+46..(off+46+nl).min(d.len())]).into_owned();
        // offset de datos: cabecera local (sus nl/el pueden diferir de los del central)
        if lho+30<=d.len() && &d[lho..lho+4]==b"PK\x03\x04" {
            let lnl=u16le(d,lho+26); let lel=u16le(d,lho+28);
            let datos_off=lho+30+lnl+lel;
            if datos_off+csize<=d.len() {
                v.push(Entrada{nombre,metodo,cifrada:gp&1!=0,datos_off,csize,crc,gp,modtime});
            }
        }
        off+=46+nl+el+cl;
    }
    v
}

/// Extensión en minúsculas de un nombre de archivo.
fn ext(nombre:&str)->String{ nombre.rsplit('/').next().unwrap_or(nombre).rsplit('.').next().filter(|e| e.len()<=8).unwrap_or("").to_lowercase() }

/// Prefijos de texto plano conocidos por tipo de archivo (los más largos y
/// fiables primero). Sirven para romper ZipCrypto sin aportar una copia: muchos
/// formatos empiezan por una cabecera fija y predecible.
pub fn prefijos_auto(nombre:&str)->Vec<Vec<u8>>{
    let e=ext(nombre);
    // IMPORTANTE: el ataque Biham–Kocher es MUCHO más rápido cuanto más largo es
    // el texto plano conocido (≈38 bytes ~110 s; 30 bytes se dispara a minutos).
    // Por eso usamos la línea de declaración XML COMPLETA (≥38 bytes), probando
    // las variantes exactas más frecuentes primero (UTF-8 / \n), no un prefijo
    // corto "universal".
    let xml_decls:&[&[u8]]=&[
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n",
        b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
        b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
    ];
    let mut v:Vec<Vec<u8>>=Vec::new();
    // Prefijos ESPECÍFICOS de la extensión primero: muchos SVG/plist empiezan por
    // su propia cabecera (no por la declaración XML), y así no gastamos el
    // presupuesto de intentos en declaraciones genéricas que no casan.
    match e.as_str(){
        "svg" => { v.push(b"<svg xmlns=\"http://www.w3.org/2000/svg\"".to_vec()); v.push(b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n".to_vec()); }
        // HTML5 (`<!DOCTYPE html>`, 15 B) es demasiado corto para un ataque viable;
        // solo el DOCTYPE XHTML largo sirve. El HTML5 normal va con --texto-plano.
        "html"|"htm"|"xhtml" => { v.push(b"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"".to_vec()); }
        "plist" => { v.push(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\"".to_vec()); }
        _ => {}
    }
    // Luego las declaraciones XML genéricas (para el resto de familias XML).
    let xml=matches!(e.as_str(),"xml"|"svg"|"plist"|"gpx"|"kml"|"rss"|"xhtml"|"xaml"|"csproj"|"vcxproj"|"resx"|"config"|"xlf"|"xliff"|"dae"|"tmx"|"xsd"|"xsl"|"xslt"|"wsdl"|"atom"|"gml"|"fods"|"fodt"|"fodp");
    if xml { for d in xml_decls { if !v.iter().any(|x| x==d) { v.push(d.to_vec()); } } }
    v
}

/// Autodetección: intenta romper ZipCrypto probando prefijos conocidos en las
/// entradas STORED, según su extensión. Devuelve (claves, descripción) del éxito.
/// `max_intentos` acota cuántos ataques se lanzan (cada uno cuesta segundos).
pub fn romper_auto(t:&Tablas, zip:&[u8], max_intentos:usize)->Option<(Keys,String)>{
    let mut tareas:Vec<(usize,usize,Vec<u8>)>=Vec::new(); // (datos_off, csize, prefijo)
    for e in entradas_locales(zip){
        if !e.cifrada || e.metodo!=0 || e.csize<12 { continue; }
        let l=e.csize-12;
        for pre in prefijos_auto(&e.nombre){
            // Mínimo 34 B: por debajo, el ataque tarda demasiado para ser útil.
            if pre.len()>=34 && pre.len()<=l { tareas.push((e.datos_off,e.csize,pre)); }
        }
    }
    // orden del catálogo = por probabilidad (la cabecera más común primero).
    for (off,csize,pre) in tareas.into_iter().take(max_intentos){
        let enc=&zip[off..off+csize];
        let data=Data::nueva(enc,&pre,0,vec![]);
        if let Some(k)=atacar(t,&data).into_iter().next(){
            return Some((k, format!("{} bytes", pre.len())));
        }
    }
    None
}

/// Verificador RÁPIDO de contraseñas para ZipCrypto tradicional: comprueba solo
/// el byte de control de la cabecera cifrada de 12 bytes, que descarta ~255/256
/// de las contraseñas erróneas al instante, sin descifrar la entrada entera.
/// Es el mismo cómputo que correría una GPU. NO sirve para AES (método 99).
pub struct VerificadorZip<'a> {
    t: &'a Tablas,
    hdr: [u8; 12],
    chk: u8,
}
impl<'a> VerificadorZip<'a> {
    /// Prepara el verificador con la primera entrada ZipCrypto tradicional.
    /// Devuelve None si el ZIP no tiene ninguna (p. ej. es AES o no está cifrado).
    pub fn nuevo(t: &'a Tablas, zip: &[u8]) -> Option<Self> {
        for e in entradas_locales(zip) {
            if !e.cifrada || e.metodo == 99 || e.csize < 12 {
                continue; // 99 = AES; sin 12 bytes de cabecera no se puede.
            }
            let hdr: [u8; 12] = zip.get(e.datos_off..e.datos_off + 12)?.try_into().ok()?;
            // Byte de control: MSB del CRC, o del mod-time si el bit 3 (data
            // descriptor) está puesto (ahí el CRC local aún no se conocía).
            let chk = if e.gp & 0x08 != 0 { (e.modtime >> 8) as u8 } else { (e.crc >> 24) as u8 };
            return Some(VerificadorZip { t, hdr, chk });
        }
        None
    }
    /// ¿Pasa la contraseña el chequeo rápido? Hay ~1/256 de falsos positivos, así
    /// que un acierto debe confirmarse con un descifrado completo.
    #[inline]
    pub fn comprueba(&self, pw: &[u8]) -> bool {
        let mut k = Keys::de_password(self.t, pw);
        let mut last = 0u8;
        for &c in &self.hdr {
            let p = c ^ k.getk(self.t);
            k.update(self.t, p);
            last = p;
        }
        last == self.chk
    }
}

/// Intenta romper un ZIP ZipCrypto usando `plano` (contenido conocido de una de
/// sus entradas STORED). Devuelve las claves del estado inicial (post-password).
pub fn romper(t:&Tablas, zip:&[u8], plano:&[u8]) -> Option<Keys> {
    if plano.len() < 20 { return None; } // hace falta suficiente texto plano
    for e in entradas_locales(zip) {
        if !e.cifrada || e.metodo!=0 || e.csize<12 { continue; } // solo STORED cifradas
        let l = e.csize-12; // tamaño del contenido (STORED)
        if l==0 { continue; }
        let n = plano.len().min(l);
        if n < 13 { continue; }
        let enc = &zip[e.datos_off..e.datos_off+e.csize]; // 12 cabecera + datos
        let data = Data::nueva(enc, &plano[..n], 0, vec![]);
        if let Some(k)=atacar(t,&data).into_iter().next() { return Some(k); }
    }
    None
}

/// Descifra TODAS las entradas del ZIP con el estado inicial recuperado.
pub fn descifrar_todo(t:&Tablas, zip:&[u8], k0:Keys, lim:u64) -> Vec<Hijo> {
    let mut hijos=Vec::new(); let mut total=0u64;
    for e in entradas_locales(zip) {
        if e.nombre.ends_with('/') { continue; }
        let crudo = &zip[e.datos_off..e.datos_off+e.csize];
        let comprimido:Vec<u8> = if e.cifrada {
            if e.csize<12 { continue; }
            // Estado inicial recuperado; descifra la cabecera (12) y los datos.
            let mut ks=k0; let mut salida=Vec::with_capacity(e.csize-12);
            for (idx,&c) in crudo.iter().enumerate(){ let p=c^ks.getk(t); ks.update(t,p); if idx>=12 { salida.push(p);} }
            salida
        } else { crudo.to_vec() };
        let datos = match e.metodo {
            0 => comprimido,
            8 => { let mut o=Vec::new(); let tope=lim.saturating_sub(total); if flate2::read::DeflateDecoder::new(&comprimido[..]).take(tope+1).read_to_end(&mut o).is_err(){ continue; } o }
            _ => continue,
        };
        total+=datos.len() as u64;
        hijos.push(Hijo{nombre:e.nombre, datos});
    }
    hijos
}

#[cfg(test)]
mod pruebas {
    use super::*;
    fn fx(n:&str)->Vec<u8>{ std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(n)).unwrap() }

    #[test]
    fn descifra_con_claves_de_password() {
        // Rápido: sin ataque. Deriva las claves de la contraseña y descifra todo.
        let t = Tablas::new();
        let zip = fx("zipcrypto_reto.zip");
        let k0 = Keys::de_password(&t, b"miClaveLarga2026");
        let hijos = descifrar_todo(&t, &zip, k0, 1<<20);
        let sec = hijos.iter().find(|h| h.nombre.ends_with("sec.txt")).expect("sec.txt");
        assert_eq!(sec.datos, b"secreto-capas-OK\n");
        let con = hijos.iter().find(|h| h.nombre.ends_with("conocido.bin")).expect("conocido.bin");
        assert_eq!(con.datos, fx("zipcrypto_conocido.bin"));
    }

    #[test]
    fn claves_ida_y_vuelta() {
        let t = Tablas::new();
        let mut k = Keys::de_password(&t, b"abc");
        let s0 = k;
        let cifrado: Vec<u8> = b"hola mundo zipcrypto".iter().map(|&p| { let c = p ^ k.getk(&t); k.update(&t, p); c }).collect();
        let mut k = s0;
        let claro: Vec<u8> = cifrado.iter().map(|&c| { let p = c ^ k.getk(&t); k.update(&t, p); p }).collect();
        assert_eq!(claro, b"hola mundo zipcrypto");
    }

    #[test]
    fn verificador_rapido_acepta_la_correcta_y_rechaza() {
        // El chequeo rápido del byte de control debe aceptar la contraseña real y
        // rechazar la inmensa mayoría de las erróneas (al instante, sin descifrar).
        let t = Tablas::new();
        let zip = fx("zipcrypto_reto.zip");
        let ver = VerificadorZip::nuevo(&t, &zip).expect("zipcrypto_reto.zip es ZipCrypto tradicional");
        assert!(ver.comprueba(b"miClaveLarga2026"), "debe aceptar la contraseña correcta");
        // Prueba muchas erróneas: casi todas deben rechazarse (1/256 de falso positivo).
        let mut falsos = 0;
        for i in 0..2000u32 {
            let pw = format!("mala{i}");
            if ver.comprueba(pw.as_bytes()) {
                falsos += 1;
            }
        }
        assert!(falsos < 40, "demasiados falsos positivos: {falsos}/2000 (esperado ~8)");
    }

    #[test] #[ignore = "ataque completo: ~10s"]
    fn ataque_texto_plano_recupera_claves() {
        let t = Tablas::new();
        let zip = fx("zipcrypto_reto.zip");
        let plano = fx("zipcrypto_conocido.bin");
        let k = romper(&t, &zip, &plano).expect("debe romper ZipCrypto");
        // las claves recuperadas deben ser las de la contraseña real
        assert_eq!(k, Keys::de_password(&t, b"miClaveLarga2026"));
        let hijos = descifrar_todo(&t, &zip, k, 1<<20);
        assert!(hijos.iter().any(|h| h.nombre.ends_with("sec.txt") && h.datos == b"secreto-capas-OK\n"));
    }

    #[test] #[ignore = "autodeteccion: cabecera corta ~2min"]
    fn autodeteccion_rompe_por_cabecera() {
        // datos.xml empieza por la cabecera XML conocida (prefijo de 30 bytes del
        // catalogo); sin aportar texto plano, la autodeteccion recupera las claves
        // y descifra tambien flag.txt.
        let t = Tablas::new();
        let zip = fx("zipcrypto_auto.zip");
        let (k, _info) = romper_auto(&t, &zip, 4).expect("la autodeteccion debe romper por cabecera XML");
        let hijos = descifrar_todo(&t, &zip, k, 1<<20);
        assert!(hijos.iter().any(|h| h.nombre.ends_with("flag.txt")
            && h.datos == b"FLAG{zipcrypto_roto_por_autodeteccion}\n"));
    }
}
