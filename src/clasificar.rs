//! Módulo de clasificación: recorre el árbol de capas, decide a qué categoría
//! pertenece cada archivo (por su contenido y su extensión) y reúne todos los
//! archivos finales en `extraidos/<categoria>/`, con un informe por categoría.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::detectar::Tipo;
use crate::motor::Nodo;
use crate::recursos::humano;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Categoria {
    Imagen,
    Audio,
    Video,
    Ejecutable,
    Bytecode,
    Codigo,
    Documento,
    Comprimido,
    RecursoJuego,
    Datos,
    Texto,
    Desconocido,
}

impl Categoria {
    pub fn nombre(self) -> &'static str {
        match self {
            Categoria::Imagen => "imagenes",
            Categoria::Audio => "audio",
            Categoria::Video => "video",
            Categoria::Ejecutable => "ejecutables",
            Categoria::Bytecode => "bytecode",
            Categoria::Codigo => "codigo_fuente",
            Categoria::Documento => "documentos",
            Categoria::Comprimido => "comprimidos",
            Categoria::RecursoJuego => "recursos_juego",
            Categoria::Datos => "datos",
            Categoria::Texto => "texto",
            Categoria::Desconocido => "desconocidos",
        }
    }

    pub fn etiqueta(self) -> &'static str {
        match self {
            Categoria::Imagen => "IMÁGENES",
            Categoria::Audio => "AUDIO",
            Categoria::Video => "VÍDEO",
            Categoria::Ejecutable => "EJECUTABLES",
            Categoria::Bytecode => "BYTECODE",
            Categoria::Codigo => "CÓDIGO FUENTE",
            Categoria::Documento => "DOCUMENTOS",
            Categoria::Comprimido => "COMPRIMIDOS",
            Categoria::RecursoJuego => "RECURSOS DE JUEGO / 3D",
            Categoria::Datos => "DATOS",
            Categoria::Texto => "TEXTO",
            Categoria::Desconocido => "DESCONOCIDOS",
        }
    }

    pub const TODAS: [Categoria; 12] = [
        Categoria::Imagen,
        Categoria::Audio,
        Categoria::Video,
        Categoria::Ejecutable,
        Categoria::Bytecode,
        Categoria::Codigo,
        Categoria::Documento,
        Categoria::Comprimido,
        Categoria::RecursoJuego,
        Categoria::Datos,
        Categoria::Texto,
        Categoria::Desconocido,
    ];
}

/// Clasifica combinando lo que detectó el analizador con la extensión del
/// nombre (que capta formatos que no tienen "número mágico" propio).
pub fn categoria(tipo: Tipo, nombre: &str) -> Categoria {
    // 1) Formatos que el analizador identifica por contenido.
    match tipo {
        Tipo::Elf | Tipo::Pe | Tipo::MachO | Tipo::MachOFat => return Categoria::Ejecutable,
        Tipo::ClaseJava | Tipo::Dex | Tipo::Pyc | Tipo::Wasm => return Categoria::Bytecode,
        Tipo::Imagen => return Categoria::Imagen,
        Tipo::Pdf => return Categoria::Documento,
        Tipo::Zip | Tipo::Gzip | Tipo::Bzip2 | Tipo::Xz | Tipo::Lzma | Tipo::Zlib | Tipo::Tar
        | Tipo::SieteZ | Tipo::Rar | Tipo::Cab | Tipo::ArUnix => return Categoria::Comprimido,
        _ => {}
    }
    // 2) Por extensión.
    let ext = extension(nombre);
    if let Some(c) = por_extension(&ext) {
        return c;
    }
    // 3) Texto como último recurso frente a desconocido.
    match tipo {
        Tipo::Texto => Categoria::Texto,
        _ => Categoria::Desconocido,
    }
}

fn extension(nombre: &str) -> String {
    nombre
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(nombre)
        .rsplit_once('.')
        .map(|(_, e)| e.to_lowercase())
        .unwrap_or_default()
}

fn por_extension(ext: &str) -> Option<Categoria> {
    use Categoria::*;
    let c = match ext {
        // Imágenes
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "tif" | "tiff" | "svg" | "ico"
        | "tga" | "psd" | "heic" | "avif" | "jfif" | "xcf" => Imagen,
        // Imágenes/texturas típicas de juegos y 3D
        "dds" | "ktx" | "ktx2" | "astc" | "pvr" | "basis" => RecursoJuego,
        // Audio
        "mp3" | "wav" | "ogg" | "flac" | "opus" | "m4a" | "aac" | "wma" | "mid" | "midi"
        | "aiff" | "oga" | "xm" | "mod" | "it" | "s3m" => Audio,
        // Vídeo
        "mp4" | "mkv" | "webm" | "avi" | "mov" | "flv" | "wmv" | "m4v" | "mpg" | "mpeg"
        | "ogv" | "3gp" => Video,
        // Ejecutables / bibliotecas
        "exe" | "dll" | "so" | "dylib" | "sys" | "o" | "bin" | "elf" | "ko"
        | "msi" | "app" | "out" => Ejecutable,
        // Bytecode / máquinas virtuales
        "class" | "jar" | "dex" | "pyc" | "pyo" | "wasm" | "luac" | "nro" | "nso" => Bytecode,
        // Documentos
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp" | "rtf"
        | "epub" | "mobi" | "djvu" | "pages" | "pdf" => Documento,
        // Código fuente / scripts
        "c" | "h" | "cpp" | "cc" | "cxx" | "hpp" | "rs" | "go" | "py" | "js" | "mjs" | "ts"
        | "tsx" | "jsx" | "java" | "kt" | "swift" | "rb" | "php" | "pl" | "lua" | "sh"
        | "bash" | "zsh" | "ps1" | "bat" | "cmd" | "cs" | "vb" | "scala" | "clj" | "hs"
        | "ml" | "r" | "sql" | "asm" | "s" | "html" | "htm" | "css" | "scss" | "vue"
        | "glsl" | "vert" | "frag" | "hlsl" | "shader" | "cmake" | "gradle" | "dockerfile" => Codigo,
        // Comprimidos / paquetes
        "zip" | "gz" | "tgz" | "bz2" | "tbz2" | "xz" | "txz" | "7z" | "rar" | "tar" | "lz"
        | "lzma" | "zst" | "cab" | "arj" | "deb" | "rpm" | "apk" | "ipa" | "whl" | "iso"
        | "dmg" | "lha" => Comprimido,
        // Recursos de juego / 3D / motores
        "obj" | "fbx" | "gltf" | "glb" | "dae" | "3ds" | "blend" | "stl" | "ply" | "md5"
        | "pak" | "pk3" | "pk4" | "vpk" | "wad" | "bsp" | "unity3d" | "assets" | "resource"
        | "uasset" | "upk" | "umap" | "rpa" | "xnb" | "gma" | "nbt" | "mca" | "mcr"
        | "schematic" | "blocky" | "vox" | "bdae" | "mdl" | "nif" | "esp" | "esm" | "ba2"
        | "bsa" | "sav" | "dat" | "pck" | "love" | "gb" | "gba" | "nes" | "smc" | "sfc"
        | "z64" | "nds" | "iso9660" => RecursoJuego,
        // Datos / configuración / bases de datos
        "json" | "xml" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf" | "csv" | "tsv"
        | "db" | "sqlite" | "sqlite3" | "mdb" | "plist" | "proto" | "pb" | "msgpack"
        | "bson" | "parquet" | "avro" | "pem" | "crt" | "cer" | "key" | "der" | "pfx"
        | "p12" | "ttf" | "otf" | "woff" | "woff2" | "eot" => Datos,
        // Texto
        "txt" | "md" | "log" | "text" | "nfo" | "me" | "readme" | "rst" | "asc" => Texto,
        _ => return None,
    };
    Some(c)
}

#[derive(Serialize)]
pub struct Entrada {
    pub categoria: Categoria,
    pub nombre: String,
    pub tamano: u64,
    pub sha256: String,
    pub origen: String,
    pub copiado_en: Option<String>,
}

#[derive(Serialize)]
pub struct Clasificacion {
    pub total: usize,
    pub por_categoria: BTreeMap<String, usize>,
    pub bytes_por_categoria: BTreeMap<String, u64>,
    pub entradas: Vec<Entrada>,
}

/// Recorre el árbol y clasifica cada bloque. Si `copiar`, reúne una copia de
/// cada archivo en `raiz/extraidos/<categoria>/`.
pub fn clasificar(arbol: &[Nodo], raiz: &Path, copiar: bool) -> std::io::Result<Clasificacion> {
    let mut cl = Clasificacion {
        total: 0,
        por_categoria: BTreeMap::new(),
        bytes_por_categoria: BTreeMap::new(),
        entradas: Vec::new(),
    };
    let base = raiz.join("extraidos");
    if copiar {
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base)?;
    }
    let mut usados: BTreeMap<PathBuf, usize> = BTreeMap::new();
    let mut vistos_sha = std::collections::HashSet::new();
    for n in arbol {
        recorrer(n, &base, copiar, &mut cl, &mut usados, &mut vistos_sha)?;
    }
    for c in Categoria::TODAS {
        cl.por_categoria.entry(c.nombre().into()).or_insert(0);
    }
    let md = informe(&cl, copiar);
    fs::write(raiz.join("clasificacion.md"), md)?;
    if let Ok(j) = serde_json::to_string_pretty(&cl) {
        let _ = fs::write(raiz.join("clasificacion.json"), j);
    }
    Ok(cl)
}

#[allow(clippy::too_many_arguments)]
fn recorrer(
    n: &Nodo,
    base: &Path,
    copiar: bool,
    cl: &mut Clasificacion,
    usados: &mut BTreeMap<PathBuf, usize>,
    vistos_sha: &mut std::collections::HashSet<String>,
) -> std::io::Result<()> {
    let cat = categoria(n.tipo, &n.nombre);
    let nombre_base = n.nombre.rsplit(['/', '\\']).next().unwrap_or(&n.nombre).to_string();
    let origen = format!("{}/{}", n.directorio, nombre_base);
    let fisico = n.ruta_fisica.clone();

    let mut copiado_en = None;
    // Un mismo contenido (sha) se copia una sola vez.
    let nuevo = vistos_sha.insert(n.sha256.clone());
    if copiar && nuevo && fisico.is_file() {
        let dir_cat = base.join(cat.nombre());
        fs::create_dir_all(&dir_cat)?;
        let destino = nombre_unico(&dir_cat, &nombre_base, usados);
        // Enlace duro (mismo sistema de ficheros) para no duplicar el disco;
        // copia solo si el enlace falla.
        let ok = fs::hard_link(&fisico, &destino).is_ok() || fs::copy(&fisico, &destino).is_ok();
        if ok {
            copiado_en = Some(format!("extraidos/{}/{}", cat.nombre(), destino.file_name().unwrap().to_string_lossy()));
        }
    }

    *cl.por_categoria.entry(cat.nombre().into()).or_insert(0) += 1;
    *cl.bytes_por_categoria.entry(cat.nombre().into()).or_insert(0) += n.tamano;
    cl.total += 1;
    cl.entradas.push(Entrada {
        categoria: cat,
        nombre: nombre_base,
        tamano: n.tamano,
        sha256: n.sha256.clone(),
        origen,
        copiado_en,
    });

    for h in &n.hijos {
        recorrer(h, base, copiar, cl, usados, vistos_sha)?;
    }
    Ok(())
}

fn nombre_unico(dir: &Path, nombre: &str, usados: &mut BTreeMap<PathBuf, usize>) -> PathBuf {
    let limpio = if nombre.is_empty() { "sin_nombre" } else { nombre };
    let p = dir.join(limpio);
    let n = usados.entry(p.clone()).or_insert(0);
    if *n == 0 && !p.exists() {
        *n += 1;
        return p;
    }
    let (tronco, ext) = match limpio.rsplit_once('.') {
        Some((t, e)) if !t.is_empty() => (t.to_string(), format!(".{e}")),
        _ => (limpio.to_string(), String::new()),
    };
    loop {
        *n += 1;
        let cand = dir.join(format!("{tronco}~{n}{ext}"));
        if !cand.exists() {
            return cand;
        }
    }
}

fn informe(cl: &Clasificacion, copiado: bool) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Clasificación de archivos\n");
    let _ = writeln!(s, "{} archivo(s) clasificados por categoría.\n", cl.total);
    if copiado {
        let _ = writeln!(s, "Copias reunidas en `extraidos/<categoria>/` (contenidos duplicados una sola vez).\n");
    }
    let _ = writeln!(s, "| Categoría | Archivos | Tamaño |");
    let _ = writeln!(s, "|---|--:|--:|");
    for c in Categoria::TODAS {
        let n = cl.por_categoria.get(c.nombre()).copied().unwrap_or(0);
        if n == 0 {
            continue;
        }
        let b = cl.bytes_por_categoria.get(c.nombre()).copied().unwrap_or(0);
        let _ = writeln!(s, "| {} | {} | {} |", c.etiqueta(), n, humano(b));
    }
    for c in Categoria::TODAS {
        let entradas: Vec<&Entrada> = cl.entradas.iter().filter(|e| e.categoria == c).collect();
        if entradas.is_empty() {
            continue;
        }
        let _ = writeln!(s, "\n## {} ({})\n", c.etiqueta(), entradas.len());
        for e in entradas {
            let destino = e.copiado_en.as_deref().map(|d| format!(" → `{d}`")).unwrap_or_default();
            let _ = writeln!(s, "- **{}** · {} · `{}`{}", e.nombre, humano(e.tamano), &e.sha256[..12], destino);
        }
    }
    let _ = writeln!(s, "\n---\n*Clasificación generada por capas — módulo de clasificación de @angelazo*");
    s
}
