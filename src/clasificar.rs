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
use crate::idioma::{tfmt, tr};
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
            Categoria::Imagen => tr("IMAGES","IMÁGENES"),
            Categoria::Audio => tr("AUDIO","AUDIO"),
            Categoria::Video => tr("VIDEO","VÍDEO"),
            Categoria::Ejecutable => tr("EXECUTABLES","EJECUTABLES"),
            Categoria::Bytecode => tr("BYTECODE","BYTECODE"),
            Categoria::Codigo => tr("SOURCE CODE","CÓDIGO FUENTE"),
            Categoria::Documento => tr("DOCUMENTS","DOCUMENTOS"),
            Categoria::Comprimido => tr("ARCHIVES","COMPRIMIDOS"),
            Categoria::RecursoJuego => tr("GAME / 3D RESOURCES","RECURSOS DE JUEGO / 3D"),
            Categoria::Datos => tr("DATA","DATOS"),
            Categoria::Texto => tr("TEXT","TEXTO"),
            Categoria::Desconocido => tr("UNKNOWN","DESCONOCIDOS"),
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

/// Nivel de confianza de una clasificación (de la guía de producto):
/// Confirmado (una firma lo prueba), Compatible (encaja estructuralmente),
/// Probable (heurística razonable), Desconocido (sin evidencia suficiente).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Confianza {
    Confirmado,
    Compatible,
    Probable,
    Desconocido,
}

impl Confianza {
    pub fn etiqueta(self) -> &'static str {
        match self {
            Confianza::Confirmado => tr("CONFIRMED", "CONFIRMADO"),
            Confianza::Compatible => tr("COMPATIBLE", "COMPATIBLE"),
            Confianza::Probable => tr("PROBABLE", "PROBABLE"),
            Confianza::Desconocido => tr("UNKNOWN", "DESCONOCIDO"),
        }
    }
    pub fn clave(self) -> &'static str {
        match self {
            Confianza::Confirmado => "confirmado",
            Confianza::Compatible => "compatible",
            Confianza::Probable => "probable",
            Confianza::Desconocido => "desconocido",
        }
    }
    pub const TODAS: [Confianza; 4] =
        [Confianza::Confirmado, Confianza::Compatible, Confianza::Probable, Confianza::Desconocido];
}

/// Decide el nivel de confianza de la identificación de un archivo y la
/// evidencia que lo respalda. Confirmado = firma binaria; Probable = solo
/// extensión o heurística de texto; Desconocido = sin evidencia. (Compatible
/// lo asignan las reglas semánticas, aún no implementadas.)
pub fn confianza(tipo: Tipo, nombre: &str) -> (Confianza, String) {
    match tipo {
        Tipo::Desconocido => {
            let ext = extension(nombre);
            if !ext.is_empty() && por_extension(&ext).is_some() {
                (Confianza::Probable, tfmt(tr("extension only: .{}", "solo extensión: .{}"), &[ext]))
            } else {
                (Confianza::Desconocido, tr("no signature or known extension", "sin firma ni extensión conocida").to_string())
            }
        }
        Tipo::Texto => (Confianza::Probable, tr("content looks like text", "el contenido parece texto").to_string()),
        t => (Confianza::Confirmado, tfmt(tr("magic bytes: {}", "firma binaria: {}"), &[t.nombre().to_string()])),
    }
}

/// Clasifica combinando lo que detectó el analizador con la extensión del
/// nombre (que capta formatos que no tienen "número mágico" propio).
pub fn categoria(tipo: Tipo, nombre: &str) -> Categoria {
    // 1) Formatos que el analizador identifica por contenido.
    match tipo {
        Tipo::Elf | Tipo::Pe | Tipo::MachO | Tipo::MachOFat => return Categoria::Ejecutable,
        Tipo::ClaseJava | Tipo::Dex | Tipo::Pyc | Tipo::Wasm | Tipo::Shader | Tipo::Lua | Tipo::Il2Cpp => return Categoria::Bytecode,
        Tipo::DotNet => return Categoria::Ejecutable,
        Tipo::Imagen => return Categoria::Imagen,
        Tipo::Audio => return Categoria::Audio,
        Tipo::Video => return Categoria::Video,
        Tipo::Fuente | Tipo::BaseDatos => return Categoria::Datos,
        Tipo::RecursoJuego => return Categoria::RecursoJuego,
        Tipo::Pdf => return Categoria::Documento,
        Tipo::Zip | Tipo::Gzip | Tipo::Bzip2 | Tipo::Xz | Tipo::Lzma | Tipo::Zlib | Tipo::Zstd
        | Tipo::Lz4 | Tipo::Iso | Tipo::Chd | Tipo::Disco | Tipo::Tar | Tipo::SieteZ | Tipo::Rar | Tipo::Cab | Tipo::ArUnix => return Categoria::Comprimido,
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
        // ── Imágenes (incl. RAW de cámara y formatos modernos, todas las plataformas)
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "tif" | "tiff" | "svg" | "ico"
        | "tga" | "psd" | "heic" | "heif" | "avif" | "jfif" | "xcf" | "exr" | "hdr" | "qoi"
        | "jp2" | "j2k" | "jpx" | "jpf" | "jxl" | "jxr" | "hdp" | "wdp" | "icns" | "cur"
        | "cr2" | "cr3" | "nef" | "arw" | "dng" | "raf" | "orf" | "rw2" | "srw" | "pef"
        | "sr2" | "raw" | "pbm" | "pgm" | "ppm" | "pnm" | "pcx" | "wbmp" | "apng" | "dib"
        | "sgi" => Imagen,
        // ── Audio (todas las plataformas; incluye trackers y sin pérdida)
        "mp3" | "wav" | "ogg" | "flac" | "opus" | "m4a" | "aac" | "wma" | "mid" | "midi"
        | "aiff" | "oga" | "xm" | "mod" | "it" | "s3m" | "aif" | "aifc" | "au" | "snd"
        | "ape" | "wv" | "mpc" | "tta" | "dsf" | "dff" | "caf" | "voc" | "spx" | "amr"
        | "ac3" | "dts" | "w64" | "bwf" | "ra" | "8svx" | "mka" | "xmf" => Audio,
        // ── Vídeo
        "mp4" | "mkv" | "webm" | "avi" | "mov" | "flv" | "wmv" | "m4v" | "mpg" | "mpeg"
        | "ogv" | "3gp" | "m2ts" | "mts" | "vob" | "ogm" | "rm" | "rmvb" | "asf" | "divx"
        | "f4v" | "mxf" | "y4m" | "yuv" | "m2v" | "3g2" | "h264" | "h265" | "hevc" => Video,
        // ── Ejecutables / bibliotecas (Windows, Linux, macOS, consolas)
        "exe" | "dll" | "so" | "dylib" | "sys" | "o" | "bin" | "elf" | "ko" | "msi" | "app"
        | "out" | "axf" | "efi" | "scr" | "com" | "drv" | "vxd" | "386" | "lib" | "rlib"
        | "prx" | "self" | "rpx" | "dol" | "xex" | "appimage" | "bundle" => Ejecutable,
        // ── Bytecode / máquinas virtuales
        "class" | "jar" | "dex" | "pyc" | "pyo" | "wasm" | "luac" | "nro" | "nso" | "pyd"
        | "beam" | "cmo" | "cmx" | "hi" | "rbc" | "swf" => Bytecode,
        // ── Documentos
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp" | "rtf"
        | "epub" | "mobi" | "djvu" | "pages" | "pdf" | "odg" | "odf" | "fodt" | "fods"
        | "fodp" | "wpd" | "wps" | "pub" | "vsd" | "vsdx" | "one" | "tex" | "ps" | "eps"
        | "xps" | "oxps" | "fb2" | "azw" | "azw3" | "cbz" | "cbr" | "cb7" | "chm" | "hlp"
        | "numbers" | "docm" | "dotx" | "dotm" | "xlsm" | "xlsb" | "xltx" | "pptm" | "potx"
        | "ppsx" => Documento,
        // ── Código fuente / scripts (multiplataforma; muchos lenguajes)
        "c" | "h" | "cpp" | "cc" | "cxx" | "hpp" | "rs" | "go" | "py" | "js" | "mjs" | "ts"
        | "tsx" | "jsx" | "java" | "kt" | "kts" | "swift" | "rb" | "php" | "pl" | "lua"
        | "sh" | "bash" | "zsh" | "fish" | "nu" | "ps1" | "psm1" | "bat" | "cmd" | "vbs"
        | "wsf" | "ahk" | "cs" | "vb" | "scala" | "clj" | "hs" | "ml" | "mli" | "r" | "sql"
        | "asm" | "s" | "html" | "htm" | "css" | "scss" | "sass" | "less" | "styl" | "vue"
        | "svelte" | "astro" | "coffee" | "pug" | "jade" | "ejs" | "hbs" | "twig" | "glsl"
        | "vert" | "frag" | "hlsl" | "shader" | "gdshader" | "wgsl" | "metal" | "cl" | "cu"
        | "cuh" | "cmake" | "gradle" | "dockerfile" | "inl" | "ipp" | "hh" | "hxx" | "m"
        | "mm" | "d" | "nim" | "zig" | "cr" | "ex" | "exs" | "erl" | "elm" | "fs" | "fsx"
        | "fsi" | "jl" | "dart" | "groovy" | "gvy" | "tcl" | "awk" | "sol" | "cairo" | "move"
        | "v" | "sv" | "vhdl" | "thrift" | "capnp" | "graphql" | "gql" | "prisma" | "tf"
        | "hcl" | "nix" | "dhall" | "jsonnet" | "bzl" | "mk" | "ninja" | "meson" | "vcxproj"
        | "sln" | "csproj" | "pbxproj" | "xcconfig" | "podspec" | "gemspec" | "rake"
        | "cabal" | "gd" | "gyp" | "cjs" | "cts" => Codigo,
        // ── Comprimidos / paquetes / imágenes de disco (todas las plataformas)
        "zip" | "gz" | "tgz" | "bz2" | "tbz2" | "xz" | "txz" | "7z" | "rar" | "tar" | "lz"
        | "lzma" | "zst" | "cab" | "arj" | "deb" | "rpm" | "apk" | "ipa" | "whl" | "iso"
        | "dmg" | "lha" | "lz4" | "lzo" | "lrz" | "br" | "z" | "taz" | "tlz" | "tzst"
        | "cpio" | "cpgz" | "sit" | "sitx" | "hqx" | "sea" | "pax" | "shar" | "wim" | "swm"
        | "esd" | "squashfs" | "sfs" | "zpaq" | "zoo" | "lzh" | "img" | "vhd" | "vhdx"
        | "vmdk" | "vdi" | "qcow" | "qcow2" | "toast" | "mdf" | "nrg" | "xar" | "pkg" | "pet"
        | "pup" | "snap" | "flatpak" | "appx" | "appxbundle" | "msix" | "msixbundle" | "crx"
        | "xpi" | "vsix" | "nupkg" | "gem" | "egg" | "war" | "ear" | "jmod" | "aar" | "aab"
        | "obb" | "xapk" | "apks" => Comprimido,
        // ── Recursos de juego / 3D / motores / ROMs (genérico, sin marca)
        "dds" | "ktx" | "ktx2" | "astc" | "pvr" | "basis" | "obj" | "fbx" | "gltf" | "glb"
        | "dae" | "3ds" | "blend" | "stl" | "ply" | "md5" | "pak" | "pk3" | "pk4" | "vpk"
        | "wad" | "bsp" | "unity3d" | "assets" | "resource" | "uasset" | "upk" | "umap"
        | "rpa" | "xnb" | "gma" | "nbt" | "mca" | "mcr" | "schematic" | "blocky" | "vox"
        | "bdae" | "mdl" | "nif" | "esp" | "esm" | "ba2" | "bsa" | "sav" | "dat" | "pck"
        | "love" | "gb" | "gba" | "nes" | "smc" | "sfc" | "z64" | "nds" | "iso9660" | "usd"
        | "usda" | "usdc" | "usdz" | "vrm" | "vmd" | "pmx" | "pmd" | "mmd" | "ms3d" | "smd"
        | "vta" | "qc" | "vtx" | "vvd" | "phy" | "max" | "ma" | "mb" | "c4d" | "lwo" | "lws"
        | "hip" | "spp" | "sbsar" | "sbs" | "ztl" | "zpr" | "tscn" | "tres" | "gdns"
        | "prefab" | "anim" | "controller" | "meta" | "shadergraph" | "cginc" | "compute"
        | "spv" | "spirv" | "vtf" | "vmt" | "wem" | "bnk" | "fsb" | "bank" | "xwb" | "xsb"
        | "acb" | "awb" | "hca" | "at9" | "vag" | "brstm" | "bfstm" | "bcstm" | "nus3bank"
        | "rpf" | "ydr" | "ytd" | "yft" | "ymap" | "ybn" | "big" | "vol" | "grp" | "rff"
        | "art" | "kvx" | "voxel" | "qb" | "qbt" | "vxl" | "kv6" | "schem" | "litematic"
        | "mcstructure" | "mcworld" | "mcpack" | "mcaddon" | "mctemplate" | "mcmeta"
        | "region" | "datapack" | "cia" | "cci" | "nsp" | "xci" | "nca" | "wbfs" | "wia"
        | "rvz" | "gcm" | "ciso" | "chd" | "cso" | "pbp" | "v64" | "n64" | "gg" | "sms"
        | "pce" | "ngp" | "a26" | "a78" | "lnx" | "d64" | "adf" | "dsk" | "fds" | "gbc"
        | "rom" | "gen" | "32x" | "umx" | "abc" => RecursoJuego,
        // ── Datos / configuración / BBDD / certificados / modelos IA / fuentes
        "json" | "xml" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf" | "csv" | "tsv"
        | "db" | "sqlite" | "sqlite3" | "mdb" | "accdb" | "plist" | "proto" | "pb"
        | "msgpack" | "bson" | "parquet" | "avro" | "orc" | "feather" | "arrow" | "pem"
        | "crt" | "cer" | "key" | "der" | "pfx" | "p12" | "csr" | "p7b" | "p7c" | "p8"
        | "jks" | "keystore" | "gpg" | "ovpn" | "kdbx" | "ttf" | "otf" | "woff" | "woff2"
        | "eot" | "ttc" | "pfb" | "pfa" | "fon" | "fnt" | "bdf" | "pcf" | "dfont" | "sfd"
        | "pfm" | "env" | "properties" | "editorconfig" | "lock" | "resx" | "har" | "etl"
        | "evtx" | "reg" | "pcap" | "pcapng" | "cap" | "pdml" | "h5" | "hdf5" | "nc" | "cdf"
        | "mat" | "npy" | "npz" | "pkl" | "pickle" | "joblib" | "gguf" | "ggml"
        | "safetensors" | "onnx" | "pt" | "pth" | "ckpt" | "tflite" | "mlmodel"
        | "caffemodel" | "ndjson" | "jsonl" | "geojson" | "topojson" | "ldb" | "sst"
        | "realm" | "dbf" | "frm" | "myd" | "myi" | "ibd" | "wal" | "shm" => Datos,
        // ── Texto llano / subtítulos / notas
        "txt" | "md" | "log" | "text" | "nfo" | "me" | "readme" | "rst" | "asc" | "markdown"
        | "mkd" | "mdown" | "textile" | "adoc" | "asciidoc" | "org" | "wiki" | "srt" | "vtt"
        | "sub" | "ass" | "ssa" | "sbv" | "lrc" | "diff" | "patch" | "po" | "ics" | "vcf"
        | "man" | "info" => Texto,
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
    let _ = writeln!(s, "# {}\n", tr("File classification","Clasificación de archivos"));
    let _ = writeln!(s, "{}", tfmt(tr("{} file(s) classified by category.\n","{} archivo(s) clasificados por categoría.\n"), &[cl.total.to_string()]));
    if copiado {
        let _ = writeln!(s, "{}", tr("Copies gathered in `extraidos/<category>/` (duplicate contents only once).\n","Copias reunidas en `extraidos/<categoria>/` (contenidos duplicados una sola vez).\n"));
    }
    let _ = writeln!(s, "| {} | {} | {} |", tr("Category","Categoría"), tr("Files","Archivos"), tr("Size","Tamaño"));
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
    let _ = writeln!(s, "\n---\n{}", tr("*Classification generated by capas — classification module by @angelazo*","*Clasificación generada por capas — módulo de clasificación de @angelazo*"));
    s
}

// ── Agrupación de conjuntos de recursos ─────────────────────────────────
// Junta los archivos que comparten nombre base en la misma carpeta de origen
// (p. ej. mundo.blocky + mundo.png + mundo.json) para tratarlos como una unidad.

pub struct Conjuntos {
    pub grupos: usize,
    pub archivos: usize,
}

struct Miembro {
    base: String,
    ruta: PathBuf,
    tipo: Tipo,
}

/// Agrupa por (paquete raíz, carpeta de origen, nombre base). Escribe
/// `conjuntos.md` y, si `empaquetar`, un `extraidos/conjuntos/<nombre>.zip` por
/// conjunto con todos sus archivos juntos.
pub fn agrupar(arbol: &[Nodo], raiz: &Path, empaquetar: bool) -> std::io::Result<Conjuntos> {
    // clave: (índice de raíz, carpeta, nombre base en minúsculas)
    let mut mapa: BTreeMap<(usize, String, String), Vec<Miembro>> = BTreeMap::new();
    for (i, n) in arbol.iter().enumerate() {
        recoge_miembros(n, i, &mut mapa);
    }
    // Un conjunto: ≥2 archivos distintos con el mismo nombre base.
    let grupos: Vec<((usize, String, String), Vec<Miembro>)> = mapa
        .into_iter()
        .filter(|(_, m)| {
            let mut bases: Vec<&str> = m.iter().map(|x| x.base.as_str()).collect();
            bases.sort_unstable();
            bases.dedup();
            bases.len() >= 2
        })
        .collect();

    let dir_zip = raiz.join("extraidos").join("conjuntos");
    if empaquetar && !grupos.is_empty() {
        fs::create_dir_all(&dir_zip)?;
    }
    let mut s = String::new();
    let _ = writeln!(s, "# {}\n", tr("Resource sets","Conjuntos de recursos"));
    let _ = writeln!(s, "{}", tfmt(tr("{} set(s): files sharing a base name in the same folder.\n","{} conjunto(s): archivos que comparten nombre base en la misma carpeta.\n"), &[grupos.len().to_string()]));

    let mut total_archivos = 0usize;
    let mut usados: BTreeMap<String, usize> = BTreeMap::new();
    for ((_, carpeta, _), miembros) in &grupos {
        // Miembros únicos por nombre, orden estable.
        let mut vistos = std::collections::HashSet::new();
        let unicos: Vec<&Miembro> = miembros.iter().filter(|m| vistos.insert(m.base.clone())).collect();
        total_archivos += unicos.len();
        let stem = unicos[0].base.rsplit_once('.').map(|(a, _)| a).unwrap_or(&unicos[0].base);
        let ubic = if carpeta.is_empty() { String::new() } else { tfmt(tr(" (in `{}`)"," (en `{}`)"), &[carpeta.clone()]) };
        let _ = writeln!(s, "## {stem}{ubic}\n");
        for m in &unicos {
            let _ = writeln!(s, "- {} — {}", m.base, categoria(m.tipo, &m.base).etiqueta());
        }

        if empaquetar {
            let nombre_zip = nombre_zip_unico(&dir_zip, stem, &mut usados);
            match empaquetar_conjunto(&dir_zip.join(&nombre_zip), &unicos) {
                Ok(_) => {
                    let _ = writeln!(s, "\n→ `extraidos/conjuntos/{nombre_zip}`");
                }
                Err(e) => {
                    let _ = writeln!(s, "{}", tfmt(tr("\n(could not bundle: {})","\n(no se pudo empaquetar: {})"), &[e.to_string()]));
                }
            }
        }
        let _ = writeln!(s);
    }
    let _ = writeln!(s, "---\n{}", tr("*Resource grouping — capas, by @angelazo*","*Agrupación de conjuntos — capas, de @angelazo*"));
    fs::write(raiz.join("conjuntos.md"), s)?;
    Ok(Conjuntos { grupos: grupos.len(), archivos: total_archivos })
}

fn recoge_miembros(n: &Nodo, raiz_idx: usize, mapa: &mut BTreeMap<(usize, String, String), Vec<Miembro>>) {
    if n.hijos.is_empty() && n.ruta_fisica.is_file() {
        let base = n.nombre.rsplit(['/', '\\']).next().unwrap_or(&n.nombre).to_string();
        let carpeta = n.nombre[..n.nombre.len() - base.len()].trim_end_matches(['/', '\\']).to_string();
        let stem = base.rsplit_once('.').map(|(a, _)| a).unwrap_or(&base).to_lowercase();
        if !stem.is_empty() {
            mapa.entry((raiz_idx, carpeta, stem)).or_default().push(Miembro {
                base,
                ruta: n.ruta_fisica.clone(),
                tipo: n.tipo,
            });
        }
    }
    for h in &n.hijos {
        recoge_miembros(h, raiz_idx, mapa);
    }
}

fn empaquetar_conjunto(destino: &Path, miembros: &[&Miembro]) -> std::io::Result<()> {
    use std::io::Write;
    let f = fs::File::create(destino)?;
    let mut zw = zip::ZipWriter::new(f);
    let op = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for m in miembros {
        let Ok(datos) = fs::read(&m.ruta) else { continue };
        zw.start_file(m.base.clone(), op).map_err(std::io::Error::other)?;
        zw.write_all(&datos)?;
    }
    zw.finish().map_err(std::io::Error::other)?;
    Ok(())
}

fn nombre_zip_unico(dir: &Path, stem: &str, usados: &mut BTreeMap<String, usize>) -> String {
    let limpio: String = stem.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let limpio = if limpio.is_empty() { "conjunto".into() } else { limpio };
    let n = usados.entry(limpio.clone()).or_insert(0);
    *n += 1;
    if *n == 1 && !dir.join(format!("{limpio}.zip")).exists() {
        format!("{limpio}.zip")
    } else {
        format!("{limpio}~{n}.zip")
    }
}

// ── Reconstrucción de paquetes ──────────────────────────────────────────
// Rearma cada paquete con su estructura de carpetas original (desde el árbol
// extraído) para que los archivos vuelvan a encontrar sus dependencias por su
// ruta. Usa los bytes ya extraídos (descifrados si venían con contraseña).

/// Reconstruye cada paquete raíz en `extraidos/reconstruido/<pack>/` y, si
/// `empaquetar`, también en un `.zip` cargable. Devuelve (paquetes, archivos).
pub fn reconstruir(arbol: &[Nodo], raiz: &Path, empaquetar: bool) -> std::io::Result<(usize, usize)> {
    let base = raiz.join("extraidos").join("reconstruido");
    let mut packs = 0;
    let mut archivos = 0;
    let mut usados: BTreeMap<String, usize> = BTreeMap::new();
    for root in arbol {
        if root.hijos.is_empty() {
            continue; // no es un contenedor: nada que rearmar
        }
        let mut hojas: Vec<(PathBuf, PathBuf)> = Vec::new(); // (ruta relativa segura, origen)
        for h in &root.hijos {
            recoge_hojas(h, Path::new(""), &mut hojas);
        }
        if hojas.is_empty() {
            continue;
        }
        let nombre = nombre_dir_unico(root.nombre.rsplit(['/', '\\']).next().unwrap_or(&root.nombre), &mut usados);
        let dir = base.join(&nombre);
        for (rel, origen) in &hojas {
            let destino = dir.join(rel);
            if let Some(p) = destino.parent() {
                let _ = fs::create_dir_all(p);
            }
            let _ = fs::hard_link(origen, &destino).or_else(|_| fs::copy(origen, &destino).map(|_| ()));
        }
        archivos += hojas.len();
        if empaquetar {
            let _ = empaquetar_arbol(&base.join(format!("{nombre}.zip")), &hojas);
        }
        packs += 1;
    }
    Ok((packs, archivos))
}

fn recoge_hojas(n: &Nodo, prefijo: &Path, hojas: &mut Vec<(PathBuf, PathBuf)>) {
    let rel = prefijo.join(crate::motor::ruta_segura(&n.nombre));
    if n.hijos.is_empty() {
        if n.ruta_fisica.is_file() {
            hojas.push((rel, n.ruta_fisica.clone()));
        }
    } else {
        for h in &n.hijos {
            recoge_hojas(h, &rel, hojas);
        }
    }
}

fn empaquetar_arbol(destino: &Path, hojas: &[(PathBuf, PathBuf)]) -> std::io::Result<()> {
    use std::io::Write;
    let f = fs::File::create(destino)?;
    let mut zw = zip::ZipWriter::new(f);
    let op = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (rel, origen) in hojas {
        let Ok(datos) = fs::read(origen) else { continue };
        let nombre = rel.to_string_lossy().replace('\\', "/");
        zw.start_file(nombre, op).map_err(std::io::Error::other)?;
        zw.write_all(&datos)?;
    }
    zw.finish().map_err(std::io::Error::other)?;
    Ok(())
}

fn nombre_dir_unico(nombre: &str, usados: &mut BTreeMap<String, usize>) -> String {
    let limpio: String = nombre.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' }).collect();
    let limpio = if limpio.is_empty() { "paquete".into() } else { limpio };
    let n = usados.entry(limpio.clone()).or_insert(0);
    *n += 1;
    if *n == 1 { limpio } else { format!("{limpio}~{n}") }
}
