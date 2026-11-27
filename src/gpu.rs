//! Aceleración por GPU (opcional) de la fuerza bruta de ZipCrypto.
//!
//! La GPU NO decompila ni descomprime: solo acelera un cómputo masivamente
//! paralelo: por cada contraseña candidata, corre el key-schedule de ZipCrypto
//! y comprueba el byte de control de la cabecera cifrada de 12 bytes. Es el
//! mismo chequeo rápido que hace la CPU (`zipcrypto::VerificadorZip`), pero en
//! decenas de miles de hilos. Los aciertos (que pasan el chequeo, 1/256 de
//! falsos positivos) se confirman luego en CPU con un descifrado completo.
//!
//! Si no hay GPU utilizable, todo esto se salta y el cracking sigue en CPU.
//! Solo se compila con la feature `gpu`.

use crate::zipcrypto::{self, Tablas};

/// Resultado de la pasada por GPU: contraseñas candidatas que PASAN el chequeo
/// rápido (hay que confirmarlas en CPU). `None` si la GPU no está disponible.
pub struct PasoGpu {
    pub candidatas: Vec<String>,
    pub descripcion: String,
}

/// Crea la instancia de wgpu respetando `WGPU_BACKEND` (gl/vulkan/dx12/metal…)
/// si está puesto; si no, prueba todos los backends disponibles.
fn instancia() -> wgpu::Instance {
    let backends = wgpu::util::backend_bits_from_env().unwrap_or_else(wgpu::Backends::all);
    wgpu::Instance::new(wgpu::InstanceDescriptor { backends, ..Default::default() })
}

/// Nombre de la GPU detectada (para mostrar en la interfaz), o None.
pub fn nombre_adaptador() -> Option<String> {
    let inst = instancia();
    let ad = pollster::block_on(inst.request_adapter(&wgpu::RequestAdapterOptions {
        power_preference: wgpu::PowerPreference::HighPerformance,
        force_fallback_adapter: false,
        compatible_surface: None,
    }))?;
    let info = ad.get_info();
    Some(format!("{} ({:?})", info.name, info.backend))
}

const WGSL: &str = r#"
// Fuerza bruta de ZipCrypto en GPU. Cada invocación prueba una contraseña,
// reconstruida desde su índice global, y comprueba el byte de control.
struct Params {
    n: u32,        // tamaño del alfabeto
    long: u32,     // longitud de la contraseña
    base: u32,     // desplazamiento del lote (índice del primer candidato)
    total: u32,    // candidatos de este lote
    chk: u32,      // byte de control esperado (0..255)
    _pad0: u32,
    _pad1: u32,
    _pad2: u32,
};

@group(0) @binding(0) var<uniform> P: Params;
@group(0) @binding(1) var<storage, read> crctab: array<u32, 256>;
@group(0) @binding(2) var<storage, read> alfabeto: array<u32>;   // bytes del alfabeto (uno por u32)
@group(0) @binding(3) var<storage, read> header: array<u32, 12>; // 12 bytes de la cabecera cifrada
@group(0) @binding(4) var<storage, read_write> hits: array<atomic<u32>>; // [0]=contador, resto índices

fn crc32(crc: u32, b: u32) -> u32 {
    return (crc >> 8u) ^ crctab[(crc ^ b) & 0xffu];
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    if (i >= P.total) { return; }
    let idx = P.base + i;

    // Estado inicial de ZipCrypto.
    var k0: u32 = 0x12345678u;
    var k1: u32 = 0x23456789u;
    var k2: u32 = 0x34567890u;

    // Reconstruye la contraseña (dígitos base-N, el menos significativo primero)
    // y alimenta el key-schedule carácter a carácter.
    var g = idx;
    for (var pos: u32 = 0u; pos < P.long; pos = pos + 1u) {
        let d = g % P.n;
        g = g / P.n;
        let ch = alfabeto[d] & 0xffu;
        // update(ch)
        k0 = crc32(k0, ch);
        k1 = (k1 + (k0 & 0xffu)) * 0x08088405u + 1u;
        k2 = crc32(k2, (k1 >> 24u) & 0xffu);
    }

    // Descifra los 12 bytes de la cabecera; el último debe igualar chk.
    var last: u32 = 0u;
    for (var j: u32 = 0u; j < 12u; j = j + 1u) {
        let temp = (k2 | 2u) & 0xffffu;
        let ks = ((temp * (temp ^ 1u)) >> 8u) & 0xffu;
        let p = (header[j] & 0xffu) ^ ks;
        // update(p)
        k0 = crc32(k0, p);
        k1 = (k1 + (k0 & 0xffu)) * 0x08088405u + 1u;
        k2 = crc32(k2, (k1 >> 24u) & 0xffu);
        last = p;
    }

    if (last == P.chk) {
        let slot = atomicAdd(&hits[0], 1u) + 1u;
        if (slot < arrayLength(&hits)) {
            atomicStore(&hits[slot], idx);
        }
    }
}
"#;

#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct Params {
    n: u32,
    long: u32,
    base: u32,
    total: u32,
    chk: u32,
    _pad0: u32,
    _pad1: u32,
    _pad2: u32,
}

/// Reconstruye la contraseña a partir de su índice global (debe coincidir
/// EXACTAMENTE con el decode del shader).
fn pw_de_indice(alfabeto: &[u8], long: u32, mut g: u64) -> String {
    let n = alfabeto.len() as u64;
    let mut bytes = vec![0u8; long as usize];
    for b in bytes.iter_mut() {
        *b = alfabeto[(g % n) as usize];
        g /= n;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Ejecuta la fuerza bruta de ZipCrypto en GPU. Devuelve las candidatas que
/// pasan el chequeo del byte de control (a confirmar en CPU), o None si no hay
/// GPU utilizable o el ZIP no es ZipCrypto tradicional.
pub fn fuerza_bruta(zip: &[u8], alfabeto: &[u8], long_max: u32, tope_hits: usize) -> Option<PasoGpu> {
    if alfabeto.is_empty() || long_max == 0 {
        return None;
    }
    let t = Tablas::new();
    // Extrae el objetivo (cabecera de 12 bytes + byte de control) reutilizando el
    // verificador de CPU para no duplicar la lógica de selección de entrada.
    let obj = zipcrypto::ObjetivoZip::nuevo(&t, zip)?;

    // Instancia + adaptador + dispositivo.
    let inst = instancia();
    let ad = pollster::block_on(inst.request_adapter(&wgpu::RequestAdapterOptions {
        power_preference: wgpu::PowerPreference::HighPerformance,
        force_fallback_adapter: false,
        compatible_surface: None,
    }))?;
    let nombre = ad.get_info().name;
    let backend = format!("{:?}", ad.get_info().backend);
    let (dev, queue) = pollster::block_on(ad.request_device(
        &wgpu::DeviceDescriptor {
            label: Some("capas-gpu"),
            required_features: wgpu::Features::empty(),
            required_limits: wgpu::Limits::downlevel_defaults(),
            memory_hints: wgpu::MemoryHints::Performance,
        },
        None,
    ))
    .ok()?;

    use wgpu::util::DeviceExt;
    let crctab: Vec<u32> = t.crc.tabla_directa().to_vec();
    let alf_u32: Vec<u32> = alfabeto.iter().map(|&b| b as u32).collect();
    let hdr_u32: [u32; 12] = {
        let mut a = [0u32; 12];
        for (i, s) in a.iter_mut().enumerate() {
            *s = obj.header[i] as u32;
        }
        a
    };

    let buf_crc = dev.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("crc"),
        contents: bytemuck::cast_slice(&crctab),
        usage: wgpu::BufferUsages::STORAGE,
    });
    let buf_alf = dev.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("alf"),
        contents: bytemuck::cast_slice(&alf_u32),
        usage: wgpu::BufferUsages::STORAGE,
    });
    let buf_hdr = dev.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("hdr"),
        contents: bytemuck::cast_slice(&hdr_u32),
        usage: wgpu::BufferUsages::STORAGE,
    });

    // Buffer de hits: [0] contador + hasta `tope_hits` índices.
    let n_hits = (tope_hits + 1) as u64;
    let buf_hits = dev.create_buffer(&wgpu::BufferDescriptor {
        label: Some("hits"),
        size: n_hits * 4,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let buf_lee = dev.create_buffer(&wgpu::BufferDescriptor {
        label: Some("lee"),
        size: n_hits * 4,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let buf_par = dev.create_buffer(&wgpu::BufferDescriptor {
        label: Some("par"),
        size: std::mem::size_of::<Params>() as u64,
        usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let modulo = dev.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("zipcrypto"),
        source: wgpu::ShaderSource::Wgsl(WGSL.into()),
    });
    let pipeline = dev.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("bf"),
        layout: None,
        module: &modulo,
        entry_point: "main",
        compilation_options: Default::default(),
        cache: None,
    });
    let bgl = pipeline.get_bind_group_layout(0);
    let bg = dev.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("bg"),
        layout: &bgl,
        entries: &[
            wgpu::BindGroupEntry { binding: 0, resource: buf_par.as_entire_binding() },
            wgpu::BindGroupEntry { binding: 1, resource: buf_crc.as_entire_binding() },
            wgpu::BindGroupEntry { binding: 2, resource: buf_alf.as_entire_binding() },
            wgpu::BindGroupEntry { binding: 3, resource: buf_hdr.as_entire_binding() },
            wgpu::BindGroupEntry { binding: 4, resource: buf_hits.as_entire_binding() },
        ],
    });

    let n = alfabeto.len() as u64;
    let mut candidatas = Vec::new();
    let lote_max: u64 = 1 << 22; // 4M candidatos por despacho

    'longs: for long in 1..=long_max {
        // total = n^long; si excede u32, esa longitud se deja a la CPU.
        let mut total: u128 = 1;
        for _ in 0..long {
            total *= n as u128;
        }
        if total > u32::MAX as u128 {
            continue; // demasiado grande para el índice u32 del shader
        }
        let total = total as u64;
        let mut base = 0u64;
        while base < total {
            let este = (total - base).min(lote_max);
            // Reinicia el contador de hits.
            queue.write_buffer(&buf_hits, 0, bytemuck::cast_slice(&[0u32]));
            let par = Params {
                n: n as u32,
                long,
                base: base as u32,
                total: este as u32,
                chk: obj.chk as u32,
                _pad0: 0,
                _pad1: 0,
                _pad2: 0,
            };
            queue.write_buffer(&buf_par, 0, bytemuck::bytes_of(&par));

            let grupos = ((este as u32) + 63) / 64;
            let mut enc = dev.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
            {
                let mut cp = enc.begin_compute_pass(&wgpu::ComputePassDescriptor { label: None, timestamp_writes: None });
                cp.set_pipeline(&pipeline);
                cp.set_bind_group(0, &bg, &[]);
                cp.dispatch_workgroups(grupos, 1, 1);
            }
            enc.copy_buffer_to_buffer(&buf_hits, 0, &buf_lee, 0, n_hits * 4);
            queue.submit(Some(enc.finish()));

            // Lee los hits.
            let sl = buf_lee.slice(..);
            let (tx, rx) = std::sync::mpsc::channel();
            sl.map_async(wgpu::MapMode::Read, move |r| { let _ = tx.send(r); });
            dev.poll(wgpu::Maintain::Wait);
            if rx.recv().ok().and_then(|r| r.ok()).is_none() {
                return None;
            }
            {
                let datos = sl.get_mapped_range();
                let u: &[u32] = bytemuck::cast_slice(&datos);
                let cuenta = (u[0] as usize).min(tope_hits);
                for &idx in &u[1..=cuenta] {
                    candidatas.push(pw_de_indice(alfabeto, long, idx as u64));
                    if candidatas.len() >= tope_hits {
                        drop(datos);
                        buf_lee.unmap();
                        break 'longs;
                    }
                }
            }
            buf_lee.unmap();
            base += este;
        }
    }

    Some(PasoGpu {
        candidatas,
        descripcion: format!("{nombre} [{backend}]"),
    })
}

#[cfg(test)]
mod pruebas_gpu {
    use super::*;

    fn fx(n: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(n)).unwrap()
    }

    #[test]
    #[ignore = "necesita una GPU/driver utilizable (wgpu)"]
    fn gpu_encuentra_la_contrasena_corta() {
        // zipcrypto_bf.zip tiene la contraseña "wxyz" (a-z, longitud 4).
        let zip = fx("zipcrypto_bf.zip");
        let abc: Vec<u8> = (b'a'..=b'z').collect();
        match fuerza_bruta(&zip, &abc, 4, 4096) {
            Some(paso) => {
                eprintln!("GPU {} → {} candidatas pasaron el chequeo; wxyz presente: {}", paso.descripcion, paso.candidatas.len(), paso.candidatas.iter().any(|c| c == "wxyz"));
                // El kernel debe dejar pasar la correcta (entre ~1/256 de falsos
                // positivos), y confirmamos que da el MISMO resultado que la CPU.
                assert!(paso.candidatas.iter().any(|c| c == "wxyz"), "la GPU debe pasar 'wxyz' ({})", paso.descripcion);
                let t = Tablas::new();
                let ver = zipcrypto::VerificadorZip::nuevo(&t, &zip).unwrap();
                for c in &paso.candidatas {
                    assert!(ver.comprueba(c.as_bytes()), "la CPU debe confirmar el chequeo del candidato GPU '{c}'");
                }
            }
            None => eprintln!("sin GPU utilizable en este entorno: no se valida el kernel aquí"),
        }
    }
}
