# Plan nativo-primero — recortar dependencias de terceros

> **Estado (v0.1.3): Tier 1 y Tier 2 COMPLETADOS, y además decompiladores
> nativos de Java y Python.** Verificado con 37 tests automáticos, 114 módulos
> reales de la stdlib de Python (3.8/3.11/3.12/3.14) y 400 clases reales del
> JDK sin un solo fallo.

| Herramienta | Sustituto nativo | Estado |
| --- | --- | --- |
| 7z (7z) | `sevenz-rust2` (AES + cabeceras cifradas) | ✅ hecho |
| 7z (RAR) | `unrar` (librería UnRAR enlazada; su licencia permite extraer en software propio) | ✅ hecho |
| 7z (CAB) | `cab` | ✅ hecho |
| 7z (MSI) | `cfb` (OLE/Compound File, nombres MSI decodificados) | ✅ hecho |
| 7z (ISO) | ya era nativo | ✅ |
| chdman | `chd` (CD → ISO, DVD/HDD → imagen) | ✅ hecho |
| readelf | `goblin` ampliado (segmentos, dinámica, reubicaciones, build-id) | ✅ hecho |
| objdump | `iced-x86` + `yaxpeax-arm` (ARM64/ARM/Thumb) + `yaxpeax-mips` | ✅ hecho (otras arquitecturas siguen usando objdump si está) |
| file | detección nativa | ✅ hecho |
| javap | `cafebabe` + formateador propio | ✅ hecho |
| cfr / procyon | **decompilador Java propio** (pseudo-fuente legible) | ✅ hecho · externos solo para salida recompilable |
| jadx | `dex` + desensamblador Dalvik propio | ✅ listado · jadx opcional para fuente Java |
| pycdc / decompyle3 / uncompyle6 | lector `marshal` + tablas de opcodes generadas de CPython 3.6–3.14 + **decompilador propio** | ✅ hecho |
| wasm2wat | `wasmprinter` | ✅ hecho |
| wasm-decompile, retdec, r2, Ghidra | — | opcionales (investigación; Tier 3) |

---

Objetivo: que CAPAS cubra en **Rust puro** todo lo razonable (extracción,
detección, desensamblado, listado de bytecode) y deje como **motores
opcionales** solo lo que es investigación pura (decompilación a fuente y
nativo→C). Todas las crates propuestas son de licencia permisiva (MIT/Apache/
0BSD) — aptas para un producto de pago, sin GPL ni unrar.

Regla de transición (no rompe nada): en cada formato se intenta **primero la
ruta nativa**; si falla o no cubre un caso, se cae a la herramienta externa
como hasta ahora. Se elimina la dependencia de la lista "necesarias" solo
cuando la ruta nativa pasa sus tests con archivos de muestra.

## Lo que YA es nativo (no tocar)

| Capa | Implementación |
| --- | --- |
| gzip, zlib, bzip2, xz, lzma, zstd, lz4 | `flate2`, `bzip2`, `lzma-rs`, `ruzstd`, `lz4_flex` (extraer.rs) |
| zip, tar, ar/.deb, Mach-O FAT, flujos PDF | `zip`, `tar`, `goblin` (extraer.rs) |
| Detección por contenido (729 ext) | nativo, bytes mágicos (detectar.rs) |
| Cabeceras ELF/PE/Mach-O + símbolos | `goblin` (ejecutables.rs) |
| Desensamblado x86/x64 | `iced-x86` (ejecutables.rs) |
| Tallado por firma, strings, base64, bundles Unity/Godot | nativo (extraer.rs) |

## Tier 1 — alto valor, esfuerzo bajo/medio (hacer primero)

Quita las dependencias más molestas del día a día. Es el mayor golpe de fricción.

| Herramienta hoy | Para qué | Sustituto nativo | Esfuerzo | Nota |
| --- | --- | --- | --- | --- |
| **7z** (7z) | extraer .7z | `sevenz-rust` | ~1-2 d | El caso más pedido. RAR se queda aparte (ver Tier 3). |
| **7z** (ISO) | extraer .iso | `cdfs` / `iso9660` | ~1 d | ISO9660 |
| **7z** (CAB) | extraer .cab | `cab` | ~0.5-1 d | |
| **7z** (MSI) | extraer .msi | `msi` | ~0.5-1 d | MSI = contenedor OLE |
| **wasm2wat** | .wasm → texto WAT | `wasmprinter` | ~0.5 d | de wasm-tools, exacto |
| **readelf** | volcado cabeceras ELF | ya cubierto por `goblin` | ~1 d | ampliar la salida de ejecutables.rs y quitar readelf de "necesarias" |

Al cerrar Tier 1, el `.exe` abre 7z/ISO/CAB/MSI y lee WASM **sin instalar nada**.
Solo RAR seguiría pidiendo un motor externo.

## Tier 2 — esfuerzo medio, amplía desensamblado y bytecode

| Herramienta hoy | Para qué | Sustituto nativo | Esfuerzo | Nota |
| --- | --- | --- | --- | --- |
| **objdump** | desensamblar no-x86 (ARM/MIPS…) | `yaxpeax-*` | ~3-5 d | multi-arquitectura en Rust |
| **javap** | listar bytecode .class | `cafebabe` | ~2-3 d | parseo de .class + listado |
| **pycdc/uncompyle6** (parcial) | listar bytecode .pyc | parser nativo de marshal/bytecode | ~2-3 d | solo *listado* tipo `dis`, no fuente |
| **file** | etiqueta de respaldo | ampliar detección nativa | ~0.5 d | ya detectamos nativo; quitar el fallback |

Tras Tier 2, objdump/javap/file dejan de ser necesarios. Queda solo
decompilación a fuente de verdad.

## Tier 3 — mantener externo (investigación; no reimplementar)

No hay crate Rust que iguale esto, y reescribirlo sería años de trabajo peor.

| Motor | Para qué | Por qué se queda |
| --- | --- | --- |
| cfr / procyon | Java → **código fuente** | décadas de trabajo; sin equivalente Rust |
| jadx | DEX/APK → Java | ídem; decompilación de alto nivel |
| decompyle3 | .pyc → **fuente** Python | específico por versión de Python |
| retdec-decompiler | nativo → C | problema no resuelto del área |
| analyzeHeadless (Ghidra) | nativo → C | millones de líneas; estándar del sector |
| r2 (radare2) | análisis por funciones | análisis profundo; nativo solo cubre parte |
| **RAR** (vía 7z) | extraer .rar | formato propietario; libs con licencia no redistribuible |
| chdman | CHD (MAME) → BIN/CUE | nicho; `chd-rs` posible pero baja prioridad |

**Reducir fricción sin reimplementar:** los redistribuibles (jadx Apache-2.0,
radare2 LGPL, Ghidra Apache-2.0) se pueden **empaquetar** con el producto para
que no haya que instalarlos. RAR y cualquier GPL fuerte: fuera del bundle, se
instalan aparte (ya lo cubre el instalador con un clic).

## Orden sugerido

1. **7z nativo** (`sevenz-rust`) — mayor impacto de fricción.
2. ISO + CAB + MSI nativos — cierra contenedores comunes.
3. **wasm2wat** (`wasmprinter`) — barato y completo.
4. Ampliar `goblin` y retirar **readelf**.
5. **objdump** → `yaxpeax` (empezar por ARM64).
6. **javap** → `cafebabe`; luego listado de .pyc.
7. Retirar **file**.

Con 1-4 (Tier 1) ya puedes afirmar con verdad: *analizador, extractor y
desensamblador **autónomo**; decompilación profunda conectando motores de
primera (opcional, un clic)*.

## Licencias de las crates propuestas

`sevenz-rust` (MIT/Apache-2.0), `cdfs`/`iso9660` (MIT), `cab` (MIT), `msi`
(MIT), `wasmprinter` (Apache-2.0 w/ LLVM exc.), `yaxpeax-*` (0BSD), `cafebabe`
(MIT/Apache-2.0). Todas permisivas: compatibles con un binario comercial.
