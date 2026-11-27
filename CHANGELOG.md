# Changelog

Todas las novedades relevantes de CAPAS. El formato sigue
[Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/)
y el versionado [SemVer](https://semver.org/lang/es/).

## [0.1.6] — 2026-11-27

### Añadido — fuerza bruta de ZipCrypto mucho más rápida (CPU y GPU)
- **Chequeo rápido del byte de control.** Al probar contraseñas contra un ZIP
  con ZipCrypto tradicional, ahora se comprueba primero el byte de control de la
  cabecera cifrada de 12 bytes (descarta ~255/256 de las erróneas al instante) y
  solo se descifra la entrada entera cuando ese chequeo pasa. En una prueba,
  ~457.000 candidatas en ~1,2 s con 4 hilos.
- **Aceleración por GPU (opcional).** La misma comprobación corre en la GPU,
  masivamente en paralelo: cada hilo genera una contraseña desde su índice,
  ejecuta el key-schedule de ZipCrypto y comprueba el byte de control; los
  aciertos se confirman en CPU. Interruptor «Usar GPU» en el módulo de Claves
  (solo si se detecta una GPU utilizable) y `--gpu` en la línea de comandos; si
  no hay GPU, cae a CPU automáticamente. La GPU solo acelera esta fuerza bruta,
  no la decompilación. Se puede compilar sin ella con `--no-default-features`.

### Añadido — archivos grandes (varios GiB) y claridad de la interfaz
- **Mapeo en memoria (mmap) del archivo de entrada.** El fichero de nivel 0 ya
  no se carga entero en RAM: el sistema trae las páginas bajo demanda, así que
  una ISO o un juego de varios GiB se puede analizar sin agotar la memoria.
- **Volcado a disco en streaming de los ficheros grandes de una ISO.** Los
  ficheros de una imagen que no caben en el presupuesto de memoria se escriben
  directamente a la carpeta de salida en trozos (sin cargarlos en RAM) y
  aparecen como resultados abribles. Los que caben siguen el análisis por capas.
- **Interfaz explicada de arriba abajo.** Cada vista del menú, cada sección
  (Núcleos, Memoria, Motores, Parámetros, Claves) y cada botón (Analizar,
  Extraer, Vista previa…) dicen para qué sirven, con subtítulos y con ayuda al
  pasar el ratón. Objetivo: que quien no conozca la herramienta sepa siempre qué
  está tocando (analizar vs decompilar).

### Corregido — ISO grandes (imágenes de disco de varios GiB)
- **Una ISO ya no se descarta entera por el límite de memoria.** Antes, una
  imagen ISO 9660 mayor que el límite por bloque fallaba con «¿bomba de
  descompresión?», lo cual era engañoso: una ISO no está comprimida (ratio 1:1),
  el límite es de MEMORIA (CAPAS mantiene lo extraído en RAM). Ahora extrae los
  ficheros que caben, los grandes se vuelcan a disco (ver arriba) y, si no hay
  dónde volcarlos, se omiten con una nota y un resumen claro.

## [0.1.5] — 2026-11-27

### Corregido — autoactualización en bucle
- **La versión del binario ahora coincide con la etiqueta de la release.** El
  workflow de release sella en `Cargo.toml` el número de la etiqueta (`vX.Y.Z`)
  **antes de compilar**. Antes, el `.exe` publicado como v0.1.4 reportaba
  internamente 0.1.3, así que tras «actualizar» la app volvía a ver una versión
  mayor en GitHub y **pedía actualización sin parar**. (La release v0.1.4 quedó
  afectada por esto; v0.1.5 la sustituye.)
- **Reemplazo del ejecutable más robusto en Windows.** El script de
  autoactualización renombra el `.exe` en marcha (en vez de intentar borrarlo en
  un bucle infinito), con reintentos acotados y cierre garantizado de la
  consola: ya no se queda una ventana `cmd` abierta.

## [0.1.3] — 2026-11-26

### Añadido — recuperación de ZipCrypto (sin contraseña)
- **Detección de cifrado**: CAPAS distingue **ZipCrypto** (clásico, débil) de
  **AES** (fuerte) en cada ZIP y lo dice en claro: ZipCrypto se puede recuperar
  sin la contraseña con un texto plano conocido; AES no se rompe (solo con
  contraseña / diccionario / fuerza bruta con abecedario).
- **Ataque de texto plano conocido** (Biham–Kocher, implementación nativa en
  Rust): con una copia sin cifrar de una de las entradas STORED (`--texto-plano
  ARCHIVO`, o el selector del módulo de Claves en la app), rompe el ZipCrypto
  **sin la contraseña**, recupera el estado del cifrador y descifra TODAS las
  entradas, que siguen el análisis por capas. No toca AES.
- **Autodetección de cabeceras conocidas** (`--auto-texto-plano`, o la casilla
  del módulo de Claves): si una entrada STORED es XML/SVG/HTML/plist…, CAPAS
  prueba su cabecera típica (p. ej. `<?xml version="1.0" encoding="`) como texto
  plano y rompe el ZipCrypto **sin aportar ninguna copia**. Es más lento (cada
  intento cuesta unos minutos) y va desactivado por defecto.

### Añadido — lector nativo de .NET / CLI
- **Ensamblados .NET** (PE con cabecera CLR) se detectan y se les lee la
  **estructura** de forma nativa (metadatos ECMA-335, sin .NET instalado):
  espacios de nombres, clases, campos y métodos (con `static`), estilo `ildasm`.
  Muy útil para la lógica de juegos Unity (`Assembly-CSharp.dll`). Además del
  análisis PE habitual. Disponible con `--listar-codigo`/`--decompilar` y en la
  app. (El pseudo-C# completo y el desensamblado CIL quedan para más adelante.)

### Añadido — decompilador de shaders (SPIR-V → WGSL)
- **Shaders SPIR-V** (Vulkan/OpenGL/WebGPU) se detectan por contenido y se
  decompilan a **WGSL legible** de forma nativa (con naga, ya incluido). Sigue el
  análisis por capas, con `--decompilar`/`--listar-codigo` y en la app.

### Añadido — motor 100 % nativo
- **Contenedores sin herramientas externas**: 7z (incluido AES y cabeceras
  cifradas), RAR v2–v5 (cifrados y sólidos), CAB, MSI/MSP y cualquier archivo
  compuesto OLE (Office 97-2003, thumbs.db…), y CHD de MAME (las pistas de
  datos de CD pasan a ISO). Prueban las contraseñas del módulo de Claves.
- **Decompilador Java nativo** a pseudo-fuente legible: nombres reales de
  variables, `if/else`, `while`, `? :`, lambdas en línea, concatenación de
  cadenas, `new`, arrays inicializados e imports. Además, listado tipo
  `javap -c -p` sin JDK.
- **Decompilador Python nativo** para `.pyc` de 3.6 a 3.14: clases,
  decoradores, comprensiones, `try/except/finally`, comparaciones encadenadas,
  f-strings, `async/await`, `and/or`. Desensamblado exacto (verificado contra
  `dis` en las 7 versiones).
- **Android DEX nativo**: clases, campos, métodos y bytecode Dalvik con
  cadenas, tipos y miembros resueltos.
- **WebAssembly → WAT** nativo.
- **Desensamblado ARM64, ARM/Thumb y MIPS** (además de x86/x64), con destinos
  de salto y símbolos; cabeceras ELF completas (segmentos, sección dinámica,
  reubicaciones, build-id). Ya no hacen falta `readelf` ni `objdump`.
- Nuevas opciones: `--decompilar ARCHIVO` y `--listar-codigo ARCHIVO`.
- Puente MCP: nueva herramienta `capas_decompile_file` (Studio).
- Herramientas: lo cubierto por el motor nativo aparece como **INTEGRADO**;
  solo Ghidra, RetDec, radare2 y wasm-decompile quedan como opcionales.

### Cambiado
- Las herramientas externas pasan a ser **respaldo opcional**: CAPAS intenta
  primero la vía nativa y solo recurre a ellas si están instaladas y la nativa
  no puede.

## [0.1.2] — 2026-11-26

### Añadido
- **Motores con un clic.** En la vista de Herramientas, cada subsistema
  externo ausente (7-Zip, jadx, radare2, CFR, pycdc, Ghidra…) muestra un
  botón para instalarlo: en Windows lanza `winget` con el id del paquete, y
  en el resto abre la página oficial de descarga. Botón **Rescan** para
  volver a detectar sin reiniciar y contador «activas/total».
- **Puente MCP para IA (Studio).** Servidor MCP por `stdio` (`capas --mcp`)
  con las herramientas `capas_analyze_file`, `capas_list_formats` e
  `capas_inspect_output`. Se activa y configura desde Ajustes para Claude
  Desktop, un modelo local (Ollama) o la nube. Gated a edición Studio.
- **Autoactualización dentro de la app.** Cuando hay una versión nueva en
  GitHub Releases aparece un aviso (o desde Ajustes); al aceptar, el
  programa se cierra, se reemplaza solo y se vuelve a abrir.
- **Aviso de 7-Zip** en la vista de Formatos cuando falta, con botón de
  instalación directa.

### Corregido
- **Archivos protegidos con contraseña** (RAR/7z/CAB/ISO): se prueba la
  contraseña indicada y las habituales, con tope de intentos, en lugar de
  descartar el archivo. No rompe cifrado fuerte.
- Los archivos de entrada de nivel superior ya no se descartaban por el
  límite de tamaño por bloque.
- En Windows se detecta 7-Zip en `Program Files` aunque no esté en el PATH,
  y también junto al propio ejecutable (uso portable).

## [0.1.1] — 2026-11

### Añadido
- Rebranding completo de la interfaz: barra lateral, tarjetas, tres paneles,
  tipografía Inter y paleta índigo; tema «Serio» por defecto.
- Vistas de Explorar, Comparar (Pro), Formatos y Ajustes.

## [0.1.0]

### Añadido
- Primera versión: motor de análisis por capas, detección por contenido de
  cientos de formatos, extracción recursiva, índice SQLite, auditoría de
  packs y mods, módulo de claves e informes. Núcleo gratuito; Pro y Studio
  por licencia firmada (Ed25519) sin conexión.

[0.1.6]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.6
[0.1.5]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.5
[0.1.3]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.3
[0.1.2]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.2
[0.1.1]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.1
[0.1.0]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.0
