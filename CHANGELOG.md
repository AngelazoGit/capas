# Changelog

Todas las novedades relevantes de CAPAS. El formato sigue
[Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/)
y el versionado [SemVer](https://semver.org/lang/es/).

## [0.1.3] — 2026-11-26

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

[0.1.3]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.3
[0.1.2]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.2
[0.1.1]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.1
[0.1.0]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.0
