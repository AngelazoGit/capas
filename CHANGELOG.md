# Changelog

Todas las novedades relevantes de CAPAS. El formato sigue
[Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/)
y el versionado [SemVer](https://semver.org/lang/es/).

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

[0.1.2]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.2
[0.1.1]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.1
[0.1.0]: https://github.com/AngelazoGit/capas/releases/tag/v0.1.0
