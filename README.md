# capas

**by @angelazo** · [Español](README.es.md)

![capas analyzing a file](docs/analizando.png)

Take files (or folders) apart **layer by layer** and decompile them using your
computer's resources: every CPU core, a memory budget tuned to the free RAM, and
whatever reverse-engineering tools you have installed.

```
sample.tar.gz  (GZIP)
└─ sample.tar  (TAR)
   └─ inner.zip  (ZIP)
      ├─ app.jar (ZIP) ─ Main.class ─> javap / CFR
      ├─ app (ELF x86-64) ─> headers, symbols, disassembly, objdump, Ghidra…
      ├─ sfx (ELF) ─ carved_0x3e78.zip ─ main.c   ← zip hidden after the binary
      └─ install.sh (text) ─ base64_0x13.gz ─ secret.txt   ← embedded payload
```

A single program with a **graphical interface** and a **console mode**. Builds to a
portable Windows `.exe`. Default UI language is **English** (Spanish available), and
it ships with a calm **"Serene"** theme plus the original intense **"Command"** look.

## How it works

Every file is a **block**. For each block, capas:

1. **Identifies** the format by its content (magic numbers), not its extension.
2. **Analyzes / decompiles** it: disassembles executables, pulls their headers and
   symbols, decompiles bytecode, extracts strings, measures entropy.
3. **Extracts the next layer**: decompresses, opens the container, carves embedded
   files by signature, and produces the child blocks.
4. **Repeats** on each child, in **parallel** across all cores, until there are no
   more layers or the depth limit is hit.

Identical blocks (same SHA-256) are analyzed once. There are per-block and total
limits to stop decompression bombs.

## Build

```bash
cargo build --release
```

The binary lands at `target/release/capas` (`capas.exe` on Windows).

### Windows: portable `.exe`

`capas.exe` (x64) is **portable**: a single file, no install, no external DLLs.
Double-click it for the GUI, or run `capas.exe file.zip` from a terminal for the
console mode. **Direct download:** [`dist/capas.exe`](https://github.com/AngelazoGit/capas/raw/main/dist/capas.exe)
(SmartScreen may warn because it is unsigned → *More info → Run anyway*).

Cross-compile the `.exe` from Linux:

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt-get install -y gcc-mingw-w64-x86-64
cargo build --release --target x86_64-pc-windows-gnu
```

On Linux the GUI needs the usual desktop libraries (`libxkbcommon-x11`, OpenGL).

## Usage

```bash
capas                      # open the GUI (empty)
capas --gui file.zip       # open the GUI and start analyzing
capas file.zip -s out      # console mode
capas --recursos           # show detected CPU/RAM/tools and exit
capas --idioma es          # Spanish UI (default is English; also auto-detected)
capas --help               # all options
```

## What each layer does

| Format | Built-in (Rust) | External if installed |
|---|---|---|
| gzip, bzip2, xz, lzma, zlib, zip/jar/apk, tar, ar/.deb, Mach-O fat | extraction | — |
| 7z, RAR, CAB | — | `7z` |
| PDF | extracts and inflates its streams | — |
| ELF / PE / Mach-O | headers, sections, imports, symbols, x86/x64 disassembly with symbol labels | `readelf`, `objdump`, `r2`, `retdec-decompiler`, Ghidra → C |
| Java class | — | `javap`, `cfr`, `procyon` |
| DEX | — | `jadx` |
| .pyc | — | `pycdc`, `decompyle3`, `uncompyle6` |
| WebAssembly | — | `wasm2wat`, `wasm-decompile` |
| audio/video/fonts/DB | OGG, WAV, MP3, FLAC, MP4, WebM, AVI, SQLite, TTF/OTF/WOFF… by content | — |
| text/scripts | detects embedded base64 payloads | — |
| any binary | ASCII/UTF-16 strings, entropy, signature carving of embedded files | `file` |

Whatever isn't recognized by content is collected in **`desconocidos.txt`**, grouped
by magic bytes + extension, so detection can be extended for custom formats.

## Features

- **Confidence levels** — every file is labelled **Confirmed / Compatible / Probable
  / Unknown** with the evidence behind it: Confirmed = a magic signature proves it;
  Probable = extension only or text heuristic; Unknown = no evidence. `Unknown` is not
  a failure — it is what keeps the report honest instead of falsely confident. Shown in
  the GUI (confidence panel + per-block badge) and in the reports.
- **SQLite index** — every run writes an index (`capas.db` in the output, or a fixed DB
  with `--indice path.db`) that is the source of truth: tables `files` (keyed by SHA-256),
  `containers`, `relations`, `findings`, `runs`. With the hash as key, the same file is one
  row even across folders and runs, so it is counted once and you can query and compare
  versions. Disable with `--sin-indice`.
- **Family relations** — builds the relation graph inside a package generically (no
  per-game branding): a text/manifest file that names another → *references*; files
  sharing a base name in the same folder → *family*; same SHA-256 → *duplicate*. A file
  **referenced by a manifest becomes Confirmed**; referenced by any other file becomes
  **Compatible**. Written to `relaciones.md`/`.json`, and it raises the confidence of the
  referenced files with the evidence (`referenced by …`).
- **Classification** — sorts every final file into a category and gathers copies in
  `extraidos/<category>/` (hard links, no disk duplication).
- **Password recovery** (`--clave`, `--comunes`, `--diccionario`, `--fuerza-bruta`) —
  opens protected ZIPs (ZipCrypto and AES) you are entitled to open, so it keeps
  peeling them. Does not break strong AES passwords.
- **Package audit** (`--auditar`) — a defensive verdict per package
  (APPROVED / QUARANTINE / REJECTED) from escape paths, manifest validity, active
  code / native libs, and an extension allowlist. Writes `auditoria.md`.
- **Gate mode** (`--vigilar … --aprobados … --cuarentena …`) — watches an `incoming/`
  folder, audits each package and routes it: approved → the server's Mods folder,
  the rest → quarantine. The server only loads audited packs.
- **Client cache watch** (`--vigilar … --solo-informe`) — audits/classifies whatever
  a server writes to your cache, **without moving or deleting anything**. Detection,
  not pre-load blocking.
- **Cache locator** (`--localizar-cache "App" [--observar N]`) — finds where an app
  stores its cache (by name, or by watching which folder it writes while running).
- **Group related resources** (`--agrupar`) — files sharing a base name in the same
  folder (`world.blocky` + `world.png` + `world.json`) are bundled into one `.zip`.
- **Rebuild packages** (`--reconstruir`) — rebuilds each package's original folder
  tree and a loadable `.zip`, from the already-extracted bytes (decrypted if it was
  password-protected) so files find their dependencies by path again.
- **Plugin / active-code report** — whenever code appears (ELF/PE/Mach-O or bytecode),
  writes `plugins.md`: each plugin with its **functions** and **imported APIs**,
  highlighting sensitive capabilities (network, files, processes, registry, crypto).
  capas **never runs** the code.

## Output

```
out/
  informe.md / .json       the layer tree
  clasificacion.md / .json  files grouped by category
  desconocidos.txt          magic + extension of unrecognized files
  plugins.md / .json        active code with its functions and APIs
  conjuntos.md              resources grouped by base name (--agrupar)
  auditoria.md / .json      per-package verdict (--auditar)
  extraidos/<category>/     a copy of each final file, by category
  extraidos/conjuntos/<name>.zip        each resource set bundled (--agrupar)
  extraidos/reconstruido/<pack>/ and .zip   rebuilt, loadable package (--reconstruir)
  <file>/
    analisis/   headers.txt, disassembly.asm, objdump.asm, javap.txt, strings.txt…
    capas/<child>/   the extracted file + its own analisis/ and capas/ (recursive)
```

## Security

- Extracted paths are sanitized (no `..`, no absolute paths); everything stays under
  the output folder.
- Per-block and total extraction limits guard against decompression bombs.
- Duplicate contents (same SHA-256) are analyzed once.
- Analyzed files are **never executed**; external tools run with a timeout.
- The password module is for archives you are entitled to open (your own forgotten
  passwords, CTFs, authorized forensics). It works on a single file you give it, has
  an attempt cap, and does not brute-force strong crypto.

## Author

Created by **@angelazo**. The signature appears in the window, in `capas --help` and
at the end of each report. MIT license (see `LICENSE`).

The interface is an original design with a '90s "command center" aesthetic (purple,
green, orange). It uses no logos, names or assets from any existing work.
