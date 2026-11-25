# CAPAS — puente MCP para IA / MCP bridge for AI

CAPAS puede funcionar como **servidor MCP** (Model Context Protocol): expone su
análisis por capas como *herramientas* que cualquier IA con cliente MCP puede
usar — **Claude Desktop (Anthropic)**, clientes con **OpenAI**, o una IA **local
con Ollama**.

**CAPAS nunca llama a ninguna IA.** Es la IA quien llama a CAPAS. El análisis
sigue siendo 100% local; lo único que puede salir a la nube es lo que *tú* decidas
enviarle a tu modelo a través de su cliente. Un servidor MCP local **no** implica
que el modelo sea local.

---

## Arrancarlo / Run it

```bash
capas --mcp
```

Habla JSON-RPC 2.0 por **stdio** (mensajes separados por saltos de línea). No lo
ejecutas a mano: lo lanza tu cliente de IA con la configuración de abajo. La
salida de diagnóstico va a *stderr*; *stdout* es solo el protocolo.

## Herramientas expuestas / Tools

| Tool | Qué hace |
|---|---|
| `capas_analyze_file` | Analiza un archivo/carpeta capa a capa y devuelve el árbol de bloques (tipo, confianza, tamaño, incompletos) + rutas de informe. Args: `path` (obligatorio), `max_depth`, `classify`, `audit`, `use_external_tools`. |
| `capas_list_formats` | Las 729 extensiones en 11 categorías y qué hace CAPAS con cada una. |
| `capas_inspect_output` | Resume un análisis previo (lee su `informe.json`). Arg: `folder`. |

---

## Conectar una IA / Connect an AI

Pon la **ruta absoluta** a tu binario (`capas.exe` en Windows, `capas` en
Linux/macOS).

### Claude Desktop (Anthropic)
Edita `claude_desktop_config.json`
(Windows: `%APPDATA%\Claude\`, macOS: `~/Library/Application Support/Claude/`):

```json
{
  "mcpServers": {
    "capas": {
      "command": "C:\\ruta\\a\\capas.exe",
      "args": ["--mcp"]
    }
  }
}
```
Reinicia Claude Desktop; verás las tools de CAPAS disponibles.

### VS Code (Cline / Continue) u otros clientes MCP
Añade un servidor MCP con el comando `capas` y el argumento `--mcp`:

```json
{
  "mcpServers": {
    "capas": { "command": "capas", "args": ["--mcp"] }
  }
}
```

### IA local con Ollama (vía mcphost)
[mcphost](https://github.com/mark3labs/mcphost) conecta modelos de Ollama con
servidores MCP. `mcp.json`:

```json
{
  "mcpServers": {
    "capas": { "command": "capas", "args": ["--mcp"] }
  }
}
```
```bash
ollama pull qwen2.5
mcphost --config mcp.json -m ollama:qwen2.5
```

### OpenAI y otros
Cualquier cliente/host compatible con MCP (p. ej. LibreChat, Cline, o el
*OpenAI Agents SDK* con soporte MCP) puede conectar `capas --mcp` igual que
arriba: comando `capas`, argumento `--mcp`.

---

## Privacidad / Privacy

- CAPAS lee y extrae **en local**; nunca ejecuta lo que inspecciona ni abre
  conexiones por su cuenta.
- Lo que el modelo reciba (nombres, árbol, fragmentos que le pidas) **sale a ese
  proveedor** si el modelo es en la nube. Con Ollama local, nada sale del equipo.
- Decide qué compartir. Para análisis sensibles, usa un modelo local.

## Problemas / Troubleshooting

- El cliente no ve las tools → revisa la ruta absoluta del binario y que
  `capas --mcp` arranca a mano (debería quedarse esperando entrada).
- Prueba rápida por stdio:
  ```bash
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | capas --mcp
  ```
  Debe devolver la lista de `tools`.
