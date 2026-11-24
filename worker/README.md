# CAPAS — Worker de entrega automática de licencias

Firma una clave única `CAPAS-...` por venta y la envía por email al comprador,
al instante, sin que tú toques nada. Validado: la firma Ed25519 en WebCrypto es
byte-compatible con la verificación del binario.

Flujo:  Lemon Squeezy (venta) → webhook → este Worker (firma + email con Resend) → comprador.

## Piezas y secretos
- **KV binding** `CAPAS_KEYS` (guarda la clave por pedido; idempotente).
- **Secretos** (cifrados): 
  - `CAPAS_PRIVATE_KEY` = tu clave privada (contenido de `capas_private.key`, 64 hex).
    Debe ser la pareja de la pública incrustada en el .exe (`8f979b...`).
  - `LS_WEBHOOK_SECRET` = el secreto de firma del webhook de Lemon Squeezy.
  - `RESEND_API_KEY` = API key de Resend (para enviar el email).
  - `ADMIN_SECRET` (opcional) = cualquier cadena aleatoria, para `/lookup`.
- **Variables** (opcionales): `FROM_EMAIL` (por defecto `CAPAS <keys@capas.dev>`),
  `STUDIO_VARIANT_ID`, `PRO_VARIANT_ID` (si prefieres mapear por ID en vez de por nombre).

## Paso 1 — Resend (envío de email)
1. Crea cuenta en resend.com.
2. **Add Domain** → `capas.dev`. Resend te da unos registros DNS (TXT/DKIM/MX).
   Añádelos en Cloudflare → DNS de `capas.dev` (te los paso yo si quieres) → Verify.
3. **API Keys → Create** → copia la clave (es `RESEND_API_KEY`).

## Paso 2 — Cloudflare Worker
1. **Workers & Pages → Create → Workers → Create Worker**. Nómbralo `capas-license` → Deploy.
2. **Edit code**: borra el ejemplo, pega `worker.js` de esta carpeta → **Deploy**.
3. Crea un KV: **Storage & Databases → KV → Create namespace** → `capas-keys`.
4. En el Worker: **Settings → Bindings → Add → KV namespace**:
   variable `CAPAS_KEYS` → namespace `capas-keys`.
5. En el Worker: **Settings → Variables and Secrets** → añade como **Secret (Encrypt)**:
   `CAPAS_PRIVATE_KEY`, `LS_WEBHOOK_SECRET`, `RESEND_API_KEY` (y `ADMIN_SECRET` si quieres).
6. Copia la **URL del Worker** (`https://capas-license.<tu-subdominio>.workers.dev`).
   (Opcional: en Settings → Domains & Routes, ponle `license.capas.dev`.)

## Paso 3 — Webhook en Lemon Squeezy
1. **Settings → Webhooks → Add webhook**.
2. **Callback URL** = la URL del Worker.
3. **Signing secret** = inventa una cadena aleatoria y pon ESA MISMA en el secreto
   `LS_WEBHOOK_SECRET` del Worker.
4. **Events**: marca **order_created**. Guarda.
5. En los productos Pro/Studio: NO hace falta subir archivo; el Worker entrega la clave.

## Paso 4 — Probar
En modo test de Lemon Squeezy, haz una compra de prueba. En segundos debería
llegar el email con la clave. Pégala en CAPAS → Parámetros → Activar con clave.

## Reenviar una clave (soporte)
Si un cliente pierde el email: `GET /lookup?order=<ID>` con cabecera
`Authorization: Bearer <ADMIN_SECRET>` devuelve la clave guardada.

> La clave privada vive SOLO como secreto del Worker; nunca en el repo ni en el chat.
