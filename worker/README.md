# CAPAS — Worker de entrega automática de licencias (Stripe)

Firma una clave única `CAPAS-...` por venta y la envía por email al comprador al
instante. La firma Ed25519 (WebCrypto) es byte-compatible con la verificación del
binario. Pensado para **Stripe** (Checkout / Payment Links / Managed Payments).

Flujo:  Stripe (venta) → webhook `checkout.session.completed` → este Worker (firma + email con Resend) → comprador.

## Piezas
- **KV binding** `CAPAS_KEYS` (guarda la clave por pedido; idempotente).
- **Secretos** (cifrados):
  - `CAPAS_PRIVATE_KEY` = tu clave privada Ed25519 (64 hex). Pareja de la pública del .exe.
  - `STRIPE_WEBHOOK_SECRET` = el "Signing secret" (`whsec_...`) que te da Stripe al crear el webhook.
    (El Worker también acepta el valor en `LS_WEBHOOK_SECRET` por compatibilidad, así puedes
    reutilizar ese mismo secreto cambiándole el valor al `whsec_...`.)
  - `RESEND_API_KEY` = API key de Resend.
  - `ADMIN_SECRET` (opcional) = para el endpoint de reenvío `/lookup`.
- **Variables** (opcionales): `FROM_EMAIL` (por defecto `CAPAS <keys@capas.dev>`).

## Edición Pro vs Studio
El Worker la decide así:
1. Si el Payment Link lleva **metadata `edition` = `pro` o `studio`** → usa eso (recomendado).
2. Si no, por el **importe**: `amount_total` ≥ 3800 (38 $) → Studio; si no → Pro.
   (Separa Pro de Studio incluso con el 40% de descuento: Studio con descuento = 47,40 $.)

Al crear los Payment Links en Stripe, añade metadata `edition=pro` / `edition=studio`
para que sea exacto aunque cambies precios.

## Despliegue (resumen)
1. **Cloudflare Worker** `capas-license`: pega `worker.js`, crea KV `capas-keys` y
   enlázalo como `CAPAS_KEYS`. Añade los secretos de arriba. Deploy.
2. **Stripe → Developers → Webhooks → Add endpoint**:
   - URL = la del Worker (`https://capas-license.<sub>.workers.dev`).
   - Evento = **`checkout.session.completed`**.
   - Copia el **Signing secret** (`whsec_...`) → ponlo en el secreto `STRIPE_WEBHOOK_SECRET`
     del Worker (o reutiliza `LS_WEBHOOK_SECRET` con ese valor).
3. **Stripe → Products**: crea CAPAS Pro (29 $) y CAPAS Studio (79 $), y un **Payment Link**
   por producto, con metadata `edition=pro` / `edition=studio`. Esos enlaces son los botones de la web.
4. **Probar**: compra de prueba en modo test → llega el email con la clave → se activa en CAPAS.

## Reenviar una clave (soporte)
`GET /lookup?order=<session_id>` con cabecera `Authorization: Bearer <ADMIN_SECRET>`.

> La clave privada vive SOLO como secreto del Worker; nunca en el repo ni en el chat.
