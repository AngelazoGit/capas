// CAPAS — entrega automática de licencias (Cloudflare Worker).
//
// Al recibir el webhook "order_created" de Lemon Squeezy: verifica la firma,
// decide la edición (Pro/Studio), firma una clave única CAPAS-... con la clave
// privada Ed25519 (secreto del Worker) y la envía por email al comprador con
// Resend. Idempotente: cada pedido conserva su misma clave aunque el webhook
// se reintente. Nada de esto expone la clave privada: vive solo como secreto.
//
// Secretos (Settings → Variables → Encrypt): CAPAS_PRIVATE_KEY, LS_WEBHOOK_SECRET,
// RESEND_API_KEY. Variables normales: FROM_EMAIL (opcional), STUDIO_VARIANT_ID /
// PRO_VARIANT_ID (opcional). Binding KV: CAPAS_KEYS. Secreto opcional: ADMIN_SECRET.

const subtle = globalThis.crypto.subtle;
const enc = (s) => new TextEncoder().encode(s);
const hexToBytes = (h) => new Uint8Array(h.trim().match(/.{2}/g).map((x) => parseInt(x, 16)));
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function b64url(d) {
  let s = '';
  for (let i = 0; i < d.length; i += 3) {
    const b = [d[i], d[i + 1] || 0, d[i + 2] || 0];
    const n = (b[0] << 16) | (b[1] << 8) | b[2];
    const take = Math.min(3, d.length - i) + 1;
    for (let j = 0; j < take; j++) s += B64[(n >> (18 - 6 * j)) & 0x3f];
  }
  return s;
}
function u64le(buf, off, num) {
  let v = BigInt(num);
  for (let i = 0; i < 8; i++) { buf[off + i] = Number(v & 0xffn); v >>= 8n; }
}

// Firma una clave CAPAS-... (mismo formato que el binario: 24 datos + 64 firma).
async function firmarClave(privHex, edicion, dias) {
  const seed = hexToBytes(privHex);
  if (seed.length !== 32) throw new Error('CAPAS_PRIVATE_KEY debe ser 32 bytes (64 hex)');
  const pkcs8 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, ...seed]);
  const key = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  const now = Math.floor(Date.now() / 1000);
  const expira = dias > 0 ? now + dias * 86400 : 0;
  const id = crypto.getRandomValues(new Uint8Array(6));
  const msg = new Uint8Array(24);
  msg[0] = 1;
  msg[1] = edicion === 'studio' ? 2 : edicion === 'pro' ? 1 : 0;
  u64le(msg, 2, now);
  u64le(msg, 10, expira);
  msg.set(id, 18);
  const sig = new Uint8Array(await subtle.sign('Ed25519', key, msg));
  const payload = new Uint8Array(88);
  payload.set(msg, 0);
  payload.set(sig, 24);
  return 'CAPAS-' + b64url(payload);
}

// Verifica la firma de un webhook de Stripe (cabecera Stripe-Signature: t=..,v1=..).
async function verificarStripe(secret, header, cuerpo) {
  if (!header) return false;
  const p = {};
  for (const kv of header.split(',')) { const i = kv.indexOf('='); if (i > 0) p[kv.slice(0, i).trim()] = kv.slice(i + 1).trim(); }
  if (!p.t || !p.v1) return false;
  if (Math.abs(Date.now() / 1000 - Number(p.t)) > 300) return false; // tolerancia 5 min
  const key = await subtle.importKey('raw', enc(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  try { return await subtle.verify('HMAC', key, hexToBytes(p.v1), enc(`${p.t}.${cuerpo}`)); } catch { return false; }
}

function edicionDesde(session) {
  // Preferimos metadata.edition del Payment Link; si no, por el importe (2900=Pro, 7900=Studio).
  const m = (session?.metadata?.edition || '').toLowerCase();
  if (m === 'studio' || m === 'pro') return m;
  return Number(session?.amount_total) >= 5000 ? 'studio' : 'pro';
}

function emailHtml(token, edicion) {
  return `<div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;color:#1a1b1f">
    <h2 style="font-family:Georgia,serif">Your CAPAS ${edicion === 'studio' ? 'Studio' : 'Pro'} license</h2>
    <p>Thanks for your purchase. Here is your license key:</p>
    <pre style="background:#f1f1f4;border:1px solid #e4e4ea;padding:12px;font-size:13px;white-space:pre-wrap;word-break:break-all">${token}</pre>
    <p><b>How to activate (any one):</b></p>
    <ul>
      <li>Open CAPAS → <b>Parameters</b> → <b>Activate with key</b> → paste the key.</li>
      <li>Or save it as a file named <code>capas.lic</code> next to <code>capas.exe</code>.</li>
      <li>Or run: <code>capas.exe --licencia-clave &lt;key&gt;</code></li>
    </ul>
    <p style="color:#73767f;font-size:13px">It works offline — no account needed. Keep this email to re-activate on another machine.</p>
    <hr style="border:none;border-top:1px solid #e4e4ea">
    <p style="color:#73767f;font-size:12px">CAPAS · capas.dev</p>
  </div>`;
}

async function enviarEmail(env, to, token, edicion) {
  const from = env.FROM_EMAIL || 'CAPAS <keys@capas.dev>';
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from, to: [to], subject: `Your CAPAS ${edicion === 'studio' ? 'Studio' : 'Pro'} license key`, html: emailHtml(token, edicion) }),
  });
  if (!r.ok) throw new Error(`Resend ${r.status}: ${await r.text()}`);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (req.method === 'GET' && url.pathname === '/') {
      return new Response('CAPAS license worker: OK', { status: 200 });
    }

    // Reenvío manual de una clave ya emitida (soporte): /lookup?order=ID
    if (req.method === 'GET' && url.pathname === '/lookup') {
      const auth = req.headers.get('Authorization') || '';
      if (!env.ADMIN_SECRET || auth !== `Bearer ${env.ADMIN_SECRET}`) return new Response('unauthorized', { status: 401 });
      const rec = await env.CAPAS_KEYS.get(`order:${url.searchParams.get('order')}`);
      return rec ? new Response(rec, { status: 200, headers: { 'Content-Type': 'application/json' } }) : new Response('not found', { status: 404 });
    }

    if (req.method !== 'POST') return new Response('method not allowed', { status: 405 });

    const raw = await req.text();
    const secreto = env.STRIPE_WEBHOOK_SECRET || env.LS_WEBHOOK_SECRET;
    if (!(await verificarStripe(secreto, req.headers.get('Stripe-Signature'), raw))) {
      return new Response('bad signature', { status: 401 });
    }

    let body;
    try { body = JSON.parse(raw); } catch { return new Response('bad json', { status: 400 }); }

    if (body?.type !== 'checkout.session.completed') return new Response('ignored', { status: 200 });

    const session = body?.data?.object || {};
    const orderId = String(session.id ?? '');
    const email = session.customer_details?.email || session.customer_email;
    if (!orderId || !email) return new Response('missing order/email', { status: 200 });
    if (session.payment_status && session.payment_status !== 'paid') return new Response('unpaid', { status: 200 });

    const clave = `order:${orderId}`;
    let rec = await env.CAPAS_KEYS.get(clave, { type: 'json' });
    if (!rec) {
      const edicion = edicionDesde(session);
      const token = await firmarClave(env.CAPAS_PRIVATE_KEY, edicion, 0);
      rec = { token, edicion, email, ts: Date.now() };
      await env.CAPAS_KEYS.put(clave, JSON.stringify(rec));
    }

    // Enviar (o reenviar) el email. Si falla, 500 → Lemon Squeezy reintenta
    // y reutiliza la misma clave almacenada.
    try {
      await enviarEmail(env, rec.email, rec.token, rec.edicion);
    } catch (e) {
      return new Response(`email failed: ${e.message}`, { status: 500 });
    }

    return new Response('ok', { status: 200 });
  },
};
