// Genera docs/es/index.html (versión en español, indexable) a partir de
// docs/index.html (inglés). El texto español sale de los atributos data-es /
// data-es-html que ya lleva la página inglesa, así no se mantienen dos copias.
//
// Uso:
//   npm i playwright        (una vez)
//   node docs/tools/make_es.js
//
// Ejecútalo cada vez que cambies textos en docs/index.html.

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const DOCS = path.join(__dirname, '..');
const SRC = path.join(DOCS, 'index.html');
const OUT_DIR = path.join(DOCS, 'es');
const OUT = path.join(OUT_DIR, 'index.html');

(async () => {
  const b = await chromium.launch({ args: ['--no-sandbox', '--headless=new'] });
  const p = await b.newPage();
  await p.goto('file://' + SRC, { waitUntil: 'networkidle' });
  await p.waitForTimeout(900); // deja que el script popule data-en
  const html = await p.evaluate(() => {
    document.documentElement.setAttribute('lang', 'es');
    document.querySelectorAll('[data-es]').forEach(e => { e.textContent = e.getAttribute('data-es'); });
    document.querySelectorAll('[data-es-html]').forEach(e => { e.innerHTML = e.getAttribute('data-es-html'); });
    // rutas relativas suben un nivel desde /es/
    const img = document.querySelector('.appshot img'); if (img) img.setAttribute('src', '../capas-app.png');
    const fav = document.querySelector('link[rel="icon"]'); if (fav) fav.setAttribute('href', '../favicon.svg');
    // head en español + canonical /es/
    document.title = 'CAPAS — Decompilador de archivos por capas';
    const set = (sel, attr, val) => { const el = document.querySelector(sel); if (el) el.setAttribute(attr, val); };
    set('meta[name="description"]', 'content', 'Abre cualquier archivo y lee todas sus capas. CAPAS identifica por contenido, decompila, extrae cada capa y audita packs y mods — sin conexión, y nunca ejecuta lo que analiza. Núcleo gratis; Pro desempaqueta bundles de Unity y Godot.');
    set('link[rel="canonical"]', 'href', 'https://capas.dev/es/');
    set('meta[property="og:title"]', 'content', 'CAPAS — decompilador de archivos por capas');
    set('meta[property="og:description"]', 'content', 'Mira lo que hay de verdad dentro de cualquier archivo. Gratis, sin conexión, y nunca ejecuta lo que analiza.');
    set('meta[property="og:url"]', 'content', 'https://capas.dev/es/');
    set('meta[name="twitter:title"]', 'content', 'CAPAS — decompilador de archivos por capas');
    set('meta[name="twitter:description"]', 'content', 'Abre cualquier archivo y lee todas sus capas. Sin conexión, núcleo gratis.');
    const sc = [...document.querySelectorAll('script')].find(s => s.textContent.includes('capas-lang'));
    if (sc) sc.textContent = sc.textContent.replace('var lang="en"', 'var lang="es"');
    return '<!doctype html>\n' + document.documentElement.outerHTML;
  });
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(OUT, html);
  await b.close();
  console.log('docs/es/index.html regenerado (' + html.length + ' bytes)');
})();
