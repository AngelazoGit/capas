// Renderiza las tarjetas OG (1200x630) con el número de versión estampado.
// Uso: node build.cjs v0.1.7   (o VERSION=v0.1.7 node build.cjs)
// Las plantillas og.html / og-es.html llevan el marcador __VER__.
const { chromium } = require('playwright');
const { readFileSync, writeFileSync, unlinkSync } = require('fs');
const { join } = require('path');

const raw = process.argv[2] || process.env.VERSION || 'v0.0.0';
const ver = 'v' + raw.replace(/^v/, '');
const here = __dirname;
const cards = [['og.html', 'og.png'], ['og-es.html', 'og-es.png']];

(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  for (const [tpl, out] of cards) {
    const html = readFileSync(join(here, tpl), 'utf8').split('__VER__').join(ver);
    const tmp = join(here, '.tmp-' + tpl);
    writeFileSync(tmp, html);
    const page = await browser.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1 });
    await page.goto('file://' + tmp);
    await page.waitForTimeout(400);
    await page.screenshot({ path: join(here, '..', out) });
    await page.close();
    unlinkSync(tmp);
  }
  await browser.close();
  console.log('OG cards rendered for', ver);
})();
