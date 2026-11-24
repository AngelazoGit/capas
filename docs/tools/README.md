# Herramientas de la web

## make_es.js
Regenera `docs/es/index.html` (español, indexable) desde `docs/index.html`.
El texto español vive en los atributos `data-es` / `data-es-html` de la página
inglesa, así que sólo se mantiene **una** página fuente.

```bash
npm i playwright     # una vez
node docs/tools/make_es.js
```

Ejecútalo cada vez que edites textos en `docs/index.html`, y vuelve a hacer
commit de `docs/es/index.html`.
