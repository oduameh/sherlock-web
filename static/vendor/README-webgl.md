# Vendored browser libraries

Prebuilt UMD browser bundles, no build step. Each is loaded once from
`static/index.html` via a classic `<script>`/`<link>` tag and exposes a window
global. Nothing is fetched from a CDN at runtime.

Provenance check: `shasum -a 256 static/vendor/* static/vendor/fonts/*` must
reproduce the hashes below (`tests/test_app.py` re-checks the font hashes on
every run). Re-record the hash whenever a bundle is upgraded.

## Case-graph workspace (WebGL)

| File | Package | Version | Global | Origin | sha256 |
|------|---------|---------|--------|--------|--------|
| sigma.min.js | sigma | 2.4.0 | `Sigma` | https://cdnjs.cloudflare.com/ajax/libs/sigma.js/2.4.0/sigma.min.js | `a86b7eb3578e9028ee84d792bf20f1503f0335ce769d5ad454252dc0a5787618` |
| graphology.umd.min.js | graphology | 0.25.4 | `graphology` | https://cdnjs.cloudflare.com/ajax/libs/graphology/0.25.4/graphology.umd.min.js | `641ea047e2f414dead999769d62567ce3c6f1ddc334f1e728bd5edb19d337977` |

sigma.js © Alexis Jacomy et al. — MIT. graphology © Guillaume Plique — MIT.
Neither minified bundle carries a version literal; the versions above are the
ones fetched from the origin URLs and are otherwise unverifiable offline.

## Footprint map

| File | Package | Version | Global | Origin | sha256 |
|------|---------|---------|--------|--------|--------|
| leaflet.js | leaflet | 1.9.4 | `L` | https://unpkg.com/leaflet@1.9.4/dist/leaflet.js | `db49d009c841f5ca34a888c96511ae936fd9f5533e90d8b2c4d57596f4e5641a` |
| leaflet.css | leaflet | 1.9.4 | — | https://unpkg.com/leaflet@1.9.4/dist/leaflet.css | `a7837102824184820dfa198d1ebcd109ff6d0ff9a2672a074b9a1b4d147d04c6` |

Leaflet © 2010-2023 Vladimir Agafonkin, (c) 2010-2011 CloudMade — BSD-2-Clause
(`leaflet.js` carries the `@preserve Leaflet 1.9.4` banner). Basemap tiles are
OpenStreetMap (© OpenStreetMap contributors, ODbL) and are fetched by the
browser at view time; attribution is rendered on the map.

## Self-hosted fonts (Increment H2, 2026-09-06)

`static/index.html` used to load Inter and JetBrains Mono from Google Fonts on
every page view — a third-party request, with the analyst's IP and browser,
each time the console was opened (audit F-11). The families are now served
from `static/vendor/fonts/` and declared by the `@font-face` block at the top
of `static/css/app.css`; the CSP `font-src` is `'self' data:`.

The files are the variable-weight (`wght` axis) woff2 builds that the Google
Fonts API serves to a current Chrome (fetched 2026-09-06 with
`https://fonts.googleapis.com/css2?family=Inter:wght@100..900&family=JetBrains+Mono:wght@100..800`),
split by script with the same `unicode-range` declarations, so a page fetches
only the subsets it renders. Variable builds were chosen deliberately: the
stylesheet uses intermediate weights (450, 560, 620, 650, 680) that static
400/500/600/700 files would snap.

| File | Family | Subset | Weight axis | Bytes | Origin | sha256 |
|------|--------|--------|-------------|-------|--------|--------|
| fonts/inter-cyrillic-ext-normal-wght.woff2 | Inter | cyrillic-ext | 100 900 | 25,844 | https://fonts.gstatic.com/s/inter/v20/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa2JL7W0Q5n-wU.woff2 | `fccca918fea40089dacadc7045861314d1a6bc91f1f323cc1eeb22ebcdb321b5` |
| fonts/inter-cyrillic-normal-wght.woff2 | Inter | cyrillic | 100 900 | 18,744 | https://fonts.gstatic.com/s/inter/v20/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa0ZL7W0Q5n-wU.woff2 | `aebf2ab4a4ce6810d73c1ac7be7cafb4e5ec4cee2d6db5fb3e09691747ec4bd6` |
| fonts/inter-greek-ext-normal-wght.woff2 | Inter | greek-ext | 100 900 | 11,272 | https://fonts.gstatic.com/s/inter/v20/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa2ZL7W0Q5n-wU.woff2 | `a2e2c783ca6f9c20486e81e72a279203e86730bbf8f01ff6a5ee9dbd09e1c271` |
| fonts/inter-greek-normal-wght.woff2 | Inter | greek | 100 900 | 19,044 | https://fonts.gstatic.com/s/inter/v20/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa1pL7W0Q5n-wU.woff2 | `46dd4cdca58c26ae87cc6927657bf83b2e8abfc39ffd0ab176e301a8d28d22bf` |
| fonts/inter-vietnamese-normal-wght.woff2 | Inter | vietnamese | 100 900 | 10,280 | https://fonts.gstatic.com/s/inter/v20/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa2pL7W0Q5n-wU.woff2 | `8db00ff46c67b22cda8bed865acf7077651cac8d2841d5b40980556b48961931` |
| fonts/inter-latin-ext-normal-wght.woff2 | Inter | latin-ext | 100 900 | 85,272 | https://fonts.gstatic.com/s/inter/v20/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa25L7W0Q5n-wU.woff2 | `a28eb6d3ccb534ae0c94ca999371df024aab60b08c3c8a5720ee9e32fa0faaa2` |
| fonts/inter-latin-normal-wght.woff2 | Inter | latin | 100 900 | 48,432 | https://fonts.gstatic.com/s/inter/v20/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa1ZL7W0Q5nw.woff2 | `c940764593d0fe5d596be327ca7558855e018039fb78509aa21921fd3644c3e4` |
| fonts/jetbrainsmono-cyrillic-ext-normal-wght.woff2 | JetBrains Mono | cyrillic-ext | 100 800 | 2,020 | https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbV2o-flEEny0FZhsfKu5WU4xD2OwGtT0rU3BE.woff2 | `992eea2f70210457ddd1196de4df3240919ffe068ad188c79d985fba4565d3bf` |
| fonts/jetbrainsmono-cyrillic-normal-wght.woff2 | JetBrains Mono | cyrillic | 100 800 | 12,064 | https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbV2o-flEEny0FZhsfKu5WU4xD_OwGtT0rU3BE.woff2 | `af7486955880be1c2b972e9c766acffb776768d669b6576ed9a0919ce72e7ca6` |
| fonts/jetbrainsmono-greek-normal-wght.woff2 | JetBrains Mono | greek | 100 800 | 9,084 | https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbV2o-flEEny0FZhsfKu5WU4xD4OwGtT0rU3BE.woff2 | `3edf363dbf9d5fa0cdc784ae2b431a8a4152f4055a8a8858028c0bd668808273` |
| fonts/jetbrainsmono-vietnamese-normal-wght.woff2 | JetBrains Mono | vietnamese | 100 800 | 7,468 | https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbV2o-flEEny0FZhsfKu5WU4xD0OwGtT0rU3BE.woff2 | `1390e86cc2823e759358918c01c4fcc1b6e4f01bca915bdbeb6d68eb5c244405` |
| fonts/jetbrainsmono-latin-ext-normal-wght.woff2 | JetBrains Mono | latin-ext | 100 800 | 15,204 | https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbV2o-flEEny0FZhsfKu5WU4xD1OwGtT0rU3BE.woff2 | `7db7affbce1fdee69c1ffc2641bbca289b049867f524c9d861fe35ab6670bf29` |
| fonts/jetbrainsmono-latin-normal-wght.woff2 | JetBrains Mono | latin | 100 800 | 40,480 | https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbV2o-flEEny0FZhsfKu5WU4xD7OwGtT0rU.woff2 | `1e06740a02a443fb7f3eeda8fcaa685a0f6c620e3f01e6666e847295469ce3ad` |

Inter © 2016–2024 The Inter Project Authors (rsms.me/inter) — SIL Open Font
License 1.1. JetBrains Mono © 2020 The JetBrains Mono Project Authors
(github.com/JetBrains/JetBrainsMono) — SIL Open Font License 1.1. The OFL
permits bundling and redistribution of the font files with software; the
Google-served builds carry no version literal, so the `v20`/`v24` path
segments above are the only version marker and are otherwise unverifiable
offline. Total 305 KB; a Latin-only page fetches 89 KB.

## Removed (Increment F, 2026-09-06)

The inline Cytoscape identity graph had no caller (`renderGraph` was never
invoked once the Graph action opened the case graph), so its whole vendor
stack was deleted along with the graph panel markup, its JS and its CSS:

| File | Package | Size | Reason |
|------|---------|------|--------|
| cytoscape.min.js | cytoscape 3.30.4 | 374 KB | unreachable renderer |
| layout-base.js | cytoscape-layout-base 2.0.1 | 148 KB | fcose dependency |
| cose-base.js | cose-base 2.2.0 | 119 KB | fcose dependency |
| cytoscape-fcose.js | cytoscape-fcose 2.2.0 | 57 KB | layout for the removed renderer |
| cytoscape-navigator.js / .css | cytoscape.js-navigator 2.0.2 | 30 KB | minimap for the removed renderer |
| graphology-library.min.js | graphology-library 0.8.0 | 168 KB | never referenced by any `<script>` tag or JS |

Roughly 900 KB of JavaScript no longer ships or parses on every page load.
