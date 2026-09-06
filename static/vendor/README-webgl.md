# Vendored browser libraries

Prebuilt UMD browser bundles, no build step. Each is loaded once from
`static/index.html` via a classic `<script>`/`<link>` tag and exposes a window
global. Nothing is fetched from a CDN at runtime.

Provenance check: `shasum -a 256 static/vendor/*` must reproduce the hashes
below. Re-record the hash whenever a bundle is upgraded.

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
